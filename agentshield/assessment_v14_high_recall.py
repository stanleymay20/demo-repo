"""AgentShield assessment v14 high-recall research experiment.

Research-only successor experiment. It does not modify the frozen assessment notebook.
Benchmark/test labels are never accessed.
"""

from __future__ import annotations

import gc
import hashlib
import json
import os
import re
import time
import warnings

import numpy as np
import pandas as pd
from bs4 import BeautifulSoup, Comment
from datasets import load_dataset
from scipy.sparse import hstack
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
    roc_curve,
)
from sklearn.model_selection import train_test_split
from sklearn.svm import LinearSVC

warnings.filterwarnings("ignore")

SEED = 42
np.random.seed(SEED)
LAB = {"no": 0, "yes": 1}
WS = re.compile(r"\s+")
MAX_FPR = 0.01


def normalized_digest(s: str | None) -> bytes:
    text = "" if s is None else str(s)
    norm = WS.sub(" ", text.lower()).strip()
    return hashlib.sha256(norm.encode("utf-8", "ignore")).digest()


def clean_training_split(train, test):
    # Test labels are deliberately never read; content hashes only remove overlap.
    test_hashes = {normalized_digest(x) for x in test["content"]}
    seen, keep = set(), []
    dups = overlap = 0
    for i, content in enumerate(train["content"]):
        h = normalized_digest(content)
        if h in seen:
            dups += 1
            continue
        if h in test_hashes:
            overlap += 1
            continue
        seen.add(h)
        keep.append(i)
    return train.select(keep), dups, overlap


def make_views(raw):
    raw = "" if raw is None else str(raw)
    soup = BeautifulSoup(raw, "lxml")
    comments = [str(x) for x in soup.find_all(string=lambda t: isinstance(t, Comment))]
    hidden, attrs = [], []
    interesting = {
        "aria-label", "title", "alt", "value", "style", "hidden",
        "placeholder", "onclick", "role",
    }
    for tag in soup.find_all(True):
        style = str(tag.get("style", "")).lower().replace(" ", "")
        if (
            tag.has_attr("hidden")
            or "display:none" in style
            or "visibility:hidden" in style
            or (tag.name == "input" and str(tag.get("type", "")).lower() == "hidden")
        ):
            hidden.append(tag.get_text(" ", strip=True))
        for key, value in tag.attrs.items():
            if key.startswith("data-") or key in interesting:
                if isinstance(value, list):
                    value = " ".join(map(str, value))
                attrs.append(f"{key} {value}")
    for tag in soup(["script", "style"]):
        tag.decompose()
    text = " ".join(soup.stripped_strings)
    evidence = " ".join(comments + hidden + attrs)
    combined = f"[TEXT] {text} [HIDDEN] {evidence}"
    return raw, text, evidence, combined


def frame(dataset, ids):
    rows = []
    subset = dataset.select([int(i) for i in ids])
    for batch in subset.iter(batch_size=16):
        for raw, label in zip(batch["content"], batch["label"]):
            raw_html, text, evidence, combined = make_views(raw)
            rows.append(
                {
                    "raw": raw_html,
                    "text": text,
                    "evidence": evidence,
                    "combined": combined,
                    "y": LAB[label],
                }
            )
    return pd.DataFrame(rows)


def metrics(y, score, threshold):
    pred = (score >= threshold).astype(np.int8)
    tn, fp, fn, tp = confusion_matrix(y, pred).ravel()
    return {
        "threshold": float(threshold),
        "precision": float(precision_score(y, pred, zero_division=0)),
        "recall": float(recall_score(y, pred, zero_division=0)),
        "f1": float(f1_score(y, pred, zero_division=0)),
        "roc_auc": float(roc_auc_score(y, score)),
        "fpr": float(fp / (fp + tn)),
        "tn": int(tn),
        "fp": int(fp),
        "fn": int(fn),
        "tp": int(tp),
    }


def threshold_at_fpr(y, score, max_fpr=MAX_FPR):
    fpr, tpr, thresholds = roc_curve(y, score)
    valid = np.where(fpr <= max_fpr)[0]
    best_tpr = tpr[valid].max()
    tied = valid[tpr[valid] == best_tpr]
    # Conservative tie break: highest threshold.
    return float(np.max(thresholds[tied]))


def wilson(k, n, z=1.96):
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * np.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return [float(c - h), float(c + h)]


def fit_features(dev, val):
    # E01-style semantic stack.
    word = TfidfVectorizer(
        ngram_range=(1, 2), min_df=2, max_df=0.995, max_features=60000,
        sublinear_tf=True, strip_accents="unicode", dtype=np.float32,
    )
    char = TfidfVectorizer(
        analyzer="char_wb", ngram_range=(3, 5), min_df=2, max_features=90000,
        sublinear_tf=True, dtype=np.float32,
    )
    evidence = TfidfVectorizer(
        analyzer="char", ngram_range=(3, 5), min_df=2, max_features=30000,
        sublinear_tf=True, dtype=np.float32,
    )
    raw_char = TfidfVectorizer(
        analyzer="char", ngram_range=(3, 5), min_df=2, max_features=120000,
        sublinear_tf=True, dtype=np.float32,
    )

    t0 = time.time()
    dw = word.fit_transform(dev["combined"])
    dc = char.fit_transform(dev["combined"])
    de = evidence.fit_transform(dev["evidence"])
    dr = raw_char.fit_transform(dev["raw"])

    vw = word.transform(val["combined"])
    vc = char.transform(val["combined"])
    ve = evidence.transform(val["evidence"])
    vr = raw_char.transform(val["raw"])

    semantic_d = hstack([dw, dc, de], format="csr")
    semantic_v = hstack([vw, vc, ve], format="csr")
    raw_d, raw_v = dr, vr
    hybrid_d = hstack([semantic_d, dr], format="csr")
    hybrid_v = hstack([semantic_v, vr], format="csr")

    meta = {
        "word_features": int(dw.shape[1]),
        "combined_char_features": int(dc.shape[1]),
        "evidence_features": int(de.shape[1]),
        "raw_html_char_features": int(dr.shape[1]),
        "semantic_features": int(semantic_d.shape[1]),
        "hybrid_features": int(hybrid_d.shape[1]),
        "fit_transform_s": float(time.time() - t0),
    }
    vectorizers = {"word": word, "char": char, "evidence": evidence, "raw_char": raw_char}
    matrices = {
        "semantic": (semantic_d, semantic_v),
        "raw_html": (raw_d, raw_v),
        "hybrid": (hybrid_d, hybrid_v),
    }
    return vectorizers, matrices, meta


def audit_matrix(audit, vectorizers, family):
    vw = vectorizers["word"].transform(audit["combined"])
    vc = vectorizers["char"].transform(audit["combined"])
    ve = vectorizers["evidence"].transform(audit["evidence"])
    vr = vectorizers["raw_char"].transform(audit["raw"])
    semantic = hstack([vw, vc, ve], format="csr")
    if family == "semantic":
        return semantic
    if family == "raw_html":
        return vr
    if family == "hybrid":
        return hstack([semantic, vr], format="csr")
    raise ValueError(f"unknown family {family}")


def model_score(model, matrix, model_type):
    if model_type == "svc":
        return model.decision_function(matrix)
    return model.predict_proba(matrix)[:, 1]


def main():
    os.makedirs("agentshield/results", exist_ok=True)
    print("Loading BrowseSafe...")
    ds = load_dataset("perplexity-ai/browsesafe-bench", token=False)
    train_raw, test = ds["train"], ds["test"]
    train, dup_count, overlap_count = clean_training_split(train_raw, test)
    print("Removed normalized train duplicates:", dup_count)
    print("Removed train/test content overlap:", overlap_count)

    y = np.array([LAB[x] for x in train["label"]], dtype=np.int8)
    idx = np.arange(len(train))
    work, audit_idx = train_test_split(idx, test_size=0.15, stratify=y, random_state=SEED)
    dev_idx, val_idx = train_test_split(
        work, test_size=0.1764706, stratify=y[work], random_state=SEED
    )
    print("Development / validation / audit:", len(dev_idx), len(val_idx), len(audit_idx))

    t0 = time.time()
    dev, val = frame(train, dev_idx), frame(train, val_idx)
    print("Development+validation extraction s:", round(time.time() - t0, 2))

    vectorizers, matrices, feature_meta = fit_features(dev, val)
    yd, yv = dev.y.to_numpy(), val.y.to_numpy()
    print("Feature metadata:", json.dumps(feature_meta, indent=2))

    rows = []
    candidates = {}
    val_scores = {}

    svc_cs = [0.05, 0.1, 0.25, 0.5, 1.0, 2.0]
    pos_weights = [1.0, 1.5, 2.0, 3.0]

    for family in ("semantic", "raw_html", "hybrid"):
        dmat, vmat = matrices[family]
        for c in svc_cs:
            for pw in pos_weights:
                name = f"{family}|svc|C={c:g}|pw={pw:g}"
                model = LinearSVC(
                    C=c,
                    class_weight={0: 1.0, 1: pw},
                    random_state=SEED,
                    max_iter=5000,
                )
                t = time.time()
                model.fit(dmat, yd)
                fit_s = time.time() - t
                score = model.decision_function(vmat)
                threshold = threshold_at_fpr(yv, score)
                m = metrics(yv, score, threshold)
                m.update(name=name, family=family, model_type="svc", fit_s=float(fit_s))
                rows.append(m)
                candidates[name] = model
                val_scores[name] = score
                print("VAL", name, "recall", round(m["recall"], 5), "fpr", round(m["fpr"], 5), "auc", round(m["roc_auc"], 5))

    # Probabilistic comparison over the two richest text views.
    for family in ("semantic", "hybrid"):
        dmat, vmat = matrices[family]
        for c in [0.25, 0.5, 1.0, 2.0]:
            for pw in [1.0, 1.5, 2.0]:
                name = f"{family}|logreg|C={c:g}|pw={pw:g}"
                model = LogisticRegression(
                    C=c,
                    class_weight={0: 1.0, 1: pw},
                    max_iter=1800,
                    solver="liblinear",
                    random_state=SEED,
                )
                t = time.time()
                model.fit(dmat, yd)
                fit_s = time.time() - t
                score = model.predict_proba(vmat)[:, 1]
                threshold = threshold_at_fpr(yv, score)
                m = metrics(yv, score, threshold)
                m.update(name=name, family=family, model_type="logreg", fit_s=float(fit_s))
                rows.append(m)
                candidates[name] = model
                val_scores[name] = score
                print("VAL", name, "recall", round(m["recall"], 5), "fpr", round(m["fpr"], 5), "auc", round(m["roc_auc"], 5))

    base_df = pd.DataFrame(rows)
    base_df = base_df.sort_values(
        ["recall", "roc_auc", "precision", "threshold"],
        ascending=[False, False, False, False],
    ).reset_index(drop=True)

    # Best validation candidate from each family is eligible for pairwise fusion.
    family_winners = {}
    for family in ("semantic", "raw_html", "hybrid"):
        family_winners[family] = base_df[base_df.family == family].iloc[0]["name"]
    print("FAMILY WINNERS", json.dumps(family_winners, indent=2))

    fusion_rows = []
    fusion_specs = {}
    families = list(family_winners)
    for i in range(len(families)):
        for j in range(i + 1, len(families)):
            fa, fb = families[i], families[j]
            na, nb = family_winners[fa], family_winners[fb]
            sa, sb = val_scores[na], val_scores[nb]
            ma, sda = float(sa.mean()), float(sa.std() or 1.0)
            mb, sdb = float(sb.mean()), float(sb.std() or 1.0)
            za, zb = (sa - ma) / sda, (sb - mb) / sdb
            for alpha in np.linspace(0.1, 0.9, 9):
                score = alpha * za + (1 - alpha) * zb
                threshold = threshold_at_fpr(yv, score)
                m = metrics(yv, score, threshold)
                name = f"fusion|{fa}+{fb}|alpha={alpha:.1f}"
                m.update(name=name, family="fusion", model_type="fusion", fit_s=0.0)
                fusion_rows.append(m)
                fusion_specs[name] = {
                    "a_name": na,
                    "b_name": nb,
                    "a_family": fa,
                    "b_family": fb,
                    "alpha": float(alpha),
                    "a_mean": ma,
                    "a_std": sda,
                    "b_mean": mb,
                    "b_std": sdb,
                }
                val_scores[name] = score
                print("VAL", name, "recall", round(m["recall"], 5), "fpr", round(m["fpr"], 5), "auc", round(m["roc_auc"], 5))

    all_df = pd.concat([base_df, pd.DataFrame(fusion_rows)], ignore_index=True)
    all_df = all_df.sort_values(
        ["recall", "roc_auc", "precision", "threshold"],
        ascending=[False, False, False, False],
    ).reset_index(drop=True)
    all_df.to_csv("agentshield/results/assessment_v14_validation.csv", index=False)

    winner = all_df.iloc[0].to_dict()
    winner_name = winner["name"]
    print("VALIDATION WINNER", json.dumps(winner, indent=2))

    # Only now construct and score the audit split.
    t0 = time.time()
    audit = frame(train, audit_idx)
    print("Audit extraction s:", round(time.time() - t0, 2))
    ya = audit.y.to_numpy()

    if winner["model_type"] != "fusion":
        fam = winner["family"]
        amat = audit_matrix(audit, vectorizers, fam)
        audit_score = model_score(candidates[winner_name], amat, winner["model_type"])
        audit_spec = {"type": "base", "name": winner_name, "family": fam}
    else:
        spec = fusion_specs[winner_name]
        amat_a = audit_matrix(audit, vectorizers, spec["a_family"])
        amat_b = audit_matrix(audit, vectorizers, spec["b_family"])
        row_a = base_df[base_df.name == spec["a_name"]].iloc[0]
        row_b = base_df[base_df.name == spec["b_name"]].iloc[0]
        score_a = model_score(candidates[spec["a_name"]], amat_a, row_a["model_type"])
        score_b = model_score(candidates[spec["b_name"]], amat_b, row_b["model_type"])
        za = (score_a - spec["a_mean"]) / spec["a_std"]
        zb = (score_b - spec["b_mean"]) / spec["b_std"]
        audit_score = spec["alpha"] * za + (1 - spec["alpha"]) * zb
        audit_spec = {"type": "fusion", **spec}

    audit_m = metrics(ya, audit_score, float(winner["threshold"]))
    audit_m["recall_ci95"] = wilson(audit_m["tp"], audit_m["tp"] + audit_m["fn"])
    audit_m["fpr_ci95"] = wilson(audit_m["fp"], audit_m["fp"] + audit_m["tn"])
    print("AUDIT RESULT", json.dumps(audit_m, indent=2))

    gates = {
        "A_50pct": bool(audit_m["recall"] >= 0.50 and audit_m["fpr"] <= MAX_FPR),
        "B_70pct": bool(audit_m["recall"] >= 0.70 and audit_m["fpr"] <= MAX_FPR),
        "C_85pct": bool(audit_m["recall"] >= 0.85 and audit_m["fpr"] <= MAX_FPR),
        "D_90pct": bool(audit_m["recall"] >= 0.90 and audit_m["fpr"] <= MAX_FPR),
        "stretch_99_9pct": bool(audit_m["recall"] >= 0.999 and audit_m["fpr"] <= MAX_FPR),
    }

    evidence = {
        "protocol_file": "agentshield/ASSESSMENT_V14_HIGH_RECALL_PROTOCOL.md",
        "research_only": True,
        "seed": SEED,
        "max_observed_validation_fpr": MAX_FPR,
        "benchmark_labels_accessed": False,
        "dataset": "perplexity-ai/browsesafe-bench",
        "dataset_fingerprints": {
            "train_raw": getattr(train_raw, "_fingerprint", None),
            "test_content_source": getattr(test, "_fingerprint", None),
        },
        "removed_internal_duplicates": int(dup_count),
        "removed_train_test_overlap": int(overlap_count),
        "splits": {
            "development": int(len(dev_idx)),
            "validation": int(len(val_idx)),
            "audit": int(len(audit_idx)),
        },
        "feature_meta": feature_meta,
        "family_winners": family_winners,
        "validation_winner": winner,
        "audit_spec": audit_spec,
        "audit": audit_m,
        "gates": gates,
    }
    with open("agentshield/results/assessment_v14_evidence.json", "w") as f:
        json.dump(evidence, f, indent=2)

    assert len(dev_idx) > 7000 and len(val_idx) > 1500 and len(audit_idx) > 1500
    assert 0.0 <= audit_m["recall"] <= 1.0
    assert 0.0 <= audit_m["fpr"] <= 1.0
    print("ASSESSMENT_V14_HIGH_RECALL=COMPLETE")
    print("GATES", json.dumps(gates, indent=2))


if __name__ == "__main__":
    main()
