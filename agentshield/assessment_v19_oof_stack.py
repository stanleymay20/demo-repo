"""AgentShield assessment v19 OOF multi-view stacked ensemble.

Research-only successor. Frozen assessment notebook and earlier champions are untouched.
BrowseSafe benchmark/test labels are never accessed.
The internal audit has been observed previously and is comparative only.
"""
from __future__ import annotations

import gc
import hashlib
import json
import math
import platform
import re
import sys
import time
import warnings
from pathlib import Path

import numpy as np
import pandas as pd
from bs4 import BeautifulSoup, Comment
from datasets import load_dataset
from scipy.sparse import hstack
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import confusion_matrix, f1_score, precision_score, recall_score, roc_auc_score, roc_curve
from sklearn.model_selection import StratifiedKFold, train_test_split
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler

warnings.filterwarnings("ignore")
SEED = 42
np.random.seed(SEED)
LAB = {"no": 0, "yes": 1}
WS = re.compile(r"\s+")
RESULT_DIR = Path("agentshield/results")
TARGET_VAL_FPR = 0.006
OPERATING_FPR = 0.01
EPS = 1e-8
EXPERT_NAMES = ["combined_nb", "combined_lr", "visible_lr", "hidden_lr", "context_lr"]


def normalized_digest(s: str | None) -> bytes:
    text = "" if s is None else str(s)
    norm = WS.sub(" ", text.lower()).strip()
    return hashlib.sha256(norm.encode("utf-8", "ignore")).digest()


def clean_training_split(train, test):
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


def make_views(raw: str | None):
    raw = "" if raw is None else str(raw)
    soup = BeautifulSoup(raw, "lxml")
    comments = [str(x) for x in soup.find_all(string=lambda t: isinstance(t, Comment))]
    hidden, attrs, scripts = [], [], []
    interesting = {"aria-label", "title", "alt", "value", "style", "hidden", "placeholder", "onclick", "role"}
    for tag in soup.find_all(True):
        style = str(tag.get("style", "")).lower().replace(" ", "")
        if tag.has_attr("hidden") or "display:none" in style or "visibility:hidden" in style or (
            tag.name == "input" and str(tag.get("type", "")).lower() == "hidden"
        ):
            hidden.append(tag.get_text(" ", strip=True))
        if tag.name == "script":
            scripts.append(tag.get_text(" ", strip=True))
        for key, value in tag.attrs.items():
            if key.startswith("data-") or key in interesting:
                if isinstance(value, list):
                    value = " ".join(map(str, value))
                attrs.append(f"{key} {value}")
    for tag in soup(["script", "style"]):
        tag.decompose()
    text = " ".join(soup.stripped_strings)
    evidence = " ".join(comments + hidden + attrs)
    script_text = " ".join(scripts)
    combined = f"[TEXT] {text} [HIDDEN] {evidence} [SCRIPT] {script_text}"
    context = sample_context(text, evidence, script_text)
    hidden_script = f"[HIDDEN] {evidence} [SCRIPT] {script_text}"
    return text, evidence, script_text, combined, context, hidden_script


def clipped_words(s: str, head: int, tail: int = 0):
    words = WS.split((s or "").strip()) if s else []
    if tail and len(words) > head + tail:
        return words[:head] + words[-tail:]
    return words[:head] if len(words) > head else words


def sample_context(text: str, evidence: str, script_text: str) -> str:
    words = WS.split((text or "").strip()) if text else []
    if len(words) > 240:
        mid = len(words) // 2
        words = words[:90] + words[max(0, mid - 30):mid + 30] + words[-90:]
    ev = clipped_words(evidence, 50, 50)
    sc = clipped_words(script_text, 40, 40)
    return (
        "visible text: " + " ".join(words)
        + " hidden evidence: " + " ".join(ev)
        + " script cues: " + " ".join(sc)
    ).strip()


def frame(dataset, ids):
    rows = []
    subset = dataset.select([int(i) for i in ids])
    for batch in subset.iter(batch_size=16):
        for raw, label in zip(batch["content"], batch["label"]):
            text, evidence, script_text, combined, context, hidden_script = make_views(raw)
            rows.append({
                "text": text,
                "evidence": evidence,
                "script": script_text,
                "combined": combined,
                "context": context,
                "hidden_script": hidden_script,
                "y": LAB[label],
            })
    return pd.DataFrame(rows)


def nb_log_count_ratio(x, y):
    xb = x.copy().tocsr()
    xb.data = np.ones_like(xb.data)
    pos = np.asarray(xb[y == 1].sum(axis=0)).ravel()
    neg = np.asarray(xb[y == 0].sum(axis=0)).ravel()
    p = (pos + 1.0) / (float((y == 1).sum()) + 1.0)
    q = (neg + 1.0) / (float((y == 0).sum()) + 1.0)
    return np.log(p / q).astype(np.float32)


def metrics(y, score, threshold):
    pred = (np.asarray(score) >= float(threshold)).astype(np.int8)
    tn, fp, fn, tp = confusion_matrix(y, pred).ravel()
    return {
        "threshold": float(threshold),
        "precision": float(precision_score(y, pred, zero_division=0)),
        "recall": float(recall_score(y, pred, zero_division=0)),
        "f1": float(f1_score(y, pred, zero_division=0)),
        "roc_auc": float(roc_auc_score(y, score)),
        "fpr": float(fp / (fp + tn)),
        "tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp),
    }


def threshold_at_fpr(y, score, max_fpr=TARGET_VAL_FPR):
    fpr, tpr, thresholds = roc_curve(y, score)
    valid = np.where(fpr <= max_fpr)[0]
    if len(valid) == 0:
        raise RuntimeError("No threshold satisfies requested FPR")
    best_tpr = tpr[valid].max()
    tied = valid[tpr[valid] == best_tpr]
    return float(np.max(thresholds[tied]))


def wilson(k, n, z=1.96):
    p = k / n
    d = 1 + z*z/n
    c = (p + z*z/(2*n)) / d
    h = z*np.sqrt(p*(1-p)/n + z*z/(4*n*n)) / d
    return [float(c-h), float(c+h)]


def fit_combined(train_df, eval_df):
    word = TfidfVectorizer(ngram_range=(1, 2), min_df=2, max_df=.995, max_features=55000,
                           sublinear_tf=True, strip_accents="unicode", dtype=np.float32)
    char = TfidfVectorizer(analyzer="char_wb", ngram_range=(3, 5), min_df=2, max_features=75000,
                           sublinear_tf=True, dtype=np.float32)
    evidence = TfidfVectorizer(analyzer="char", ngram_range=(3, 5), min_df=2, max_features=25000,
                               sublinear_tf=True, dtype=np.float32)
    dw = word.fit_transform(train_df["combined"]); ew = word.transform(eval_df["combined"])
    dc = char.fit_transform(train_df["combined"]); ec = char.transform(eval_df["combined"])
    de = evidence.fit_transform(train_df["evidence"]); ee = evidence.transform(eval_df["evidence"])
    return {"word": word, "char": char, "evidence": evidence}, hstack([dw, dc, de], format="csr"), hstack([ew, ec, ee], format="csr")


def transform_combined(df, vec):
    return hstack([vec["word"].transform(df["combined"]), vec["char"].transform(df["combined"]),
                   vec["evidence"].transform(df["evidence"])], format="csr")


def fit_dual(train_series, eval_series, word_features, char_features, char_range=(3,5)):
    word = TfidfVectorizer(ngram_range=(1, 2), min_df=2, max_df=.995, max_features=word_features,
                           sublinear_tf=True, strip_accents="unicode", dtype=np.float32)
    char = TfidfVectorizer(analyzer="char_wb", ngram_range=char_range, min_df=2, max_features=char_features,
                           sublinear_tf=True, dtype=np.float32)
    tw = word.fit_transform(train_series); ew = word.transform(eval_series)
    tc = char.fit_transform(train_series); ec = char.transform(eval_series)
    return {"word": word, "char": char}, hstack([tw, tc], format="csr"), hstack([ew, ec], format="csr")


def transform_dual(series, vec):
    return hstack([vec["word"].transform(series), vec["char"].transform(series)], format="csr")


def fit_experts(train_df, eval_df, keep=False):
    y = train_df.y.to_numpy(dtype=np.int8)
    scores = {}
    package = {} if keep else None

    vec, x, xe = fit_combined(train_df, eval_df)
    r = nb_log_count_ratio(x, y)
    nb = LogisticRegression(C=1.0, max_iter=1800, solver="liblinear", random_state=SEED)
    nb.fit(x.multiply(r).tocsr(), y)
    scores["combined_nb"] = nb.predict_proba(xe.multiply(r).tocsr())[:, 1]
    lr = LogisticRegression(C=1.0, max_iter=1800, solver="liblinear", random_state=SEED)
    lr.fit(x, y)
    scores["combined_lr"] = lr.predict_proba(xe)[:, 1]
    if keep: package["combined"] = {"vec": vec, "r": r, "nb": nb, "lr": lr}
    del x, xe; gc.collect()

    vec, x, xe = fit_dual(train_df["text"], eval_df["text"], 40000, 50000)
    m = LogisticRegression(C=1.0, max_iter=1600, solver="liblinear", random_state=SEED)
    m.fit(x, y); scores["visible_lr"] = m.predict_proba(xe)[:, 1]
    if keep: package["visible"] = {"vec": vec, "model": m}
    del x, xe; gc.collect()

    vec, x, xe = fit_dual(train_df["hidden_script"], eval_df["hidden_script"], 18000, 45000, char_range=(2,6))
    r = nb_log_count_ratio(x, y)
    m = LogisticRegression(C=1.0, max_iter=1600, solver="liblinear", random_state=SEED)
    m.fit(x.multiply(r).tocsr(), y); scores["hidden_lr"] = m.predict_proba(xe.multiply(r).tocsr())[:, 1]
    if keep: package["hidden"] = {"vec": vec, "r": r, "model": m}
    del x, xe; gc.collect()

    vec, x, xe = fit_dual(train_df["context"], eval_df["context"], 35000, 35000)
    m = LogisticRegression(C=1.0, max_iter=1600, solver="liblinear", random_state=SEED)
    m.fit(x, y); scores["context_lr"] = m.predict_proba(xe)[:, 1]
    if keep: package["context"] = {"vec": vec, "model": m}
    del x, xe; gc.collect()

    return scores, package


def score_experts(df, package):
    out = {}
    p = package["combined"]
    x = transform_combined(df, p["vec"])
    out["combined_nb"] = p["nb"].predict_proba(x.multiply(p["r"]).tocsr())[:, 1]
    out["combined_lr"] = p["lr"].predict_proba(x)[:, 1]
    del x; gc.collect()

    p = package["visible"]
    x = transform_dual(df["text"], p["vec"])
    out["visible_lr"] = p["model"].predict_proba(x)[:, 1]
    del x; gc.collect()

    p = package["hidden"]
    x = transform_dual(df["hidden_script"], p["vec"])
    out["hidden_lr"] = p["model"].predict_proba(x.multiply(p["r"]).tocsr())[:, 1]
    del x; gc.collect()

    p = package["context"]
    x = transform_dual(df["context"], p["vec"])
    out["context_lr"] = p["model"].predict_proba(x)[:, 1]
    del x; gc.collect()
    return out


def score_matrix(score_map):
    return np.column_stack([np.asarray(score_map[n], dtype=np.float64) for n in EXPERT_NAMES])


def meta_expand(x):
    x = np.clip(np.asarray(x, dtype=np.float64), EPS, 1-EPS)
    logits = np.log(x/(1-x))
    sx = np.sort(x, axis=1)
    extra = np.column_stack([
        x.mean(axis=1), x.max(axis=1), x.min(axis=1), x.std(axis=1),
        sx[:, -2:].mean(axis=1), (x > .5).sum(axis=1),
        logits.mean(axis=1), logits.max(axis=1), logits.std(axis=1),
    ])
    return np.column_stack([logits, extra])


def json_safe(value):
    if isinstance(value, dict): return {k: json_safe(v) for k, v in value.items()}
    if isinstance(value, list): return [json_safe(v) for v in value]
    if isinstance(value, tuple): return [json_safe(v) for v in value]
    if isinstance(value, (float, np.floating)) and not np.isfinite(value): return None
    if isinstance(value, np.integer): return int(value)
    if isinstance(value, np.floating): return float(value)
    return value


def main():
    RESULT_DIR.mkdir(parents=True, exist_ok=True)
    print("Loading BrowseSafe...", flush=True)
    ds = load_dataset("perplexity-ai/browsesafe-bench", token=False)
    train_raw, test = ds["train"], ds["test"]
    train_fp = getattr(train_raw, "_fingerprint", None)
    test_fp = getattr(test, "_fingerprint", None)
    train, dup_count, overlap_count = clean_training_split(train_raw, test)

    y = np.array([LAB[x] for x in train["label"]], dtype=np.int8)
    idx = np.arange(len(train))
    work, audit_idx = train_test_split(idx, test_size=0.15, stratify=y, random_state=SEED)
    dev_idx, val_idx = train_test_split(work, test_size=0.1764706, stratify=y[work], random_state=SEED)
    print("Development / validation / comparative audit:", len(dev_idx), len(val_idx), len(audit_idx), flush=True)

    t0 = time.time()
    dev, val = frame(train, dev_idx), frame(train, val_idx)
    frame_seconds = time.time() - t0
    yd, yv = dev.y.to_numpy(dtype=np.int8), val.y.to_numpy(dtype=np.int8)

    oof = np.zeros((len(dev), len(EXPERT_NAMES)), dtype=np.float64)
    cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=SEED)
    for fold, (tr, ho) in enumerate(cv.split(np.zeros(len(yd)), yd), start=1):
        fold_scores, _ = fit_experts(dev.iloc[tr].reset_index(drop=True), dev.iloc[ho].reset_index(drop=True), keep=False)
        oof[ho] = score_matrix(fold_scores)
        print(f"OOF expert fold {fold}/5 complete", flush=True)
        gc.collect()

    full_scores, package = fit_experts(dev, val, keep=True)
    xv = score_matrix(full_scores)
    xm = meta_expand(oof)
    xvm = meta_expand(xv)

    rows = []
    score_map = dict(full_scores)
    for name in EXPERT_NAMES:
        th = threshold_at_fpr(yv, score_map[name])
        row = metrics(yv, score_map[name], th); row.update(name=name, family="expert")
        rows.append(row)
        print("VAL", name, round(row["recall"], 6), round(row["fpr"], 6), flush=True)

    simple = {
        "expert_mean": xv.mean(axis=1),
        "expert_max": xv.max(axis=1),
        "expert_top2_mean": np.sort(xv, axis=1)[:, -2:].mean(axis=1),
    }
    for name, score in simple.items():
        score_map[name] = score
        th = threshold_at_fpr(yv, score)
        row = metrics(yv, score, th); row.update(name=name, family="simple_fusion")
        rows.append(row)
        print("VAL", name, round(row["recall"], 6), round(row["fpr"], 6), flush=True)

    meta_models = {}
    for c in [0.1, 1.0, 10.0]:
        name = f"stack_logreg|C={c:g}"
        model = make_pipeline(StandardScaler(), LogisticRegression(C=c, max_iter=1500, solver="liblinear", random_state=SEED))
        model.fit(xm, yd)
        score = model.predict_proba(xvm)[:, 1]
        meta_models[name] = model; score_map[name] = score
        th = threshold_at_fpr(yv, score)
        row = metrics(yv, score, th); row.update(name=name, family="stack_logreg")
        rows.append(row)
        print("VAL", name, round(row["recall"], 6), round(row["fpr"], 6), flush=True)

    for leaves in [5, 9, 15]:
        name = f"stack_hgb|leaves={leaves}"
        model = HistGradientBoostingClassifier(max_iter=180, learning_rate=.05, max_leaf_nodes=leaves,
                                               min_samples_leaf=40, l2_regularization=2.0, random_state=SEED)
        model.fit(xm, yd)
        score = model.predict_proba(xvm)[:, 1]
        meta_models[name] = model; score_map[name] = score
        th = threshold_at_fpr(yv, score)
        row = metrics(yv, score, th); row.update(name=name, family="stack_hgb")
        rows.append(row)
        print("VAL", name, round(row["recall"], 6), round(row["fpr"], 6), flush=True)

    validation_df = pd.DataFrame(rows).sort_values(["recall", "precision", "fpr"], ascending=[False, False, True]).reset_index(drop=True)
    validation_df.to_csv(RESULT_DIR / "assessment_v19_validation.csv", index=False)
    winner = validation_df.iloc[0].to_dict()
    winner_name = str(winner["name"])
    print("VALIDATION WINNER", json.dumps(json_safe(winner), indent=2), flush=True)

    t0 = time.time()
    audit = frame(train, audit_idx)
    ya = audit.y.to_numpy(dtype=np.int8)
    audit_expert_scores = score_experts(audit, package)
    xa = score_matrix(audit_expert_scores)
    xam = meta_expand(xa)
    if winner_name in audit_expert_scores:
        audit_score = audit_expert_scores[winner_name]
    elif winner_name == "expert_mean":
        audit_score = xa.mean(axis=1)
    elif winner_name == "expert_max":
        audit_score = xa.max(axis=1)
    elif winner_name == "expert_top2_mean":
        audit_score = np.sort(xa, axis=1)[:, -2:].mean(axis=1)
    else:
        audit_score = meta_models[winner_name].predict_proba(xam)[:, 1]
    audit_m = metrics(ya, audit_score, float(winner["threshold"]))
    audit_seconds = time.time() - t0
    audit_m["recall_ci95"] = wilson(audit_m["tp"], audit_m["tp"] + audit_m["fn"])
    audit_m["fpr_ci95"] = wilson(audit_m["fp"], audit_m["fp"] + audit_m["tn"])

    evidence = json_safe({
        "protocol_file": "agentshield/ASSESSMENT_V19_OOF_STACK_PROTOCOL.md",
        "research_only": True,
        "seed": SEED,
        "target_validation_fpr": TARGET_VAL_FPR,
        "operating_fpr_ceiling": OPERATING_FPR,
        "selection_reason": "v18 plateaued with highly correlated sparse experts; v19 tests diverse multi-view OOF stacking",
        "benchmark_labels_accessed": False,
        "audit_is_pristine": False,
        "audit_role": "comparative only; previously observed in earlier experiments",
        "validation_role": "developmental selection set; repeatedly used across the controlled research programme",
        "dataset": "perplexity-ai/browsesafe-bench",
        "dataset_fingerprints": {"train_raw": train_fp, "test_content_source": test_fp},
        "removed_internal_duplicates": int(dup_count),
        "removed_train_test_overlap": int(overlap_count),
        "splits": {"development": len(dev_idx), "validation": len(val_idx), "comparative_audit": len(audit_idx)},
        "oof_stacking": {"folds": 5, "expert_names": EXPERT_NAMES,
                         "meta_features": int(xm.shape[1]),
                         "no_in_sample_expert_predictions_for_meta_training": True},
        "validation_winner": winner,
        "comparative_audit": audit_m,
        "gates": {
            "B_70pct": bool(audit_m["recall"] >= .70 and audit_m["fpr"] <= .01),
            "C_85pct": bool(audit_m["recall"] >= .85 and audit_m["fpr"] <= .01),
            "D_90pct": bool(audit_m["recall"] >= .90 and audit_m["fpr"] <= .01),
            "E_95pct": bool(audit_m["recall"] >= .95 and audit_m["fpr"] <= .01),
        },
        "timing": {"frame_dev_val_s": frame_seconds, "audit_representation_scoring_s": audit_seconds},
        "runtime": {"python": sys.version, "platform": platform.platform()},
    })
    with open(RESULT_DIR / "assessment_v19_evidence.json", "w") as f:
        json.dump(evidence, f, indent=2, allow_nan=False)
    print("V19 EVIDENCE", json.dumps(evidence, indent=2, allow_nan=False), flush=True)


if __name__ == "__main__":
    main()
