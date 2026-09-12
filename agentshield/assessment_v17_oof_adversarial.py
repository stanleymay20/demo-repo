"""AgentShield assessment v17 OOF-hard/adversarial sparse experiment.

Research-only successor. Frozen assessment notebook is untouched.
BrowseSafe benchmark/test labels are never accessed.
The internal audit has been observed previously and is comparative only.
"""
from __future__ import annotations

import hashlib
import json
import math
import platform
import re
import sys
import time
from pathlib import Path

import numpy as np
import pandas as pd
from datasets import load_dataset
from scipy.sparse import hstack
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import StratifiedKFold, train_test_split
from sklearn.svm import LinearSVC

from assessment_v16_hard_rescue import (
    LAB,
    MAX_FPR,
    SEED,
    clean_training_split,
    constrained_union_search,
    evaluate_union,
    fit_sparse,
    frame,
    metrics,
    nb_log_count_ratio,
    sparse_transform,
    threshold_at_fpr,
    wilson,
)

np.random.seed(SEED)
RESULT_DIR = Path("agentshield/results")
TOKEN_RE = re.compile(r"\b[A-Za-z]{6,}\b")
BENIGN_NOISE = (
    " home products services documentation pricing support privacy contact "
    " accessibility terms help account preferences navigation "
)


def stable_fragment(text: str) -> str:
    """Deterministically fragment a subset of long alphabetic tokens."""
    text = "" if text is None else str(text)

    def repl(match):
        token = match.group(0)
        h = hashlib.sha256(token.lower().encode("utf-8", "ignore")).digest()[0]
        if h % 4:
            return token
        cut = max(2, min(len(token) - 2, len(token) // 2))
        return token[:cut] + "-" + token[cut:]

    return TOKEN_RE.sub(repl, text)


def build_adversarial_dev(dev: pd.DataFrame, hard_pos_mask: np.ndarray):
    """Create development-only label-preserving obfuscation/dilution variants."""
    variants = []
    hard = dev.loc[np.asarray(hard_pos_mask)].copy()
    if len(hard):
        frag = hard.copy()
        for col in ("text", "evidence", "script", "combined", "context"):
            frag[col] = frag[col].map(stable_fragment)
        frag["aug_kind"] = "fragment"
        variants.append(frag)

        dilute = hard.copy()
        dilute["combined"] = BENIGN_NOISE + dilute["combined"].astype(str) + BENIGN_NOISE
        dilute["context"] = BENIGN_NOISE + dilute["context"].astype(str) + BENIGN_NOISE
        dilute["aug_kind"] = "dilute"
        variants.append(dilute)

    original = dev.copy()
    original["aug_kind"] = "original"
    if variants:
        out = pd.concat([original] + variants, ignore_index=True)
    else:
        out = original
    return out


def oof_nb_scores(x, y, folds=5):
    """OOF development scores: hardness is not measured on fitted-in-sample scores."""
    score = np.zeros(len(y), dtype=np.float64)
    cv = StratifiedKFold(n_splits=folds, shuffle=True, random_state=SEED)
    for fold, (tr, ho) in enumerate(cv.split(np.zeros(len(y)), y), start=1):
        r = nb_log_count_ratio(x[tr], y[tr])
        m = LogisticRegression(C=1.0, max_iter=1800, solver="liblinear", random_state=SEED)
        m.fit(x[tr].multiply(r).tocsr(), y[tr])
        score[ho] = m.predict_proba(x[ho].multiply(r).tocsr())[:, 1]
        print(f"OOF fold {fold}/{folds} complete", flush=True)
    return score


def hard_weights(scores, y, hp_mult, hn_mult, hp_cut, hn_cut):
    w = np.ones(len(y), dtype=np.float64)
    hp = (y == 1) & (scores <= hp_cut)
    hn = (y == 0) & (scores >= hn_cut)
    w[hp] *= float(hp_mult)
    w[hn] *= float(hn_mult)
    return w, hp, hn


def residual_text(df: pd.DataFrame):
    return (
        df["combined"].fillna("").astype(str)
        + " [EVIDENCE] " + df["evidence"].fillna("").astype(str)
        + " [SCRIPT] " + df["script"].fillna("").astype(str)
    )


def fit_residual_features(dev, val):
    vec = TfidfVectorizer(
        analyzer="char",
        ngram_range=(2, 6),
        min_df=2,
        max_features=160000,
        sublinear_tf=True,
        dtype=np.float32,
    )
    d = vec.fit_transform(residual_text(dev))
    v = vec.transform(residual_text(val))
    return vec, d.tocsr(), v.tocsr()


def residual_transform(df, vec):
    return vec.transform(residual_text(df)).tocsr()


def best_by_family(df, family):
    return df[df.family == family].sort_values(
        ["recall", "precision", "fpr"], ascending=[False, False, True]
    ).iloc[0]


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
    dev_idx, val_idx = train_test_split(
        work, test_size=0.1764706, stratify=y[work], random_state=SEED
    )
    print("Development / validation / comparative audit:", len(dev_idx), len(val_idx), len(audit_idx), flush=True)

    t0 = time.time()
    dev, val = frame(train, dev_idx), frame(train, val_idx)
    frame_seconds = time.time() - t0
    yd, yv = dev.y.to_numpy(), val.y.to_numpy()

    vectorizers, dmat, vmat = fit_sparse(dev, val)
    oof = oof_nb_scores(dmat, yd, folds=5)
    hp_cut = float(np.quantile(oof[yd == 1], 0.45))
    hn_cut = float(np.quantile(oof[yd == 0], 0.95))
    _, hp_mask, hn_mask = hard_weights(oof, yd, 1, 1, hp_cut, hn_cut)
    print("OOF hard cutoffs", hp_cut, hn_cut, "counts", int(hp_mask.sum()), int(hn_mask.sum()), flush=True)

    r = nb_log_count_ratio(dmat, yd)
    d_nb, v_nb = dmat.multiply(r).tocsr(), vmat.multiply(r).tocsr()
    rows, score_map, models = [], {}, {}

    base = LogisticRegression(C=1.0, max_iter=1800, solver="liblinear", random_state=SEED)
    base.fit(d_nb, yd)
    base_val = base.predict_proba(v_nb)[:, 1]
    base_th = threshold_at_fpr(yv, base_val)
    base_m = metrics(yv, base_val, base_th)
    base_m.update(name="nb_logreg_base", family="base")
    rows.append(base_m); score_map["nb_logreg_base"] = base_val; models["nb_logreg_base"] = base

    for c in [1.0, 2.0, 4.0]:
        for hp_mult in [2.0, 4.0, 6.0, 8.0]:
            for hn_mult in [2.0, 4.0, 6.0]:
                w, _, _ = hard_weights(oof, yd, hp_mult, hn_mult, hp_cut, hn_cut)
                name = f"oof_hard_nb|C={c:g}|hp={hp_mult:g}|hn={hn_mult:g}"
                clf = LogisticRegression(C=c, max_iter=1800, solver="liblinear", random_state=SEED)
                clf.fit(d_nb, yd, sample_weight=w)
                score = clf.predict_proba(v_nb)[:, 1]
                th = threshold_at_fpr(yv, score)
                m = metrics(yv, score, th); m.update(name=name, family="oof_hard_nb")
                rows.append(m); score_map[name] = score; models[name] = clf
                print("VAL", name, round(m["recall"], 6), round(m["fpr"], 6), flush=True)

    adv_dev = build_adversarial_dev(dev, hp_mask)
    adv_y = adv_dev.y.to_numpy(dtype=np.int8)
    adv_vec, adv_dmat, adv_vmat = fit_sparse(adv_dev, val)
    adv_r = nb_log_count_ratio(adv_dmat, adv_y)
    adv_dnb, adv_vnb = adv_dmat.multiply(adv_r).tocsr(), adv_vmat.multiply(adv_r).tocsr()
    adv_weights = np.ones(len(adv_dev), dtype=np.float64)
    original_n = len(dev)
    adv_weights[:original_n][hp_mask] *= 2.0
    adv_weights[:original_n][hn_mask] *= 4.0
    adv_weights[original_n:] *= 1.5
    adv_models = {}
    for c in [0.5, 1.0, 2.0, 4.0]:
        name = f"adv_nb|C={c:g}"
        clf = LogisticRegression(C=c, max_iter=1800, solver="liblinear", random_state=SEED)
        clf.fit(adv_dnb, adv_y, sample_weight=adv_weights)
        score = clf.predict_proba(adv_vnb)[:, 1]
        th = threshold_at_fpr(yv, score)
        m = metrics(yv, score, th); m.update(name=name, family="adv_nb")
        rows.append(m); score_map[name] = score; adv_models[name] = clf
        print("VAL", name, round(m["recall"], 6), round(m["fpr"], 6), flush=True)

    residual_vec, rd, rv = fit_residual_features(dev, val)
    residual_models = {}
    for c in [0.05, 0.1, 0.25, 0.5]:
        for hp_mult in [4.0, 8.0]:
            for hn_mult in [2.0, 4.0]:
                w, _, _ = hard_weights(oof, yd, hp_mult, hn_mult, hp_cut, hn_cut)
                name = f"residual_svc|C={c:g}|hp={hp_mult:g}|hn={hn_mult:g}"
                clf = LinearSVC(C=c, random_state=SEED, max_iter=5000)
                clf.fit(rd, yd, sample_weight=w)
                score = clf.decision_function(rv)
                th = threshold_at_fpr(yv, score)
                m = metrics(yv, score, th); m.update(name=name, family="residual_svc")
                rows.append(m); score_map[name] = score; residual_models[name] = clf
                print("VAL", name, round(m["recall"], 6), round(m["fpr"], 6), flush=True)

    candidate_df = pd.DataFrame(rows)
    winners = {
        "oof_hard_nb": best_by_family(candidate_df, "oof_hard_nb")["name"],
        "adv_nb": best_by_family(candidate_df, "adv_nb")["name"],
        "residual_svc": best_by_family(candidate_df, "residual_svc")["name"],
    }
    print("FAMILY WINNERS", json.dumps(winners, indent=2), flush=True)

    cascade_rows = []
    winner_names = list(winners.values())
    for i in range(len(winner_names)):
        for j in range(i + 1, len(winner_names)):
            names = [winner_names[i], winner_names[j]]
            m = constrained_union_search(yv, score_map, names)
            name = "or|" + "+".join(names)
            cascade_rows.append({**m, "name": name, "family": "or_pair", "members_list": names})
            print("VAL", name, json.dumps(m), flush=True)
    tri_m = constrained_union_search(yv, score_map, winner_names)
    tri_name = "or3|" + "+".join(winner_names)
    cascade_rows.append({**tri_m, "name": tri_name, "family": "or_three", "members_list": winner_names})
    print("VAL", tri_name, json.dumps(tri_m), flush=True)

    all_df = pd.concat([candidate_df, pd.DataFrame(cascade_rows)], ignore_index=True, sort=False)
    all_df = all_df.sort_values(["recall", "precision", "fpr"], ascending=[False, False, True]).reset_index(drop=True)
    all_df.to_csv(RESULT_DIR / "assessment_v17_validation.csv", index=False)
    winner = all_df.iloc[0].to_dict()
    winner_name = str(winner["name"])
    print("VALIDATION WINNER", json.dumps(winner, indent=2, default=str), flush=True)

    t0 = time.time()
    audit = frame(train, audit_idx)
    ya = audit.y.to_numpy()
    amat = sparse_transform(audit, vectorizers).multiply(r).tocsr()
    adv_amat = sparse_transform(audit, adv_vec).multiply(adv_r).tocsr()
    ramat = residual_transform(audit, residual_vec)

    audit_scores = {}
    for name in set(winners.values()) | {winner_name}:
        if name.startswith("oof_hard_nb"):
            audit_scores[name] = models[name].predict_proba(amat)[:, 1]
        elif name.startswith("adv_nb"):
            audit_scores[name] = adv_models[name].predict_proba(adv_amat)[:, 1]
        elif name.startswith("residual_svc"):
            audit_scores[name] = residual_models[name].decision_function(ramat)
        elif name == "nb_logreg_base":
            audit_scores[name] = base.predict_proba(amat)[:, 1]
    audit_seconds = time.time() - t0

    if str(winner.get("family")) in {"or_pair", "or_three"}:
        thresholds = winner["thresholds"]
        members = list(thresholds.keys())
        for name in members:
            if name in audit_scores:
                continue
            if name.startswith("oof_hard_nb"):
                audit_scores[name] = models[name].predict_proba(amat)[:, 1]
            elif name.startswith("adv_nb"):
                audit_scores[name] = adv_models[name].predict_proba(adv_amat)[:, 1]
            elif name.startswith("residual_svc"):
                audit_scores[name] = residual_models[name].decision_function(ramat)
        audit_m = evaluate_union(ya, audit_scores, {m: float(thresholds[m]) for m in members})
        audit_spec = {"type": str(winner["family"]), "members": members, "thresholds": {m: float(thresholds[m]) for m in members}}
    else:
        if winner_name.startswith("oof_hard_nb"):
            score = models[winner_name].predict_proba(amat)[:, 1]
        elif winner_name.startswith("adv_nb"):
            score = adv_models[winner_name].predict_proba(adv_amat)[:, 1]
        elif winner_name.startswith("residual_svc"):
            score = residual_models[winner_name].decision_function(ramat)
        else:
            score = base.predict_proba(amat)[:, 1]
        audit_m = metrics(ya, score, float(winner["threshold"]))
        audit_spec = {"type": "single", "name": winner_name, "threshold": float(winner["threshold"])}

    audit_m["recall_ci95"] = wilson(audit_m["tp"], audit_m["tp"] + audit_m["fn"])
    audit_m["fpr_ci95"] = wilson(audit_m["fp"], audit_m["fp"] + audit_m["tn"])

    evidence = {
        "protocol_file": "agentshield/ASSESSMENT_V17_OOF_ADVERSARIAL_PROTOCOL.md",
        "research_only": True,
        "seed": SEED,
        "max_observed_validation_fpr": MAX_FPR,
        "benchmark_labels_accessed": False,
        "audit_is_pristine": False,
        "audit_role": "comparative only; previously observed in earlier experiments",
        "dataset": "perplexity-ai/browsesafe-bench",
        "dataset_fingerprints": {"train_raw": train_fp, "test_content_source": test_fp},
        "removed_internal_duplicates": int(dup_count),
        "removed_train_test_overlap": int(overlap_count),
        "splits": {"development": len(dev_idx), "validation": len(val_idx), "comparative_audit": len(audit_idx)},
        "oof_hard_mining": {
            "folds": 5,
            "hard_positive_quantile": 0.45,
            "hard_negative_quantile": 0.95,
            "hard_positive_cutoff": hp_cut,
            "hard_negative_cutoff": hn_cut,
            "hard_positive_count": int(hp_mask.sum()),
            "hard_negative_count": int(hn_mask.sum()),
        },
        "adversarial_augmentation": {
            "source": "development hard positives only",
            "kinds": ["deterministic token fragmentation", "benign-noise dilution"],
            "original_rows": int(len(dev)),
            "augmented_rows_total": int(len(adv_dev)),
        },
        "family_winners": winners,
        "validation_winner": winner,
        "audit_spec": audit_spec,
        "comparative_audit": audit_m,
        "gates": {
            "B_70pct": bool(audit_m["recall"] >= .70 and audit_m["fpr"] <= .01),
            "C_85pct": bool(audit_m["recall"] >= .85 and audit_m["fpr"] <= .01),
            "D_90pct": bool(audit_m["recall"] >= .90 and audit_m["fpr"] <= .01),
            "stretch_99_9pct": bool(audit_m["recall"] >= .999 and audit_m["fpr"] <= .01),
        },
        "timing": {"frame_dev_val_s": frame_seconds, "audit_representation_scoring_s": audit_seconds},
        "runtime": {"python": sys.version, "platform": platform.platform()},
    }
    with open(RESULT_DIR / "assessment_v17_evidence.json", "w") as f:
        json.dump(evidence, f, indent=2, allow_nan=False)
    print("V17 EVIDENCE", json.dumps(evidence, indent=2), flush=True)


if __name__ == "__main__":
    main()
