"""AgentShield assessment v18 FPR-stable sparse fusion experiment.

Research-only successor. Frozen assessment notebook and v16 champion are untouched.
BrowseSafe benchmark/test labels are never accessed.
The internal audit has been observed previously and is comparative only.
"""
from __future__ import annotations

import json
import math
import platform
import sys
import time
from pathlib import Path

import numpy as np
import pandas as pd
from datasets import load_dataset
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split

from assessment_v16_hard_rescue import (
    LAB, SEED, clean_training_split, fit_sparse, frame, metrics,
    nb_log_count_ratio, sparse_transform, threshold_at_fpr, wilson,
)
from assessment_v17_oof_adversarial import build_adversarial_dev, hard_weights, oof_nb_scores

np.random.seed(SEED)
RESULT_DIR = Path("agentshield/results")
TARGET_VAL_FPR = 0.006
OPERATING_FPR = 0.01
EPS = 1e-8


def logit(p):
    p = np.clip(np.asarray(p, dtype=np.float64), EPS, 1.0 - EPS)
    return np.log(p / (1.0 - p))


def sigmoid(z):
    z = np.clip(np.asarray(z, dtype=np.float64), -40.0, 40.0)
    return 1.0 / (1.0 + np.exp(-z))


def thresholds_for_budget(y, score, max_fpr):
    y = np.asarray(y)
    benign = np.where(y == 0)[0]
    max_fp = int(math.floor(float(max_fpr) * len(benign)))
    b = np.sort(np.asarray(score)[benign])[::-1]
    out = [float(np.nextafter(b[0], np.inf))]
    for k in range(1, max_fp + 1):
        hi = b[k - 1]
        lo = b[k] if k < len(b) else -np.inf
        out.append(float((hi + lo) / 2.0 if np.isfinite(lo) else np.nextafter(hi, -np.inf)))
    return out


def evaluate_union(y, score_map, threshold_map):
    y = np.asarray(y)
    pred = np.zeros(len(y), dtype=bool)
    for name, threshold in threshold_map.items():
        pred |= np.asarray(score_map[name]) >= float(threshold)
    tn = int(((y == 0) & (~pred)).sum())
    fp = int(((y == 0) & pred).sum())
    fn = int(((y == 1) & (~pred)).sum())
    tp = int(((y == 1) & pred).sum())
    precision = tp / max(1, tp + fp)
    recall = tp / max(1, tp + fn)
    fpr = fp / max(1, fp + tn)
    f1 = 2 * precision * recall / max(EPS, precision + recall)
    return {"precision": float(precision), "recall": float(recall), "f1": float(f1), "fpr": float(fpr),
            "tn": tn, "fp": fp, "fn": fn, "tp": tp}


def constrained_union_search(y, score_map, names, max_fpr):
    y = np.asarray(y)
    max_fp = int(math.floor(float(max_fpr) * int((y == 0).sum())))
    lists = {name: thresholds_for_budget(y, score_map[name], max_fpr) for name in names}
    best_key = None
    best = None
    for t0 in lists[names[0]]:
        for t1 in lists[names[1]]:
            th = {names[0]: t0, names[1]: t1}
            m = evaluate_union(y, score_map, th)
            if m["fp"] > max_fp:
                continue
            key = (m["recall"], m["precision"], -m["fpr"])
            if best_key is None or key > best_key:
                best_key = key
                best = {**m, "thresholds": th}
    if best is None:
        raise RuntimeError("No feasible union configuration")
    return best


def candidate_row(name, family, y, score, **extra):
    th = threshold_at_fpr(y, score, max_fpr=TARGET_VAL_FPR)
    m = metrics(y, score, th)
    return {**m, "name": name, "family": family, **extra}


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
    for c in [0.5, 1.0, 2.0]:
        for hp_mult in [1.0, 2.0, 4.0]:
            for hn_mult in [4.0, 6.0, 8.0]:
                w, _, _ = hard_weights(oof, yd, hp_mult, hn_mult, hp_cut, hn_cut)
                name = f"stable_hard_nb|C={c:g}|hp={hp_mult:g}|hn={hn_mult:g}"
                clf = LogisticRegression(C=c, max_iter=1800, solver="liblinear", random_state=SEED)
                clf.fit(d_nb, yd, sample_weight=w)
                score = clf.predict_proba(v_nb)[:, 1]
                row = candidate_row(name, "stable_hard_nb", yv, score)
                rows.append(row); score_map[name] = score; models[name] = clf
                print("VAL", name, round(row["recall"], 6), round(row["fpr"], 6), flush=True)

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
        name = f"stable_adv_nb|C={c:g}"
        clf = LogisticRegression(C=c, max_iter=1800, solver="liblinear", random_state=SEED)
        clf.fit(adv_dnb, adv_y, sample_weight=adv_weights)
        score = clf.predict_proba(adv_vnb)[:, 1]
        row = candidate_row(name, "stable_adv_nb", yv, score)
        rows.append(row); score_map[name] = score; adv_models[name] = clf
        print("VAL", name, round(row["recall"], 6), round(row["fpr"], 6), flush=True)

    candidate_df = pd.DataFrame(rows)
    hard_best = candidate_df[candidate_df.family == "stable_hard_nb"].sort_values(
        ["recall", "precision", "fpr"], ascending=[False, False, True]).iloc[0]
    adv_best = candidate_df[candidate_df.family == "stable_adv_nb"].sort_values(
        ["recall", "precision", "fpr"], ascending=[False, False, True]).iloc[0]
    hard_name, adv_name = str(hard_best["name"]), str(adv_best["name"])
    print("FAMILY WINNERS", hard_name, adv_name, flush=True)

    union = constrained_union_search(yv, score_map, [hard_name, adv_name], TARGET_VAL_FPR)
    union_row = {**union, "name": f"stable_or|{hard_name}+{adv_name}", "family": "stable_or",
                 "members": [hard_name, adv_name], "threshold": np.nan, "roc_auc": np.nan}
    rows.append(union_row)
    print("VAL", union_row["name"], json.dumps(union), flush=True)

    for alpha in np.linspace(0.1, 0.9, 9):
        fused = sigmoid(alpha * logit(score_map[hard_name]) + (1.0 - alpha) * logit(score_map[adv_name]))
        name = f"logit_fusion|alpha={alpha:.1f}|hard={hard_name}|adv={adv_name}"
        row = candidate_row(name, "logit_fusion", yv, fused, alpha=float(alpha),
                            hard_member=hard_name, adv_member=adv_name)
        rows.append(row); score_map[name] = fused
        print("VAL", name, round(row["recall"], 6), round(row["fpr"], 6), flush=True)

    all_df = pd.DataFrame(rows).sort_values(
        ["recall", "precision", "fpr"], ascending=[False, False, True]).reset_index(drop=True)
    all_df.to_csv(RESULT_DIR / "assessment_v18_validation.csv", index=False)
    winner = all_df.iloc[0].to_dict()
    winner_name = str(winner["name"])
    print("VALIDATION WINNER", json.dumps(json_safe(winner), indent=2), flush=True)

    t0 = time.time()
    audit = frame(train, audit_idx)
    ya = audit.y.to_numpy()
    amat = sparse_transform(audit, vectorizers).multiply(r).tocsr()
    adv_amat = sparse_transform(audit, adv_vec).multiply(adv_r).tocsr()

    def audit_score_for(name):
        if name.startswith("stable_hard_nb"): return models[name].predict_proba(amat)[:, 1]
        if name.startswith("stable_adv_nb"): return adv_models[name].predict_proba(adv_amat)[:, 1]
        raise KeyError(name)

    if winner["family"] == "stable_or":
        thresholds = winner["thresholds"]
        members = list(thresholds.keys())
        audit_scores = {m: audit_score_for(m) for m in members}
        audit_m = evaluate_union(ya, audit_scores, {m: float(thresholds[m]) for m in members})
        audit_spec = {"type": "or_pair", "members": members, "thresholds": {m: float(thresholds[m]) for m in members}}
    elif winner["family"] == "logit_fusion":
        alpha = float(winner["alpha"])
        hname, aname = str(winner["hard_member"]), str(winner["adv_member"])
        fused = sigmoid(alpha * logit(audit_score_for(hname)) + (1.0 - alpha) * logit(audit_score_for(aname)))
        audit_m = metrics(ya, fused, float(winner["threshold"]))
        audit_spec = {"type": "logit_fusion", "alpha": alpha, "hard_member": hname, "adv_member": aname,
                      "threshold": float(winner["threshold"])}
    else:
        audit_m = metrics(ya, audit_score_for(winner_name), float(winner["threshold"]))
        audit_spec = {"type": "single", "name": winner_name, "threshold": float(winner["threshold"])}
    audit_seconds = time.time() - t0

    audit_m["recall_ci95"] = wilson(audit_m["tp"], audit_m["tp"] + audit_m["fn"])
    audit_m["fpr_ci95"] = wilson(audit_m["fp"], audit_m["fp"] + audit_m["tn"])

    evidence = json_safe({
        "protocol_file": "agentshield/ASSESSMENT_V18_FPR_STABLE_PROTOCOL.md",
        "research_only": True,
        "seed": SEED,
        "target_validation_fpr": TARGET_VAL_FPR,
        "operating_fpr_ceiling": OPERATING_FPR,
        "selection_reason": "v17 exceeded the audit FPR ceiling; v18 reserves validation headroom and tests smooth fusion",
        "benchmark_labels_accessed": False,
        "audit_is_pristine": False,
        "audit_role": "comparative only; previously observed in earlier experiments",
        "dataset": "perplexity-ai/browsesafe-bench",
        "dataset_fingerprints": {"train_raw": train_fp, "test_content_source": test_fp},
        "removed_internal_duplicates": int(dup_count),
        "removed_train_test_overlap": int(overlap_count),
        "splits": {"development": len(dev_idx), "validation": len(val_idx), "comparative_audit": len(audit_idx)},
        "oof_hard_mining": {"folds": 5, "hard_positive_quantile": 0.45, "hard_negative_quantile": 0.95,
                            "hard_positive_cutoff": hp_cut, "hard_negative_cutoff": hn_cut,
                            "hard_positive_count": int(hp_mask.sum()), "hard_negative_count": int(hn_mask.sum())},
        "adversarial_augmentation": {"source": "development hard positives only",
                                     "kinds": ["deterministic token fragmentation", "benign-noise dilution"],
                                     "original_rows": int(len(dev)), "augmented_rows_total": int(len(adv_dev))},
        "validation_winner": winner,
        "audit_spec": audit_spec,
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
    with open(RESULT_DIR / "assessment_v18_evidence.json", "w") as f:
        json.dump(evidence, f, indent=2, allow_nan=False)
    print("V18 EVIDENCE", json.dumps(evidence, indent=2, allow_nan=False), flush=True)


if __name__ == "__main__":
    main()
