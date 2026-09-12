"""AgentShield assessment v21 chunk-residual experiment.

Research-only successor to verified v18 champion.
BrowseSafe benchmark/test labels are never accessed.
Comparative audit is non-pristine and evaluated only after validation freeze.
"""
from __future__ import annotations

import json
import math
import platform
import re
import sys
import time
from itertools import product
from pathlib import Path

import numpy as np
import pandas as pd
from datasets import load_dataset
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split
from sklearn.svm import LinearSVC

from assessment_v16_hard_rescue import (
    LAB, SEED, clean_training_split, fit_sparse, frame, metrics,
    nb_log_count_ratio, sparse_transform, threshold_at_fpr, wilson,
)
from assessment_v17_oof_adversarial import build_adversarial_dev, hard_weights, oof_nb_scores

np.random.seed(SEED)
RESULT_DIR = Path("agentshield/results")
TARGET_VAL_FPR = 0.006
OPERATING_FPR = 0.01
V18_RECALL = 600.0 / 821.0
V18_FPR = 7.0 / 835.0
CHUNK_WINDOW = 1400
CHUNK_STRIDE = 700
MAX_CHUNKS_PER_PAGE = 10
WS = re.compile(r"\s+")


def json_safe(value):
    if isinstance(value, dict): return {str(k): json_safe(v) for k, v in value.items()}
    if isinstance(value, list): return [json_safe(v) for v in value]
    if isinstance(value, tuple): return [json_safe(v) for v in value]
    if isinstance(value, np.ndarray): return [json_safe(v) for v in value.tolist()]
    if isinstance(value, (float, np.floating)): return None if not np.isfinite(value) else float(value)
    if isinstance(value, (int, np.integer)): return int(value)
    if isinstance(value, (bool, np.bool_)): return bool(value)
    return value


def thresholds_for_budget(y, score, max_fpr):
    y = np.asarray(y); score = np.asarray(score)
    benign_scores = np.sort(score[y == 0])[::-1]
    max_fp = int(math.floor(float(max_fpr) * int((y == 0).sum())))
    if len(benign_scores) == 0: raise RuntimeError("No benign validation rows")
    out = [float(np.nextafter(benign_scores[0], np.inf))]
    for k in range(1, max_fp + 1):
        hi = benign_scores[k - 1]; lo = benign_scores[k] if k < len(benign_scores) else -np.inf
        out.append(float((hi + lo) / 2.0 if np.isfinite(lo) else np.nextafter(hi, -np.inf)))
    return out


def evaluate_union(y, score_map, threshold_map):
    y = np.asarray(y); pred = np.zeros(len(y), dtype=bool)
    for name, threshold in threshold_map.items(): pred |= np.asarray(score_map[name]) >= float(threshold)
    tn = int(((y == 0) & (~pred)).sum()); fp = int(((y == 0) & pred).sum())
    fn = int(((y == 1) & (~pred)).sum()); tp = int(((y == 1) & pred).sum())
    precision = tp / max(1, tp + fp); recall = tp / max(1, tp + fn); fpr = fp / max(1, fp + tn)
    f1 = 2.0 * precision * recall / max(1e-12, precision + recall)
    return {"precision": float(precision), "recall": float(recall), "f1": float(f1), "fpr": float(fpr),
            "tn": tn, "fp": fp, "fn": fn, "tp": tp}


def constrained_union_search(y, score_map, names, max_fpr):
    y = np.asarray(y); max_fp = int(math.floor(float(max_fpr) * int((y == 0).sum())))
    lists = [thresholds_for_budget(y, score_map[name], max_fpr) for name in names]
    best = None; best_key = None
    for values in product(*lists):
        th = {name: float(value) for name, value in zip(names, values)}
        m = evaluate_union(y, score_map, th)
        if m["fp"] > max_fp: continue
        key = (m["recall"], m["precision"], -m["fpr"])
        if best_key is None or key > best_key: best_key = key; best = {**m, "thresholds": th}
    if best is None: raise RuntimeError("No feasible constrained union")
    return best


def candidate_row(name, family, y, score, **extra):
    th = threshold_at_fpr(y, score, max_fpr=TARGET_VAL_FPR)
    m = metrics(y, score, th)
    return {**m, "name": name, "family": family, **extra}


def best_family(df, family):
    sub = df[df.family == family]
    if len(sub) == 0: raise RuntimeError(f"No rows for family {family}")
    return sub.sort_values(["recall", "precision", "fpr"], ascending=[False, False, True]).iloc[0]


def location_label(start, end, total):
    frac = ((start + end) / 2.0) / max(1.0, float(total))
    if frac < 1.0 / 3.0: return "HEAD"
    if frac < 2.0 / 3.0: return "MID"
    return "TAIL"


def raw_chunks(raw):
    text = WS.sub(" ", "" if raw is None else str(raw)).strip()
    if not text: return ["[HEAD] "]
    total = len(text)
    if total <= CHUNK_WINDOW: return [f"[HEAD] {text}"]
    last = max(0, total - CHUNK_WINDOW)
    starts = list(range(0, last + 1, CHUNK_STRIDE))
    if starts[-1] != last: starts.append(last)
    if len(starts) > MAX_CHUNKS_PER_PAGE:
        idx = np.linspace(0, len(starts) - 1, MAX_CHUNKS_PER_PAGE)
        starts = sorted(set(starts[int(round(i))] for i in idx))
    out = []
    for start in starts:
        end = min(total, start + CHUNK_WINDOW)
        out.append(f"[{location_label(start, end, total)}] {text[start:end]}")
    return out


def build_chunk_corpus(dataset, ids, labels):
    subset = dataset.select([int(i) for i in ids])
    texts, page_index, y_chunk, counts = [], [], [], []
    for page_i, (raw, label) in enumerate(zip(subset["content"], labels)):
        chunks = raw_chunks(raw); counts.append(len(chunks)); texts.extend(chunks)
        page_index.extend([page_i] * len(chunks)); y_chunk.extend([int(label)] * len(chunks))
    return texts, np.asarray(page_index, dtype=np.int32), np.asarray(y_chunk, dtype=np.int8), np.asarray(counts, dtype=np.int32)


def chunk_weights(page_index, counts, hp_mask, hn_mask, hp_mult, hn_mult):
    w = 1.0 / counts[page_index].astype(np.float64)
    w[np.asarray(hp_mask)[page_index]] *= float(hp_mult)
    w[np.asarray(hn_mask)[page_index]] *= float(hn_mult)
    return w


def aggregate_page_scores(chunk_scores, page_index, n_pages, mode):
    groups = [[] for _ in range(n_pages)]
    for s, p in zip(np.asarray(chunk_scores), np.asarray(page_index)): groups[int(p)].append(float(s))
    out = np.empty(n_pages, dtype=np.float64)
    for i, vals in enumerate(groups):
        if not vals: raise RuntimeError(f"Page {i} has no chunks")
        vals = sorted(vals, reverse=True)
        out[i] = vals[0] if mode == "max" else float(np.mean(vals[:2]))
    return out


def main():
    RESULT_DIR.mkdir(parents=True, exist_ok=True)
    print("Loading BrowseSafe...", flush=True)
    ds = load_dataset("perplexity-ai/browsesafe-bench", token=False)
    train_raw, test = ds["train"], ds["test"]
    train_fp = getattr(train_raw, "_fingerprint", None); test_fp = getattr(test, "_fingerprint", None)
    train, dup_count, overlap_count = clean_training_split(train_raw, test)
    y = np.array([LAB[x] for x in train["label"]], dtype=np.int8); idx = np.arange(len(train))
    work, audit_idx = train_test_split(idx, test_size=0.15, stratify=y, random_state=SEED)
    dev_idx, val_idx = train_test_split(work, test_size=0.1764706, stratify=y[work], random_state=SEED)
    print("Development / validation / comparative audit:", len(dev_idx), len(val_idx), len(audit_idx), flush=True)

    t0 = time.time(); dev, val = frame(train, dev_idx), frame(train, val_idx); frame_seconds = time.time() - t0
    yd, yv = dev.y.to_numpy(), val.y.to_numpy()
    vectorizers, dmat, vmat = fit_sparse(dev, val)
    oof = oof_nb_scores(dmat, yd, folds=5)
    hp_cut = float(np.quantile(oof[yd == 1], 0.45)); hn_cut = float(np.quantile(oof[yd == 0], 0.95))
    _, hp_mask, hn_mask = hard_weights(oof, yd, 1, 1, hp_cut, hn_cut)
    print("OOF hard cutoffs", hp_cut, hn_cut, "counts", int(hp_mask.sum()), int(hn_mask.sum()), flush=True)

    r = nb_log_count_ratio(dmat, yd); d_nb, v_nb = dmat.multiply(r).tocsr(), vmat.multiply(r).tocsr()
    rows, score_map, hard_models = [], {}, {}
    for c in [0.5, 1.0, 2.0]:
        for hp_mult in [1.0, 2.0, 4.0]:
            for hn_mult in [4.0, 6.0, 8.0]:
                w, _, _ = hard_weights(oof, yd, hp_mult, hn_mult, hp_cut, hn_cut)
                name = f"v21_hard|C={c:g}|hp={hp_mult:g}|hn={hn_mult:g}"
                clf = LogisticRegression(C=c, max_iter=1800, solver="liblinear", random_state=SEED)
                clf.fit(d_nb, yd, sample_weight=w); score = clf.predict_proba(v_nb)[:, 1]
                rows.append(candidate_row(name, "hard", yv, score)); score_map[name] = score; hard_models[name] = clf
    hard_name = str(best_family(pd.DataFrame(rows), "hard")["name"])

    adv_dev = build_adversarial_dev(dev, hp_mask); adv_y = adv_dev.y.to_numpy(dtype=np.int8)
    adv_vec, adv_dmat, adv_vmat = fit_sparse(adv_dev, val); adv_r = nb_log_count_ratio(adv_dmat, adv_y)
    adv_dnb, adv_vnb = adv_dmat.multiply(adv_r).tocsr(), adv_vmat.multiply(adv_r).tocsr()
    adv_weights = np.ones(len(adv_dev), dtype=np.float64); original_n = len(dev)
    adv_weights[:original_n][hp_mask] *= 2.0; adv_weights[:original_n][hn_mask] *= 4.0; adv_weights[original_n:] *= 1.5
    adv_models = {}
    for c in [0.5, 1.0, 2.0, 4.0]:
        name = f"v21_adv|C={c:g}"; clf = LogisticRegression(C=c, max_iter=1800, solver="liblinear", random_state=SEED)
        clf.fit(adv_dnb, adv_y, sample_weight=adv_weights); score = clf.predict_proba(adv_vnb)[:, 1]
        rows.append(candidate_row(name, "adv", yv, score)); score_map[name] = score; adv_models[name] = clf
    adv_name = str(best_family(pd.DataFrame(rows), "adv")["name"])
    print("ANCHOR FAMILY WINNERS", hard_name, adv_name, flush=True)

    anchor_union = constrained_union_search(yv, score_map, [hard_name, adv_name], TARGET_VAL_FPR)
    anchor_row = {**anchor_union, "name": f"anchor_or|{hard_name}+{adv_name}", "family": "anchor_or",
                  "members": [hard_name, adv_name], "threshold": np.nan, "roc_auc": np.nan}
    rows.append(anchor_row); print("VAL ANCHOR", json.dumps(json_safe(anchor_row)), flush=True)

    print("Building chunk corpora...", flush=True)
    dev_chunk_text, dev_page_idx, ydc, dev_counts = build_chunk_corpus(train, dev_idx, yd)
    val_chunk_text, val_page_idx, yvc, val_counts = build_chunk_corpus(train, val_idx, yv)
    chunk_vec = TfidfVectorizer(analyzer="char", ngram_range=(3, 5), min_df=2, max_features=120000,
                                sublinear_tf=True, dtype=np.float32)
    xdc = chunk_vec.fit_transform(dev_chunk_text).tocsr(); xvc = chunk_vec.transform(val_chunk_text).tocsr()
    print("Chunk rows dev/val", len(dev_chunk_text), len(val_chunk_text), "features", xdc.shape[1], flush=True)

    chunk_best_key = chunk_best = chunk_best_model = chunk_best_score = chunk_best_mode = None
    for c in [0.05, 0.1, 0.25, 0.5]:
        for hp_mult in [1.0, 2.0, 4.0]:
            for hn_mult in [1.0, 2.0, 4.0]:
                w = chunk_weights(dev_page_idx, dev_counts, hp_mask, hn_mask, hp_mult, hn_mult)
                clf = LinearSVC(C=c, random_state=SEED, max_iter=5000); clf.fit(xdc, ydc, sample_weight=w)
                chunk_val = clf.decision_function(xvc)
                for mode in ["max", "top2_mean"]:
                    page_score = aggregate_page_scores(chunk_val, val_page_idx, len(val), mode)
                    name = f"chunk_svc|C={c:g}|hp={hp_mult:g}|hn={hn_mult:g}|agg={mode}"
                    row = candidate_row(name, "chunk", yv, page_score, c=float(c), hp_mult=float(hp_mult),
                                        hn_mult=float(hn_mult), aggregation=mode)
                    rows.append(row); key = (row["recall"], row["precision"], -row["fpr"])
                    if chunk_best_key is None or key > chunk_best_key:
                        chunk_best_key, chunk_best, chunk_best_model = key, row.copy(), clf
                        chunk_best_score, chunk_best_mode = page_score.copy(), mode
                    print("VAL", name, round(row["recall"], 6), round(row["fpr"], 6), flush=True)
    if chunk_best is None: raise RuntimeError("No chunk winner")
    chunk_name = str(chunk_best["name"]); score_map[chunk_name] = chunk_best_score
    print("CHUNK WINNER", json.dumps(json_safe(chunk_best), indent=2), flush=True)

    three = constrained_union_search(yv, score_map, [hard_name, adv_name, chunk_name], TARGET_VAL_FPR)
    three_row = {**three, "name": f"or3|{hard_name}+{adv_name}+{chunk_name}", "family": "three_way_or",
                 "members": [hard_name, adv_name, chunk_name], "threshold": np.nan, "roc_auc": np.nan}
    rows.append(three_row); print("VAL THREE-WAY", json.dumps(json_safe(three_row)), flush=True)

    all_df = pd.DataFrame(rows).sort_values(["recall", "precision", "fpr"], ascending=[False, False, True]).reset_index(drop=True)
    all_df.to_csv(RESULT_DIR / "assessment_v21_validation.csv", index=False)
    winner = all_df.iloc[0].to_dict(); winner_name = str(winner["name"])
    print("VALIDATION WINNER", json.dumps(json_safe(winner), indent=2), flush=True)

    t0 = time.time(); audit = frame(train, audit_idx); ya = audit.y.to_numpy()
    amat = sparse_transform(audit, vectorizers).multiply(r).tocsr(); adv_amat = sparse_transform(audit, adv_vec).multiply(adv_r).tocsr()
    audit_chunk_text, audit_page_idx, yac, audit_counts = build_chunk_corpus(train, audit_idx, ya)
    xac = chunk_vec.transform(audit_chunk_text).tocsr(); audit_chunk_raw = chunk_best_model.decision_function(xac)
    chunk_audit_page = aggregate_page_scores(audit_chunk_raw, audit_page_idx, len(audit), chunk_best_mode)

    def audit_score(name):
        if name.startswith("v21_hard"): return hard_models[name].predict_proba(amat)[:, 1]
        if name.startswith("v21_adv"): return adv_models[name].predict_proba(adv_amat)[:, 1]
        if name == chunk_name: return chunk_audit_page
        raise KeyError(name)

    family = str(winner["family"])
    if family in {"anchor_or", "three_way_or"}:
        thresholds = winner["thresholds"]; members = list(thresholds.keys())
        amap = {m: audit_score(m) for m in members}
        audit_m = evaluate_union(ya, amap, {m: float(thresholds[m]) for m in members})
        audit_spec = {"type": family, "members": members, "thresholds": {m: float(thresholds[m]) for m in members}}
    else:
        audit_m = metrics(ya, audit_score(winner_name), float(winner["threshold"]))
        audit_spec = {"type": "single", "family": family, "name": winner_name, "threshold": float(winner["threshold"])}
    audit_seconds = time.time() - t0
    audit_m["recall_ci95"] = wilson(audit_m["tp"], audit_m["tp"] + audit_m["fn"])
    audit_m["fpr_ci95"] = wilson(audit_m["fp"], audit_m["fp"] + audit_m["tn"])

    promotion = {"reference_v18_recall_exact": V18_RECALL, "reference_v18_fpr_exact": V18_FPR,
                 "strictly_beats_v18_recall": bool(audit_m["recall"] > V18_RECALL + 1e-12),
                 "within_operating_fpr": bool(audit_m["fpr"] <= OPERATING_FPR)}
    promotion["promotable_over_v18"] = bool(promotion["strictly_beats_v18_recall"] and promotion["within_operating_fpr"])

    evidence = json_safe({
        "protocol_file": "agentshield/ASSESSMENT_V21_CHUNK_RESIDUAL_PROTOCOL.md", "research_only": True, "seed": SEED,
        "target_validation_fpr": TARGET_VAL_FPR, "operating_fpr_ceiling": OPERATING_FPR,
        "reference_champion": {"version": "v18", "commit": "92b5e23d143397d8732673ee2e5715b5c81e82c1",
                               "tp": 600, "fn": 221, "fp": 7, "tn": 828, "recall_exact": V18_RECALL, "fpr_exact": V18_FPR},
        "benchmark_labels_accessed": False, "audit_is_pristine": False,
        "audit_role": "comparative only; previously observed in earlier experiments",
        "dataset": "perplexity-ai/browsesafe-bench",
        "dataset_fingerprints": {"train_raw": train_fp, "test_content_source": test_fp},
        "removed_internal_duplicates": int(dup_count), "removed_train_test_overlap": int(overlap_count),
        "splits": {"development": len(dev_idx), "validation": len(val_idx), "comparative_audit": len(audit_idx)},
        "oof_hard_mining": {"folds": 5, "hard_positive_quantile": 0.45, "hard_negative_quantile": 0.95,
                            "hard_positive_cutoff": hp_cut, "hard_negative_cutoff": hn_cut,
                            "hard_positive_count": int(hp_mask.sum()), "hard_negative_count": int(hn_mask.sum())},
        "chunk_specialist": {"window_chars": CHUNK_WINDOW, "stride_chars": CHUNK_STRIDE,
                             "max_chunks_per_page": MAX_CHUNKS_PER_PAGE, "location_markers": ["HEAD", "MID", "TAIL"],
                             "vectorizer": "character tf-idf 3-5 grams", "max_features": 120000,
                             "development_chunk_rows": len(dev_chunk_text), "validation_chunk_rows": len(val_chunk_text),
                             "audit_chunk_rows": len(audit_chunk_text), "winner": chunk_best},
        "anchor_family_winners": {"hard": hard_name, "adversarial": adv_name},
        "validation_winner": winner, "audit_spec": audit_spec, "comparative_audit": audit_m, "promotion": promotion,
        "gates": {"B_70pct": bool(audit_m["recall"] >= .70 and audit_m["fpr"] <= .01),
                  "C_85pct": bool(audit_m["recall"] >= .85 and audit_m["fpr"] <= .01),
                  "D_90pct": bool(audit_m["recall"] >= .90 and audit_m["fpr"] <= .01),
                  "E_95pct": bool(audit_m["recall"] >= .95 and audit_m["fpr"] <= .01)},
        "timing": {"frame_dev_val_s": frame_seconds, "audit_representation_scoring_s": audit_seconds},
        "runtime": {"python": sys.version, "platform": platform.platform()},
    })
    with open(RESULT_DIR / "assessment_v21_evidence.json", "w") as f: json.dump(evidence, f, indent=2, allow_nan=False)
    print("V21 EVIDENCE", json.dumps(evidence, indent=2), flush=True)


if __name__ == "__main__": main()
