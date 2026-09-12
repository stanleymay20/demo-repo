"""AgentShield assessment v20 semantic residual rescue experiment.

Research-only successor. Frozen assessment notebook and verified v18 champion are untouched.
BrowseSafe benchmark/test labels are never accessed.
The internal audit has been observed previously and is comparative only.
"""
from __future__ import annotations

import json
import math
import os
import platform
import sys
import time
from pathlib import Path

import numpy as np
import pandas as pd
import torch
from datasets import load_dataset
from huggingface_hub import HfApi
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split
from transformers import AutoModel, AutoTokenizer

from assessment_v16_hard_rescue import (
    LAB, SEED, clean_training_split, fit_sparse, frame, metrics,
    nb_log_count_ratio, sparse_transform, threshold_at_fpr, wilson,
)
from assessment_v17_oof_adversarial import build_adversarial_dev, hard_weights, oof_nb_scores
from assessment_v18_fpr_stable import (
    evaluate_union, json_safe, logit, sigmoid, thresholds_for_budget,
)

np.random.seed(SEED)
torch.manual_seed(SEED)
RESULT_DIR = Path("agentshield/results")
TARGET_VAL_FPR = 0.006
OPERATING_FPR = 0.01
MODEL_ID = "BAAI/bge-small-en-v1.5"
MAX_LENGTH = 384
BATCH_SIZE = 32
EPS = 1e-8


def mean_pool(last_hidden, attention_mask):
    mask = attention_mask.unsqueeze(-1).expand(last_hidden.size()).float()
    summed = torch.sum(last_hidden * mask, dim=1)
    denom = torch.clamp(mask.sum(dim=1), min=1e-9)
    return summed / denom


def encode_contexts(texts, tokenizer, model, device):
    arr = []
    model.eval()
    with torch.no_grad():
        for start in range(0, len(texts), BATCH_SIZE):
            batch = [str(x) for x in texts[start:start + BATCH_SIZE]]
            tok = tokenizer(
                batch,
                padding=True,
                truncation=True,
                max_length=MAX_LENGTH,
                return_tensors="pt",
            )
            tok = {k: v.to(device) for k, v in tok.items()}
            out = model(**tok)
            emb = mean_pool(out.last_hidden_state, tok["attention_mask"])
            emb = torch.nn.functional.normalize(emb, p=2, dim=1)
            arr.append(emb.cpu().numpy().astype(np.float32))
            if (start // BATCH_SIZE) % 20 == 0:
                print(f"semantic encode {min(start + BATCH_SIZE, len(texts))}/{len(texts)}", flush=True)
    return np.vstack(arr)


def constrained_three_way(y, score_map, names, max_fpr):
    y = np.asarray(y)
    max_fp = int(math.floor(float(max_fpr) * int((y == 0).sum())))
    lists = {name: thresholds_for_budget(y, score_map[name], max_fpr) for name in names}
    best_key = None
    best = None
    for t0 in lists[names[0]]:
        for t1 in lists[names[1]]:
            for t2 in lists[names[2]]:
                th = {names[0]: t0, names[1]: t1, names[2]: t2}
                m = evaluate_union(y, score_map, th)
                if m["fp"] > max_fp:
                    continue
                key = (m["recall"], m["precision"], -m["fpr"])
                if best_key is None or key > best_key:
                    best_key = key
                    best = {**m, "thresholds": th}
    if best is None:
        raise RuntimeError("No feasible three-way union")
    return best


def evaluate_gated(y, hard_score, adv_score, sem_score, hard_th, adv_th, sem_th, gate_th):
    y = np.asarray(y)
    sparse_fused = sigmoid(0.5 * logit(hard_score) + 0.5 * logit(adv_score))
    pred = (
        (np.asarray(hard_score) >= float(hard_th))
        | (np.asarray(adv_score) >= float(adv_th))
        | ((np.asarray(sem_score) >= float(sem_th)) & (sparse_fused >= float(gate_th)))
    )
    tn = int(((y == 0) & (~pred)).sum())
    fp = int(((y == 0) & pred).sum())
    fn = int(((y == 1) & (~pred)).sum())
    tp = int(((y == 1) & pred).sum())
    precision = tp / max(1, tp + fp)
    recall = tp / max(1, tp + fn)
    fpr = fp / max(1, fp + tn)
    f1 = 2 * precision * recall / max(EPS, precision + recall)
    return {
        "precision": float(precision), "recall": float(recall), "f1": float(f1),
        "fpr": float(fpr), "tn": tn, "fp": fp, "fn": fn, "tp": tp,
    }


def gated_search(y, hard_score, adv_score, sem_score, max_fpr):
    y = np.asarray(y)
    max_fp = int(math.floor(float(max_fpr) * int((y == 0).sum())))
    hard_ts = thresholds_for_budget(y, hard_score, max_fpr)
    adv_ts = thresholds_for_budget(y, adv_score, max_fpr)
    sem_ts = thresholds_for_budget(y, sem_score, max_fpr)
    sparse_fused = sigmoid(0.5 * logit(hard_score) + 0.5 * logit(adv_score))
    gate_q = [0.35, 0.50, 0.65, 0.75, 0.85, 0.90, 0.95]
    gate_ts = sorted({float(np.quantile(sparse_fused, q)) for q in gate_q})
    best_key = None
    best = None
    for h in hard_ts:
        for a in adv_ts:
            for s in sem_ts:
                for g in gate_ts:
                    m = evaluate_gated(y, hard_score, adv_score, sem_score, h, a, s, g)
                    if m["fp"] > max_fp:
                        continue
                    key = (m["recall"], m["precision"], -m["fpr"])
                    if best_key is None or key > best_key:
                        best_key = key
                        best = {
                            **m,
                            "hard_threshold": float(h),
                            "adv_threshold": float(a),
                            "semantic_threshold": float(s),
                            "sparse_gate_threshold": float(g),
                        }
    if best is None:
        raise RuntimeError("No feasible gated rescue")
    return best


def candidate_row(name, family, y, score, **extra):
    th = threshold_at_fpr(y, score, max_fpr=TARGET_VAL_FPR)
    m = metrics(y, score, th)
    return {**m, "name": name, "family": family, **extra}


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

    # Reconstruct v18 sparse anchor family.
    vectorizers, dmat, vmat = fit_sparse(dev, val)
    oof = oof_nb_scores(dmat, yd, folds=5)
    hp_cut = float(np.quantile(oof[yd == 1], 0.45))
    hn_cut = float(np.quantile(oof[yd == 0], 0.95))
    _, hp_mask, hn_mask = hard_weights(oof, yd, 1, 1, hp_cut, hn_cut)
    print("OOF hard cutoffs", hp_cut, hn_cut, "counts", int(hp_mask.sum()), int(hn_mask.sum()), flush=True)

    r = nb_log_count_ratio(dmat, yd)
    d_nb, v_nb = dmat.multiply(r).tocsr(), vmat.multiply(r).tocsr()
    sparse_rows, sparse_scores, hard_models = [], {}, {}
    for c in [0.5, 1.0, 2.0]:
        for hp_mult in [1.0, 2.0, 4.0]:
            for hn_mult in [4.0, 6.0, 8.0]:
                w, _, _ = hard_weights(oof, yd, hp_mult, hn_mult, hp_cut, hn_cut)
                name = f"v18_hard|C={c:g}|hp={hp_mult:g}|hn={hn_mult:g}"
                clf = LogisticRegression(C=c, max_iter=1800, solver="liblinear", random_state=SEED)
                clf.fit(d_nb, yd, sample_weight=w)
                score = clf.predict_proba(v_nb)[:, 1]
                row = candidate_row(name, "hard", yv, score)
                sparse_rows.append(row); sparse_scores[name] = score; hard_models[name] = clf

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
        name = f"v18_adv|C={c:g}"
        clf = LogisticRegression(C=c, max_iter=1800, solver="liblinear", random_state=SEED)
        clf.fit(adv_dnb, adv_y, sample_weight=adv_weights)
        score = clf.predict_proba(adv_vnb)[:, 1]
        row = candidate_row(name, "adv", yv, score)
        sparse_rows.append(row); sparse_scores[name] = score; adv_models[name] = clf

    sparse_df = pd.DataFrame(sparse_rows)
    hard_best = sparse_df[sparse_df.family == "hard"].sort_values(
        ["recall", "precision", "fpr"], ascending=[False, False, True]
    ).iloc[0]
    adv_best = sparse_df[sparse_df.family == "adv"].sort_values(
        ["recall", "precision", "fpr"], ascending=[False, False, True]
    ).iloc[0]
    hard_name, adv_name = str(hard_best["name"]), str(adv_best["name"])
    print("SPARSE FAMILY WINNERS", hard_name, adv_name, flush=True)

    anchor = None
    hard_ts = thresholds_for_budget(yv, sparse_scores[hard_name], TARGET_VAL_FPR)
    adv_ts = thresholds_for_budget(yv, sparse_scores[adv_name], TARGET_VAL_FPR)
    max_fp = int(math.floor(TARGET_VAL_FPR * int((yv == 0).sum())))
    for ht in hard_ts:
        for at in adv_ts:
            m = evaluate_union(yv, sparse_scores, {hard_name: ht, adv_name: at})
            if m["fp"] > max_fp:
                continue
            key = (m["recall"], m["precision"], -m["fpr"])
            if anchor is None or key > anchor["_key"]:
                anchor = {**m, "thresholds": {hard_name: float(ht), adv_name: float(at)}, "_key": key}
    anchor.pop("_key")
    print("V18-STYLE ANCHOR", json.dumps(json_safe(anchor), indent=2), flush=True)

    resolved_revision = HfApi().model_info(MODEL_ID).sha
    print("Semantic model", MODEL_ID, "revision", resolved_revision, flush=True)
    tokenizer = AutoTokenizer.from_pretrained(MODEL_ID, revision=resolved_revision, trust_remote_code=False)
    encoder = AutoModel.from_pretrained(MODEL_ID, revision=resolved_revision, trust_remote_code=False)
    device = torch.device("cpu")
    encoder.to(device)
    torch.set_num_threads(max(1, min(8, os.cpu_count() or 2)))

    t0 = time.time()
    dev_emb = encode_contexts(dev["context"].tolist(), tokenizer, encoder, device)
    val_emb = encode_contexts(val["context"].tolist(), tokenizer, encoder, device)
    semantic_encode_seconds = time.time() - t0

    sem_rows, sem_scores, sem_models = [], {}, {}
    for c in [0.05, 0.1, 0.25, 0.5, 1.0, 2.0]:
        for hp_mult in [2.0, 4.0, 8.0]:
            for hn_mult in [1.0, 2.0, 4.0]:
                w, _, _ = hard_weights(oof, yd, hp_mult, hn_mult, hp_cut, hn_cut)
                name = f"bge_residual|C={c:g}|hp={hp_mult:g}|hn={hn_mult:g}"
                clf = LogisticRegression(C=c, max_iter=2500, solver="liblinear", random_state=SEED)
                clf.fit(dev_emb, yd, sample_weight=w)
                score = clf.predict_proba(val_emb)[:, 1]
                row = candidate_row(name, "semantic", yv, score)
                sem_rows.append(row); sem_scores[name] = score; sem_models[name] = clf
                print("VAL", name, round(row["recall"], 6), round(row["fpr"], 6), flush=True)

    sem_df = pd.DataFrame(sem_rows).sort_values(
        ["recall", "precision", "fpr"], ascending=[False, False, True]
    ).reset_index(drop=True)
    sem_best = sem_df.iloc[0]
    sem_name = str(sem_best["name"])
    print("SEMANTIC WINNER", sem_name, flush=True)

    score_map = {
        hard_name: sparse_scores[hard_name],
        adv_name: sparse_scores[adv_name],
        sem_name: sem_scores[sem_name],
    }

    tri = constrained_three_way(yv, score_map, [hard_name, adv_name, sem_name], TARGET_VAL_FPR)
    gated = gated_search(
        yv, score_map[hard_name], score_map[adv_name], score_map[sem_name], TARGET_VAL_FPR
    )

    candidates = [
        {
            **anchor,
            "name": "v18_style_anchor",
            "family": "anchor",
            "members": [hard_name, adv_name],
            "threshold": np.nan,
            "roc_auc": np.nan,
        },
        {
            **{k: sem_best[k] for k in ["threshold", "precision", "recall", "f1", "roc_auc", "fpr", "tn", "fp", "fn", "tp"]},
            "name": sem_name,
            "family": "semantic",
        },
        {
            **tri,
            "name": "semantic_three_way_or",
            "family": "three_way_or",
            "members": [hard_name, adv_name, sem_name],
            "threshold": np.nan,
            "roc_auc": np.nan,
        },
        {
            **gated,
            "name": "semantic_residual_gate",
            "family": "gated_rescue",
            "members": [hard_name, adv_name, sem_name],
            "threshold": np.nan,
            "roc_auc": np.nan,
        },
    ]
    val_df = pd.DataFrame(candidates).sort_values(
        ["recall", "precision", "fpr"], ascending=[False, False, True]
    ).reset_index(drop=True)
    val_df.to_csv(RESULT_DIR / "assessment_v20_validation.csv", index=False)
    winner = val_df.iloc[0].to_dict()
    print("VALIDATION WINNER", json.dumps(json_safe(winner), indent=2), flush=True)

    t0 = time.time()
    audit = frame(train, audit_idx)
    ya = audit.y.to_numpy()
    amat = sparse_transform(audit, vectorizers).multiply(r).tocsr()
    adv_amat = sparse_transform(audit, adv_vec).multiply(adv_r).tocsr()
    audit_hard = hard_models[hard_name].predict_proba(amat)[:, 1]
    audit_adv = adv_models[adv_name].predict_proba(adv_amat)[:, 1]
    audit_emb = encode_contexts(audit["context"].tolist(), tokenizer, encoder, device)
    audit_sem = sem_models[sem_name].predict_proba(audit_emb)[:, 1]
    audit_seconds = time.time() - t0

    fam = str(winner["family"])
    if fam == "anchor":
        th = anchor["thresholds"]
        audit_m = evaluate_union(
            ya,
            {hard_name: audit_hard, adv_name: audit_adv},
            {hard_name: float(th[hard_name]), adv_name: float(th[adv_name])},
        )
        audit_spec = {"type": "v18_style_anchor", "thresholds": th}
    elif fam == "semantic":
        audit_m = metrics(ya, audit_sem, float(winner["threshold"]))
        audit_spec = {"type": "semantic_only", "name": sem_name, "threshold": float(winner["threshold"])}
    elif fam == "three_way_or":
        th = winner["thresholds"]
        audit_m = evaluate_union(
            ya,
            {hard_name: audit_hard, adv_name: audit_adv, sem_name: audit_sem},
            {hard_name: float(th[hard_name]), adv_name: float(th[adv_name]), sem_name: float(th[sem_name])},
        )
        audit_spec = {"type": "three_way_or", "thresholds": th}
    elif fam == "gated_rescue":
        audit_m = evaluate_gated(
            ya, audit_hard, audit_adv, audit_sem,
            float(winner["hard_threshold"]),
            float(winner["adv_threshold"]),
            float(winner["semantic_threshold"]),
            float(winner["sparse_gate_threshold"]),
        )
        audit_spec = {
            "type": "semantic_residual_gate",
            "hard_threshold": float(winner["hard_threshold"]),
            "adv_threshold": float(winner["adv_threshold"]),
            "semantic_threshold": float(winner["semantic_threshold"]),
            "sparse_gate_threshold": float(winner["sparse_gate_threshold"]),
        }
    else:
        raise RuntimeError(f"Unknown winner family {fam}")

    audit_m["recall_ci95"] = wilson(audit_m["tp"], audit_m["tp"] + audit_m["fn"])
    audit_m["fpr_ci95"] = wilson(audit_m["fp"], audit_m["fp"] + audit_m["tn"])

    evidence = json_safe({
        "protocol_file": "agentshield/ASSESSMENT_V20_SEMANTIC_RESIDUAL_PROTOCOL.md",
        "research_only": True,
        "seed": SEED,
        "target_validation_fpr": TARGET_VAL_FPR,
        "operating_fpr_ceiling": OPERATING_FPR,
        "reference_champion": {
            "version": "v18",
            "commit": "92b5e23d143397d8732673ee2e5715b5c81e82c1",
            "comparative_audit_recall": 0.7308,
            "comparative_audit_fpr": 0.00838,
        },
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
        "semantic_encoder": {
            "model_id": MODEL_ID,
            "resolved_revision": resolved_revision,
            "frozen": True,
            "max_length": MAX_LENGTH,
            "batch_size": BATCH_SIZE,
            "pooling": "attention-mask mean pooling + L2 normalization",
            "input_view": "controlled context: visible text + hidden evidence + script cues",
        },
        "semantic_family_winner": sem_name,
        "validation_winner": winner,
        "audit_spec": audit_spec,
        "comparative_audit": audit_m,
        "promotion": {
            "beats_v18_recall_point_estimate": bool(audit_m["recall"] > 0.7308),
            "within_operating_fpr": bool(audit_m["fpr"] <= OPERATING_FPR),
            "promotable_over_v18": bool(audit_m["recall"] > 0.7308 and audit_m["fpr"] <= OPERATING_FPR),
        },
        "gates": {
            "B_70pct": bool(audit_m["recall"] >= .70 and audit_m["fpr"] <= .01),
            "C_85pct": bool(audit_m["recall"] >= .85 and audit_m["fpr"] <= .01),
            "D_90pct": bool(audit_m["recall"] >= .90 and audit_m["fpr"] <= .01),
            "E_95pct": bool(audit_m["recall"] >= .95 and audit_m["fpr"] <= .01),
        },
        "timing": {
            "frame_dev_val_s": frame_seconds,
            "semantic_dev_val_encode_s": semantic_encode_seconds,
            "audit_representation_scoring_s": audit_seconds,
        },
        "runtime": {
            "python": sys.version,
            "platform": platform.platform(),
            "torch": torch.__version__,
        },
    })
    with open(RESULT_DIR / "assessment_v20_evidence.json", "w") as f:
        json.dump(evidence, f, indent=2, allow_nan=False)
    print("V20 EVIDENCE", json.dumps(evidence, indent=2), flush=True)


if __name__ == "__main__":
    main()
