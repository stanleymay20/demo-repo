"""AgentShield assessment v23: development-residual ELECTRA sequence specialist.

Research only. Frozen assessment notebook untouched.
BrowseSafe benchmark/test labels are never accessed.
Comparative audit is non-pristine and evaluated only after validation freeze.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import platform
import random
import sys
import time
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
import torch
from datasets import load_dataset
from scipy.sparse import load_npz, save_npz
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split
from torch.utils.data import DataLoader, Dataset
from transformers import AutoModelForSequenceClassification, AutoTokenizer, get_linear_schedule_with_warmup

from assessment_v16_hard_rescue import (
    LAB,
    SEED,
    clean_training_split,
    fit_sparse,
    frame,
    metrics,
    nb_log_count_ratio,
    sparse_transform,
    threshold_at_fpr,
    wilson,
)
from assessment_v17_oof_adversarial import build_adversarial_dev, hard_weights, oof_nb_scores

np.random.seed(SEED)
random.seed(SEED)
torch.manual_seed(SEED)

PROTOCOL = Path("agentshield/ASSESSMENT_V23_SEQUENCE_RESIDUAL_PROTOCOL.md")
RESULT_DIR = Path("agentshield/results")
MODEL_ID = "google/electra-small-discriminator"
MODEL_REVISION = "fa8239aadc095e9164941d05878b98afe9b953c3"
TARGET_VAL_FPR = 0.006
OPERATING_FPR = 0.01
V18_RECALL = 600.0 / 821.0
V18_FPR = 7.0 / 835.0
MAX_LENGTH = 256
EPOCHS = 2
LR = 3e-5
WEIGHT_DECAY = 0.01
BATCH_SIZE = 16
WARMUP_RATIO = 0.06
EPS = 1e-12
EXPECTED_SPLITS = (7725, 1656, 1656)


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def sha256_texts(texts) -> str:
    h = hashlib.sha256()
    for text in texts:
        b = ("" if text is None else str(text)).encode("utf-8", "ignore")
        h.update(len(b).to_bytes(8, "little")); h.update(b)
    return h.hexdigest()


def write_manifest(directory: Path, name: str) -> Path:
    entries = []
    for p in sorted(directory.rglob("*")):
        if p.is_file() and p.name != name:
            entries.append({"path": str(p.relative_to(directory)), "size": p.stat().st_size, "sha256": sha256_file(p)})
    out = directory / name
    out.write_text(json.dumps({"files": entries}, indent=2), encoding="utf-8")
    return out


def verify_manifest(directory: Path, name: str) -> str:
    path = directory / name
    payload = json.loads(path.read_text(encoding="utf-8"))
    for row in payload["files"]:
        p = directory / row["path"]
        if not p.is_file():
            raise RuntimeError(f"Missing checkpoint file: {p}")
        if p.stat().st_size != int(row["size"]):
            raise RuntimeError(f"Checkpoint size mismatch: {p}")
        got = sha256_file(p)
        if got != row["sha256"]:
            raise RuntimeError(f"Checkpoint SHA mismatch: {p} {got} != {row['sha256']}")
    return sha256_file(path)


def json_safe(value):
    if isinstance(value, dict): return {str(k): json_safe(v) for k, v in value.items()}
    if isinstance(value, list): return [json_safe(v) for v in value]
    if isinstance(value, tuple): return [json_safe(v) for v in value]
    if isinstance(value, np.ndarray): return [json_safe(v) for v in value.tolist()]
    if isinstance(value, (float, np.floating)): return None if not np.isfinite(value) else float(value)
    if isinstance(value, (int, np.integer)): return int(value)
    if isinstance(value, (bool, np.bool_)): return bool(value)
    return value


def split_dataset():
    ds = load_dataset("perplexity-ai/browsesafe-bench", token=False)
    train_raw, test = ds["train"], ds["test"]
    train_fp = getattr(train_raw, "_fingerprint", None)
    test_fp = getattr(test, "_fingerprint", None)
    train, dup_count, overlap_count = clean_training_split(train_raw, test)
    y = np.array([LAB[x] for x in train["label"]], dtype=np.int8)
    idx = np.arange(len(train))
    work, audit_idx = train_test_split(idx, test_size=0.15, stratify=y, random_state=SEED)
    dev_idx, val_idx = train_test_split(work, test_size=0.1764706, stratify=y[work], random_state=SEED)
    if (len(dev_idx), len(val_idx), len(audit_idx)) != EXPECTED_SPLITS:
        raise RuntimeError(f"Unexpected split sizes: {len(dev_idx)}, {len(val_idx)}, {len(audit_idx)}")
    return train, train_fp, test_fp, int(dup_count), int(overlap_count), y, dev_idx, val_idx, audit_idx


def thresholds_for_budget(y, score, max_fpr):
    y = np.asarray(y); score = np.asarray(score)
    benign_scores = np.sort(score[y == 0])[::-1]
    max_fp = int(math.floor(float(max_fpr) * int((y == 0).sum())))
    if len(benign_scores) == 0: raise RuntimeError("No benign rows")
    out = [float(np.nextafter(benign_scores[0], np.inf))]
    for k in range(1, max_fp + 1):
        hi = benign_scores[k - 1]
        lo = benign_scores[k] if k < len(benign_scores) else -np.inf
        out.append(float((hi + lo) / 2.0 if np.isfinite(lo) else np.nextafter(hi, -np.inf)))
    return out


def evaluate_union(y, score_map, threshold_map):
    y = np.asarray(y)
    pred = np.zeros(len(y), dtype=bool)
    for name, threshold in threshold_map.items():
        pred |= np.asarray(score_map[name]) >= float(threshold)
    tn = int(((y == 0) & (~pred)).sum()); fp = int(((y == 0) & pred).sum())
    fn = int(((y == 1) & (~pred)).sum()); tp = int(((y == 1) & pred).sum())
    precision = tp / max(1, tp + fp); recall = tp / max(1, tp + fn); fpr = fp / max(1, fp + tn)
    f1 = 2.0 * precision * recall / max(EPS, precision + recall)
    return {"precision": float(precision), "recall": float(recall), "f1": float(f1), "fpr": float(fpr),
            "tn": tn, "fp": fp, "fn": fn, "tp": tp}


def constrained_union_search(y, score_map, names, max_fpr):
    max_fp = int(math.floor(float(max_fpr) * int((np.asarray(y) == 0).sum())))
    lists = [thresholds_for_budget(y, score_map[n], max_fpr) for n in names]
    best_key = None; best = None

    def rec(i, current):
        nonlocal best_key, best
        if i == len(names):
            m = evaluate_union(y, score_map, current)
            if m["fp"] > max_fp: return
            key = (m["recall"], m["precision"], -m["fpr"])
            if best_key is None or key > best_key:
                best_key = key; best = {**m, "thresholds": dict(current)}
            return
        name = names[i]
        for th in lists[i]:
            current[name] = float(th); rec(i + 1, current)
        current.pop(name, None)

    rec(0, {})
    if best is None: raise RuntimeError("No feasible constrained union")
    return best


class WeightedEncodedDataset(Dataset):
    def __init__(self, encodings, labels, weights):
        self.encodings = encodings
        self.labels = torch.as_tensor(labels, dtype=torch.long)
        self.weights = torch.as_tensor(weights, dtype=torch.float32)
    def __len__(self): return len(self.labels)
    def __getitem__(self, idx):
        item = {k: v[idx] for k, v in self.encodings.items()}
        item["labels"] = self.labels[idx]
        item["example_weight"] = self.weights[idx]
        return item


@torch.no_grad()
def model_scores(tokenizer, model, texts, batch_size=32):
    model.eval(); out = []
    for start in range(0, len(texts), batch_size):
        enc = tokenizer(list(texts[start:start + batch_size]), padding=True, truncation=True,
                        max_length=MAX_LENGTH, return_tensors="pt")
        logits = model(**enc).logits
        out.extend(torch.softmax(logits, dim=1)[:, 1].cpu().numpy().tolist())
    return np.asarray(out, dtype=np.float64)


def stage1(out_dir: Path):
    out_dir.mkdir(parents=True, exist_ok=True)
    print("STAGE1 loading BrowseSafe", flush=True)
    train, train_fp, test_fp, dup_count, overlap_count, y, dev_idx, val_idx, audit_idx = split_dataset()
    t0 = time.time()
    dev, val = frame(train, dev_idx), frame(train, val_idx)
    yd, yv = dev.y.to_numpy(dtype=np.int8), val.y.to_numpy(dtype=np.int8)
    vectorizers, dmat, vmat = fit_sparse(dev, val)
    oof = oof_nb_scores(dmat, yd, folds=5)
    residual_th = threshold_at_fpr(yd, oof, max_fpr=TARGET_VAL_FPR)
    residual_metrics = metrics(yd, oof, residual_th)
    residual_pos = (yd == 1) & (oof < residual_th)
    hard_benign_cut = float(np.quantile(oof[yd == 0], 0.95))
    hard_benign = (yd == 0) & (oof >= hard_benign_cut)
    hp_cut = float(np.quantile(oof[yd == 1], 0.45)); hn_cut = float(np.quantile(oof[yd == 0], 0.95))
    _, hp_mask, hn_mask = hard_weights(oof, yd, 1, 1, hp_cut, hn_cut)
    elapsed = time.time() - t0
    print("STAGE1 residual", json.dumps(json_safe({"threshold": residual_th, "metrics": residual_metrics,
          "residual_positive_count": int(residual_pos.sum()), "hard_benign_count": int(hard_benign.sum()),
          "hp_count": int(hp_mask.sum()), "hn_count": int(hn_mask.sum())})), flush=True)

    dev.to_pickle(out_dir / "dev.pkl"); val.to_pickle(out_dir / "val.pkl")
    joblib.dump(vectorizers, out_dir / "vectorizers.joblib", compress=3)
    save_npz(out_dir / "dmat.npz", dmat, compressed=True); save_npz(out_dir / "vmat.npz", vmat, compressed=True)
    np.savez_compressed(out_dir / "arrays.npz", dev_idx=dev_idx, val_idx=val_idx, audit_idx=audit_idx,
                        yd=yd, yv=yv, oof=oof, residual_pos=residual_pos, hard_benign=hard_benign,
                        hp_mask=hp_mask, hn_mask=hn_mask)
    meta = {
        "stage": 1, "protocol_sha256": sha256_file(PROTOCOL), "model_id": MODEL_ID, "model_revision": MODEL_REVISION,
        "seed": SEED, "target_validation_fpr": TARGET_VAL_FPR,
        "dataset_fingerprints": {"train_raw": train_fp, "test_content_source": test_fp},
        "removed_internal_duplicates": dup_count, "removed_train_test_overlap": overlap_count,
        "splits": {"development": len(dev_idx), "validation": len(val_idx), "comparative_audit": len(audit_idx)},
        "residual_discovery": {"folds": 5, "threshold": residual_th, "metrics": residual_metrics,
            "residual_positive_count": int(residual_pos.sum()), "hard_benign_cutoff": hard_benign_cut,
            "hard_benign_count": int(hard_benign.sum()), "hard_positive_cutoff": hp_cut,
            "hard_negative_cutoff": hn_cut, "hard_positive_count": int(hp_mask.sum()), "hard_negative_count": int(hn_mask.sum())},
        "context_sha256": {"development": sha256_texts(dev["context"].tolist()), "validation": sha256_texts(val["context"].tolist())},
        "elapsed_seconds": elapsed,
    }
    (out_dir / "meta.json").write_text(json.dumps(json_safe(meta), indent=2), encoding="utf-8")
    manifest = write_manifest(out_dir, "MANIFEST.json")
    print("STAGE1 manifest", sha256_file(manifest), flush=True)


def verify_stage1(stage1_dir: Path):
    manifest_sha = verify_manifest(stage1_dir, "MANIFEST.json")
    meta = json.loads((stage1_dir / "meta.json").read_text(encoding="utf-8"))
    if meta["protocol_sha256"] != sha256_file(PROTOCOL): raise RuntimeError("Protocol SHA mismatch")
    if meta["model_id"] != MODEL_ID or meta["model_revision"] != MODEL_REVISION: raise RuntimeError("Model identity mismatch")
    train, train_fp, test_fp, dup_count, overlap_count, y, dev_idx, val_idx, audit_idx = split_dataset()
    arr = np.load(stage1_dir / "arrays.npz")
    for name, expected in [("dev_idx", dev_idx), ("val_idx", val_idx), ("audit_idx", audit_idx)]:
        if not np.array_equal(arr[name], expected): raise RuntimeError(f"Split mismatch: {name}")
    if not np.array_equal(arr["yd"], y[dev_idx]) or not np.array_equal(arr["yv"], y[val_idx]): raise RuntimeError("Label mismatch")
    if meta["dataset_fingerprints"] != {"train_raw": train_fp, "test_content_source": test_fp}: raise RuntimeError("Dataset fingerprint mismatch")
    if meta["removed_internal_duplicates"] != dup_count or meta["removed_train_test_overlap"] != overlap_count: raise RuntimeError("Cleanup count mismatch")
    dev = pd.read_pickle(stage1_dir / "dev.pkl"); val = pd.read_pickle(stage1_dir / "val.pkl")
    if sha256_texts(dev["context"].tolist()) != meta["context_sha256"]["development"]: raise RuntimeError("Development context mismatch")
    if sha256_texts(val["context"].tolist()) != meta["context_sha256"]["validation"]: raise RuntimeError("Validation context mismatch")
    return manifest_sha, meta, train, y, dev_idx, val_idx, audit_idx, arr, dev, val


def stage2(stage1_dir: Path, out_dir: Path):
    out_dir.mkdir(parents=True, exist_ok=True)
    stage1_manifest_sha, meta1, train, y, dev_idx, val_idx, audit_idx, arr, dev, val = verify_stage1(stage1_dir)
    yd = arr["yd"].astype(np.int8); residual = arr["residual_pos"].astype(bool); hard_benign = arr["hard_benign"].astype(bool)
    keep = residual | (yd == 0)
    train_texts = dev.loc[keep, "context"].tolist(); train_y = yd[keep]
    n_pos = int((train_y == 1).sum()); n_neg = int((train_y == 0).sum())
    if n_pos <= 0 or n_neg <= 0: raise RuntimeError("Residual training population is degenerate")
    positive_weight = float(n_neg / n_pos)
    weights = np.ones(len(train_y), dtype=np.float64)
    weights[train_y == 1] *= positive_weight
    keep_idx = np.where(keep)[0]
    hb_in_keep = hard_benign[keep_idx]
    weights[(train_y == 0) & hb_in_keep] *= 2.0
    print("STAGE2 population", len(train_y), "residual_pos", n_pos, "benign", n_neg,
          "positive_weight", positive_weight, "hard_benign", int(hb_in_keep.sum()), flush=True)

    torch.manual_seed(SEED); random.seed(SEED); np.random.seed(SEED)
    torch.use_deterministic_algorithms(True, warn_only=True)
    if os.cpu_count(): torch.set_num_threads(max(1, min(4, os.cpu_count())))
    tokenizer = AutoTokenizer.from_pretrained(MODEL_ID, revision=MODEL_REVISION)
    model = AutoModelForSequenceClassification.from_pretrained(MODEL_ID, revision=MODEL_REVISION, num_labels=2)
    enc = tokenizer(train_texts, padding=True, truncation=True, max_length=MAX_LENGTH, return_tensors="pt")
    ds = WeightedEncodedDataset(enc, train_y, weights)
    generator = torch.Generator().manual_seed(SEED)
    loader = DataLoader(ds, batch_size=BATCH_SIZE, shuffle=True, generator=generator)
    optimizer = torch.optim.AdamW(model.parameters(), lr=LR, weight_decay=WEIGHT_DECAY)
    total_updates = len(loader) * EPOCHS; warmup = int(total_updates * WARMUP_RATIO)
    scheduler = get_linear_schedule_with_warmup(optimizer, warmup, total_updates)
    ce = torch.nn.CrossEntropyLoss(reduction="none")
    losses = []; t0 = time.time(); model.train()
    for epoch in range(EPOCHS):
        running = 0.0
        for batch in loader:
            ew = batch.pop("example_weight"); labels = batch.pop("labels")
            logits = model(**batch).logits
            per = ce(logits, labels); loss = (per * ew).sum() / ew.sum().clamp_min(1e-6)
            loss.backward(); torch.nn.utils.clip_grad_norm_(model.parameters(), 1.0)
            optimizer.step(); scheduler.step(); optimizer.zero_grad(set_to_none=True)
            running += float(loss.detach())
        epoch_loss = running / max(1, len(loader)); losses.append(epoch_loss)
        print(f"STAGE2 epoch={epoch+1}/{EPOCHS} weighted_loss={epoch_loss:.6f}", flush=True)
    train_seconds = time.time() - t0
    val_scores = model_scores(tokenizer, model, val["context"].tolist())

    model_dir = out_dir / "model"; model_dir.mkdir(parents=True, exist_ok=True)
    model.save_pretrained(model_dir, safe_serialization=True); tokenizer.save_pretrained(model_dir)
    np.save(out_dir / "sequence_val.npy", val_scores)
    meta2 = {
        "stage": 2, "source_stage1_manifest_sha256": stage1_manifest_sha,
        "protocol_sha256": sha256_file(PROTOCOL), "model_id": MODEL_ID, "model_revision": MODEL_REVISION,
        "training_population": {"rows": len(train_y), "residual_positive": n_pos, "benign": n_neg,
                                "positive_balance_weight": positive_weight, "hard_benign_multiplier": 2.0,
                                "anchor_caught_development_positives_excluded": int(((yd == 1) & (~residual)).sum())},
        "hyperparameters": {"max_length": MAX_LENGTH, "epochs": EPOCHS, "learning_rate": LR,
                            "weight_decay": WEIGHT_DECAY, "batch_size": BATCH_SIZE, "warmup_ratio": WARMUP_RATIO,
                            "gradient_clip": 1.0, "seed": SEED},
        "epoch_losses": losses, "train_seconds": train_seconds,
        "validation_score_sha256": sha256_file(out_dir / "sequence_val.npy"),
        "runtime": {"python": sys.version, "platform": platform.platform(), "torch": torch.__version__},
    }
    (out_dir / "meta.json").write_text(json.dumps(json_safe(meta2), indent=2), encoding="utf-8")
    manifest = write_manifest(out_dir, "MANIFEST.json")
    print("STAGE2 manifest", sha256_file(manifest), flush=True)


def verify_stage2(stage2_dir: Path, stage1_manifest_sha: str):
    manifest_sha = verify_manifest(stage2_dir, "MANIFEST.json")
    meta = json.loads((stage2_dir / "meta.json").read_text(encoding="utf-8"))
    if meta["source_stage1_manifest_sha256"] != stage1_manifest_sha: raise RuntimeError("Stage1 transport linkage mismatch")
    if meta["protocol_sha256"] != sha256_file(PROTOCOL): raise RuntimeError("Stage2 protocol SHA mismatch")
    if meta["model_id"] != MODEL_ID or meta["model_revision"] != MODEL_REVISION: raise RuntimeError("Stage2 model identity mismatch")
    return manifest_sha, meta


def family_best(rows, family):
    df = pd.DataFrame(rows)
    return df[df.family == family].sort_values(["recall", "precision", "fpr"], ascending=[False, False, True]).iloc[0]


def stage3(stage1_dir: Path, stage2_dir: Path, result_dir: Path):
    result_dir.mkdir(parents=True, exist_ok=True)
    stage1_manifest_sha, meta1, train, y, dev_idx, val_idx, audit_idx, arr, dev, val = verify_stage1(stage1_dir)
    stage2_manifest_sha, meta2 = verify_stage2(stage2_dir, stage1_manifest_sha)
    yd, yv = arr["yd"].astype(np.int8), arr["yv"].astype(np.int8)
    oof = arr["oof"].astype(np.float64); hp_mask = arr["hp_mask"].astype(bool); hn_mask = arr["hn_mask"].astype(bool)
    hp_cut = float(meta1["residual_discovery"]["hard_positive_cutoff"]); hn_cut = float(meta1["residual_discovery"]["hard_negative_cutoff"])
    dmat, vmat = load_npz(stage1_dir / "dmat.npz"), load_npz(stage1_dir / "vmat.npz")
    vectorizers = joblib.load(stage1_dir / "vectorizers.joblib")

    r = nb_log_count_ratio(dmat, yd); d_nb, v_nb = dmat.multiply(r).tocsr(), vmat.multiply(r).tocsr()
    rows = []; score_map = {}; hard_models = {}
    for c in [0.5, 1.0, 2.0]:
        for hp_mult in [1.0, 2.0, 4.0]:
            for hn_mult in [4.0, 6.0, 8.0]:
                w, _, _ = hard_weights(oof, yd, hp_mult, hn_mult, hp_cut, hn_cut)
                name = f"v23_hard|C={c:g}|hp={hp_mult:g}|hn={hn_mult:g}"
                clf = LogisticRegression(C=c, max_iter=1800, solver="liblinear", random_state=SEED)
                clf.fit(d_nb, yd, sample_weight=w); s = clf.predict_proba(v_nb)[:, 1]
                th = threshold_at_fpr(yv, s, max_fpr=TARGET_VAL_FPR); m = metrics(yv, s, th)
                rows.append({**m, "name": name, "family": "hard", "eligible_for_selection": False})
                score_map[name] = s; hard_models[name] = clf
    hard_name = str(family_best(rows, "hard")["name"])

    adv_dev = build_adversarial_dev(dev, hp_mask); adv_y = adv_dev.y.to_numpy(dtype=np.int8)
    adv_vec, adv_dmat, adv_vmat = fit_sparse(adv_dev, val); adv_r = nb_log_count_ratio(adv_dmat, adv_y)
    adv_dnb, adv_vnb = adv_dmat.multiply(adv_r).tocsr(), adv_vmat.multiply(adv_r).tocsr()
    adv_weights = np.ones(len(adv_dev), dtype=np.float64); original_n = len(dev)
    adv_weights[:original_n][hp_mask] *= 2.0; adv_weights[:original_n][hn_mask] *= 4.0; adv_weights[original_n:] *= 1.5
    adv_models = {}
    for c in [0.5, 1.0, 2.0, 4.0]:
        name = f"v23_adv|C={c:g}"
        clf = LogisticRegression(C=c, max_iter=1800, solver="liblinear", random_state=SEED)
        clf.fit(adv_dnb, adv_y, sample_weight=adv_weights); s = clf.predict_proba(adv_vnb)[:, 1]
        th = threshold_at_fpr(yv, s, max_fpr=TARGET_VAL_FPR); m = metrics(yv, s, th)
        rows.append({**m, "name": name, "family": "adv", "eligible_for_selection": False})
        score_map[name] = s; adv_models[name] = clf
    adv_name = str(family_best(rows, "adv")["name"])
    print("STAGE3 anchor family winners", hard_name, adv_name, flush=True)

    seq_name = "electra_residual"
    seq_val = np.load(stage2_dir / "sequence_val.npy")
    if len(seq_val) != len(yv): raise RuntimeError("Sequence validation length mismatch")
    score_map[seq_name] = seq_val
    seq_th = threshold_at_fpr(yv, seq_val, max_fpr=TARGET_VAL_FPR); seq_m = metrics(yv, seq_val, seq_th)
    seq_row = {**seq_m, "name": seq_name, "family": "sequence", "eligible_for_selection": True}

    anchor_m = constrained_union_search(yv, score_map, [hard_name, adv_name], TARGET_VAL_FPR)
    anchor_row = {**anchor_m, "name": f"anchor_or|{hard_name}+{adv_name}", "family": "anchor_or",
                  "members": [hard_name, adv_name], "threshold": np.nan, "roc_auc": np.nan, "eligible_for_selection": True}
    tri_m = constrained_union_search(yv, score_map, [hard_name, adv_name, seq_name], TARGET_VAL_FPR)
    tri_row = {**tri_m, "name": f"anchor_electra|{hard_name}+{adv_name}+{seq_name}", "family": "anchor_electra",
               "members": [hard_name, adv_name, seq_name], "threshold": np.nan, "roc_auc": np.nan, "eligible_for_selection": True}
    rows.extend([seq_row, anchor_row, tri_row])

    selector = pd.DataFrame([anchor_row, seq_row, tri_row]).sort_values(
        ["recall", "precision", "fpr"], ascending=[False, False, True]).reset_index(drop=True)
    winner = selector.iloc[0].to_dict(); winner_name = str(winner["name"]); family = str(winner["family"])
    pd.DataFrame(rows).to_csv(result_dir / "assessment_v23_validation.csv", index=False)
    (result_dir / "assessment_v23_validation_winner.json").write_text(json.dumps(json_safe(winner), indent=2), encoding="utf-8")
    print("VALIDATION WINNER", json.dumps(json_safe(winner), indent=2), flush=True)

    # Comparative audit starts only after the validation winner above is frozen on disk.
    t0 = time.time(); audit = frame(train, audit_idx); ya = audit.y.to_numpy(dtype=np.int8)
    amat = sparse_transform(audit, vectorizers).multiply(r).tocsr()
    adv_amat = sparse_transform(audit, adv_vec).multiply(adv_r).tocsr()

    def anchor_score(name):
        if name.startswith("v23_hard"): return hard_models[name].predict_proba(amat)[:, 1]
        if name.startswith("v23_adv"): return adv_models[name].predict_proba(adv_amat)[:, 1]
        raise KeyError(name)

    audit_scores = {hard_name: anchor_score(hard_name), adv_name: anchor_score(adv_name)}
    sequence_audit_scored = False
    if family in {"sequence", "anchor_electra"}:
        tokenizer = AutoTokenizer.from_pretrained(stage2_dir / "model")
        model = AutoModelForSequenceClassification.from_pretrained(stage2_dir / "model")
        audit_scores[seq_name] = model_scores(tokenizer, model, audit["context"].tolist())
        sequence_audit_scored = True

    if family == "anchor_or":
        thresholds = {k: float(v) for k, v in winner["thresholds"].items()}
        audit_m = evaluate_union(ya, audit_scores, thresholds); audit_spec = {"type": family, "thresholds": thresholds}
    elif family == "anchor_electra":
        thresholds = {k: float(v) for k, v in winner["thresholds"].items()}
        audit_m = evaluate_union(ya, audit_scores, thresholds); audit_spec = {"type": family, "thresholds": thresholds}
    elif family == "sequence":
        audit_m = metrics(ya, audit_scores[seq_name], float(winner["threshold"])); audit_spec = {"type": family, "threshold": float(winner["threshold"])}
    else:
        raise RuntimeError(f"Unexpected winner family {family}")
    audit_seconds = time.time() - t0
    audit_m["recall_ci95"] = wilson(audit_m["tp"], audit_m["tp"] + audit_m["fn"])
    audit_m["fpr_ci95"] = wilson(audit_m["fp"], audit_m["fp"] + audit_m["tn"])
    promotion = {
        "reference_v18_recall_exact": V18_RECALL, "reference_v18_fpr_exact": V18_FPR,
        "strictly_beats_v18_recall": bool(audit_m["recall"] > V18_RECALL + 1e-12),
        "within_operating_fpr": bool(audit_m["fpr"] <= OPERATING_FPR),
    }
    promotion["promotable_over_v18"] = bool(promotion["strictly_beats_v18_recall"] and promotion["within_operating_fpr"])

    evidence = json_safe({
        "protocol_file": str(PROTOCOL), "protocol_sha256": sha256_file(PROTOCOL), "research_only": True, "seed": SEED,
        "target_validation_fpr": TARGET_VAL_FPR, "operating_fpr_ceiling": OPERATING_FPR,
        "reference_champion": {"version": "v18", "commit": "92b5e23d143397d8732673ee2e5715b5c81e82c1",
                               "tp": 600, "fn": 221, "fp": 7, "tn": 828, "recall_exact": V18_RECALL, "fpr_exact": V18_FPR},
        "benchmark_labels_accessed": False, "audit_is_pristine": False,
        "audit_role": "comparative only; previously observed in earlier experiments",
        "dataset": "perplexity-ai/browsesafe-bench", "dataset_fingerprints": meta1["dataset_fingerprints"],
        "removed_internal_duplicates": meta1["removed_internal_duplicates"],
        "removed_train_test_overlap": meta1["removed_train_test_overlap"], "splits": meta1["splits"],
        "stage_transport": {"stage1_manifest_sha256": stage1_manifest_sha, "stage2_manifest_sha256": stage2_manifest_sha},
        "development_residual_discovery": meta1["residual_discovery"],
        "sequence_specialist": {"model_id": MODEL_ID, "revision": MODEL_REVISION, "training": meta2["training_population"],
                                "hyperparameters": meta2["hyperparameters"], "epoch_losses": meta2["epoch_losses"],
                                "train_seconds": meta2["train_seconds"], "validation": seq_row,
                                "audit_scored": sequence_audit_scored},
        "anchor_family_winners": {"hard": hard_name, "adversarial": adv_name},
        "validation_candidates": {"anchor_or": anchor_row, "sequence": seq_row, "anchor_electra": tri_row},
        "validation_winner": winner, "audit_spec": audit_spec, "comparative_audit": audit_m, "promotion": promotion,
        "gates": {"B_70pct": bool(audit_m["recall"] >= .70 and audit_m["fpr"] <= .01),
                  "C_85pct": bool(audit_m["recall"] >= .85 and audit_m["fpr"] <= .01),
                  "D_90pct": bool(audit_m["recall"] >= .90 and audit_m["fpr"] <= .01),
                  "E_95pct": bool(audit_m["recall"] >= .95 and audit_m["fpr"] <= .01)},
        "timing": {"comparative_audit_representation_and_scoring_s": audit_seconds},
        "runtime": {"python": sys.version, "platform": platform.platform(), "torch": torch.__version__},
    })
    (result_dir / "assessment_v23_evidence.json").write_text(json.dumps(evidence, indent=2, allow_nan=False), encoding="utf-8")
    print("V23 EVIDENCE", json.dumps(evidence, indent=2), flush=True)


def main():
    p = argparse.ArgumentParser(); sub = p.add_subparsers(dest="stage", required=True)
    p1 = sub.add_parser("stage1"); p1.add_argument("--out", required=True)
    p2 = sub.add_parser("stage2"); p2.add_argument("--stage1", required=True); p2.add_argument("--out", required=True)
    p3 = sub.add_parser("stage3"); p3.add_argument("--stage1", required=True); p3.add_argument("--stage2", required=True); p3.add_argument("--results", required=True)
    a = p.parse_args()
    if a.stage == "stage1": stage1(Path(a.out))
    elif a.stage == "stage2": stage2(Path(a.stage1), Path(a.out))
    elif a.stage == "stage3": stage3(Path(a.stage1), Path(a.stage2), Path(a.results))


if __name__ == "__main__": main()
