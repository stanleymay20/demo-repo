"""AgentShield assessment v24: pairwise residual ranking specialist.

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
import torch.nn.functional as F
from datasets import load_dataset
from huggingface_hub import HfApi
from scipy.sparse import load_npz, save_npz
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split
from torch.utils.data import DataLoader, TensorDataset
from transformers import AutoModel, AutoTokenizer

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

PROTOCOL = Path("agentshield/ASSESSMENT_V24_PAIRWISE_RESIDUAL_RANKING_PROTOCOL.md")
RESULT_DIR = Path("agentshield/results")
MODEL_ID = "BAAI/bge-small-en-v1.5"
TARGET_VAL_FPR = 0.006
OPERATING_FPR = 0.01
V18_RECALL = 600.0 / 821.0
V18_FPR = 7.0 / 835.0
MAX_LENGTH = 384
EMBED_BATCH = 32
TOP_K_HARD_BENIGN = 4
RANK_EPOCHS = 80
RANK_LR = 0.03
RANK_WEIGHT_DECAY = 0.01
RANK_BATCH_SIZE = 256
GRAD_CLIP = 1.0
EPS = 1e-12
EXPECTED_SPLITS = (7725, 1656, 1656)


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def sha256_array(a: np.ndarray) -> str:
    a = np.ascontiguousarray(a)
    h = hashlib.sha256()
    h.update(str(a.dtype).encode())
    h.update(str(tuple(a.shape)).encode())
    h.update(a.tobytes())
    return h.hexdigest()


def sha256_texts(texts) -> str:
    h = hashlib.sha256()
    for text in texts:
        b = ("" if text is None else str(text)).encode("utf-8", "ignore")
        h.update(len(b).to_bytes(8, "little"))
        h.update(b)
    return h.hexdigest()


def write_manifest(directory: Path, name: str = "MANIFEST.json") -> Path:
    entries = []
    for p in sorted(directory.rglob("*")):
        if p.is_file() and p.name != name:
            entries.append({
                "path": str(p.relative_to(directory)),
                "size": p.stat().st_size,
                "sha256": sha256_file(p),
            })
    out = directory / name
    out.write_text(json.dumps({"files": entries}, indent=2), encoding="utf-8")
    return out


def verify_manifest(directory: Path, name: str = "MANIFEST.json") -> str:
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
            raise RuntimeError(f"Checkpoint SHA mismatch: {p}: {got} != {row['sha256']}")
    return sha256_file(path)


def json_safe(value):
    if isinstance(value, dict):
        return {str(k): json_safe(v) for k, v in value.items()}
    if isinstance(value, list):
        return [json_safe(v) for v in value]
    if isinstance(value, tuple):
        return [json_safe(v) for v in value]
    if isinstance(value, np.ndarray):
        return [json_safe(v) for v in value.tolist()]
    if isinstance(value, (float, np.floating)):
        return None if not np.isfinite(value) else float(value)
    if isinstance(value, (int, np.integer)):
        return int(value)
    if isinstance(value, (bool, np.bool_)):
        return bool(value)
    return value


def split_dataset():
    ds = load_dataset("perplexity-ai/browsesafe-bench", token=False)
    train_raw, test = ds["train"], ds["test"]
    train_fp = getattr(train_raw, "_fingerprint", None)
    test_fp = getattr(test, "_fingerprint", None)
    train, dup_count, overlap_count = clean_training_split(train_raw, test)
    y = np.array([LAB[x] for x in train["label"]], dtype=np.int8)
    idx = np.arange(len(train))
    work, audit_idx = train_test_split(
        idx, test_size=0.15, stratify=y, random_state=SEED
    )
    dev_idx, val_idx = train_test_split(
        work, test_size=0.1764706, stratify=y[work], random_state=SEED
    )
    if (len(dev_idx), len(val_idx), len(audit_idx)) != EXPECTED_SPLITS:
        raise RuntimeError(
            f"Unexpected split sizes: {len(dev_idx)}, {len(val_idx)}, {len(audit_idx)}"
        )
    return (
        train, train_fp, test_fp, int(dup_count), int(overlap_count),
        y, dev_idx, val_idx, audit_idx,
    )


def thresholds_for_budget(y, score, max_fpr):
    y = np.asarray(y)
    score = np.asarray(score)
    benign_scores = np.sort(score[y == 0])[::-1]
    max_fp = int(math.floor(float(max_fpr) * int((y == 0).sum())))
    if len(benign_scores) == 0:
        raise RuntimeError("No benign rows")
    out = [float(np.nextafter(benign_scores[0], np.inf))]
    for k in range(1, max_fp + 1):
        hi = benign_scores[k - 1]
        lo = benign_scores[k] if k < len(benign_scores) else -np.inf
        out.append(
            float((hi + lo) / 2.0 if np.isfinite(lo) else np.nextafter(hi, -np.inf))
        )
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
    f1 = 2.0 * precision * recall / max(EPS, precision + recall)
    return {
        "precision": float(precision), "recall": float(recall),
        "f1": float(f1), "fpr": float(fpr),
        "tn": tn, "fp": fp, "fn": fn, "tp": tp,
    }


def constrained_union_search(y, score_map, names, max_fpr):
    y = np.asarray(y)
    max_fp = int(math.floor(float(max_fpr) * int((y == 0).sum())))
    lists = [thresholds_for_budget(y, score_map[n], max_fpr) for n in names]
    best_key = None
    best = None

    def rec(i, current):
        nonlocal best_key, best
        if i == len(names):
            m = evaluate_union(y, score_map, current)
            if m["fp"] > max_fp:
                return
            key = (m["recall"], m["precision"], -m["fpr"])
            if best_key is None or key > best_key:
                best_key = key
                best = {**m, "thresholds": dict(current)}
            return
        name = names[i]
        for th in lists[i]:
            current[name] = float(th)
            rec(i + 1, current)
        current.pop(name, None)

    rec(0, {})
    if best is None:
        raise RuntimeError("No feasible constrained union")
    return best


@torch.no_grad()
def embed_texts(texts, revision: str, batch_size: int = EMBED_BATCH) -> np.ndarray:
    tokenizer = AutoTokenizer.from_pretrained(MODEL_ID, revision=revision)
    model = AutoModel.from_pretrained(MODEL_ID, revision=revision)
    model.eval()
    out = []
    for start in range(0, len(texts), batch_size):
        batch = list(texts[start:start + batch_size])
        enc = tokenizer(
            batch, padding=True, truncation=True, max_length=MAX_LENGTH,
            return_tensors="pt",
        )
        result = model(**enc)
        hidden = result.last_hidden_state
        mask = enc["attention_mask"].unsqueeze(-1).to(hidden.dtype)
        pooled = (hidden * mask).sum(dim=1) / mask.sum(dim=1).clamp_min(1.0)
        pooled = F.normalize(pooled, p=2, dim=1)
        out.append(pooled.cpu().numpy().astype(np.float32))
    return np.concatenate(out, axis=0)


def family_best(rows, family):
    df = pd.DataFrame(rows)
    return df[df.family == family].sort_values(
        ["recall", "precision", "fpr"],
        ascending=[False, False, True],
    ).iloc[0]


def stage1(out_dir: Path):
    out_dir.mkdir(parents=True, exist_ok=True)
    print("STAGE1 loading BrowseSafe", flush=True)
    (
        train, train_fp, test_fp, dup_count, overlap_count, y,
        dev_idx, val_idx, audit_idx,
    ) = split_dataset()

    dev, val = frame(train, dev_idx), frame(train, val_idx)
    yd = dev.y.to_numpy(dtype=np.int8)
    vectorizers, dmat, vmat = fit_sparse(dev, val)
    oof = oof_nb_scores(dmat, yd, folds=5)

    residual_th = threshold_at_fpr(yd, oof, max_fpr=TARGET_VAL_FPR)
    residual_metrics = metrics(yd, oof, residual_th)
    residual_pos = (yd == 1) & (oof < residual_th)
    hard_benign_cut = float(np.quantile(oof[yd == 0], 0.95))
    hard_benign = (yd == 0) & (oof >= hard_benign_cut)
    hp_cut = float(np.quantile(oof[yd == 1], 0.45))
    hn_cut = float(np.quantile(oof[yd == 0], 0.95))
    _, hp_mask, hn_mask = hard_weights(oof, yd, 1, 1, hp_cut, hn_cut)

    revision = HfApi().model_info(MODEL_ID).sha
    if not revision or len(revision) < 20:
        raise RuntimeError(f"Could not resolve exact model revision for {MODEL_ID}")
    print("STAGE1 resolved model revision", revision, flush=True)

    t0 = time.time()
    dev_embeddings = embed_texts(dev["context"].tolist(), revision)
    embed_seconds = time.time() - t0
    if dev_embeddings.shape[0] != len(dev):
        raise RuntimeError("Development embedding row-count mismatch")
    if not np.all(np.isfinite(dev_embeddings)):
        raise RuntimeError("Development embeddings contain non-finite values")

    print("STAGE1 residual", json.dumps(json_safe({
        "threshold": residual_th,
        "metrics": residual_metrics,
        "residual_positive_count": int(residual_pos.sum()),
        "hard_benign_count": int(hard_benign.sum()),
        "embedding_shape": dev_embeddings.shape,
    })), flush=True)

    dev.to_pickle(out_dir / "dev.pkl")
    val.to_pickle(out_dir / "val.pkl")
    joblib.dump(vectorizers, out_dir / "vectorizers.joblib", compress=3)
    save_npz(out_dir / "dmat.npz", dmat, compressed=True)
    save_npz(out_dir / "vmat.npz", vmat, compressed=True)
    np.save(out_dir / "dev_embeddings.npy", dev_embeddings)
    np.savez_compressed(
        out_dir / "arrays.npz",
        dev_idx=dev_idx, val_idx=val_idx, audit_idx=audit_idx,
        yd=yd, oof=oof,
        residual_pos=residual_pos, hard_benign=hard_benign,
        hp_mask=hp_mask, hn_mask=hn_mask,
    )

    meta = {
        "stage": 1,
        "protocol_sha256": sha256_file(PROTOCOL),
        "source_sha256": sha256_file(Path(__file__)),
        "model_id": MODEL_ID,
        "model_revision": revision,
        "seed": SEED,
        "target_validation_fpr": TARGET_VAL_FPR,
        "dataset_fingerprints": {
            "train_raw": train_fp,
            "test_content_source": test_fp,
        },
        "removed_internal_duplicates": dup_count,
        "removed_train_test_overlap": overlap_count,
        "splits": {
            "development": len(dev_idx),
            "validation": len(val_idx),
            "comparative_audit": len(audit_idx),
        },
        "residual_discovery": {
            "folds": 5,
            "threshold": residual_th,
            "metrics": residual_metrics,
            "residual_positive_count": int(residual_pos.sum()),
            "hard_benign_cutoff": hard_benign_cut,
            "hard_benign_count": int(hard_benign.sum()),
            "hard_positive_cutoff": hp_cut,
            "hard_negative_cutoff": hn_cut,
            "hard_positive_count": int(hp_mask.sum()),
            "hard_negative_count": int(hn_mask.sum()),
        },
        "representation": {
            "view": "established context view",
            "pooling": "attention-mask mean pooling then L2 normalization",
            "max_length": MAX_LENGTH,
            "embedding_dimension": int(dev_embeddings.shape[1]),
            "development_embedding_sha256": sha256_array(dev_embeddings),
            "development_context_sha256": sha256_texts(dev["context"].tolist()),
            "validation_context_sha256": sha256_texts(val["context"].tolist()),
            "embedding_seconds": embed_seconds,
        },
        "benchmark_labels_accessed": False,
    }
    (out_dir / "meta.json").write_text(
        json.dumps(json_safe(meta), indent=2), encoding="utf-8"
    )
    manifest = write_manifest(out_dir)
    print("STAGE1 manifest", sha256_file(manifest), flush=True)


def verify_stage1(stage1_dir: Path):
    manifest_sha = verify_manifest(stage1_dir)
    meta = json.loads((stage1_dir / "meta.json").read_text(encoding="utf-8"))
    if meta["protocol_sha256"] != sha256_file(PROTOCOL):
        raise RuntimeError("Protocol SHA mismatch")
    if meta["source_sha256"] != sha256_file(Path(__file__)):
        raise RuntimeError("Source SHA mismatch")
    if meta["model_id"] != MODEL_ID:
        raise RuntimeError("Model identity mismatch")

    (
        train, train_fp, test_fp, dup_count, overlap_count, y,
        dev_idx, val_idx, audit_idx,
    ) = split_dataset()
    arr = np.load(stage1_dir / "arrays.npz")
    for name, expected in [
        ("dev_idx", dev_idx), ("val_idx", val_idx), ("audit_idx", audit_idx)
    ]:
        if not np.array_equal(arr[name], expected):
            raise RuntimeError(f"Split mismatch: {name}")
    if not np.array_equal(arr["yd"], y[dev_idx]):
        raise RuntimeError("Development label mismatch")
    if meta["dataset_fingerprints"] != {
        "train_raw": train_fp, "test_content_source": test_fp
    }:
        raise RuntimeError("Dataset fingerprint mismatch")
    if meta["removed_internal_duplicates"] != dup_count:
        raise RuntimeError("Internal duplicate count mismatch")
    if meta["removed_train_test_overlap"] != overlap_count:
        raise RuntimeError("Train/test overlap count mismatch")

    dev = pd.read_pickle(stage1_dir / "dev.pkl")
    val = pd.read_pickle(stage1_dir / "val.pkl")
    if sha256_texts(dev["context"].tolist()) != meta["representation"]["development_context_sha256"]:
        raise RuntimeError("Development context mismatch")
    if sha256_texts(val["context"].tolist()) != meta["representation"]["validation_context_sha256"]:
        raise RuntimeError("Validation context mismatch")

    emb = np.load(stage1_dir / "dev_embeddings.npy")
    if sha256_array(emb) != meta["representation"]["development_embedding_sha256"]:
        raise RuntimeError("Development embedding hash mismatch")
    return (
        manifest_sha, meta, train, y,
        dev_idx, val_idx, audit_idx, arr, dev, val, emb,
    )


def stage2(stage1_dir: Path, out_dir: Path):
    out_dir.mkdir(parents=True, exist_ok=True)
    (
        stage1_manifest_sha, meta1, train, y,
        dev_idx, val_idx, audit_idx, arr, dev, val, emb,
    ) = verify_stage1(stage1_dir)

    yd = arr["yd"].astype(np.int8)
    residual = arr["residual_pos"].astype(bool)
    hard_benign = arr["hard_benign"].astype(bool)
    residual_idx = np.where(residual)[0]
    benign_idx = np.where(hard_benign)[0]
    if len(residual_idx) == 0 or len(benign_idx) < TOP_K_HARD_BENIGN:
        raise RuntimeError("Degenerate pair-construction population")

    sim = emb[residual_idx] @ emb[benign_idx].T
    nearest_local = np.argsort(-sim, axis=1, kind="mergesort")[:, :TOP_K_HARD_BENIGN]
    pair_pos = np.repeat(residual_idx, TOP_K_HARD_BENIGN)
    pair_neg = benign_idx[nearest_local.reshape(-1)]
    pair_matrix = np.column_stack([pair_pos, pair_neg]).astype(np.int64)
    if np.any(yd[pair_pos] != 1) or np.any(yd[pair_neg] != 0):
        raise RuntimeError("Pair labels violate attack>benign construction")

    torch.manual_seed(SEED)
    random.seed(SEED)
    np.random.seed(SEED)
    torch.use_deterministic_algorithms(True, warn_only=True)
    if os.cpu_count():
        torch.set_num_threads(max(1, min(4, os.cpu_count())))

    pos_t = torch.from_numpy(emb[pair_pos].astype(np.float32))
    neg_t = torch.from_numpy(emb[pair_neg].astype(np.float32))
    ds = TensorDataset(pos_t, neg_t)
    generator = torch.Generator().manual_seed(SEED)
    loader = DataLoader(
        ds, batch_size=RANK_BATCH_SIZE, shuffle=True, generator=generator
    )

    w = torch.nn.Parameter(torch.zeros(emb.shape[1], dtype=torch.float32))
    optimizer = torch.optim.AdamW([w], lr=RANK_LR, weight_decay=RANK_WEIGHT_DECAY)
    losses = []
    t0 = time.time()
    for epoch in range(RANK_EPOCHS):
        running = 0.0
        count = 0
        for pos_b, neg_b in loader:
            margin = (pos_b - neg_b) @ w
            loss = F.softplus(-margin).mean()
            loss.backward()
            torch.nn.utils.clip_grad_norm_([w], GRAD_CLIP)
            optimizer.step()
            optimizer.zero_grad(set_to_none=True)
            running += float(loss.detach()) * len(pos_b)
            count += len(pos_b)
        epoch_loss = running / max(1, count)
        losses.append(epoch_loss)
        if epoch in {0, 9, 19, 39, 59, 79}:
            print(
                f"STAGE2 epoch={epoch+1}/{RANK_EPOCHS} pairwise_loss={epoch_loss:.6f}",
                flush=True,
            )
    train_seconds = time.time() - t0

    w_np = w.detach().cpu().numpy().astype(np.float32)
    margins = (emb[pair_pos] - emb[pair_neg]) @ w_np
    pair_accuracy = float((margins > 0).mean())
    margin_summary = {
        "mean": float(margins.mean()),
        "median": float(np.median(margins)),
        "p05": float(np.quantile(margins, 0.05)),
        "p95": float(np.quantile(margins, 0.95)),
    }

    np.save(out_dir / "ranker_weight.npy", w_np)
    np.savez_compressed(out_dir / "pairs.npz", pair_pos=pair_pos, pair_neg=pair_neg)
    meta2 = {
        "stage": 2,
        "source_stage1_manifest_sha256": stage1_manifest_sha,
        "protocol_sha256": sha256_file(PROTOCOL),
        "source_sha256": sha256_file(Path(__file__)),
        "model_id": MODEL_ID,
        "model_revision": meta1["model_revision"],
        "pair_construction": {
            "residual_positive_count": int(len(residual_idx)),
            "hard_benign_count": int(len(benign_idx)),
            "top_k_nearest_hard_benign": TOP_K_HARD_BENIGN,
            "pair_count": int(len(pair_pos)),
            "pair_index_sha256": sha256_array(pair_matrix),
        },
        "ranker": {
            "type": "linear pairwise scoring vector",
            "objective": "softplus(-(score_attack-score_benign))",
            "epochs": RANK_EPOCHS,
            "learning_rate": RANK_LR,
            "weight_decay": RANK_WEIGHT_DECAY,
            "batch_size_pairs": RANK_BATCH_SIZE,
            "gradient_clip": GRAD_CLIP,
            "seed": SEED,
            "epoch_losses": losses,
            "train_seconds": train_seconds,
            "pairwise_training_accuracy": pair_accuracy,
            "margin_summary": margin_summary,
            "weight_sha256": sha256_array(w_np),
            "weight_l2_norm": float(np.linalg.norm(w_np)),
        },
    }
    (out_dir / "meta.json").write_text(
        json.dumps(json_safe(meta2), indent=2), encoding="utf-8"
    )
    manifest = write_manifest(out_dir)
    print(
        "STAGE2 pairs", len(pair_pos),
        "pair_acc", pair_accuracy,
        "manifest", sha256_file(manifest),
        flush=True,
    )


def verify_stage2(stage2_dir: Path, stage1_manifest_sha: str, model_revision: str):
    manifest_sha = verify_manifest(stage2_dir)
    meta = json.loads((stage2_dir / "meta.json").read_text(encoding="utf-8"))
    if meta["source_stage1_manifest_sha256"] != stage1_manifest_sha:
        raise RuntimeError("Stage1 transport linkage mismatch")
    if meta["protocol_sha256"] != sha256_file(PROTOCOL):
        raise RuntimeError("Stage2 protocol SHA mismatch")
    if meta["source_sha256"] != sha256_file(Path(__file__)):
        raise RuntimeError("Stage2 source SHA mismatch")
    if meta["model_id"] != MODEL_ID or meta["model_revision"] != model_revision:
        raise RuntimeError("Stage2 model identity/revision mismatch")
    w = np.load(stage2_dir / "ranker_weight.npy")
    if sha256_array(w) != meta["ranker"]["weight_sha256"]:
        raise RuntimeError("Ranker weight hash mismatch")
    pairs = np.load(stage2_dir / "pairs.npz")
    pair_matrix = np.column_stack([pairs["pair_pos"], pairs["pair_neg"]]).astype(np.int64)
    if sha256_array(pair_matrix) != meta["pair_construction"]["pair_index_sha256"]:
        raise RuntimeError("Pair index hash mismatch")
    return manifest_sha, meta, w.astype(np.float32)


def stage3(stage1_dir: Path, stage2_dir: Path, result_dir: Path):
    result_dir.mkdir(parents=True, exist_ok=True)
    (
        stage1_manifest_sha, meta1, train, y,
        dev_idx, val_idx, audit_idx, arr, dev, val, dev_emb,
    ) = verify_stage1(stage1_dir)
    stage2_manifest_sha, meta2, rank_w = verify_stage2(
        stage2_dir, stage1_manifest_sha, meta1["model_revision"]
    )

    yd = arr["yd"].astype(np.int8)
    yv = y[val_idx].astype(np.int8)
    oof = arr["oof"].astype(np.float64)
    hp_mask = arr["hp_mask"].astype(bool)
    hn_mask = arr["hn_mask"].astype(bool)
    hp_cut = float(meta1["residual_discovery"]["hard_positive_cutoff"])
    hn_cut = float(meta1["residual_discovery"]["hard_negative_cutoff"])

    dmat = load_npz(stage1_dir / "dmat.npz")
    vmat = load_npz(stage1_dir / "vmat.npz")
    vectorizers = joblib.load(stage1_dir / "vectorizers.joblib")
    r = nb_log_count_ratio(dmat, yd)
    d_nb = dmat.multiply(r).tocsr()
    v_nb = vmat.multiply(r).tocsr()

    rows = []
    score_map = {}
    hard_models = {}
    for c in [0.5, 1.0, 2.0]:
        for hp_mult in [1.0, 2.0, 4.0]:
            for hn_mult in [4.0, 6.0, 8.0]:
                weights, _, _ = hard_weights(
                    oof, yd, hp_mult, hn_mult, hp_cut, hn_cut
                )
                name = f"v24_hard|C={c:g}|hp={hp_mult:g}|hn={hn_mult:g}"
                clf = LogisticRegression(
                    C=c, max_iter=1800, solver="liblinear", random_state=SEED
                )
                clf.fit(d_nb, yd, sample_weight=weights)
                s = clf.predict_proba(v_nb)[:, 1]
                th = threshold_at_fpr(yv, s, max_fpr=TARGET_VAL_FPR)
                m = metrics(yv, s, th)
                rows.append({**m, "name": name, "family": "hard", "eligible": False})
                score_map[name] = s
                hard_models[name] = clf
    hard_name = str(family_best(rows, "hard")["name"])

    adv_dev = build_adversarial_dev(dev, hp_mask)
    adv_y = adv_dev.y.to_numpy(dtype=np.int8)
    adv_vec, adv_dmat, adv_vmat = fit_sparse(adv_dev, val)
    adv_r = nb_log_count_ratio(adv_dmat, adv_y)
    adv_dnb = adv_dmat.multiply(adv_r).tocsr()
    adv_vnb = adv_vmat.multiply(adv_r).tocsr()
    adv_weights = np.ones(len(adv_dev), dtype=np.float64)
    original_n = len(dev)
    adv_weights[:original_n][hp_mask] *= 2.0
    adv_weights[:original_n][hn_mask] *= 4.0
    adv_weights[original_n:] *= 1.5
    adv_models = {}
    for c in [0.5, 1.0, 2.0, 4.0]:
        name = f"v24_adv|C={c:g}"
        clf = LogisticRegression(
            C=c, max_iter=1800, solver="liblinear", random_state=SEED
        )
        clf.fit(adv_dnb, adv_y, sample_weight=adv_weights)
        s = clf.predict_proba(adv_vnb)[:, 1]
        th = threshold_at_fpr(yv, s, max_fpr=TARGET_VAL_FPR)
        m = metrics(yv, s, th)
        rows.append({**m, "name": name, "family": "adv", "eligible": False})
        score_map[name] = s
        adv_models[name] = clf
    adv_name = str(family_best(rows, "adv")["name"])
    print("STAGE3 anchor family winners", hard_name, adv_name, flush=True)

    # Ranker is frozen before validation embedding/scoring.
    t0 = time.time()
    val_emb = embed_texts(val["context"].tolist(), meta1["model_revision"])
    val_embed_seconds = time.time() - t0
    rank_name = "bge_pairwise_ranker"
    rank_val = val_emb @ rank_w
    score_map[rank_name] = rank_val
    rank_th = threshold_at_fpr(yv, rank_val, max_fpr=TARGET_VAL_FPR)
    rank_m = metrics(yv, rank_val, rank_th)
    rank_row = {
        **rank_m, "name": rank_name, "family": "pairwise_ranker", "eligible": True
    }

    anchor_m = constrained_union_search(
        yv, score_map, [hard_name, adv_name], TARGET_VAL_FPR
    )
    anchor_row = {
        **anchor_m,
        "name": f"anchor_or|{hard_name}+{adv_name}",
        "family": "anchor_or",
        "members": [hard_name, adv_name],
        "threshold": np.nan,
        "roc_auc": np.nan,
        "eligible": True,
    }

    union_m = constrained_union_search(
        yv, score_map, [hard_name, adv_name, rank_name], TARGET_VAL_FPR
    )
    union_row = {
        **union_m,
        "name": f"anchor_pairwise|{hard_name}+{adv_name}+{rank_name}",
        "family": "anchor_pairwise",
        "members": [hard_name, adv_name, rank_name],
        "threshold": np.nan,
        "roc_auc": np.nan,
        "eligible": True,
    }
    rows.extend([rank_row, anchor_row, union_row])

    selector = pd.DataFrame([anchor_row, rank_row, union_row]).sort_values(
        ["recall", "precision", "fpr"],
        ascending=[False, False, True],
    ).reset_index(drop=True)
    winner = selector.iloc[0].to_dict()
    winner_name = str(winner["name"])
    winner_family = str(winner["family"])
    print("VALIDATION WINNER", json.dumps(json_safe(winner), indent=2), flush=True)

    all_df = pd.DataFrame(rows).sort_values(
        ["eligible", "recall", "precision", "fpr"],
        ascending=[False, False, False, True],
    ).reset_index(drop=True)
    all_df.to_csv(result_dir / "assessment_v24_validation.csv", index=False)
    winner_payload = json_safe({
        "winner": winner,
        "selection_order": "recall, then precision, then lower FPR",
        "validation_target_fpr": TARGET_VAL_FPR,
        "frozen_before_audit": True,
    })
    (result_dir / "assessment_v24_validation_winner.json").write_text(
        json.dumps(winner_payload, indent=2), encoding="utf-8"
    )

    # Audit begins only after validation winner is persisted.
    audit = frame(train, audit_idx)
    ya = audit.y.to_numpy(dtype=np.int8)
    audit_scores = {}
    audit_spec = None

    needs_anchor = winner_family in {"anchor_or", "anchor_pairwise"}
    needs_ranker = winner_family in {"pairwise_ranker", "anchor_pairwise"}

    if needs_anchor:
        amat = sparse_transform(audit, vectorizers).multiply(r).tocsr()
        adv_amat = sparse_transform(audit, adv_vec).multiply(adv_r).tocsr()
        audit_scores[hard_name] = hard_models[hard_name].predict_proba(amat)[:, 1]
        audit_scores[adv_name] = adv_models[adv_name].predict_proba(adv_amat)[:, 1]

    audit_embedding_seconds = 0.0
    if needs_ranker:
        t0 = time.time()
        audit_emb = embed_texts(audit["context"].tolist(), meta1["model_revision"])
        audit_embedding_seconds = time.time() - t0
        audit_scores[rank_name] = audit_emb @ rank_w

    if winner_family in {"anchor_or", "anchor_pairwise"}:
        thresholds = winner["thresholds"]
        members = list(thresholds.keys())
        audit_m = evaluate_union(
            ya,
            {m: audit_scores[m] for m in members},
            {m: float(thresholds[m]) for m in members},
        )
        audit_spec = {
            "type": winner_family,
            "members": members,
            "thresholds": {m: float(thresholds[m]) for m in members},
        }
    elif winner_family == "pairwise_ranker":
        audit_m = metrics(
            ya, audit_scores[rank_name], float(winner["threshold"])
        )
        audit_spec = {
            "type": "single_pairwise_ranker",
            "name": rank_name,
            "threshold": float(winner["threshold"]),
        }
    else:
        raise RuntimeError(f"Unexpected winner family: {winner_family}")

    audit_m["recall_ci95"] = wilson(
        audit_m["tp"], audit_m["tp"] + audit_m["fn"]
    )
    audit_m["fpr_ci95"] = wilson(
        audit_m["fp"], audit_m["fp"] + audit_m["tn"]
    )
    promotion = {
        "reference_v18_recall_exact": V18_RECALL,
        "reference_v18_fpr_exact": V18_FPR,
        "strictly_beats_v18_recall": bool(
            audit_m["recall"] > V18_RECALL + 1e-12
        ),
        "within_operating_fpr": bool(audit_m["fpr"] <= OPERATING_FPR),
    }
    promotion["promotable_over_v18"] = bool(
        promotion["strictly_beats_v18_recall"]
        and promotion["within_operating_fpr"]
    )

    evidence = json_safe({
        "protocol_file": str(PROTOCOL),
        "protocol_sha256": sha256_file(PROTOCOL),
        "source_sha256": sha256_file(Path(__file__)),
        "research_only": True,
        "seed": SEED,
        "target_validation_fpr": TARGET_VAL_FPR,
        "operating_fpr_ceiling": OPERATING_FPR,
        "reference_champion": {
            "version": "v18",
            "commit": "92b5e23d143397d8732673ee2e5715b5c81e82c1",
            "tp": 600, "fn": 221, "fp": 7, "tn": 828,
            "recall_exact": V18_RECALL,
            "fpr_exact": V18_FPR,
        },
        "benchmark_labels_accessed": False,
        "audit_is_pristine": False,
        "audit_role": "comparative only; previously observed in earlier experiments",
        "dataset": "perplexity-ai/browsesafe-bench",
        "dataset_fingerprints": meta1["dataset_fingerprints"],
        "removed_internal_duplicates": meta1["removed_internal_duplicates"],
        "removed_train_test_overlap": meta1["removed_train_test_overlap"],
        "splits": meta1["splits"],
        "stage1_manifest_sha256": stage1_manifest_sha,
        "stage2_manifest_sha256": stage2_manifest_sha,
        "residual_discovery": meta1["residual_discovery"],
        "pairwise_representation": {
            **meta1["representation"],
            "model_id": MODEL_ID,
            "model_revision": meta1["model_revision"],
            "validation_embedding_sha256": sha256_array(val_emb),
            "validation_embedding_seconds": val_embed_seconds,
        },
        "pair_construction": meta2["pair_construction"],
        "ranker_training": meta2["ranker"],
        "anchor_family_winners": {
            "hard": hard_name,
            "adversarial": adv_name,
        },
        "eligible_validation_systems": [
            json_safe(anchor_row), json_safe(rank_row), json_safe(union_row)
        ],
        "validation_winner": winner,
        "audit_spec": audit_spec,
        "comparative_audit": audit_m,
        "promotion": promotion,
        "gates": {
            "B_70pct": bool(audit_m["recall"] >= .70 and audit_m["fpr"] <= .01),
            "C_85pct": bool(audit_m["recall"] >= .85 and audit_m["fpr"] <= .01),
            "D_90pct": bool(audit_m["recall"] >= .90 and audit_m["fpr"] <= .01),
            "E_95pct": bool(audit_m["recall"] >= .95 and audit_m["fpr"] <= .01),
        },
        "audit_embedding_seconds_if_used": audit_embedding_seconds,
        "runtime": {
            "python": sys.version,
            "platform": platform.platform(),
            "torch": torch.__version__,
        },
    })
    (result_dir / "assessment_v24_evidence.json").write_text(
        json.dumps(evidence, indent=2, allow_nan=False), encoding="utf-8"
    )
    print("V24 EVIDENCE", json.dumps(evidence, indent=2), flush=True)


def main():
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="stage", required=True)

    p1 = sub.add_parser("stage1")
    p1.add_argument("--out", type=Path, required=True)

    p2 = sub.add_parser("stage2")
    p2.add_argument("--stage1", type=Path, required=True)
    p2.add_argument("--out", type=Path, required=True)

    p3 = sub.add_parser("stage3")
    p3.add_argument("--stage1", type=Path, required=True)
    p3.add_argument("--stage2", type=Path, required=True)
    p3.add_argument("--results", type=Path, required=True)

    args = parser.parse_args()
    if args.stage == "stage1":
        stage1(args.out)
    elif args.stage == "stage2":
        stage2(args.stage1, args.out)
    else:
        stage3(args.stage1, args.stage2, args.results)


if __name__ == "__main__":
    main()
