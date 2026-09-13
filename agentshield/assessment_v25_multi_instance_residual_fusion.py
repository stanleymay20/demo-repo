"""AgentShield assessment v25: multi-instance residual fusion.

Research only. External validation sets are never accessed here. The comparative
BrowseSafe audit is non-pristine and is scored only after a validation-only
pre-audit gate and candidate-bundle freeze.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import platform
import random
import shutil
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
from transformers import (
    AutoModelForSequenceClassification,
    AutoTokenizer,
    get_linear_schedule_with_warmup,
)

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

PROTOCOL = Path("agentshield/ASSESSMENT_V25_MULTI_INSTANCE_RESIDUAL_FUSION_PROTOCOL.md")
RESULT_DIR = Path("agentshield/results")
MODEL_ID = "google/electra-small-discriminator"
MODEL_REVISION = "fa8239aadc095e9164941d05878b98afe9b953c3"
TARGET_VAL_FPR = 0.006
OPERATING_FPR = 0.01
EXPECTED_SPLITS = (7725, 1656, 1656)
EXPECTED_TRAIN_FP = "596f8fb7871901b9"
EXPECTED_TEST_FP = "9a9a7f691f87832e"
V18_COUNTS = {"tp": 600, "fn": 221, "fp": 7, "tn": 828}
V18_RECALL = 600.0 / 821.0
V18_FPR = 7.0 / 835.0
N_VIEWS = 6
VISIBLE_WINDOW_WORDS = 220
MAX_LENGTH = 256
TAU = 0.5
EPOCHS = 3
LR = 2e-5
WEIGHT_DECAY = 0.01
DOC_BATCH_SIZE = 8
GRAD_ACCUM = 2
WARMUP_RATIO = 0.06
GRAD_CLIP = 1.0
EPS = 1e-12


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


def sha256_view_bags(bags: list[list[str]]) -> str:
    h = hashlib.sha256()
    for bag in bags:
        if len(bag) != N_VIEWS:
            raise RuntimeError(f"Unexpected view count {len(bag)}")
        for text in bag:
            b = str(text).encode("utf-8", "ignore")
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
    if train_fp != EXPECTED_TRAIN_FP or test_fp != EXPECTED_TEST_FP:
        raise RuntimeError(
            f"Dataset fingerprint drift: {(train_fp, test_fp)} != "
            f"{(EXPECTED_TRAIN_FP, EXPECTED_TEST_FP)}"
        )
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
        train, train_fp, test_fp, int(dup_count), int(overlap_count), y,
        dev_idx, val_idx, audit_idx,
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


def word_window(text: str, position: str, n: int = VISIBLE_WINDOW_WORDS) -> str:
    words = str(text or "").split()
    if not words:
        return "[EMPTY_VISIBLE_TEXT]"
    if len(words) <= n:
        return " ".join(words)
    if position == "head":
        return " ".join(words[:n])
    if position == "tail":
        return " ".join(words[-n:])
    if position == "middle":
        start = max(0, (len(words) - n) // 2)
        return " ".join(words[start:start + n])
    raise ValueError(position)


def build_view_bags(df: pd.DataFrame) -> list[list[str]]:
    bags = []
    for row in df.itertuples(index=False):
        visible = str(getattr(row, "text", "") or "")
        evidence = str(getattr(row, "evidence", "") or "").strip() or "[NO_HIDDEN_EVIDENCE]"
        script = str(getattr(row, "script", "") or "").strip() or "[NO_SCRIPT_CUES]"
        context = str(getattr(row, "context", "") or "").strip() or "[EMPTY_CONTEXT]"
        bag = [
            "[CONTEXT] " + context,
            "[VISIBLE_HEAD] " + word_window(visible, "head"),
            "[VISIBLE_MIDDLE] " + word_window(visible, "middle"),
            "[VISIBLE_TAIL] " + word_window(visible, "tail"),
            "[HIDDEN_EVIDENCE] " + evidence,
            "[SCRIPT_CUES] " + script,
        ]
        if len(bag) != N_VIEWS:
            raise RuntimeError("Multi-instance view count drift")
        bags.append(bag)
    return bags


class BagDataset(Dataset):
    def __init__(self, bags, labels, weights):
        self.bags = bags
        self.labels = np.asarray(labels, dtype=np.float32)
        self.weights = np.asarray(weights, dtype=np.float32)

    def __len__(self):
        return len(self.labels)

    def __getitem__(self, idx):
        return self.bags[idx], float(self.labels[idx]), float(self.weights[idx])


def make_collate(tokenizer):
    def collate(batch):
        flat = []
        labels = []
        weights = []
        for bag, label, weight in batch:
            if len(bag) != N_VIEWS:
                raise RuntimeError("Batch view count mismatch")
            flat.extend(bag)
            labels.append(label)
            weights.append(weight)
        enc = tokenizer(
            flat,
            padding=True,
            truncation=True,
            max_length=MAX_LENGTH,
            return_tensors="pt",
        )
        return enc, torch.tensor(labels, dtype=torch.float32), torch.tensor(weights, dtype=torch.float32)
    return collate


def bag_logits(model, enc, batch_docs: int):
    logits = model(**enc).logits
    if logits.shape[-1] != 2:
        raise RuntimeError(f"Expected two classifier logits, got {tuple(logits.shape)}")
    attack = (logits[:, 1] - logits[:, 0]).reshape(batch_docs, N_VIEWS)
    return TAU * (torch.logsumexp(attack / TAU, dim=1) - math.log(N_VIEWS))


@torch.no_grad()
def score_bags(tokenizer, model, bags, batch_size=DOC_BATCH_SIZE):
    model.eval()
    scores = []
    collate = make_collate(tokenizer)
    dummy_y = np.zeros(len(bags), dtype=np.float32)
    dummy_w = np.ones(len(bags), dtype=np.float32)
    loader = DataLoader(BagDataset(bags, dummy_y, dummy_w), batch_size=batch_size,
                        shuffle=False, collate_fn=collate)
    for enc, labels, _ in loader:
        b = len(labels)
        scores.append(bag_logits(model, enc, b).cpu().numpy().astype(np.float64))
    return np.concatenate(scores) if scores else np.array([], dtype=np.float64)


def family_best(rows, family):
    df = pd.DataFrame(rows)
    return df[df.family == family].sort_values(
        ["recall", "precision", "fpr"], ascending=[False, False, True]
    ).iloc[0]


def stage1(out_dir: Path):
    out_dir.mkdir(parents=True, exist_ok=True)
    print("STAGE1 loading controlled development data", flush=True)
    (
        train, train_fp, test_fp, dup_count, overlap_count, y,
        dev_idx, val_idx, audit_idx,
    ) = split_dataset()
    dev, val = frame(train, dev_idx), frame(train, val_idx)
    yd = dev.y.to_numpy(dtype=np.int8)
    yv = val.y.to_numpy(dtype=np.int8)
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

    dev_bags = build_view_bags(dev)
    val_bags = build_view_bags(val)
    dev.to_pickle(out_dir / "dev.pkl")
    val.to_pickle(out_dir / "val.pkl")
    joblib.dump(vectorizers, out_dir / "vectorizers.joblib", compress=3)
    save_npz(out_dir / "dmat.npz", dmat, compressed=True)
    save_npz(out_dir / "vmat.npz", vmat, compressed=True)
    np.savez_compressed(
        out_dir / "arrays.npz",
        dev_idx=dev_idx, val_idx=val_idx, audit_idx=audit_idx,
        yd=yd, yv=yv, oof=oof,
        residual_pos=residual_pos, hard_benign=hard_benign,
        hp_mask=hp_mask, hn_mask=hn_mask,
    )
    meta = {
        "stage": 1,
        "protocol_sha256": sha256_file(PROTOCOL),
        "source_sha256": sha256_file(Path(__file__)),
        "model_id": MODEL_ID,
        "model_revision": MODEL_REVISION,
        "dataset_fingerprints": {"train_raw": train_fp, "test_content_source": test_fp},
        "removed_internal_duplicates": dup_count,
        "removed_train_test_overlap": overlap_count,
        "splits": {"development": len(dev_idx), "validation": len(val_idx), "comparative_audit": len(audit_idx)},
        "split_index_sha256": {
            "development": sha256_array(dev_idx),
            "validation": sha256_array(val_idx),
            "comparative_audit": sha256_array(audit_idx),
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
        "views": {
            "count": N_VIEWS,
            "names": ["context", "visible_head", "visible_middle", "visible_tail", "hidden_evidence", "script_cues"],
            "visible_window_words": VISIBLE_WINDOW_WORDS,
            "development_sha256": sha256_view_bags(dev_bags),
            "validation_sha256": sha256_view_bags(val_bags),
        },
        "benchmark_labels_accessed": False,
        "external_validation_datasets_accessed": False,
    }
    (out_dir / "meta.json").write_text(json.dumps(json_safe(meta), indent=2), encoding="utf-8")
    manifest = write_manifest(out_dir)
    print("STAGE1 residual positives", int(residual_pos.sum()), "hard benign", int(hard_benign.sum()), flush=True)
    print("STAGE1 manifest", sha256_file(manifest), flush=True)


def verify_stage1(stage1_dir: Path):
    manifest_sha = verify_manifest(stage1_dir)
    meta = json.loads((stage1_dir / "meta.json").read_text(encoding="utf-8"))
    if meta["protocol_sha256"] != sha256_file(PROTOCOL):
        raise RuntimeError("Protocol SHA mismatch")
    if meta["source_sha256"] != sha256_file(Path(__file__)):
        raise RuntimeError("Source SHA mismatch")
    if meta["model_id"] != MODEL_ID or meta["model_revision"] != MODEL_REVISION:
        raise RuntimeError("Model identity mismatch")
    train, train_fp, test_fp, dup_count, overlap_count, y, dev_idx, val_idx, audit_idx = split_dataset()
    arr = np.load(stage1_dir / "arrays.npz")
    for name, expected in [("dev_idx", dev_idx), ("val_idx", val_idx), ("audit_idx", audit_idx)]:
        if not np.array_equal(arr[name], expected):
            raise RuntimeError(f"Split mismatch: {name}")
    if not np.array_equal(arr["yd"], y[dev_idx]) or not np.array_equal(arr["yv"], y[val_idx]):
        raise RuntimeError("Development/validation labels changed")
    if meta["dataset_fingerprints"] != {"train_raw": train_fp, "test_content_source": test_fp}:
        raise RuntimeError("Dataset fingerprint mismatch")
    if meta["removed_internal_duplicates"] != dup_count or meta["removed_train_test_overlap"] != overlap_count:
        raise RuntimeError("Cleanup count mismatch")
    dev = pd.read_pickle(stage1_dir / "dev.pkl")
    val = pd.read_pickle(stage1_dir / "val.pkl")
    if sha256_view_bags(build_view_bags(dev)) != meta["views"]["development_sha256"]:
        raise RuntimeError("Development view hash mismatch")
    if sha256_view_bags(build_view_bags(val)) != meta["views"]["validation_sha256"]:
        raise RuntimeError("Validation view hash mismatch")
    return manifest_sha, meta, train, y, dev_idx, val_idx, audit_idx, arr, dev, val


def stage2(stage1_dir: Path, out_dir: Path):
    out_dir.mkdir(parents=True, exist_ok=True)
    stage1_manifest_sha, meta1, train, y, dev_idx, val_idx, audit_idx, arr, dev, val = verify_stage1(stage1_dir)
    yd = arr["yd"].astype(np.int8)
    residual = arr["residual_pos"].astype(bool)
    hard_benign = arr["hard_benign"].astype(bool)
    weights = np.ones(len(yd), dtype=np.float32)
    weights[(yd == 1) & residual] *= 4.0
    weights[(yd == 0) & hard_benign] *= 2.0
    dev_bags = build_view_bags(dev)
    val_bags = build_view_bags(val)

    torch.manual_seed(SEED)
    random.seed(SEED)
    np.random.seed(SEED)
    torch.use_deterministic_algorithms(True, warn_only=True)
    if os.cpu_count():
        torch.set_num_threads(max(1, min(4, os.cpu_count())))

    tokenizer = AutoTokenizer.from_pretrained(MODEL_ID, revision=MODEL_REVISION)
    model = AutoModelForSequenceClassification.from_pretrained(
        MODEL_ID, revision=MODEL_REVISION, num_labels=2
    )
    ds = BagDataset(dev_bags, yd, weights)
    generator = torch.Generator().manual_seed(SEED)
    loader = DataLoader(
        ds,
        batch_size=DOC_BATCH_SIZE,
        shuffle=True,
        generator=generator,
        collate_fn=make_collate(tokenizer),
    )
    optimizer = torch.optim.AdamW(model.parameters(), lr=LR, weight_decay=WEIGHT_DECAY)
    updates_per_epoch = math.ceil(len(loader) / GRAD_ACCUM)
    total_updates = updates_per_epoch * EPOCHS
    warmup_steps = int(total_updates * WARMUP_RATIO)
    scheduler = get_linear_schedule_with_warmup(optimizer, warmup_steps, total_updates)
    bce = torch.nn.BCEWithLogitsLoss(reduction="none")

    losses = []
    t0 = time.time()
    model.train()
    optimizer.zero_grad(set_to_none=True)
    for epoch in range(EPOCHS):
        running_num = 0.0
        running_den = 0.0
        for step, (enc, labels, batch_weights) in enumerate(loader, start=1):
            bags = bag_logits(model, enc, len(labels))
            per = bce(bags, labels)
            raw_loss = (per * batch_weights).sum() / batch_weights.sum().clamp_min(1e-6)
            (raw_loss / GRAD_ACCUM).backward()
            running_num += float((per.detach() * batch_weights).sum())
            running_den += float(batch_weights.sum())
            if step % GRAD_ACCUM == 0 or step == len(loader):
                torch.nn.utils.clip_grad_norm_(model.parameters(), GRAD_CLIP)
                optimizer.step()
                scheduler.step()
                optimizer.zero_grad(set_to_none=True)
        epoch_loss = running_num / max(1e-6, running_den)
        losses.append(epoch_loss)
        print(f"STAGE2 epoch={epoch+1}/{EPOCHS} weighted_bag_loss={epoch_loss:.6f}", flush=True)
    train_seconds = time.time() - t0

    val_scores = score_bags(tokenizer, model, val_bags)
    if len(val_scores) != len(val):
        raise RuntimeError("Validation specialist score length mismatch")
    if not np.all(np.isfinite(val_scores)):
        raise RuntimeError("Non-finite validation specialist scores")

    model_dir = out_dir / "model"
    model_dir.mkdir(parents=True, exist_ok=True)
    model.save_pretrained(model_dir, safe_serialization=True)
    tokenizer.save_pretrained(model_dir)
    np.save(out_dir / "multi_instance_val.npy", val_scores)
    meta2 = {
        "stage": 2,
        "source_stage1_manifest_sha256": stage1_manifest_sha,
        "protocol_sha256": sha256_file(PROTOCOL),
        "source_sha256": sha256_file(Path(__file__)),
        "model_id": MODEL_ID,
        "model_revision": MODEL_REVISION,
        "training_population": {
            "rows": len(yd),
            "positives": int((yd == 1).sum()),
            "benign": int((yd == 0).sum()),
            "residual_positive_count": int(residual.sum()),
            "residual_positive_multiplier": 4.0,
            "hard_benign_count": int(hard_benign.sum()),
            "hard_benign_multiplier": 2.0,
        },
        "views": {
            "count": N_VIEWS,
            "pooling": "normalized log-mean-exp of per-view attack logits",
            "tau": TAU,
            "max_length": MAX_LENGTH,
            "development_sha256": sha256_view_bags(dev_bags),
            "validation_sha256": sha256_view_bags(val_bags),
        },
        "hyperparameters": {
            "epochs": EPOCHS,
            "learning_rate": LR,
            "weight_decay": WEIGHT_DECAY,
            "document_batch_size": DOC_BATCH_SIZE,
            "gradient_accumulation": GRAD_ACCUM,
            "warmup_ratio": WARMUP_RATIO,
            "gradient_clip": GRAD_CLIP,
            "seed": SEED,
        },
        "epoch_losses": losses,
        "train_seconds": train_seconds,
        "validation_score_sha256": sha256_file(out_dir / "multi_instance_val.npy"),
        "runtime": {"python": sys.version, "platform": platform.platform(), "torch": torch.__version__},
        "benchmark_labels_accessed": False,
        "external_validation_datasets_accessed": False,
    }
    (out_dir / "meta.json").write_text(json.dumps(json_safe(meta2), indent=2), encoding="utf-8")
    manifest = write_manifest(out_dir)
    print("STAGE2 manifest", sha256_file(manifest), flush=True)


def verify_stage2(stage2_dir: Path, stage1_manifest_sha: str):
    manifest_sha = verify_manifest(stage2_dir)
    meta = json.loads((stage2_dir / "meta.json").read_text(encoding="utf-8"))
    if meta["source_stage1_manifest_sha256"] != stage1_manifest_sha:
        raise RuntimeError("Stage1 transport linkage mismatch")
    if meta["protocol_sha256"] != sha256_file(PROTOCOL):
        raise RuntimeError("Stage2 protocol SHA mismatch")
    if meta["source_sha256"] != sha256_file(Path(__file__)):
        raise RuntimeError("Stage2 source SHA mismatch")
    if meta["model_id"] != MODEL_ID or meta["model_revision"] != MODEL_REVISION:
        raise RuntimeError("Stage2 model identity mismatch")
    score_path = stage2_dir / "multi_instance_val.npy"
    if sha256_file(score_path) != meta["validation_score_sha256"]:
        raise RuntimeError("Stage2 validation score SHA mismatch")
    return manifest_sha, meta


def stage3(stage1_dir: Path, stage2_dir: Path, out_dir: Path):
    out_dir.mkdir(parents=True, exist_ok=True)
    stage1_manifest_sha, meta1, train, y, dev_idx, val_idx, audit_idx, arr, dev, val = verify_stage1(stage1_dir)
    stage2_manifest_sha, meta2 = verify_stage2(stage2_dir, stage1_manifest_sha)
    yd = arr["yd"].astype(np.int8)
    yv = arr["yv"].astype(np.int8)
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
                w, _, _ = hard_weights(oof, yd, hp_mult, hn_mult, hp_cut, hn_cut)
                name = f"v25_hard|C={c:g}|hp={hp_mult:g}|hn={hn_mult:g}"
                clf = LogisticRegression(C=c, max_iter=1800, solver="liblinear", random_state=SEED)
                clf.fit(d_nb, yd, sample_weight=w)
                s = clf.predict_proba(v_nb)[:, 1]
                th = threshold_at_fpr(yv, s, max_fpr=TARGET_VAL_FPR)
                m = metrics(yv, s, th)
                rows.append({**m, "name": name, "family": "hard", "eligible_for_selection": False})
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
    # Preserve exact inherited v18/v24 semantics, including chained indexing.
    adv_weights[:original_n][hp_mask] *= 2.0
    adv_weights[:original_n][hn_mask] *= 4.0
    adv_weights[original_n:] *= 1.5
    adv_models = {}
    for c in [0.5, 1.0, 2.0, 4.0]:
        name = f"v25_adv|C={c:g}"
        clf = LogisticRegression(C=c, max_iter=1800, solver="liblinear", random_state=SEED)
        clf.fit(adv_dnb, adv_y, sample_weight=adv_weights)
        s = clf.predict_proba(adv_vnb)[:, 1]
        th = threshold_at_fpr(yv, s, max_fpr=TARGET_VAL_FPR)
        m = metrics(yv, s, th)
        rows.append({**m, "name": name, "family": "adv", "eligible_for_selection": False})
        score_map[name] = s
        adv_models[name] = clf
    adv_name = str(family_best(rows, "adv")["name"])
    print("STAGE3 anchor family winners", hard_name, adv_name, flush=True)

    mi_name = "multi_instance_electra"
    mi_val = np.load(stage2_dir / "multi_instance_val.npy").astype(np.float64)
    if len(mi_val) != len(yv):
        raise RuntimeError("Multi-instance validation length mismatch")
    score_map[mi_name] = mi_val
    mi_th = threshold_at_fpr(yv, mi_val, max_fpr=TARGET_VAL_FPR)
    mi_m = metrics(yv, mi_val, mi_th)
    mi_row = {**mi_m, "name": mi_name, "family": "multi_instance", "eligible_for_selection": True,
              "complexity_rank": 1}

    anchor_m = constrained_union_search(yv, score_map, [hard_name, adv_name], TARGET_VAL_FPR)
    anchor_row = {**anchor_m, "name": f"anchor_or|{hard_name}+{adv_name}", "family": "anchor_or",
                  "members": [hard_name, adv_name], "threshold": np.nan, "roc_auc": np.nan,
                  "eligible_for_selection": True, "complexity_rank": 0}
    tri_m = constrained_union_search(yv, score_map, [hard_name, adv_name, mi_name], TARGET_VAL_FPR)
    tri_row = {**tri_m, "name": f"anchor_multi_instance|{hard_name}+{adv_name}+{mi_name}",
               "family": "anchor_multi_instance", "members": [hard_name, adv_name, mi_name],
               "threshold": np.nan, "roc_auc": np.nan, "eligible_for_selection": True,
               "complexity_rank": 2}
    rows.extend([mi_row, anchor_row, tri_row])

    selector = pd.DataFrame([anchor_row, mi_row, tri_row]).sort_values(
        ["recall", "precision", "fpr", "complexity_rank"],
        ascending=[False, False, True, True],
    ).reset_index(drop=True)
    winner = selector.iloc[0].to_dict()
    pre_audit_gate = bool(int(winner["tp"]) > int(anchor_row["tp"]) and float(winner["fpr"]) <= TARGET_VAL_FPR)
    pd.DataFrame(rows).to_csv(out_dir / "assessment_v25_validation.csv", index=False)
    (out_dir / "assessment_v25_validation_winner.json").write_text(
        json.dumps(json_safe(winner), indent=2), encoding="utf-8"
    )

    bundle = out_dir / "candidate_bundle"
    bundle.mkdir(parents=True, exist_ok=True)
    family = str(winner["family"])
    system = {
        "version": "v25",
        "family": family,
        "winner": json_safe(winner),
        "anchor_hard_name": hard_name,
        "anchor_adv_name": adv_name,
        "pre_audit_gate_passed": pre_audit_gate,
        "target_validation_fpr": TARGET_VAL_FPR,
        "model_id": MODEL_ID,
        "model_revision": MODEL_REVISION,
        "view_count": N_VIEWS,
        "visible_window_words": VISIBLE_WINDOW_WORDS,
        "max_length": MAX_LENGTH,
        "tau": TAU,
        "external_validation_datasets_accessed": False,
    }
    if family in {"anchor_or", "anchor_multi_instance"}:
        joblib.dump(vectorizers, bundle / "vectorizers.joblib", compress=3)
        joblib.dump(hard_models[hard_name], bundle / "hard_model.joblib", compress=3)
        joblib.dump(adv_vec, bundle / "adv_vectorizers.joblib", compress=3)
        joblib.dump(adv_models[adv_name], bundle / "adv_model.joblib", compress=3)
        np.save(bundle / "r.npy", r.astype(np.float32))
        np.save(bundle / "adv_r.npy", adv_r.astype(np.float32))
    if family in {"multi_instance", "anchor_multi_instance"}:
        shutil.copytree(stage2_dir / "model", bundle / "model")
    (bundle / "system.json").write_text(json.dumps(system, indent=2), encoding="utf-8")
    bundle_manifest = write_manifest(bundle)
    bundle_manifest_sha = sha256_file(bundle_manifest)

    meta3 = {
        "stage": 3,
        "source_stage1_manifest_sha256": stage1_manifest_sha,
        "source_stage2_manifest_sha256": stage2_manifest_sha,
        "protocol_sha256": sha256_file(PROTOCOL),
        "source_sha256": sha256_file(Path(__file__)),
        "anchor_validation": json_safe(anchor_row),
        "specialist_validation": json_safe(mi_row),
        "three_way_validation": json_safe(tri_row),
        "validation_winner": json_safe(winner),
        "pre_audit_gate_passed": pre_audit_gate,
        "candidate_bundle_manifest_sha256": bundle_manifest_sha,
        "comparative_audit_scored": False,
        "benchmark_labels_accessed": False,
        "external_validation_datasets_accessed": False,
    }
    (out_dir / "meta.json").write_text(json.dumps(meta3, indent=2), encoding="utf-8")
    root_manifest = write_manifest(out_dir, "STAGE3_MANIFEST.json")
    print("VALIDATION WINNER", json.dumps(json_safe(winner), indent=2), flush=True)
    print("PRE_AUDIT_GATE", pre_audit_gate, "bundle_manifest", bundle_manifest_sha, flush=True)
    print("STAGE3 manifest", sha256_file(root_manifest), flush=True)


def verify_stage3(stage3_dir: Path, stage1_manifest_sha: str, stage2_manifest_sha: str):
    stage3_manifest_sha = verify_manifest(stage3_dir, "STAGE3_MANIFEST.json")
    meta = json.loads((stage3_dir / "meta.json").read_text(encoding="utf-8"))
    if meta["source_stage1_manifest_sha256"] != stage1_manifest_sha:
        raise RuntimeError("Stage3->Stage1 linkage mismatch")
    if meta["source_stage2_manifest_sha256"] != stage2_manifest_sha:
        raise RuntimeError("Stage3->Stage2 linkage mismatch")
    if meta["protocol_sha256"] != sha256_file(PROTOCOL):
        raise RuntimeError("Stage3 protocol SHA mismatch")
    if meta["source_sha256"] != sha256_file(Path(__file__)):
        raise RuntimeError("Stage3 source SHA mismatch")
    bundle_sha = verify_manifest(stage3_dir / "candidate_bundle")
    if bundle_sha != meta["candidate_bundle_manifest_sha256"]:
        raise RuntimeError("Candidate bundle manifest SHA mismatch")
    return stage3_manifest_sha, meta


def stage4(stage1_dir: Path, stage2_dir: Path, stage3_dir: Path, result_dir: Path):
    result_dir.mkdir(parents=True, exist_ok=True)
    stage1_manifest_sha, meta1, train, y, dev_idx, val_idx, audit_idx, arr, dev, val = verify_stage1(stage1_dir)
    stage2_manifest_sha, meta2 = verify_stage2(stage2_dir, stage1_manifest_sha)
    stage3_manifest_sha, meta3 = verify_stage3(stage3_dir, stage1_manifest_sha, stage2_manifest_sha)
    bundle = stage3_dir / "candidate_bundle"
    system = json.loads((bundle / "system.json").read_text(encoding="utf-8"))
    pre_gate = bool(meta3["pre_audit_gate_passed"])
    evidence = {
        "protocol_file": str(PROTOCOL),
        "protocol_sha256": sha256_file(PROTOCOL),
        "source_sha256": sha256_file(Path(__file__)),
        "stage_manifests": {
            "stage1": stage1_manifest_sha,
            "stage2": stage2_manifest_sha,
            "stage3": stage3_manifest_sha,
            "candidate_bundle": meta3["candidate_bundle_manifest_sha256"],
        },
        "reference_v18": {
            "counts": V18_COUNTS,
            "recall": V18_RECALL,
            "fpr": V18_FPR,
        },
        "dataset_fingerprints": meta1["dataset_fingerprints"],
        "validation": {
            "anchor": meta3["anchor_validation"],
            "specialist": meta3["specialist_validation"],
            "three_way": meta3["three_way_validation"],
            "winner": meta3["validation_winner"],
        },
        "pre_audit_gate_passed": pre_gate,
        "comparative_audit_scored": False,
        "comparative_audit": None,
        "promotion": {
            "promotable_over_v18": False,
            "reason": "comparative audit not scored because pre-audit gate failed" if not pre_gate else None,
        },
        "benchmark_labels_accessed": False,
        "external_validation_datasets_accessed": False,
        "audit_is_pristine": False,
        "audit_role": "comparative only; previously observed in earlier experiments",
    }

    if pre_gate:
        t0 = time.time()
        audit = frame(train, audit_idx)
        ya = audit.y.to_numpy(dtype=np.int8)
        family = system["family"]
        winner = system["winner"]
        score_map = {}
        if family in {"anchor_or", "anchor_multi_instance"}:
            vectorizers = joblib.load(bundle / "vectorizers.joblib")
            hard_model = joblib.load(bundle / "hard_model.joblib")
            adv_vec = joblib.load(bundle / "adv_vectorizers.joblib")
            adv_model = joblib.load(bundle / "adv_model.joblib")
            r = np.load(bundle / "r.npy")
            adv_r = np.load(bundle / "adv_r.npy")
            amat = sparse_transform(audit, vectorizers).multiply(r).tocsr()
            adv_amat = sparse_transform(audit, adv_vec).multiply(adv_r).tocsr()
            score_map[system["anchor_hard_name"]] = hard_model.predict_proba(amat)[:, 1]
            score_map[system["anchor_adv_name"]] = adv_model.predict_proba(adv_amat)[:, 1]
        if family in {"multi_instance", "anchor_multi_instance"}:
            tokenizer = AutoTokenizer.from_pretrained(bundle / "model")
            model = AutoModelForSequenceClassification.from_pretrained(bundle / "model")
            score_map["multi_instance_electra"] = score_bags(tokenizer, model, build_view_bags(audit))

        if family in {"anchor_or", "anchor_multi_instance"}:
            thresholds = {k: float(v) for k, v in winner["thresholds"].items()}
            audit_m = evaluate_union(ya, score_map, thresholds)
            audit_spec = {"type": family, "thresholds": thresholds}
        elif family == "multi_instance":
            score = score_map["multi_instance_electra"]
            audit_m = metrics(ya, score, float(winner["threshold"]))
            audit_spec = {"type": family, "threshold": float(winner["threshold"])}
        else:
            raise RuntimeError(f"Unexpected frozen family {family}")

        audit_m["recall_ci95"] = wilson(audit_m["tp"], audit_m["tp"] + audit_m["fn"])
        audit_m["fpr_ci95"] = wilson(audit_m["fp"], audit_m["fp"] + audit_m["tn"])
        promotable = bool(audit_m["tp"] >= 601 and audit_m["fp"] <= 8)
        evidence["comparative_audit_scored"] = True
        evidence["comparative_audit"] = json_safe(audit_m)
        evidence["audit_spec"] = audit_spec
        evidence["promotion"] = {
            "minimum_required_tp": 601,
            "maximum_allowed_fp": 8,
            "strictly_beats_v18_recall": bool(audit_m["tp"] > V18_COUNTS["tp"]),
            "within_operating_fpr": bool(audit_m["fpr"] <= OPERATING_FPR),
            "promotable_over_v18": promotable,
        }
        evidence["audit_seconds"] = time.time() - t0

    out = result_dir / "assessment_v25_evidence.json"
    out.write_text(json.dumps(json_safe(evidence), indent=2), encoding="utf-8")
    shutil.copy2(stage3_dir / "assessment_v25_validation.csv", result_dir / "assessment_v25_validation.csv")
    shutil.copy2(stage3_dir / "assessment_v25_validation_winner.json", result_dir / "assessment_v25_validation_winner.json")
    shutil.copy2(stage3_dir / "meta.json", result_dir / "assessment_v25_stage3_meta.json")
    shutil.copy2(stage3_dir / "candidate_bundle" / "MANIFEST.json", result_dir / "assessment_v25_candidate_bundle_MANIFEST.json")
    print("V25 EVIDENCE", json.dumps(json_safe(evidence), indent=2), flush=True)


def main():
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="cmd", required=True)
    p1 = sub.add_parser("stage1"); p1.add_argument("--out", type=Path, required=True)
    p2 = sub.add_parser("stage2"); p2.add_argument("--stage1", type=Path, required=True); p2.add_argument("--out", type=Path, required=True)
    p3 = sub.add_parser("stage3"); p3.add_argument("--stage1", type=Path, required=True); p3.add_argument("--stage2", type=Path, required=True); p3.add_argument("--out", type=Path, required=True)
    p4 = sub.add_parser("stage4"); p4.add_argument("--stage1", type=Path, required=True); p4.add_argument("--stage2", type=Path, required=True); p4.add_argument("--stage3", type=Path, required=True); p4.add_argument("--results", type=Path, required=True)
    args = parser.parse_args()
    if args.cmd == "stage1": stage1(args.out)
    elif args.cmd == "stage2": stage2(args.stage1, args.out)
    elif args.cmd == "stage3": stage3(args.stage1, args.stage2, args.out)
    elif args.cmd == "stage4": stage4(args.stage1, args.stage2, args.stage3, args.results)


if __name__ == "__main__":
    main()
