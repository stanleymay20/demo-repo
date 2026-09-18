"""AgentShield v26: development-only OOF residual forensics.

Research-only diagnostic stage for the post-submission AgentShield program.
No comparative-audit rows, BrowseSafe benchmark/test labels, or reserved external
validation datasets are accessed.
"""
from __future__ import annotations

import hashlib
import json
import math
import platform
import re
import sys
import unicodedata
from pathlib import Path
from urllib.parse import urlparse

import numpy as np
import pandas as pd
from bs4 import BeautifulSoup
from datasets import load_dataset
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import confusion_matrix
from sklearn.model_selection import StratifiedKFold, train_test_split

from assessment_v16_hard_rescue import (
    LAB,
    SEED,
    clean_training_split,
    fit_sparse,
    make_views,
    nb_log_count_ratio,
    normalized_digest,
)

PROTOCOL = Path("agentshield/AGENTSHIELD_V26_RESIDUAL_FORENSICS_PROTOCOL.md")
RESULT_DIR = Path("agentshield/results")
EXPECTED_TRAIN_FP = "596f8fb7871901b9"
EXPECTED_TEST_FP = "9a9a7f691f87832e"
EXPECTED_SPLITS = (7725, 1656, 1656)
TARGET_OOF_FPR = 0.006
FOLDS = 5

URL_RE = re.compile(r"(?:https?://|www\.|[A-Za-z0-9.-]+\.[A-Za-z]{2,}(?:/|\b))", re.I)
TAG_RE = re.compile(r"<\s*[A-Za-z][^>]*>")
REPEAT_RE = re.compile(r"(.)\1+")


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


def threshold_at_budget(y: np.ndarray, score: np.ndarray, max_fpr: float) -> float:
    """Highest-recall threshold satisfying the development-only observed FPR budget."""
    y = np.asarray(y, dtype=np.int8)
    score = np.asarray(score, dtype=np.float64)
    thresholds = np.unique(score)
    # Include a no-positive-prediction option.
    thresholds = np.r_[np.nextafter(score.max(), np.inf), thresholds[::-1]]
    best = None
    for th in thresholds:
        pred = score >= float(th)
        tn = int(((y == 0) & (~pred)).sum())
        fp = int(((y == 0) & pred).sum())
        fn = int(((y == 1) & (~pred)).sum())
        tp = int(((y == 1) & pred).sum())
        fpr = fp / max(1, fp + tn)
        if fpr > max_fpr:
            continue
        rec = tp / max(1, tp + fn)
        prec = tp / max(1, tp + fp)
        key = (rec, prec, -fpr, float(th))
        if best is None or key > best[0]:
            best = (key, float(th))
    if best is None:
        raise RuntimeError("No OOF threshold satisfies the declared FPR budget")
    return best[1]


def confusion(y: np.ndarray, score: np.ndarray, th: float) -> dict:
    pred = (np.asarray(score) >= float(th)).astype(np.int8)
    tn, fp, fn, tp = confusion_matrix(y, pred).ravel()
    return {
        "threshold": float(th),
        "tp": int(tp),
        "fn": int(fn),
        "fp": int(fp),
        "tn": int(tn),
        "recall": float(tp / max(1, tp + fn)),
        "fpr": float(fp / max(1, fp + tn)),
        "precision": float(tp / max(1, tp + fp)),
    }


def fold_local_oof(dev: pd.DataFrame) -> np.ndarray:
    """Strict OOF scores with vectorizers and classifier fitted inside each fold."""
    y = dev.y.to_numpy(dtype=np.int8)
    out = np.zeros(len(dev), dtype=np.float64)
    cv = StratifiedKFold(n_splits=FOLDS, shuffle=True, random_state=SEED)
    for fold, (tr, ho) in enumerate(cv.split(np.zeros(len(y)), y), start=1):
        tr_df = dev.iloc[tr].reset_index(drop=True)
        ho_df = dev.iloc[ho].reset_index(drop=True)
        _, xtr, xho = fit_sparse(tr_df, ho_df)
        r = nb_log_count_ratio(xtr, y[tr])
        model = LogisticRegression(
            C=1.0, max_iter=1800, solver="liblinear", random_state=SEED
        )
        model.fit(xtr.multiply(r).tocsr(), y[tr])
        out[ho] = model.predict_proba(xho.multiply(r).tocsr())[:, 1]
        print(f"OOF fold {fold}/{FOLDS} complete", flush=True)
    return out


def max_repeat_run(text: str) -> int:
    m = 1
    for hit in REPEAT_RE.finditer(text):
        m = max(m, len(hit.group(0)))
    return int(m if text else 0)


def structural_features(raw: str | None) -> dict:
    raw = "" if raw is None else str(raw)
    text, evidence, script, _ = make_views(raw)
    chars = len(raw)
    visible_words = len(text.split())
    evidence_words = len(evidence.split())
    script_words = len(script.split())
    tag_count = len(TAG_RE.findall(raw))
    visible_chars = len(text)
    markup_to_visible = chars / max(1, visible_chars)

    non_ascii = sum(ord(ch) > 127 for ch in raw)
    control_format = sum(
        unicodedata.category(ch) in {"Cc", "Cf"} and ch not in "\r\n\t"
        for ch in raw
    )
    punctuation = sum(unicodedata.category(ch).startswith("P") for ch in raw)
    digits = sum(ch.isdigit() for ch in raw)
    url_like = len(URL_RE.findall(raw))

    return {
        "raw_chars": int(chars),
        "visible_words": int(visible_words),
        "evidence_words": int(evidence_words),
        "script_words": int(script_words),
        "tag_count": int(tag_count),
        "markup_to_visible": float(markup_to_visible),
        "non_ascii_ratio": float(non_ascii / max(1, chars)),
        "control_format_count": int(control_format),
        "punctuation_ratio": float(punctuation / max(1, chars)),
        "digit_ratio": float(digits / max(1, chars)),
        "max_repeated_char_run": max_repeat_run(raw),
        "url_like_count": int(url_like),
        "visible_head_sparse": bool(visible_words < 30),
        "visible_middle_sparse": bool(visible_words < 100),
        "visible_tail_sparse": bool(visible_words < 30),
        "hidden_present": bool(evidence_words > 0),
        "script_present": bool(script_words > 0),
    }


def visible_bin(n: int) -> str:
    if n < 30:
        return "0-29"
    if n < 100:
        return "30-99"
    if n < 300:
        return "100-299"
    if n < 1000:
        return "300-999"
    return ">=1000"


def raw_size_bin(n: int) -> str:
    if n < 2 * 1024:
        return "<2KB"
    if n < 10 * 1024:
        return "2-10KB"
    if n < 50 * 1024:
        return "10-50KB"
    return ">=50KB"


def non_ascii_bin(x: float) -> str:
    if x == 0:
        return "0"
    if x <= 0.01:
        return "(0,1%]"
    if x <= 0.05:
        return "(1%,5%]"
    return ">5%"


def summarize_slices(df: pd.DataFrame) -> pd.DataFrame:
    rows = []
    positive = df[df.y == 1].copy()

    def add_slice(dimension: str, category: str, part: pd.DataFrame):
        n = int(len(part))
        residuals = int(part.residual.sum()) if n else 0
        rows.append({
            "dimension": dimension,
            "category": str(category),
            "positive_count": n,
            "residual_count": residuals,
            "residual_rate": float(residuals / n) if n else None,
            "median_oof_score": float(part.oof_score.median()) if n else None,
            "median_raw_chars": float(part.raw_chars.median()) if n else None,
            "median_visible_words": float(part.visible_words.median()) if n else None,
        })

    dims = [
        ("visible_words_bin", "visible_words_bin"),
        ("raw_size_bin", "raw_size_bin"),
        ("hidden_present", "hidden_present"),
        ("script_present", "script_present"),
        ("non_ascii_bin", "non_ascii_bin"),
        ("markup_quartile", "markup_quartile"),
    ]
    for label, col in dims:
        for cat in sorted(positive[col].dropna().unique(), key=str):
            add_slice(label, str(cat), positive[positive[col] == cat])

    return pd.DataFrame(rows).sort_values(
        ["dimension", "residual_rate", "positive_count"],
        ascending=[True, False, False],
    ).reset_index(drop=True)


def main() -> None:
    RESULT_DIR.mkdir(parents=True, exist_ok=True)
    print("Loading controlled BrowseSafe source...", flush=True)
    ds = load_dataset("perplexity-ai/browsesafe-bench", token=False)
    train_raw, public_test = ds["train"], ds["test"]

    train_fp = getattr(train_raw, "_fingerprint", None)
    test_fp = getattr(public_test, "_fingerprint", None)
    if train_fp != EXPECTED_TRAIN_FP or test_fp != EXPECTED_TEST_FP:
        raise RuntimeError(
            f"Dataset fingerprint drift: {(train_fp, test_fp)} != "
            f"{(EXPECTED_TRAIN_FP, EXPECTED_TEST_FP)}"
        )

    # clean_training_split reads public_test content only for overlap hashing.
    train, dup_count, overlap_count = clean_training_split(train_raw, public_test)
    y = np.array([LAB[x] for x in train["label"]], dtype=np.int8)
    idx = np.arange(len(train))
    work, audit_idx = train_test_split(
        idx, test_size=0.15, stratify=y, random_state=SEED
    )
    dev_idx, val_idx = train_test_split(
        work, test_size=0.1764706, stratify=y[work], random_state=SEED
    )
    got = (len(dev_idx), len(val_idx), len(audit_idx))
    if got != EXPECTED_SPLITS:
        raise RuntimeError(f"Split-size drift: {got} != {EXPECTED_SPLITS}")

    # v26 intentionally materializes DEVELOPMENT ONLY.
    dev_subset = train.select([int(i) for i in dev_idx])
    parsed_rows = []
    raw_rows = []
    for local_i, (raw, label) in enumerate(zip(dev_subset["content"], dev_subset["label"])):
        text, evidence, script, combined = make_views(raw)
        parsed_rows.append({
            "text": text,
            "evidence": evidence,
            "script": script,
            "combined": combined,
            "y": LAB[label],
        })
        feat = structural_features(raw)
        feat["dev_local_index"] = int(local_i)
        feat["digest16"] = normalized_digest(raw).hex()[:16]
        raw_rows.append(feat)

    dev = pd.DataFrame(parsed_rows)
    struct = pd.DataFrame(raw_rows)
    if not np.array_equal(dev.y.to_numpy(dtype=np.int8), y[dev_idx]):
        raise RuntimeError("Development label/order mismatch")

    print("Computing strict fold-local OOF scores...", flush=True)
    oof = fold_local_oof(dev)
    yd = dev.y.to_numpy(dtype=np.int8)
    th = threshold_at_budget(yd, oof, TARGET_OOF_FPR)
    m = confusion(yd, oof, th)
    residual = (yd == 1) & (oof < th)

    forensic = pd.concat([dev[["y"]].reset_index(drop=True), struct], axis=1)
    forensic["oof_score"] = oof
    forensic["residual"] = residual

    forensic["visible_words_bin"] = forensic.visible_words.map(visible_bin)
    forensic["raw_size_bin"] = forensic.raw_chars.map(raw_size_bin)
    forensic["non_ascii_bin"] = forensic.non_ascii_ratio.map(non_ascii_bin)

    q = forensic.markup_to_visible.quantile([0.25, 0.5, 0.75]).to_numpy()
    def qcat(x):
        return "Q1" if x <= q[0] else "Q2" if x <= q[1] else "Q3" if x <= q[2] else "Q4"
    forensic["markup_quartile"] = forensic.markup_to_visible.map(qcat)

    residual_cols = [
        "dev_local_index", "digest16", "oof_score",
        "raw_chars", "visible_words", "evidence_words", "script_words",
        "tag_count", "markup_to_visible", "non_ascii_ratio",
        "control_format_count", "punctuation_ratio", "digit_ratio",
        "max_repeated_char_run", "url_like_count",
        "hidden_present", "script_present",
        "visible_words_bin", "raw_size_bin", "non_ascii_bin", "markup_quartile",
    ]
    residual_df = forensic[(forensic.y == 1) & forensic.residual][residual_cols].copy()
    residual_df = residual_df.sort_values("oof_score").reset_index(drop=True)
    residual_df.to_csv(RESULT_DIR / "v26_residual_rows.csv", index=False)

    summary = summarize_slices(forensic)
    summary.to_csv(RESULT_DIR / "v26_slice_summary.csv", index=False)

    evidence = {
        "version": "v26",
        "purpose": "development-only OOF residual forensics",
        "program_target": {
            "attack_recall": 0.9999,
            "observed_fpr_ceiling": 0.01,
            "claim_status": "research target only",
            "approx_min_zero_miss_attacks_for_one_sided_95pct_lower_bound_99_99": 29956,
        },
        "controls": {
            "comparative_audit_accessed": False,
            "benchmark_labels_accessed": False,
            "external_validation_datasets_accessed": False,
            "submitted_assessment_modified": False,
            "raw_residual_payloads_emitted": False,
        },
        "dataset": "perplexity-ai/browsesafe-bench",
        "dataset_fingerprints": {
            "train_raw": train_fp,
            "test_content_source": test_fp,
        },
        "cleanup": {
            "removed_internal_duplicates": int(dup_count),
            "removed_train_test_overlap": int(overlap_count),
        },
        "splits": {
            "development": int(len(dev_idx)),
            "validation_not_materialized": int(len(val_idx)),
            "comparative_audit_not_materialized": int(len(audit_idx)),
            "dev_idx_sha256": sha256_array(np.asarray(dev_idx, dtype=np.int64)),
            "val_idx_sha256": sha256_array(np.asarray(val_idx, dtype=np.int64)),
            "audit_idx_sha256": sha256_array(np.asarray(audit_idx, dtype=np.int64)),
        },
        "oof": {
            "folds": FOLDS,
            "feature_fit": "strict fold-local",
            "target_observed_fpr": TARGET_OOF_FPR,
            **m,
            "residual_positive_count": int(residual.sum()),
            "positive_count": int((yd == 1).sum()),
            "benign_count": int((yd == 0).sum()),
        },
        "markup_quartile_edges": [float(x) for x in q],
        "source_sha256": sha256_file(Path(__file__)),
        "protocol_sha256": sha256_file(PROTOCOL),
        "runtime": {
            "python": sys.version,
            "platform": platform.platform(),
            "numpy": np.__version__,
            "pandas": pd.__version__,
        },
    }
    (RESULT_DIR / "v26_evidence.json").write_text(
        json.dumps(evidence, indent=2), encoding="utf-8"
    )

    print(json.dumps(evidence, indent=2), flush=True)
    print("Top residual slices:", flush=True)
    print(
        summary.sort_values(["residual_rate", "positive_count"], ascending=[False, False])
        .head(20)
        .to_string(index=False),
        flush=True,
    )


if __name__ == "__main__":
    main()
