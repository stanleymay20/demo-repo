"""AgentShield v26: development-only OOF residual forensics.

Research-only diagnostic stage for the post-submission AgentShield program.
No comparative-audit examples are materialized or scored, BrowseSafe public
benchmark/test labels are never accessed, and reserved external validation
datasets are never accessed.

The full cleaned-training label vector is used only to reproduce the already
established stratified development/validation/audit index split (seed 42).
Only development rows are materialized for forensic analysis.
"""
from __future__ import annotations

import hashlib
import json
import platform
import re
import sys
import unicodedata
from pathlib import Path

import numpy as np
import pandas as pd
from bs4 import BeautifulSoup, Comment
from datasets import load_dataset
from scipy.sparse import hstack
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import confusion_matrix
from sklearn.model_selection import StratifiedKFold, train_test_split

SEED = 42
LAB = {"no": 0, "yes": 1}
WS = re.compile(r"\s+")

PROTOCOL = Path("agentshield/AGENTSHIELD_V26_RESIDUAL_FORENSICS_PROTOCOL.md")
RESULT_DIR = Path("agentshield/results")

EXPECTED_TRAIN_FP = "596f8fb7871901b9"
EXPECTED_TEST_FP = "9a9a7f691f87832e"
EXPECTED_SPLITS = (7725, 1656, 1656)

TARGET_OOF_FPR = 0.006
FOLDS = 5

URL_RE = re.compile(
    r"(?:https?://|www\.|[A-Za-z0-9.-]+\.[A-Za-z]{2,}(?:/|\b))",
    re.I,
)
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


def normalized_digest(value: str | None) -> bytes:
    text = "" if value is None else str(value)
    norm = WS.sub(" ", text.lower()).strip()
    return hashlib.sha256(norm.encode("utf-8", "ignore")).digest()


def clean_training_split(train, test):
    """Established cleanup; public test CONTENT only is used for overlap hashing."""
    test_hashes = {normalized_digest(x) for x in test["content"]}
    seen = set()
    keep = []
    duplicates = 0
    overlap = 0

    for i, content in enumerate(train["content"]):
        digest = normalized_digest(content)
        if digest in seen:
            duplicates += 1
            continue
        if digest in test_hashes:
            overlap += 1
            continue
        seen.add(digest)
        keep.append(i)

    return train.select(keep), duplicates, overlap


def make_views(raw: str | None):
    raw = "" if raw is None else str(raw)
    soup = BeautifulSoup(raw, "lxml")

    comments = [
        str(x)
        for x in soup.find_all(string=lambda t: isinstance(t, Comment))
    ]
    hidden = []
    attrs = []
    scripts = []

    interesting = {
        "aria-label",
        "title",
        "alt",
        "value",
        "style",
        "hidden",
        "placeholder",
        "onclick",
        "role",
    }

    for tag in soup.find_all(True):
        style = str(tag.get("style", "")).lower().replace(" ", "")
        if (
            tag.has_attr("hidden")
            or "display:none" in style
            or "visibility:hidden" in style
            or (
                tag.name == "input"
                and str(tag.get("type", "")).lower() == "hidden"
            )
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
    combined = (
        f"[TEXT] {text} [HIDDEN] {evidence} [SCRIPT] {script_text}"
    )
    return text, evidence, script_text, combined


def fit_sparse(train_df: pd.DataFrame, holdout_df: pd.DataFrame):
    word = TfidfVectorizer(
        ngram_range=(1, 2),
        min_df=2,
        max_df=0.995,
        max_features=60000,
        sublinear_tf=True,
        strip_accents="unicode",
        dtype=np.float32,
    )
    char = TfidfVectorizer(
        analyzer="char_wb",
        ngram_range=(3, 5),
        min_df=2,
        max_features=90000,
        sublinear_tf=True,
        dtype=np.float32,
    )
    evidence = TfidfVectorizer(
        analyzer="char",
        ngram_range=(3, 5),
        min_df=2,
        max_features=30000,
        sublinear_tf=True,
        dtype=np.float32,
    )

    x_train = hstack(
        [
            word.fit_transform(train_df["combined"]),
            char.fit_transform(train_df["combined"]),
            evidence.fit_transform(train_df["evidence"]),
        ],
        format="csr",
    )
    x_holdout = hstack(
        [
            word.transform(holdout_df["combined"]),
            char.transform(holdout_df["combined"]),
            evidence.transform(holdout_df["evidence"]),
        ],
        format="csr",
    )
    return x_train, x_holdout


def nb_log_count_ratio(x, y):
    xb = x.copy().tocsr()
    xb.data = np.ones_like(xb.data)
    pos = np.asarray(xb[y == 1].sum(axis=0)).ravel()
    neg = np.asarray(xb[y == 0].sum(axis=0)).ravel()
    p = (pos + 1.0) / (float((y == 1).sum()) + 1.0)
    q = (neg + 1.0) / (float((y == 0).sum()) + 1.0)
    return np.log(p / q).astype(np.float32)


def threshold_at_budget(
    y: np.ndarray, score: np.ndarray, max_fpr: float
) -> float:
    """Choose highest-recall threshold under the declared OOF FPR ceiling."""
    y = np.asarray(y, dtype=np.int8)
    score = np.asarray(score, dtype=np.float64)

    order = np.argsort(-score, kind="mergesort")
    ys = y[order]
    ss = score[order]

    pos_total = int((y == 1).sum())
    neg_total = int((y == 0).sum())

    tp_cum = np.cumsum(ys == 1)
    fp_cum = np.cumsum(ys == 0)

    best_key = None
    best_threshold = float(np.nextafter(score.max(), np.inf))

    # Group equal scores so threshold >= score is represented correctly.
    boundaries = np.flatnonzero(
        np.r_[ss[:-1] != ss[1:], True]
    )

    for end in boundaries:
        tp = int(tp_cum[end])
        fp = int(fp_cum[end])
        fpr = fp / max(1, neg_total)
        if fpr > max_fpr:
            continue

        fn = pos_total - tp
        recall = tp / max(1, pos_total)
        precision = tp / max(1, tp + fp)
        threshold = float(ss[end])
        key = (recall, precision, -fpr, threshold)

        if best_key is None or key > best_key:
            best_key = key
            best_threshold = threshold

    return best_threshold


def confusion(y: np.ndarray, score: np.ndarray, threshold: float) -> dict:
    pred = (np.asarray(score) >= float(threshold)).astype(np.int8)
    tn, fp, fn, tp = confusion_matrix(y, pred).ravel()

    return {
        "threshold": float(threshold),
        "tp": int(tp),
        "fn": int(fn),
        "fp": int(fp),
        "tn": int(tn),
        "recall": float(tp / max(1, tp + fn)),
        "fpr": float(fp / max(1, fp + tn)),
        "precision": float(tp / max(1, tp + fp)),
    }


def fold_local_oof(dev: pd.DataFrame) -> np.ndarray:
    """Strict OOF: vectorizers, count ratios and classifier refit inside each fold."""
    y = dev["y"].to_numpy(dtype=np.int8)
    out = np.zeros(len(dev), dtype=np.float64)

    cv = StratifiedKFold(
        n_splits=FOLDS,
        shuffle=True,
        random_state=SEED,
    )

    for fold, (train_i, hold_i) in enumerate(
        cv.split(np.zeros(len(y)), y),
        start=1,
    ):
        train_df = dev.iloc[train_i].reset_index(drop=True)
        hold_df = dev.iloc[hold_i].reset_index(drop=True)

        x_train, x_hold = fit_sparse(train_df, hold_df)
        ratio = nb_log_count_ratio(x_train, y[train_i])

        model = LogisticRegression(
            C=1.0,
            max_iter=1800,
            solver="liblinear",
            random_state=SEED,
        )
        model.fit(
            x_train.multiply(ratio).tocsr(),
            y[train_i],
        )
        out[hold_i] = model.predict_proba(
            x_hold.multiply(ratio).tocsr()
        )[:, 1]

        print(f"OOF fold {fold}/{FOLDS} complete", flush=True)

    return out


def max_repeat_run(text: str) -> int:
    if not text:
        return 0
    longest = 1
    for hit in REPEAT_RE.finditer(text):
        longest = max(longest, len(hit.group(0)))
    return int(longest)


def structural_features(
    raw: str | None,
    parsed: tuple[str, str, str, str],
) -> dict:
    raw = "" if raw is None else str(raw)
    text, evidence, script, _ = parsed

    raw_chars = len(raw)
    visible_words = len(text.split())
    evidence_words = len(evidence.split())
    script_words = len(script.split())
    visible_chars = len(text)

    non_ascii = sum(ord(ch) > 127 for ch in raw)
    control_format = sum(
        unicodedata.category(ch) in {"Cc", "Cf"}
        and ch not in "\r\n\t"
        for ch in raw
    )
    punctuation = sum(
        unicodedata.category(ch).startswith("P")
        for ch in raw
    )
    digits = sum(ch.isdigit() for ch in raw)

    return {
        "raw_chars": int(raw_chars),
        "visible_words": int(visible_words),
        "evidence_words": int(evidence_words),
        "script_words": int(script_words),
        "tag_count": int(len(TAG_RE.findall(raw))),
        "markup_to_visible": float(
            raw_chars / max(1, visible_chars)
        ),
        "non_ascii_ratio": float(
            non_ascii / max(1, raw_chars)
        ),
        "control_format_count": int(control_format),
        "punctuation_ratio": float(
            punctuation / max(1, raw_chars)
        ),
        "digit_ratio": float(
            digits / max(1, raw_chars)
        ),
        "max_repeated_char_run": max_repeat_run(raw),
        "url_like_count": int(len(URL_RE.findall(raw))),
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


def non_ascii_bin(value: float) -> str:
    if value == 0:
        return "0"
    if value <= 0.01:
        return "(0,1%]"
    if value <= 0.05:
        return "(1%,5%]"
    return ">5%"


def summarize_slices(df: pd.DataFrame) -> pd.DataFrame:
    positive = df[df["y"] == 1].copy()
    rows = []

    def add_slice(dimension: str, category: str, part: pd.DataFrame):
        n = int(len(part))
        residuals = int(part["residual"].sum()) if n else 0
        rows.append(
            {
                "dimension": dimension,
                "category": str(category),
                "positive_count": n,
                "residual_count": residuals,
                "residual_rate": (
                    float(residuals / n) if n else None
                ),
                "median_oof_score": (
                    float(part["oof_score"].median())
                    if n
                    else None
                ),
                "median_raw_chars": (
                    float(part["raw_chars"].median())
                    if n
                    else None
                ),
                "median_visible_words": (
                    float(part["visible_words"].median())
                    if n
                    else None
                ),
            }
        )

    dimensions = [
        "visible_words_bin",
        "raw_size_bin",
        "hidden_present",
        "script_present",
        "non_ascii_bin",
        "markup_quartile",
    ]

    for column in dimensions:
        categories = sorted(
            positive[column].dropna().unique(),
            key=str,
        )
        for category in categories:
            add_slice(
                column,
                str(category),
                positive[positive[column] == category],
            )

    return (
        pd.DataFrame(rows)
        .sort_values(
            ["dimension", "residual_rate", "positive_count"],
            ascending=[True, False, False],
        )
        .reset_index(drop=True)
    )


def main() -> None:
    np.random.seed(SEED)
    RESULT_DIR.mkdir(parents=True, exist_ok=True)

    print("Loading controlled BrowseSafe source...", flush=True)
    ds = load_dataset(
        "perplexity-ai/browsesafe-bench",
        token=False,
    )
    train_raw = ds["train"]
    public_test = ds["test"]

    train_fp = getattr(train_raw, "_fingerprint", None)
    test_fp = getattr(public_test, "_fingerprint", None)

    if (
        train_fp != EXPECTED_TRAIN_FP
        or test_fp != EXPECTED_TEST_FP
    ):
        raise RuntimeError(
            "Dataset fingerprint drift: "
            f"{(train_fp, test_fp)} != "
            f"{(EXPECTED_TRAIN_FP, EXPECTED_TEST_FP)}"
        )

    # Public benchmark/test labels are never accessed.
    # Only public benchmark/test CONTENT participates in overlap hashing.
    train, duplicate_count, overlap_count = (
        clean_training_split(train_raw, public_test)
    )

    # This label vector is required only to deterministically reproduce
    # the established stratified split boundaries.
    all_train_labels = np.array(
        [LAB[x] for x in train["label"]],
        dtype=np.int8,
    )
    all_indices = np.arange(len(train))

    work_idx, audit_idx = train_test_split(
        all_indices,
        test_size=0.15,
        stratify=all_train_labels,
        random_state=SEED,
    )
    dev_idx, val_idx = train_test_split(
        work_idx,
        test_size=0.1764706,
        stratify=all_train_labels[work_idx],
        random_state=SEED,
    )

    observed_splits = (
        len(dev_idx),
        len(val_idx),
        len(audit_idx),
    )
    if observed_splits != EXPECTED_SPLITS:
        raise RuntimeError(
            f"Split-size drift: {observed_splits} "
            f"!= {EXPECTED_SPLITS}"
        )

    # v26 materializes development rows only.
    dev_subset = train.select(
        [int(i) for i in dev_idx]
    )

    parsed_rows = []
    structural_rows = []

    for local_i, (raw, label) in enumerate(
        zip(
            dev_subset["content"],
            dev_subset["label"],
        )
    ):
        parsed = make_views(raw)
        text, evidence, script, combined = parsed

        parsed_rows.append(
            {
                "text": text,
                "evidence": evidence,
                "script": script,
                "combined": combined,
                "y": LAB[label],
            }
        )

        features = structural_features(raw, parsed)
        features["dev_local_index"] = int(local_i)
        features["digest16"] = normalized_digest(raw).hex()[:16]
        structural_rows.append(features)

    dev = pd.DataFrame(parsed_rows)
    structural = pd.DataFrame(structural_rows)

    expected_dev_labels = all_train_labels[dev_idx]
    if not np.array_equal(
        dev["y"].to_numpy(dtype=np.int8),
        expected_dev_labels,
    ):
        raise RuntimeError(
            "Development row/label order mismatch"
        )

    print(
        "Computing strict fold-local OOF scores...",
        flush=True,
    )
    oof = fold_local_oof(dev)
    y_dev = dev["y"].to_numpy(dtype=np.int8)

    threshold = threshold_at_budget(
        y_dev,
        oof,
        TARGET_OOF_FPR,
    )
    metrics = confusion(
        y_dev,
        oof,
        threshold,
    )
    residual = (
        (y_dev == 1)
        & (oof < threshold)
    )

    forensic = pd.concat(
        [
            dev[["y"]].reset_index(drop=True),
            structural.reset_index(drop=True),
        ],
        axis=1,
    )
    forensic["oof_score"] = oof
    forensic["residual"] = residual

    forensic["visible_words_bin"] = (
        forensic["visible_words"].map(visible_bin)
    )
    forensic["raw_size_bin"] = (
        forensic["raw_chars"].map(raw_size_bin)
    )
    forensic["non_ascii_bin"] = (
        forensic["non_ascii_ratio"].map(non_ascii_bin)
    )

    quartile_edges = (
        forensic["markup_to_visible"]
        .quantile([0.25, 0.5, 0.75])
        .to_numpy()
    )

    def quartile_category(value: float) -> str:
        if value <= quartile_edges[0]:
            return "Q1"
        if value <= quartile_edges[1]:
            return "Q2"
        if value <= quartile_edges[2]:
            return "Q3"
        return "Q4"

    forensic["markup_quartile"] = (
        forensic["markup_to_visible"].map(
            quartile_category
        )
    )

    residual_columns = [
        "dev_local_index",
        "digest16",
        "oof_score",
        "raw_chars",
        "visible_words",
        "evidence_words",
        "script_words",
        "tag_count",
        "markup_to_visible",
        "non_ascii_ratio",
        "control_format_count",
        "punctuation_ratio",
        "digit_ratio",
        "max_repeated_char_run",
        "url_like_count",
        "hidden_present",
        "script_present",
        "visible_words_bin",
        "raw_size_bin",
        "non_ascii_bin",
        "markup_quartile",
    ]

    residual_df = forensic[
        (forensic["y"] == 1)
        & forensic["residual"]
    ][residual_columns].copy()

    residual_df = (
        residual_df
        .sort_values("oof_score")
        .reset_index(drop=True)
    )
    residual_df.to_csv(
        RESULT_DIR / "v26_residual_rows.csv",
        index=False,
    )

    summary = summarize_slices(forensic)
    summary.to_csv(
        RESULT_DIR / "v26_slice_summary.csv",
        index=False,
    )

    evidence = {
        "version": "v26",
        "purpose": (
            "development-only strict OOF residual forensics"
        ),
        "program_target": {
            "attack_recall": 0.9999,
            "observed_fpr_ceiling": 0.01,
            "claim_status": "research target only",
            "approx_min_zero_miss_attacks_for_one_sided_95pct_lower_bound_99_99": 29956,
        },
        "controls": {
            "comparative_audit_examples_materialized": False,
            "comparative_audit_scored": False,
            "comparative_audit_examples_inspected": False,
            "comparative_audit_labels_used_for_redesign": False,
            "full_training_labels_used_only_to_reproduce_established_stratified_split": True,
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
            "removed_internal_duplicates": int(
                duplicate_count
            ),
            "removed_train_test_overlap": int(
                overlap_count
            ),
        },
        "splits": {
            "development": int(len(dev_idx)),
            "validation_not_materialized": int(
                len(val_idx)
            ),
            "comparative_audit_not_materialized": int(
                len(audit_idx)
            ),
            "dev_idx_sha256": sha256_array(
                np.asarray(dev_idx, dtype=np.int64)
            ),
            "val_idx_sha256": sha256_array(
                np.asarray(val_idx, dtype=np.int64)
            ),
            "audit_idx_sha256": sha256_array(
                np.asarray(audit_idx, dtype=np.int64)
            ),
        },
        "oof": {
            "folds": FOLDS,
            "feature_fit": "strict fold-local",
            "target_observed_fpr": TARGET_OOF_FPR,
            **metrics,
            "residual_positive_count": int(
                residual.sum()
            ),
            "positive_count": int(
                (y_dev == 1).sum()
            ),
            "benign_count": int(
                (y_dev == 0).sum()
            ),
        },
        "markup_quartile_edges": [
            float(x) for x in quartile_edges
        ],
        "source_sha256": sha256_file(Path(__file__)),
        "protocol_sha256": sha256_file(PROTOCOL),
        "runtime": {
            "python": sys.version,
            "platform": platform.platform(),
            "numpy": np.__version__,
            "pandas": pd.__version__,
        },
    }

    (
        RESULT_DIR / "v26_evidence.json"
    ).write_text(
        json.dumps(evidence, indent=2),
        encoding="utf-8",
    )

    print(
        json.dumps(evidence, indent=2),
        flush=True,
    )

    print("Top residual slices:", flush=True)
    print(
        summary.sort_values(
            ["residual_rate", "positive_count"],
            ascending=[False, False],
        )
        .head(20)
        .to_string(index=False),
        flush=True,
    )


if __name__ == "__main__":
    main()
