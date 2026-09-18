"""AgentShield v27: targeted long-context + Unicode rescue.

Research-only successor. Development and validation are used for training and
selection. Comparative-audit rows are not materialized until an exact candidate
bundle has been serialized, SHA-frozen, and has passed the predeclared
validation promotion gate. Public benchmark/test labels and reserved external
validation datasets are never accessed.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import platform
import random
import re
import shutil
import sys
import unicodedata
from pathlib import Path

import joblib
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
TOKEN_RE = re.compile(r"\b[A-Za-z]{6,}\b")

PROTOCOL = Path("agentshield/AGENTSHIELD_V27_TARGETED_RESCUE_PROTOCOL.md")
SOURCE = Path("agentshield/agentshield_v27_targeted_rescue.py")
WORKFLOW = Path(".github/workflows/agentshield-v27-targeted-rescue.yml")

EXPECTED_TRAIN_FP = "596f8fb7871901b9"
EXPECTED_TEST_FP = "9a9a7f691f87832e"
EXPECTED_SPLITS = (7725, 1656, 1656)

TARGET_FPR = 0.006
OPERATING_FPR = 0.01
FOLDS = 5

LONG_RAW_BYTES = 50 * 1024
LONG_VISIBLE_WORDS = 1000
LONG_WINDOW_WORDS = 320
LONG_N_VIEWS = 5
UNICODE_RATIO_GATE = 0.01

V18_COUNTS = {"tp": 600, "fn": 221, "fp": 7, "tn": 828}
BENIGN_NOISE = (
    " home products services documentation pricing support privacy contact "
    " accessibility terms help account preferences navigation "
)

np.random.seed(SEED)
random.seed(SEED)


# ----------------------------- integrity helpers -----------------------------

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


def write_manifest(directory: Path, name: str = "MANIFEST.json") -> Path:
    rows = []
    for path in sorted(directory.rglob("*")):
        if path.is_file() and path.name != name:
            rows.append(
                {
                    "path": str(path.relative_to(directory)),
                    "size": int(path.stat().st_size),
                    "sha256": sha256_file(path),
                }
            )
    out = directory / name
    out.write_text(json.dumps({"files": rows}, indent=2), encoding="utf-8")
    return out


def verify_manifest(directory: Path, name: str = "MANIFEST.json") -> str:
    path = directory / name
    payload = json.loads(path.read_text(encoding="utf-8"))
    for row in payload["files"]:
        target = directory / row["path"]
        if not target.is_file():
            raise RuntimeError(f"Missing frozen file: {target}")
        if target.stat().st_size != int(row["size"]):
            raise RuntimeError(f"Frozen size mismatch: {target}")
        got = sha256_file(target)
        if got != row["sha256"]:
            raise RuntimeError(
                f"Frozen SHA mismatch: {target}: {got} != {row['sha256']}"
            )
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
    if isinstance(value, (np.integer,)):
        return int(value)
    if isinstance(value, (np.floating, float)):
        return None if not np.isfinite(value) else float(value)
    if isinstance(value, (np.bool_, bool)):
        return bool(value)
    return value


# ----------------------------- dataset controls -----------------------------

def normalized_digest(value: str | None) -> bytes:
    text = "" if value is None else str(value)
    norm = WS.sub(" ", text.lower()).strip()
    return hashlib.sha256(norm.encode("utf-8", "ignore")).digest()


def clean_training_split(train, public_test):
    # Public benchmark/test CONTENT is used only for overlap hashing.
    test_hashes = {normalized_digest(x) for x in public_test["content"]}
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


def split_dataset():
    ds = load_dataset("perplexity-ai/browsesafe-bench", token=False)
    train_raw = ds["train"]
    public_test = ds["test"]

    train_fp = getattr(train_raw, "_fingerprint", None)
    test_fp = getattr(public_test, "_fingerprint", None)

    if train_fp != EXPECTED_TRAIN_FP or test_fp != EXPECTED_TEST_FP:
        raise RuntimeError(
            f"Dataset fingerprint drift: {(train_fp, test_fp)} != "
            f"{(EXPECTED_TRAIN_FP, EXPECTED_TEST_FP)}"
        )

    train, duplicate_count, overlap_count = clean_training_split(
        train_raw, public_test
    )

    y = np.array([LAB[x] for x in train["label"]], dtype=np.int8)
    idx = np.arange(len(train))

    work_idx, audit_idx = train_test_split(
        idx,
        test_size=0.15,
        stratify=y,
        random_state=SEED,
    )
    dev_idx, val_idx = train_test_split(
        work_idx,
        test_size=0.1764706,
        stratify=y[work_idx],
        random_state=SEED,
    )

    observed = (len(dev_idx), len(val_idx), len(audit_idx))
    if observed != EXPECTED_SPLITS:
        raise RuntimeError(f"Split drift: {observed} != {EXPECTED_SPLITS}")

    return {
        "train": train,
        "y": y,
        "dev_idx": np.asarray(dev_idx, dtype=np.int64),
        "val_idx": np.asarray(val_idx, dtype=np.int64),
        "audit_idx": np.asarray(audit_idx, dtype=np.int64),
        "train_fp": train_fp,
        "test_fp": test_fp,
        "duplicate_count": int(duplicate_count),
        "overlap_count": int(overlap_count),
    }


# --------------------------------- parsing ----------------------------------

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
    script = " ".join(scripts)
    combined = f"[TEXT] {text} [HIDDEN] {evidence} [SCRIPT] {script}"

    return text, evidence, script, combined


def non_ascii_ratio(raw: str) -> float:
    raw = "" if raw is None else str(raw)
    return float(sum(ord(ch) > 127 for ch in raw) / max(1, len(raw)))


def frame(dataset, indices) -> pd.DataFrame:
    rows = []
    subset = dataset.select([int(i) for i in indices])
    for batch in subset.iter(batch_size=16):
        for raw, label in zip(batch["content"], batch["label"]):
            raw = "" if raw is None else str(raw)
            text, evidence, script, combined = make_views(raw)
            rows.append(
                {
                    "raw": raw,
                    "text": text,
                    "evidence": evidence,
                    "script": script,
                    "combined": combined,
                    "raw_chars": len(raw),
                    "visible_words": len(text.split()),
                    "non_ascii_ratio": non_ascii_ratio(raw),
                    "y": LAB[label],
                }
            )
    return pd.DataFrame(rows)


# ------------------------------- core metrics --------------------------------

def metrics_from_pred(y, pred) -> dict:
    y = np.asarray(y, dtype=np.int8)
    pred = np.asarray(pred, dtype=bool)
    tn = int(((y == 0) & (~pred)).sum())
    fp = int(((y == 0) & pred).sum())
    fn = int(((y == 1) & (~pred)).sum())
    tp = int(((y == 1) & pred).sum())

    precision = tp / max(1, tp + fp)
    recall = tp / max(1, tp + fn)
    fpr = fp / max(1, fp + tn)
    f1 = 2 * precision * recall / max(1e-15, precision + recall)

    return {
        "precision": float(precision),
        "recall": float(recall),
        "f1": float(f1),
        "fpr": float(fpr),
        "tn": tn,
        "fp": fp,
        "fn": fn,
        "tp": tp,
    }


def metrics(y, score, threshold) -> dict:
    score = np.asarray(score, dtype=np.float64)
    pred = score >= float(threshold)
    return {
        **metrics_from_pred(y, pred),
        "threshold": float(threshold),
    }


def wilson(k: int, n: int, z: float = 1.96):
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * np.sqrt(
        p * (1 - p) / n + z * z / (4 * n * n)
    ) / d
    return [float(c - h), float(c + h)]


def thresholds_for_budget(y, score, max_fpr=TARGET_FPR):
    y = np.asarray(y, dtype=np.int8)
    score = np.asarray(score, dtype=np.float64)
    benign_scores = np.sort(score[y == 0])[::-1]
    max_fp = int(math.floor(float(max_fpr) * int((y == 0).sum())))

    if len(benign_scores) == 0:
        raise RuntimeError("No benign rows")

    out = [float(np.nextafter(benign_scores[0], np.inf))]
    for k in range(1, max_fp + 1):
        hi = benign_scores[k - 1]
        lo = benign_scores[k] if k < len(benign_scores) else -np.inf
        if np.isfinite(lo):
            out.append(float((hi + lo) / 2.0))
        else:
            out.append(float(np.nextafter(hi, -np.inf)))

    return out


def best_single_threshold(y, score, max_fpr=TARGET_FPR):
    best_key = None
    best = None
    for threshold in thresholds_for_budget(y, score, max_fpr):
        m = metrics(y, score, threshold)
        key = (m["recall"], m["precision"], -m["fpr"], threshold)
        if best_key is None or key > best_key:
            best_key = key
            best = m
    if best is None:
        raise RuntimeError("No eligible threshold")
    return best


def evaluate_union(y, score_map, threshold_map):
    pred = np.zeros(len(y), dtype=bool)
    for name, threshold in threshold_map.items():
        pred |= np.asarray(score_map[name]) >= float(threshold)
    return metrics_from_pred(y, pred)


def constrained_union_search(y, score_map, names, max_fpr=TARGET_FPR):
    max_fp = int(math.floor(float(max_fpr) * int((np.asarray(y) == 0).sum())))
    threshold_lists = {
        name: thresholds_for_budget(y, score_map[name], max_fpr)
        for name in names
    }

    best_key = None
    best = None

    def recurse(i, current):
        nonlocal best_key, best
        if i == len(names):
            m = evaluate_union(y, score_map, current)
            if m["fp"] > max_fp:
                return
            key = (m["recall"], m["precision"], -m["fpr"])
            if best_key is None or key > best_key:
                best_key = key
                best = {
                    **m,
                    "thresholds": {
                        k: float(v) for k, v in current.items()
                    },
                }
            return

        name = names[i]
        for threshold in threshold_lists[name]:
            current[name] = float(threshold)
            recurse(i + 1, current)
        current.pop(name, None)

    recurse(0, {})

    if best is None:
        raise RuntimeError(f"No feasible constrained union for {names}")

    return best


# ---------------------------- sparse anchor family ---------------------------

def fit_sparse(train_df, holdout_df):
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

    return {
        "word": word,
        "char": char,
        "evidence": evidence,
    }, x_train, x_holdout


def sparse_transform(df, vectorizers):
    return hstack(
        [
            vectorizers["word"].transform(df["combined"]),
            vectorizers["char"].transform(df["combined"]),
            vectorizers["evidence"].transform(df["evidence"]),
        ],
        format="csr",
    )


def nb_log_count_ratio(x, y):
    xb = x.copy().tocsr()
    xb.data = np.ones_like(xb.data)
    pos = np.asarray(xb[y == 1].sum(axis=0)).ravel()
    neg = np.asarray(xb[y == 0].sum(axis=0)).ravel()
    p = (pos + 1.0) / (float((y == 1).sum()) + 1.0)
    q = (neg + 1.0) / (float((y == 0).sum()) + 1.0)
    return np.log(p / q).astype(np.float32)


def strict_oof_scores(dev):
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

        _, x_train, x_hold = fit_sparse(train_df, hold_df)
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


def hard_masks(y, oof):
    oof_m = best_single_threshold(y, oof, TARGET_FPR)
    residual_positive = (
        (np.asarray(y) == 1)
        & (np.asarray(oof) < float(oof_m["threshold"]))
    )

    benign_scores = np.asarray(oof)[np.asarray(y) == 0]
    hard_benign_cutoff = float(np.quantile(benign_scores, 0.95))
    hard_benign = (
        (np.asarray(y) == 0)
        & (np.asarray(oof) >= hard_benign_cutoff)
    )

    return oof_m, residual_positive, hard_benign, hard_benign_cutoff


def weighted_rows(n, residual_positive, hard_benign, hp_mult, hn_mult):
    w = np.ones(n, dtype=np.float64)
    w[np.asarray(residual_positive, dtype=bool)] *= float(hp_mult)
    w[np.asarray(hard_benign, dtype=bool)] *= float(hn_mult)
    return w


def stable_fragment(text: str) -> str:
    text = "" if text is None else str(text)

    def repl(match):
        token = match.group(0)
        h = hashlib.sha256(
            token.lower().encode("utf-8", "ignore")
        ).digest()[0]
        if h % 4:
            return token
        cut = max(2, min(len(token) - 2, len(token) // 2))
        return token[:cut] + "-" + token[cut:]

    return TOKEN_RE.sub(repl, text)


def build_adversarial_dev(dev, residual_positive):
    variants = []
    hard = dev.loc[np.asarray(residual_positive)].copy()

    if len(hard):
        fragment = hard.copy()
        for col in ("text", "evidence", "script", "combined"):
            fragment[col] = fragment[col].map(stable_fragment)
        variants.append(fragment)

        dilute = hard.copy()
        dilute["combined"] = (
            BENIGN_NOISE
            + dilute["combined"].astype(str)
            + BENIGN_NOISE
        )
        variants.append(dilute)

    if variants:
        return pd.concat([dev.copy()] + variants, ignore_index=True)
    return dev.copy()


# --------------------------- long-context specialist -------------------------

def long_gate(df):
    return (
        (df["raw_chars"].to_numpy() >= LONG_RAW_BYTES)
        | (df["visible_words"].to_numpy() >= LONG_VISIBLE_WORDS)
    )


def position_windows(text: str, n=LONG_WINDOW_WORDS):
    words = str(text or "").split()
    if not words:
        return [""] * LONG_N_VIEWS

    if len(words) <= n:
        joined = " ".join(words)
        return [joined] * LONG_N_VIEWS

    max_start = len(words) - n
    fractions = [0.0, 0.25, 0.50, 0.75, 1.0]
    out = []

    for fraction in fractions:
        start = int(round(max_start * fraction))
        start = max(0, min(max_start, start))
        out.append(" ".join(words[start : start + n]))

    return out


def fit_long_specialist(dev, val, residual_positive, hard_benign):
    train_texts = []
    train_labels = []
    train_weights = []

    row_weights = np.ones(len(dev), dtype=np.float64)
    row_weights[np.asarray(residual_positive)] *= 4.0
    row_weights[np.asarray(hard_benign)] *= 2.0

    for text, label, weight in zip(
        dev["text"],
        dev["y"],
        row_weights,
    ):
        windows = position_windows(text)
        train_texts.extend(windows)
        train_labels.extend([int(label)] * LONG_N_VIEWS)
        train_weights.extend([float(weight)] * LONG_N_VIEWS)

    vectorizer = TfidfVectorizer(
        ngram_range=(1, 2),
        min_df=2,
        max_df=0.995,
        max_features=60000,
        sublinear_tf=True,
        strip_accents="unicode",
        dtype=np.float32,
    )

    x_train = vectorizer.fit_transform(train_texts)
    model = LogisticRegression(
        C=1.0,
        max_iter=1400,
        solver="liblinear",
        random_state=SEED,
    )
    model.fit(
        x_train,
        np.asarray(train_labels, dtype=np.int8),
        sample_weight=np.asarray(train_weights, dtype=np.float64),
    )

    val_scores = score_long_specialist(
        val,
        vectorizer,
        model,
    )

    return vectorizer, model, val_scores


def score_long_specialist(df, vectorizer, model):
    all_windows = []
    for text in df["text"]:
        all_windows.extend(position_windows(text))

    matrix = vectorizer.transform(all_windows)
    probabilities = model.predict_proba(matrix)[:, 1]
    probabilities = probabilities.reshape(
        len(df),
        LONG_N_VIEWS,
    )
    scores = probabilities.max(axis=1)

    gate = long_gate(df)
    return np.where(gate, scores, -1.0).astype(np.float64)


# ----------------------------- Unicode specialist ----------------------------

def unicode_gate(df):
    return df["non_ascii_ratio"].to_numpy() > UNICODE_RATIO_GATE


def unicode_view(raw: str) -> str:
    raw = "" if raw is None else str(raw)
    normalized = unicodedata.normalize("NFKC", raw)

    clean_chars = []
    category_runs = []
    previous_category = None

    for ch in normalized:
        category = unicodedata.category(ch)

        if category in {"Cc", "Cf"} and ch not in "\r\n\t":
            continue

        clean_chars.append(ch.lower())

        if ord(ch) > 127:
            if category != previous_category:
                category_runs.append(f" U_{category} ")
            previous_category = category
        else:
            previous_category = None

    clean = WS.sub(" ", "".join(clean_chars)).strip()
    skeleton = "".join(category_runs)

    return clean + " [UNICODE_CATEGORIES] " + skeleton


def fit_unicode_specialist(dev, val, residual_positive, hard_benign):
    weights = np.ones(len(dev), dtype=np.float64)
    weights[np.asarray(residual_positive)] *= 4.0
    weights[np.asarray(hard_benign)] *= 2.0

    vectorizer = TfidfVectorizer(
        analyzer="char",
        ngram_range=(2, 6),
        min_df=2,
        max_features=100000,
        sublinear_tf=True,
        dtype=np.float32,
    )

    train_views = [unicode_view(x) for x in dev["raw"]]
    x_train = vectorizer.fit_transform(train_views)

    model = LogisticRegression(
        C=1.0,
        max_iter=1400,
        solver="liblinear",
        random_state=SEED,
    )
    model.fit(
        x_train,
        dev["y"].to_numpy(dtype=np.int8),
        sample_weight=weights,
    )

    val_scores = score_unicode_specialist(
        val,
        vectorizer,
        model,
    )

    return vectorizer, model, val_scores


def score_unicode_specialist(df, vectorizer, model):
    views = [unicode_view(x) for x in df["raw"]]
    matrix = vectorizer.transform(views)
    scores = model.predict_proba(matrix)[:, 1]

    gate = unicode_gate(df)
    return np.where(gate, scores, -1.0).astype(np.float64)


# ----------------------------- stage 1 / freeze ------------------------------

def stage1(out_dir: Path):
    out_dir.mkdir(parents=True, exist_ok=True)

    state = split_dataset()
    train = state["train"]
    dev_idx = state["dev_idx"]
    val_idx = state["val_idx"]
    audit_idx = state["audit_idx"]

    print(
        "Materializing development and validation only:",
        len(dev_idx),
        len(val_idx),
        flush=True,
    )

    dev = frame(train, dev_idx)
    val = frame(train, val_idx)

    y_dev = dev["y"].to_numpy(dtype=np.int8)
    y_val = val["y"].to_numpy(dtype=np.int8)

    print("Reproducing strict v26-style development OOF scores...", flush=True)
    oof = strict_oof_scores(dev)
    (
        oof_metrics,
        residual_positive,
        hard_benign,
        hard_benign_cutoff,
    ) = hard_masks(y_dev, oof)

    print(
        "OOF diagnostics:",
        json.dumps(
            {
                **oof_metrics,
                "residual_positive_count": int(residual_positive.sum()),
                "hard_benign_count": int(hard_benign.sum()),
                "hard_benign_cutoff": hard_benign_cutoff,
            },
            indent=2,
        ),
        flush=True,
    )

    # ----- sparse anchor families -----
    print("Fitting full-development sparse anchor representation...", flush=True)
    vectorizers, x_dev, x_val = fit_sparse(dev, val)
    ratio = nb_log_count_ratio(x_dev, y_dev)
    x_dev_nb = x_dev.multiply(ratio).tocsr()
    x_val_nb = x_val.multiply(ratio).tocsr()

    candidate_rows = []
    score_map = {}
    hard_models = {}

    for c in [0.5, 1.0, 2.0]:
        for hp_mult in [1.0, 2.0, 4.0]:
            for hn_mult in [4.0, 6.0, 8.0]:
                weights = weighted_rows(
                    len(dev),
                    residual_positive,
                    hard_benign,
                    hp_mult,
                    hn_mult,
                )
                name = (
                    f"v27_hard|C={c:g}|hp={hp_mult:g}|hn={hn_mult:g}"
                )
                model = LogisticRegression(
                    C=c,
                    max_iter=1800,
                    solver="liblinear",
                    random_state=SEED,
                )
                model.fit(
                    x_dev_nb,
                    y_dev,
                    sample_weight=weights,
                )
                score = model.predict_proba(x_val_nb)[:, 1]
                m = best_single_threshold(
                    y_val,
                    score,
                    TARGET_FPR,
                )
                candidate_rows.append(
                    {
                        **m,
                        "name": name,
                        "family": "hard",
                    }
                )
                score_map[name] = score
                hard_models[name] = model

    hard_df = pd.DataFrame(candidate_rows)
    hard_best = (
        hard_df[hard_df["family"] == "hard"]
        .sort_values(
            ["recall", "precision", "fpr"],
            ascending=[False, False, True],
        )
        .iloc[0]
    )
    hard_name = str(hard_best["name"])

    # ----- adversarial family -----
    print("Fitting development-only adversarial family...", flush=True)
    adv_dev = build_adversarial_dev(dev, residual_positive)
    adv_y = adv_dev["y"].to_numpy(dtype=np.int8)

    adv_vectorizers, adv_x_dev, adv_x_val = fit_sparse(
        adv_dev,
        val,
    )
    adv_ratio = nb_log_count_ratio(
        adv_x_dev,
        adv_y,
    )

    adv_x_dev_nb = adv_x_dev.multiply(adv_ratio).tocsr()
    adv_x_val_nb = adv_x_val.multiply(adv_ratio).tocsr()

    adv_weights = np.ones(len(adv_dev), dtype=np.float64)
    original_n = len(dev)
    original_weights = adv_weights[:original_n]
    original_weights[np.asarray(residual_positive, dtype=bool)] *= 2.0
    original_weights[np.asarray(hard_benign, dtype=bool)] *= 4.0
    adv_weights[:original_n] = original_weights
    adv_weights[original_n:] *= 1.5

    adv_models = {}

    for c in [0.5, 1.0, 2.0, 4.0]:
        name = f"v27_adv|C={c:g}"
        model = LogisticRegression(
            C=c,
            max_iter=1800,
            solver="liblinear",
            random_state=SEED,
        )
        model.fit(
            adv_x_dev_nb,
            adv_y,
            sample_weight=adv_weights,
        )
        score = model.predict_proba(adv_x_val_nb)[:, 1]
        m = best_single_threshold(
            y_val,
            score,
            TARGET_FPR,
        )
        candidate_rows.append(
            {
                **m,
                "name": name,
                "family": "adv",
            }
        )
        score_map[name] = score
        adv_models[name] = model

    all_family_df = pd.DataFrame(candidate_rows)
    adv_best = (
        all_family_df[all_family_df["family"] == "adv"]
        .sort_values(
            ["recall", "precision", "fpr"],
            ascending=[False, False, True],
        )
        .iloc[0]
    )
    adv_name = str(adv_best["name"])

    anchor = constrained_union_search(
        y_val,
        score_map,
        [hard_name, adv_name],
        TARGET_FPR,
    )
    anchor_row = {
        **anchor,
        "name": "anchor",
        "members": [hard_name, adv_name],
        "complexity_rank": 0,
    }

    print(
        "Anchor validation:",
        json.dumps(json_safe(anchor_row), indent=2),
        flush=True,
    )

    # ----- targeted specialists -----
    print("Training long-context rescue specialist...", flush=True)
    (
        long_vectorizer,
        long_model,
        long_val,
    ) = fit_long_specialist(
        dev,
        val,
        residual_positive,
        hard_benign,
    )
    score_map["long_specialist"] = long_val

    print("Training Unicode/obfuscation rescue specialist...", flush=True)
    (
        unicode_vectorizer,
        unicode_model,
        unicode_val,
    ) = fit_unicode_specialist(
        dev,
        val,
        residual_positive,
        hard_benign,
    )
    score_map["unicode_specialist"] = unicode_val

    systems = [
        (
            "anchor",
            [hard_name, adv_name],
            0,
        ),
        (
            "anchor_plus_long",
            [hard_name, adv_name, "long_specialist"],
            1,
        ),
        (
            "anchor_plus_unicode",
            [hard_name, adv_name, "unicode_specialist"],
            1,
        ),
        (
            "anchor_plus_long_unicode",
            [
                hard_name,
                adv_name,
                "long_specialist",
                "unicode_specialist",
            ],
            2,
        ),
    ]

    system_rows = []
    for system_name, members, complexity_rank in systems:
        m = constrained_union_search(
            y_val,
            score_map,
            members,
            TARGET_FPR,
        )
        row = {
            **m,
            "name": system_name,
            "members": members,
            "complexity_rank": complexity_rank,
        }
        system_rows.append(row)
        print(
            "VALIDATION SYSTEM",
            system_name,
            json.dumps(json_safe(row)),
            flush=True,
        )

    system_df = pd.DataFrame(system_rows)
    system_df = system_df.sort_values(
        ["recall", "precision", "fpr", "complexity_rank"],
        ascending=[False, False, True, True],
    ).reset_index(drop=True)

    winner = system_df.iloc[0].to_dict()
    anchor_selected = next(
        row for row in system_rows if row["name"] == "anchor"
    )

    promotion_gate = bool(
        int(winner["tp"]) >= int(anchor_selected["tp"]) + 5
        and float(winner["fpr"]) <= TARGET_FPR
    )

    # Save human-readable validation evidence before freeze.
    pd.DataFrame(candidate_rows).to_csv(
        out_dir / "v27_family_candidates.csv",
        index=False,
    )
    system_df.to_csv(
        out_dir / "v27_validation_systems.csv",
        index=False,
    )
    (
        out_dir / "v27_validation_winner.json"
    ).write_text(
        json.dumps(json_safe(winner), indent=2),
        encoding="utf-8",
    )

    # ----- exact candidate bundle freeze -----
    bundle = out_dir / "candidate_bundle"
    bundle.mkdir(parents=True, exist_ok=True)

    joblib.dump(
        vectorizers,
        bundle / "anchor_vectorizers.joblib",
        compress=3,
    )
    joblib.dump(
        hard_models[hard_name],
        bundle / "hard_model.joblib",
        compress=3,
    )
    np.save(
        bundle / "anchor_ratio.npy",
        ratio.astype(np.float32),
    )

    joblib.dump(
        adv_vectorizers,
        bundle / "adv_vectorizers.joblib",
        compress=3,
    )
    joblib.dump(
        adv_models[adv_name],
        bundle / "adv_model.joblib",
        compress=3,
    )
    np.save(
        bundle / "adv_ratio.npy",
        adv_ratio.astype(np.float32),
    )

    joblib.dump(
        long_vectorizer,
        bundle / "long_vectorizer.joblib",
        compress=3,
    )
    joblib.dump(
        long_model,
        bundle / "long_model.joblib",
        compress=3,
    )

    joblib.dump(
        unicode_vectorizer,
        bundle / "unicode_vectorizer.joblib",
        compress=3,
    )
    joblib.dump(
        unicode_model,
        bundle / "unicode_model.joblib",
        compress=3,
    )

    system_spec = {
        "version": "v27",
        "winner": json_safe(winner),
        "anchor": json_safe(anchor_selected),
        "hard_name": hard_name,
        "adv_name": adv_name,
        "promotion_gate_passed": promotion_gate,
        "target_validation_fpr": TARGET_FPR,
        "operating_fpr_ceiling": OPERATING_FPR,
        "long_gate": {
            "raw_chars_gte": LONG_RAW_BYTES,
            "visible_words_gte": LONG_VISIBLE_WORDS,
            "logic": "OR",
        },
        "long_window_words": LONG_WINDOW_WORDS,
        "long_views": LONG_N_VIEWS,
        "unicode_ratio_gate_gt": UNICODE_RATIO_GATE,
        "external_validation_datasets_accessed": False,
        "benchmark_labels_accessed": False,
    }
    (
        bundle / "system.json"
    ).write_text(
        json.dumps(system_spec, indent=2),
        encoding="utf-8",
    )

    bundle_manifest = write_manifest(bundle)
    bundle_manifest_sha = sha256_file(bundle_manifest)

    meta = {
        "version": "v27",
        "stage": "freeze_candidate",
        "protocol_sha256": sha256_file(PROTOCOL),
        "source_sha256": sha256_file(SOURCE),
        "workflow_sha256": (
            sha256_file(WORKFLOW)
            if WORKFLOW.is_file()
            else None
        ),
        "dataset_fingerprints": {
            "train_raw": state["train_fp"],
            "test_content_source": state["test_fp"],
        },
        "cleanup": {
            "removed_internal_duplicates": state["duplicate_count"],
            "removed_train_test_overlap": state["overlap_count"],
        },
        "splits": {
            "development": int(len(dev_idx)),
            "validation": int(len(val_idx)),
            "comparative_audit_not_materialized": int(len(audit_idx)),
            "dev_idx_sha256": sha256_array(dev_idx),
            "val_idx_sha256": sha256_array(val_idx),
            "audit_idx_sha256": sha256_array(audit_idx),
        },
        "development_oof": {
            **json_safe(oof_metrics),
            "residual_positive_count": int(residual_positive.sum()),
            "hard_benign_count": int(hard_benign.sum()),
            "hard_benign_cutoff": hard_benign_cutoff,
            "strict_fold_local_feature_fit": True,
        },
        "validation_anchor": json_safe(anchor_selected),
        "validation_winner": json_safe(winner),
        "validation_tp_gain_over_anchor": int(
            winner["tp"] - anchor_selected["tp"]
        ),
        "promotion_gate_passed": promotion_gate,
        "candidate_bundle_manifest_sha256": bundle_manifest_sha,
        "controls": {
            "comparative_audit_examples_materialized": False,
            "comparative_audit_scored": False,
            "comparative_audit_examples_inspected": False,
            "comparative_audit_labels_used_for_redesign": False,
            "benchmark_labels_accessed": False,
            "external_validation_datasets_accessed": False,
            "submitted_assessment_modified": False,
        },
        "runtime": {
            "python": sys.version,
            "platform": platform.platform(),
            "numpy": np.__version__,
            "pandas": pd.__version__,
        },
    }

    (
        out_dir / "v27_stage1_meta.json"
    ).write_text(
        json.dumps(meta, indent=2),
        encoding="utf-8",
    )

    top_manifest = write_manifest(
        out_dir,
        name="STAGE1_MANIFEST.json",
    )

    print(
        "V27 STAGE1 FREEZE",
        json.dumps(meta, indent=2),
        flush=True,
    )
    print(
        "STAGE1_MANIFEST_SHA256",
        sha256_file(top_manifest),
        flush=True,
    )


# ------------------------------- stage 2 audit -------------------------------

def load_bundle_scores(df, bundle, system_spec):
    score_map = {}

    members = list(system_spec["winner"]["members"])

    if any(name.startswith("v27_hard") for name in members):
        vectorizers = joblib.load(
            bundle / "anchor_vectorizers.joblib"
        )
        model = joblib.load(bundle / "hard_model.joblib")
        ratio = np.load(bundle / "anchor_ratio.npy")
        matrix = sparse_transform(df, vectorizers)
        matrix = matrix.multiply(ratio).tocsr()
        score_map[system_spec["hard_name"]] = (
            model.predict_proba(matrix)[:, 1]
        )

    if any(name.startswith("v27_adv") for name in members):
        vectorizers = joblib.load(
            bundle / "adv_vectorizers.joblib"
        )
        model = joblib.load(bundle / "adv_model.joblib")
        ratio = np.load(bundle / "adv_ratio.npy")
        matrix = sparse_transform(df, vectorizers)
        matrix = matrix.multiply(ratio).tocsr()
        score_map[system_spec["adv_name"]] = (
            model.predict_proba(matrix)[:, 1]
        )

    if "long_specialist" in members:
        vectorizer = joblib.load(
            bundle / "long_vectorizer.joblib"
        )
        model = joblib.load(
            bundle / "long_model.joblib"
        )
        score_map["long_specialist"] = score_long_specialist(
            df,
            vectorizer,
            model,
        )

    if "unicode_specialist" in members:
        vectorizer = joblib.load(
            bundle / "unicode_vectorizer.joblib"
        )
        model = joblib.load(
            bundle / "unicode_model.joblib"
        )
        score_map["unicode_specialist"] = score_unicode_specialist(
            df,
            vectorizer,
            model,
        )

    return score_map


def stage2(stage1_dir: Path, results_dir: Path):
    results_dir.mkdir(parents=True, exist_ok=True)

    stage1_manifest_sha = verify_manifest(
        stage1_dir,
        name="STAGE1_MANIFEST.json",
    )

    meta = json.loads(
        (stage1_dir / "v27_stage1_meta.json").read_text(
            encoding="utf-8"
        )
    )

    bundle = stage1_dir / "candidate_bundle"
    bundle_manifest_sha = verify_manifest(bundle)

    if (
        bundle_manifest_sha
        != meta["candidate_bundle_manifest_sha256"]
    ):
        raise RuntimeError(
            "Candidate-bundle manifest SHA does not match frozen stage-one meta"
        )

    system_spec = json.loads(
        (bundle / "system.json").read_text(encoding="utf-8")
    )

    # Fail closed before dataset re-load if promotion did not pass.
    if not bool(system_spec["promotion_gate_passed"]):
        evidence = {
            "version": "v27",
            "stage": "comparative_audit",
            "promotion_gate_passed": False,
            "comparative_audit_scored": False,
            "comparative_audit_examples_materialized": False,
            "candidate_bundle_manifest_sha256": bundle_manifest_sha,
            "stage1_manifest_sha256": stage1_manifest_sha,
            "validation_anchor": meta["validation_anchor"],
            "validation_winner": meta["validation_winner"],
            "reason": (
                "Predeclared validation promotion gate did not pass; "
                "comparative audit remains untouched."
            ),
            "controls": {
                "benchmark_labels_accessed": False,
                "external_validation_datasets_accessed": False,
                "submitted_assessment_modified": False,
            },
        }
        (
            results_dir / "v27_evidence.json"
        ).write_text(
            json.dumps(evidence, indent=2),
            encoding="utf-8",
        )
        print(json.dumps(evidence, indent=2), flush=True)
        return

    # Gate passed: reproduce split, verify all lineage digests, then materialize audit.
    state = split_dataset()

    if state["train_fp"] != meta["dataset_fingerprints"]["train_raw"]:
        raise RuntimeError("Train fingerprint mismatch at audit stage")
    if state["test_fp"] != meta["dataset_fingerprints"]["test_content_source"]:
        raise RuntimeError("Test/content fingerprint mismatch at audit stage")

    for key, arr in (
        ("dev_idx_sha256", state["dev_idx"]),
        ("val_idx_sha256", state["val_idx"]),
        ("audit_idx_sha256", state["audit_idx"]),
    ):
        got = sha256_array(arr)
        expected = meta["splits"][key]
        if got != expected:
            raise RuntimeError(
                f"Split digest mismatch {key}: {got} != {expected}"
            )

    # Comparative-audit rows are first materialized here, after bundle freeze.
    audit = frame(
        state["train"],
        state["audit_idx"],
    )
    y_audit = audit["y"].to_numpy(dtype=np.int8)

    score_map = load_bundle_scores(
        audit,
        bundle,
        system_spec,
    )

    thresholds = {
        k: float(v)
        for k, v in system_spec["winner"]["thresholds"].items()
    }

    audit_metrics = evaluate_union(
        y_audit,
        score_map,
        thresholds,
    )

    audit_metrics["recall_ci95"] = wilson(
        audit_metrics["tp"],
        audit_metrics["tp"] + audit_metrics["fn"],
    )
    audit_metrics["fpr_ci95"] = wilson(
        audit_metrics["fp"],
        audit_metrics["fp"] + audit_metrics["tn"],
    )

    evidence = {
        "version": "v27",
        "stage": "comparative_audit",
        "promotion_gate_passed": True,
        "candidate_bundle_manifest_sha256": bundle_manifest_sha,
        "stage1_manifest_sha256": stage1_manifest_sha,
        "validation_anchor": meta["validation_anchor"],
        "validation_winner": meta["validation_winner"],
        "comparative_audit": json_safe(audit_metrics),
        "historical_v18": {
            **V18_COUNTS,
            "recall": V18_COUNTS["tp"]
            / (V18_COUNTS["tp"] + V18_COUNTS["fn"]),
            "fpr": V18_COUNTS["fp"]
            / (V18_COUNTS["fp"] + V18_COUNTS["tn"]),
        },
        "delta_vs_v18": {
            "tp": int(audit_metrics["tp"] - V18_COUNTS["tp"]),
            "fn": int(audit_metrics["fn"] - V18_COUNTS["fn"]),
            "fp": int(audit_metrics["fp"] - V18_COUNTS["fp"]),
            "tn": int(audit_metrics["tn"] - V18_COUNTS["tn"]),
            "recall_points": float(
                audit_metrics["recall"]
                - (
                    V18_COUNTS["tp"]
                    / (V18_COUNTS["tp"] + V18_COUNTS["fn"])
                )
            ),
            "fpr_points": float(
                audit_metrics["fpr"]
                - (
                    V18_COUNTS["fp"]
                    / (V18_COUNTS["fp"] + V18_COUNTS["tn"])
                )
            ),
        },
        "gates": {
            "90pct": bool(
                audit_metrics["recall"] >= 0.90
                and audit_metrics["fpr"] <= OPERATING_FPR
            ),
            "95pct": bool(
                audit_metrics["recall"] >= 0.95
                and audit_metrics["fpr"] <= OPERATING_FPR
            ),
            "99pct": bool(
                audit_metrics["recall"] >= 0.99
                and audit_metrics["fpr"] <= OPERATING_FPR
            ),
            "99_9pct": bool(
                audit_metrics["recall"] >= 0.999
                and audit_metrics["fpr"] <= OPERATING_FPR
            ),
            "99_99pct_observed_only": bool(
                audit_metrics["recall"] >= 0.9999
                and audit_metrics["fpr"] <= OPERATING_FPR
            ),
        },
        "controls": {
            "audit_is_pristine": False,
            "audit_role": "comparative internal evidence only",
            "comparative_audit_examples_inspected_for_redesign": False,
            "benchmark_labels_accessed": False,
            "external_validation_datasets_accessed": False,
            "submitted_assessment_modified": False,
        },
        "runtime": {
            "python": sys.version,
            "platform": platform.platform(),
        },
    }

    (
        results_dir / "v27_evidence.json"
    ).write_text(
        json.dumps(evidence, indent=2),
        encoding="utf-8",
    )

    print(
        "V27 COMPARATIVE AUDIT",
        json.dumps(evidence, indent=2),
        flush=True,
    )


def main():
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="stage", required=True)

    p1 = sub.add_parser("stage1")
    p1.add_argument("--out", required=True)

    p2 = sub.add_parser("stage2")
    p2.add_argument("--stage1", required=True)
    p2.add_argument("--results", required=True)

    args = parser.parse_args()

    if args.stage == "stage1":
        stage1(Path(args.out))
    elif args.stage == "stage2":
        stage2(
            Path(args.stage1),
            Path(args.results),
        )
    else:
        raise RuntimeError(args.stage)


if __name__ == "__main__":
    main()
