"""AgentShield assessment v15 contextual high-recall research experiment.

Research-only successor. Does not modify the frozen assessment notebook.
Benchmark/test labels are deliberately never accessed.
"""
from __future__ import annotations

import gc
import hashlib
import json
import math
import os
import platform
import random
import re
import sys
import time
import warnings
from pathlib import Path

import numpy as np
import pandas as pd
import torch
from bs4 import BeautifulSoup, Comment
from datasets import load_dataset
from huggingface_hub import HfApi
from scipy.sparse import hstack
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import confusion_matrix, f1_score, precision_score, recall_score, roc_auc_score, roc_curve
from sklearn.model_selection import train_test_split
from torch.utils.data import DataLoader, Dataset
from transformers import AutoModelForSequenceClassification, AutoTokenizer, get_linear_schedule_with_warmup

warnings.filterwarnings("ignore")

SEED = 42
MAX_FPR = 0.01
LAB = {"no": 0, "yes": 1}
WS = re.compile(r"\s+")
MODEL_ID = "microsoft/MiniLM-L12-H384-uncased"
MAX_LENGTH = 256
EPOCHS = 3
LR = 2e-5
WEIGHT_DECAY = 0.01
BATCH_SIZE = 8
GRAD_ACCUM = 2
WARMUP_RATIO = 0.06
RESULT_DIR = Path("agentshield/results")

random.seed(SEED)
np.random.seed(SEED)
torch.manual_seed(SEED)
torch.set_num_threads(max(1, min(4, os.cpu_count() or 1)))


def normalized_digest(s: str | None) -> bytes:
    text = "" if s is None else str(s)
    norm = WS.sub(" ", text.lower()).strip()
    return hashlib.sha256(norm.encode("utf-8", "ignore")).digest()


def clean_training_split(train, test):
    # Benchmark labels are never read. Test content hashes are used only for decontamination.
    test_hashes = {normalized_digest(x) for x in test["content"]}
    seen, keep = set(), []
    dups = overlap = 0
    for i, content in enumerate(train["content"]):
        h = normalized_digest(content)
        if h in seen:
            dups += 1
            continue
        if h in test_hashes:
            overlap += 1
            continue
        seen.add(h)
        keep.append(i)
    return train.select(keep), dups, overlap


def make_views(raw: str | None):
    raw = "" if raw is None else str(raw)
    soup = BeautifulSoup(raw, "lxml")
    comments = [str(x) for x in soup.find_all(string=lambda t: isinstance(t, Comment))]
    hidden, attrs = [], []
    interesting = {
        "aria-label", "title", "alt", "value", "style", "hidden",
        "placeholder", "onclick", "role",
    }
    for tag in soup.find_all(True):
        style = str(tag.get("style", "")).lower().replace(" ", "")
        if (
            tag.has_attr("hidden")
            or "display:none" in style
            or "visibility:hidden" in style
            or (tag.name == "input" and str(tag.get("type", "")).lower() == "hidden")
        ):
            hidden.append(tag.get_text(" ", strip=True))
        for key, value in tag.attrs.items():
            if key.startswith("data-") or key in interesting:
                if isinstance(value, list):
                    value = " ".join(map(str, value))
                attrs.append(f"{key} {value}")
    for tag in soup(["script", "style"]):
        tag.decompose()
    text = " ".join(soup.stripped_strings)
    evidence = " ".join(comments + hidden + attrs)
    combined = f"[TEXT] {text} [HIDDEN] {evidence}"
    return text, evidence, combined


def sample_context(text: str, evidence: str) -> str:
    # Deterministic head/middle/tail coverage. No claim of full-document coverage.
    words = WS.split((text or "").strip()) if text else []
    if len(words) > 220:
        mid = len(words) // 2
        words = words[:85] + words[max(0, mid - 25): mid + 25] + words[-85:]
    ev_words = WS.split((evidence or "").strip()) if evidence else []
    if len(ev_words) > 80:
        ev_words = ev_words[:40] + ev_words[-40:]
    visible = " ".join(words)
    hidden = " ".join(ev_words)
    return f"visible text: {visible} hidden evidence: {hidden}".strip()


def frame(dataset, ids):
    rows = []
    subset = dataset.select([int(i) for i in ids])
    for batch in subset.iter(batch_size=16):
        for raw, label in zip(batch["content"], batch["label"]):
            text, evidence, combined = make_views(raw)
            rows.append({
                "text": text,
                "evidence": evidence,
                "combined": combined,
                "context": sample_context(text, evidence),
                "y": LAB[label],
            })
    return pd.DataFrame(rows)


def metrics(y, score, threshold):
    pred = (np.asarray(score) >= float(threshold)).astype(np.int8)
    tn, fp, fn, tp = confusion_matrix(y, pred).ravel()
    return {
        "threshold": float(threshold),
        "precision": float(precision_score(y, pred, zero_division=0)),
        "recall": float(recall_score(y, pred, zero_division=0)),
        "f1": float(f1_score(y, pred, zero_division=0)),
        "roc_auc": float(roc_auc_score(y, score)),
        "fpr": float(fp / (fp + tn)),
        "tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp),
    }


def threshold_at_fpr(y, score, max_fpr=MAX_FPR):
    fpr, tpr, thresholds = roc_curve(y, score)
    valid = np.where(fpr <= max_fpr)[0]
    if len(valid) == 0:
        raise RuntimeError("No threshold satisfies requested validation FPR")
    best_tpr = tpr[valid].max()
    tied = valid[tpr[valid] == best_tpr]
    return float(np.max(thresholds[tied]))


def wilson(k, n, z=1.96):
    p = k / n
    d = 1 + z*z/n
    c = (p + z*z/(2*n)) / d
    h = z*np.sqrt(p*(1-p)/n + z*z/(4*n*n)) / d
    return [float(c-h), float(c+h)]


def fit_sparse(dev, val):
    word = TfidfVectorizer(
        ngram_range=(1, 2), min_df=2, max_df=.995, max_features=60000,
        sublinear_tf=True, strip_accents="unicode", dtype=np.float32,
    )
    char = TfidfVectorizer(
        analyzer="char_wb", ngram_range=(3, 5), min_df=2, max_features=90000,
        sublinear_tf=True, dtype=np.float32,
    )
    evidence = TfidfVectorizer(
        analyzer="char", ngram_range=(3, 5), min_df=2, max_features=30000,
        sublinear_tf=True, dtype=np.float32,
    )
    dw = word.fit_transform(dev["combined"])
    dc = char.fit_transform(dev["combined"])
    de = evidence.fit_transform(dev["evidence"])
    vw = word.transform(val["combined"])
    vc = char.transform(val["combined"])
    ve = evidence.transform(val["evidence"])
    dmat = hstack([dw, dc, de], format="csr")
    vmat = hstack([vw, vc, ve], format="csr")
    return {"word": word, "char": char, "evidence": evidence}, dmat, vmat


def sparse_transform(df, vec):
    return hstack([
        vec["word"].transform(df["combined"]),
        vec["char"].transform(df["combined"]),
        vec["evidence"].transform(df["evidence"]),
    ], format="csr")


def nb_log_count_ratio(x, y):
    # NBSVM-style supervised reweighting learned from development data only.
    xb = x.copy().tocsr()
    xb.data = np.ones_like(xb.data)
    pos = np.asarray(xb[y == 1].sum(axis=0)).ravel()
    neg = np.asarray(xb[y == 0].sum(axis=0)).ravel()
    p = (pos + 1.0) / (float((y == 1).sum()) + 1.0)
    q = (neg + 1.0) / (float((y == 0).sum()) + 1.0)
    return np.log(p / q).astype(np.float32)


class EncodedDataset(Dataset):
    def __init__(self, encodings, labels):
        self.encodings = encodings
        self.labels = torch.as_tensor(labels, dtype=torch.long)

    def __len__(self):
        return len(self.labels)

    def __getitem__(self, idx):
        item = {k: v[idx] for k, v in self.encodings.items()}
        item["labels"] = self.labels[idx]
        return item


def encode_texts(tokenizer, texts):
    return tokenizer(
        list(texts), padding=True, truncation=True, max_length=MAX_LENGTH,
        return_tensors="pt",
    )


def fine_tune_contextual(dev, model_revision):
    tokenizer = AutoTokenizer.from_pretrained(MODEL_ID, revision=model_revision)
    model = AutoModelForSequenceClassification.from_pretrained(
        MODEL_ID, revision=model_revision, num_labels=2
    )
    enc = encode_texts(tokenizer, dev["context"].tolist())
    ds = EncodedDataset(enc, dev.y.to_numpy())
    generator = torch.Generator().manual_seed(SEED)
    loader = DataLoader(ds, batch_size=BATCH_SIZE, shuffle=True, generator=generator)
    optimizer = torch.optim.AdamW(model.parameters(), lr=LR, weight_decay=WEIGHT_DECAY)
    update_steps_per_epoch = math.ceil(len(loader) / GRAD_ACCUM)
    total_updates = update_steps_per_epoch * EPOCHS
    warmup = int(total_updates * WARMUP_RATIO)
    scheduler = get_linear_schedule_with_warmup(optimizer, warmup, total_updates)
    model.train()
    optimizer.zero_grad(set_to_none=True)
    losses = []
    t0 = time.time()
    for epoch in range(EPOCHS):
        running = 0.0
        for step, batch in enumerate(loader, start=1):
            out = model(**batch)
            loss = out.loss / GRAD_ACCUM
            loss.backward()
            running += float(out.loss.detach())
            if step % GRAD_ACCUM == 0 or step == len(loader):
                torch.nn.utils.clip_grad_norm_(model.parameters(), 1.0)
                optimizer.step()
                scheduler.step()
                optimizer.zero_grad(set_to_none=True)
        epoch_loss = running / max(1, len(loader))
        losses.append(epoch_loss)
        print(f"CONTEXT epoch={epoch+1}/{EPOCHS} loss={epoch_loss:.6f}", flush=True)
    return tokenizer, model, {"epoch_losses": losses, "train_seconds": time.time()-t0}


@torch.no_grad()
def contextual_scores(tokenizer, model, texts):
    model.eval()
    scores = []
    for start in range(0, len(texts), BATCH_SIZE * 2):
        chunk = list(texts[start:start + BATCH_SIZE * 2])
        enc = tokenizer(
            chunk, padding=True, truncation=True, max_length=MAX_LENGTH,
            return_tensors="pt",
        )
        logits = model(**enc).logits
        probs = torch.softmax(logits, dim=1)[:, 1]
        scores.extend(probs.cpu().numpy().tolist())
    return np.asarray(scores, dtype=np.float64)


def standardize(score):
    mu = float(np.mean(score))
    sd = float(np.std(score)) or 1.0
    return (np.asarray(score) - mu) / sd, mu, sd


def constrained_or_search(y, score_a, score_b):
    """Search validation-only OR thresholds under an integer false-positive budget."""
    y = np.asarray(y)
    benign = np.where(y == 0)[0]
    attack = np.where(y == 1)[0]
    max_fp = int(math.floor(MAX_FPR * len(benign)))

    def thresholds_for_budget(score):
        b = np.sort(np.asarray(score)[benign])[::-1]
        out = [float(np.nextafter(b[0], np.inf))]
        for k in range(1, max_fp + 1):
            hi = b[k-1]
            lo = b[k] if k < len(b) else -np.inf
            out.append(float((hi + lo) / 2.0 if np.isfinite(lo) else np.nextafter(hi, -np.inf)))
        return out

    ta_list, tb_list = thresholds_for_budget(score_a), thresholds_for_budget(score_b)
    best = None
    for ta in ta_list:
        pa = np.asarray(score_a) >= ta
        for tb in tb_list:
            pred = pa | (np.asarray(score_b) >= tb)
            fp = int(pred[benign].sum())
            if fp > max_fp:
                continue
            tp = int(pred[attack].sum())
            rec = tp / len(attack)
            fpr = fp / len(benign)
            precision = tp / max(1, tp + fp)
            f1 = 2 * precision * rec / max(1e-15, precision + rec)
            candidate = (rec, precision, -fpr, ta, tb, tp, fp, f1)
            if best is None or candidate[:3] > best[:3]:
                best = candidate
    if best is None:
        raise RuntimeError("OR search found no feasible configuration")
    rec, precision, neg_fpr, ta, tb, tp, fp, f1 = best
    tn = len(benign) - fp
    fn = len(attack) - tp
    return {
        "threshold_a": float(ta), "threshold_b": float(tb),
        "precision": float(precision), "recall": float(rec), "f1": float(f1),
        "fpr": float(-neg_fpr), "tn": tn, "fp": fp, "fn": fn, "tp": tp,
    }


def evaluate_or(y, score_a, score_b, ta, tb):
    pred = (np.asarray(score_a) >= ta) | (np.asarray(score_b) >= tb)
    tn, fp, fn, tp = confusion_matrix(y, pred.astype(np.int8)).ravel()
    precision = tp / max(1, tp + fp)
    recall = tp / max(1, tp + fn)
    f1 = 2 * precision * recall / max(1e-15, precision + recall)
    return {
        "threshold_a": float(ta), "threshold_b": float(tb),
        "precision": float(precision), "recall": float(recall), "f1": float(f1),
        "fpr": float(fp / (fp + tn)), "tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp),
    }


def main():
    RESULT_DIR.mkdir(parents=True, exist_ok=True)
    print("Loading BrowseSafe...", flush=True)
    ds = load_dataset("perplexity-ai/browsesafe-bench", token=False)
    train_raw, test = ds["train"], ds["test"]
    train, dup_count, overlap_count = clean_training_split(train_raw, test)
    print("Removed train duplicates:", dup_count, "train/test overlap:", overlap_count, flush=True)

    y = np.asarray([LAB[x] for x in train["label"]], dtype=np.int8)
    idx = np.arange(len(train))
    work, audit_idx = train_test_split(idx, test_size=.15, stratify=y, random_state=SEED)
    dev_idx, val_idx = train_test_split(work, test_size=.1764706, stratify=y[work], random_state=SEED)
    print("Development / validation / comparative audit:", len(dev_idx), len(val_idx), len(audit_idx), flush=True)

    t0 = time.time()
    dev, val = frame(train, dev_idx), frame(train, val_idx)
    print("Frame dev+val seconds:", round(time.time()-t0, 2), flush=True)
    yd, yv = dev.y.to_numpy(), val.y.to_numpy()

    # 1) Frozen v14 sparse baseline.
    t0 = time.time()
    vectorizers, dmat, vmat = fit_sparse(dev, val)
    sparse = LogisticRegression(C=1.0, class_weight={0:1.0, 1:1.0}, max_iter=1800, solver="liblinear", random_state=SEED)
    sparse.fit(dmat, yd)
    sparse_val = sparse.predict_proba(vmat)[:,1]
    sparse_th = threshold_at_fpr(yv, sparse_val)
    sparse_m = metrics(yv, sparse_val, sparse_th)
    sparse_m.update(name="sparse_v14", family="sparse")
    print("VAL sparse_v14", json.dumps(sparse_m), flush=True)

    # 2) NBSVM-style reweighting on same representation.
    r = nb_log_count_ratio(dmat, yd)
    nb_d = dmat.multiply(r).tocsr()
    nb_v = vmat.multiply(r).tocsr()
    nb = LogisticRegression(C=1.0, class_weight={0:1.0,1:1.0}, max_iter=1800, solver="liblinear", random_state=SEED)
    nb.fit(nb_d, yd)
    nb_val = nb.predict_proba(nb_v)[:,1]
    nb_th = threshold_at_fpr(yv, nb_val)
    nb_m = metrics(yv, nb_val, nb_th)
    nb_m.update(name="nb_logreg", family="nb_sparse")
    print("VAL nb_logreg", json.dumps(nb_m), flush=True)
    sparse_seconds = time.time()-t0

    # 3) Task-specific contextual model, exact revision pinned before download/training.
    model_revision = HfApi().model_info(MODEL_ID).sha
    print("Resolved contextual model revision:", model_revision, flush=True)
    tokenizer, context_model, train_meta = fine_tune_contextual(dev, model_revision)
    context_val = contextual_scores(tokenizer, context_model, val["context"].tolist())
    context_th = threshold_at_fpr(yv, context_val)
    context_m = metrics(yv, context_val, context_th)
    context_m.update(name="minilm_finetuned", family="contextual")
    print("VAL minilm_finetuned", json.dumps(context_m), flush=True)

    rows = [sparse_m, nb_m, context_m]
    score_map = {"sparse_v14": sparse_val, "nb_logreg": nb_val, "minilm_finetuned": context_val}

    # 4) Standardized score fusion on validation only.
    for sparse_name in ["sparse_v14", "nb_logreg"]:
        sa = score_map[sparse_name]
        za, ma, sda = standardize(sa)
        zb, mb, sdb = standardize(context_val)
        for alpha in np.linspace(.1, .9, 9):
            fused = alpha*za + (1-alpha)*zb
            th = threshold_at_fpr(yv, fused)
            m = metrics(yv, fused, th)
            name = f"fusion|{sparse_name}+context|alpha={alpha:.1f}"
            m.update(name=name, family="fusion", sparse_name=sparse_name,
                     alpha=float(alpha), a_mean=ma, a_std=sda, b_mean=mb, b_std=sdb)
            rows.append(m)
            score_map[name] = fused
            print("VAL", name, json.dumps(m), flush=True)

    # 5) Explicit OR-cascade with validation false-positive union constrained to <=1%.
    for sparse_name in ["sparse_v14", "nb_logreg"]:
        om = constrained_or_search(yv, score_map[sparse_name], context_val)
        name = f"or|{sparse_name}+context"
        om.update(name=name, family="or_cascade", sparse_name=sparse_name)
        rows.append(om)
        print("VAL", name, json.dumps(om), flush=True)

    table = pd.DataFrame(rows)
    table = table.sort_values(["recall", "fpr", "precision"], ascending=[False, True, False]).reset_index(drop=True)
    table.to_csv(RESULT_DIR / "assessment_v15_validation.csv", index=False)
    winner = table.iloc[0].to_dict()
    winner_name = str(winner["name"])
    print("VALIDATION WINNER", json.dumps(winner, indent=2, default=str), flush=True)

    # Freeze before comparative audit construction/scoring.
    t0 = time.time()
    audit = frame(train, audit_idx)
    ya = audit.y.to_numpy()
    amat = sparse_transform(audit, vectorizers)
    sparse_audit = sparse.predict_proba(amat)[:,1]
    nb_audit = nb.predict_proba(amat.multiply(r).tocsr())[:,1]
    context_audit = contextual_scores(tokenizer, context_model, audit["context"].tolist())
    print("Audit representation/scoring seconds:", round(time.time()-t0,2), flush=True)

    if winner_name == "sparse_v14":
        audit_m = metrics(ya, sparse_audit, float(winner["threshold"]))
        audit_spec = {"type":"base", "name":winner_name}
    elif winner_name == "nb_logreg":
        audit_m = metrics(ya, nb_audit, float(winner["threshold"]))
        audit_spec = {"type":"base", "name":winner_name}
    elif winner_name == "minilm_finetuned":
        audit_m = metrics(ya, context_audit, float(winner["threshold"]))
        audit_spec = {"type":"base", "name":winner_name}
    elif winner_name.startswith("fusion|"):
        sparse_name = str(winner["sparse_name"])
        a = sparse_audit if sparse_name == "sparse_v14" else nb_audit
        za = (a - float(winner["a_mean"])) / float(winner["a_std"])
        zb = (context_audit - float(winner["b_mean"])) / float(winner["b_std"])
        fused = float(winner["alpha"])*za + (1-float(winner["alpha"]))*zb
        audit_m = metrics(ya, fused, float(winner["threshold"]))
        audit_spec = {"type":"fusion", "name":winner_name, "sparse_name":sparse_name, "alpha":float(winner["alpha"])}
    elif winner_name.startswith("or|"):
        sparse_name = str(winner["sparse_name"])
        a = sparse_audit if sparse_name == "sparse_v14" else nb_audit
        audit_m = evaluate_or(ya, a, context_audit, float(winner["threshold_a"]), float(winner["threshold_b"]))
        audit_spec = {"type":"or_cascade", "name":winner_name, "sparse_name":sparse_name,
                      "threshold_a":float(winner["threshold_a"]), "threshold_b":float(winner["threshold_b"])}
    else:
        raise RuntimeError(f"Unknown winner {winner_name}")

    audit_m["recall_ci95"] = wilson(audit_m["tp"], audit_m["tp"] + audit_m["fn"])
    audit_m["fpr_ci95"] = wilson(audit_m["fp"], audit_m["fp"] + audit_m["tn"])
    print("COMPARATIVE AUDIT", json.dumps(audit_m, indent=2), flush=True)

    evidence = {
        "protocol_file": "agentshield/ASSESSMENT_V15_CONTEXTUAL_PROTOCOL.md",
        "research_only": True,
        "seed": SEED,
        "max_observed_validation_fpr": MAX_FPR,
        "benchmark_labels_accessed": False,
        "audit_is_pristine": False,
        "audit_role": "comparative only; previously observed in earlier experiments",
        "dataset": "perplexity-ai/browsesafe-bench",
        "dataset_fingerprints": {
            "train_raw": getattr(train_raw, "_fingerprint", None),
            "test_content_source": getattr(test, "_fingerprint", None),
        },
        "removed_internal_duplicates": int(dup_count),
        "removed_train_test_overlap": int(overlap_count),
        "splits": {"development": len(dev_idx), "validation": len(val_idx), "comparative_audit": len(audit_idx)},
        "sparse_feature_count": int(dmat.shape[1]),
        "contextual": {
            "model_id": MODEL_ID, "revision": model_revision, "max_length": MAX_LENGTH,
            "epochs": EPOCHS, "learning_rate": LR, "weight_decay": WEIGHT_DECAY,
            "batch_size": BATCH_SIZE, "grad_accum": GRAD_ACCUM, "warmup_ratio": WARMUP_RATIO,
            **train_meta,
        },
        "sparse_seconds": float(sparse_seconds),
        "validation_winner": winner,
        "audit_spec": audit_spec,
        "comparative_audit": audit_m,
        "gates": {
            "B_70pct": bool(audit_m["recall"] >= .70 and audit_m["fpr"] <= .01),
            "C_85pct": bool(audit_m["recall"] >= .85 and audit_m["fpr"] <= .01),
            "D_90pct": bool(audit_m["recall"] >= .90 and audit_m["fpr"] <= .01),
            "stretch_99_9pct": bool(audit_m["recall"] >= .999 and audit_m["fpr"] <= .01),
        },
        "runtime": {"python":sys.version, "platform":platform.platform(), "torch":torch.__version__},
    }
    with open(RESULT_DIR / "assessment_v15_evidence.json", "w") as f:
        json.dump(evidence, f, indent=2, default=str)

    # Integrity assertions only, never desired-performance assertions.
    assert len(dev_idx) == 7725 and len(val_idx) == 1656 and len(audit_idx) == 1656
    assert dup_count == 1 and overlap_count == 1
    assert 0 <= audit_m["recall"] <= 1 and 0 <= audit_m["fpr"] <= 1
    print("AGENTSHIELD_ASSESSMENT_V15=COMPLETE", flush=True)
    gc.collect()


if __name__ == "__main__":
    main()
