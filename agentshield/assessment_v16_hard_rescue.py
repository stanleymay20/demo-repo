"""AgentShield assessment v16 hard-example rescue experiment.

Research-only successor. Frozen assessment notebook is untouched.
BrowseSafe benchmark/test labels are never accessed.
"""

from __future__ import annotations

import hashlib
import json
import math
import os
import platform
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
np.random.seed(SEED)
torch.manual_seed(SEED)
LAB = {"no": 0, "yes": 1}
WS = re.compile(r"\s+")
MAX_FPR = 0.01
RESULT_DIR = Path("agentshield/results")
MODEL_ID = "microsoft/MiniLM-L12-H384-uncased"
MAX_LENGTH = 256
EPOCHS = 3
LR = 2e-5
WEIGHT_DECAY = 0.01
BATCH_SIZE = 8
GRAD_ACCUM = 2
WARMUP_RATIO = 0.06
HP_CONTEXT_MULT = 4.0
HN_CONTEXT_MULT = 2.0


def normalized_digest(s: str | None) -> bytes:
    text = "" if s is None else str(s)
    norm = WS.sub(" ", text.lower()).strip()
    return hashlib.sha256(norm.encode("utf-8", "ignore")).digest()


def clean_training_split(train, test):
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
    hidden, attrs, scripts = [], [], []
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
    combined = f"[TEXT] {text} [HIDDEN] {evidence} [SCRIPT] {script_text}"
    return text, evidence, script_text, combined


def clipped_words(s: str, head: int, tail: int = 0):
    words = WS.split((s or "").strip()) if s else []
    if tail and len(words) > head + tail:
        return words[:head] + words[-tail:]
    return words[:head] if len(words) > head else words


def sample_context(text: str, evidence: str, script_text: str) -> str:
    words = WS.split((text or "").strip()) if text else []
    if len(words) > 190:
        mid = len(words) // 2
        words = words[:70] + words[max(0, mid - 25):mid + 25] + words[-70:]
    ev = clipped_words(evidence, 35, 35)
    sc = clipped_words(script_text, 25, 25)
    return (
        "visible text: " + " ".join(words)
        + " hidden evidence: " + " ".join(ev)
        + " script cues: " + " ".join(sc)
    ).strip()


def frame(dataset, ids):
    rows = []
    subset = dataset.select([int(i) for i in ids])
    for batch in subset.iter(batch_size=16):
        for raw, label in zip(batch["content"], batch["label"]):
            text, evidence, script_text, combined = make_views(raw)
            rows.append({
                "text": text,
                "evidence": evidence,
                "script": script_text,
                "combined": combined,
                "context": sample_context(text, evidence, script_text),
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
    return {"word": word, "char": char, "evidence": evidence}, hstack([dw, dc, de], format="csr"), hstack([vw, vc, ve], format="csr")


def sparse_transform(df, vec):
    return hstack([
        vec["word"].transform(df["combined"]),
        vec["char"].transform(df["combined"]),
        vec["evidence"].transform(df["evidence"]),
    ], format="csr")


def nb_log_count_ratio(x, y):
    xb = x.copy().tocsr()
    xb.data = np.ones_like(xb.data)
    pos = np.asarray(xb[y == 1].sum(axis=0)).ravel()
    neg = np.asarray(xb[y == 0].sum(axis=0)).ravel()
    p = (pos + 1.0) / (float((y == 1).sum()) + 1.0)
    q = (neg + 1.0) / (float((y == 0).sum()) + 1.0)
    return np.log(p / q).astype(np.float32)


def hard_example_weights(scores, y, hp_mult, hn_mult, hp_cut, hn_cut):
    w = np.ones(len(y), dtype=np.float64)
    hard_pos = (y == 1) & (scores <= hp_cut)
    hard_neg = (y == 0) & (scores >= hn_cut)
    w[hard_pos] *= float(hp_mult)
    w[hard_neg] *= float(hn_mult)
    return w, hard_pos, hard_neg


class WeightedEncodedDataset(Dataset):
    def __init__(self, encodings, labels, weights):
        self.encodings = encodings
        self.labels = torch.as_tensor(labels, dtype=torch.long)
        self.weights = torch.as_tensor(weights, dtype=torch.float32)

    def __len__(self):
        return len(self.labels)

    def __getitem__(self, idx):
        item = {k: v[idx] for k, v in self.encodings.items()}
        item["labels"] = self.labels[idx]
        item["example_weight"] = self.weights[idx]
        return item


def encode_texts(tokenizer, texts):
    return tokenizer(list(texts), padding=True, truncation=True, max_length=MAX_LENGTH, return_tensors="pt")


def fine_tune_contextual(dev, weights, model_revision):
    tokenizer = AutoTokenizer.from_pretrained(MODEL_ID, revision=model_revision)
    model = AutoModelForSequenceClassification.from_pretrained(MODEL_ID, revision=model_revision, num_labels=2)
    enc = encode_texts(tokenizer, dev["context"].tolist())
    ds = WeightedEncodedDataset(enc, dev.y.to_numpy(), weights)
    generator = torch.Generator().manual_seed(SEED)
    loader = DataLoader(ds, batch_size=BATCH_SIZE, shuffle=True, generator=generator)
    optimizer = torch.optim.AdamW(model.parameters(), lr=LR, weight_decay=WEIGHT_DECAY)
    updates_per_epoch = math.ceil(len(loader) / GRAD_ACCUM)
    total_updates = updates_per_epoch * EPOCHS
    warmup = int(total_updates * WARMUP_RATIO)
    scheduler = get_linear_schedule_with_warmup(optimizer, warmup, total_updates)
    ce = torch.nn.CrossEntropyLoss(reduction="none")
    model.train()
    optimizer.zero_grad(set_to_none=True)
    losses = []
    t0 = time.time()
    for epoch in range(EPOCHS):
        running = 0.0
        for step, batch in enumerate(loader, start=1):
            ew = batch.pop("example_weight")
            labels = batch["labels"]
            logits = model(**{k:v for k,v in batch.items() if k != "labels"}).logits
            per = ce(logits, labels)
            loss_full = (per * ew).sum() / ew.sum().clamp_min(1e-6)
            (loss_full / GRAD_ACCUM).backward()
            running += float(loss_full.detach())
            if step % GRAD_ACCUM == 0 or step == len(loader):
                torch.nn.utils.clip_grad_norm_(model.parameters(), 1.0)
                optimizer.step(); scheduler.step(); optimizer.zero_grad(set_to_none=True)
        epoch_loss = running / max(1, len(loader))
        losses.append(epoch_loss)
        print(f"CONTEXT epoch={epoch+1}/{EPOCHS} weighted_loss={epoch_loss:.6f}", flush=True)
    return tokenizer, model, {"epoch_losses": losses, "train_seconds": time.time()-t0}


@torch.no_grad()
def contextual_scores(tokenizer, model, texts):
    model.eval()
    scores = []
    step = BATCH_SIZE * 2
    for start in range(0, len(texts), step):
        enc = tokenizer(list(texts[start:start+step]), padding=True, truncation=True, max_length=MAX_LENGTH, return_tensors="pt")
        logits = model(**enc).logits
        scores.extend(torch.softmax(logits, dim=1)[:,1].cpu().numpy().tolist())
    return np.asarray(scores, dtype=np.float64)


def thresholds_for_budget(y, score):
    y = np.asarray(y)
    benign = np.where(y == 0)[0]
    max_fp = int(math.floor(MAX_FPR * len(benign)))
    b = np.sort(np.asarray(score)[benign])[::-1]
    out = [float(np.nextafter(b[0], np.inf))]
    for k in range(1, max_fp + 1):
        hi = b[k-1]
        lo = b[k] if k < len(b) else -np.inf
        out.append(float((hi + lo)/2.0 if np.isfinite(lo) else np.nextafter(hi, -np.inf)))
    return out


def evaluate_union(y, score_map, threshold_map):
    y = np.asarray(y)
    pred = np.zeros(len(y), dtype=bool)
    for name, threshold in threshold_map.items():
        pred |= np.asarray(score_map[name]) >= float(threshold)
    tn, fp, fn, tp = confusion_matrix(y, pred.astype(np.int8)).ravel()
    precision = tp / max(1, tp + fp)
    recall = tp / max(1, tp + fn)
    fpr = fp / (fp + tn)
    f1 = 2 * precision * recall / max(1e-15, precision + recall)
    return {"precision":float(precision), "recall":float(recall), "f1":float(f1), "fpr":float(fpr), "tn":int(tn), "fp":int(fp), "fn":int(fn), "tp":int(tp)}


def constrained_union_search(y, score_map, names):
    y = np.asarray(y)
    benign_n = int((y == 0).sum())
    max_fp = int(math.floor(MAX_FPR * benign_n))
    lists = {name: thresholds_for_budget(y, score_map[name]) for name in names}
    best = None
    best_payload = None

    def recurse(i, current):
        nonlocal best, best_payload
        if i == len(names):
            m = evaluate_union(y, score_map, current)
            if m["fp"] > max_fp:
                return
            key = (m["recall"], m["precision"], -m["fpr"])
            if best is None or key > best:
                best = key
                best_payload = {**m, "thresholds": dict(current)}
            return
        name = names[i]
        for th in lists[name]:
            current[name] = th
            recurse(i+1, current)
        current.pop(name, None)

    recurse(0, {})
    if best_payload is None:
        raise RuntimeError("No feasible union configuration")
    return best_payload


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
    work, audit_idx = train_test_split(idx, test_size=.15, stratify=y, random_state=SEED)
    dev_idx, val_idx = train_test_split(work, test_size=.1764706, stratify=y[work], random_state=SEED)
    print("Development / validation / comparative audit:", len(dev_idx), len(val_idx), len(audit_idx), flush=True)

    t0 = time.time()
    dev, val = frame(train, dev_idx), frame(train, val_idx)
    frame_seconds = time.time()-t0
    yd, yv = dev.y.to_numpy(), val.y.to_numpy()

    vectorizers, dmat, vmat = fit_sparse(dev, val)
    r = nb_log_count_ratio(dmat, yd)
    d_nb = dmat.multiply(r).tocsr(); v_nb = vmat.multiply(r).tocsr()
    base = LogisticRegression(C=1.0, max_iter=1800, solver="liblinear", random_state=SEED)
    base.fit(d_nb, yd)
    base_dev = base.predict_proba(d_nb)[:,1]
    base_val = base.predict_proba(v_nb)[:,1]
    base_th = threshold_at_fpr(yv, base_val)
    base_m = metrics(yv, base_val, base_th)
    base_m.update(name="nb_logreg_base", family="base")
    print("VAL base", json.dumps(base_m), flush=True)

    hp_cut = float(np.quantile(base_dev[yd == 1], .45))
    hn_cut = float(np.quantile(base_dev[yd == 0], .95))
    print("Hard cutoffs", hp_cut, hn_cut, flush=True)

    rows = [base_m]
    score_map = {"nb_logreg_base": base_val}
    models = {"nb_logreg_base": base}

    for c in [0.5, 1.0, 2.0]:
        for hp_mult in [2.0, 4.0, 6.0]:
            for hn_mult in [1.0, 2.0, 4.0]:
                w, hp_mask, hn_mask = hard_example_weights(base_dev, yd, hp_mult, hn_mult, hp_cut, hn_cut)
                name = f"hard_nb|C={c:g}|hp={hp_mult:g}|hn={hn_mult:g}"
                clf = LogisticRegression(C=c, max_iter=1800, solver="liblinear", random_state=SEED)
                clf.fit(d_nb, yd, sample_weight=w)
                score = clf.predict_proba(v_nb)[:,1]
                th = threshold_at_fpr(yv, score)
                m = metrics(yv, score, th)
                m.update(name=name, family="hard_nb")
                rows.append(m); score_map[name] = score; models[name] = clf
                print("VAL", name, "recall", round(m["recall"],6), "fpr", round(m["fpr"],6), flush=True)

    sparse_df = pd.DataFrame(rows).sort_values(["recall","roc_auc","precision"], ascending=False).reset_index(drop=True)
    best_hard_name = sparse_df[sparse_df.family == "hard_nb"].iloc[0]["name"]
    print("BEST HARD", best_hard_name, flush=True)

    context_w, hp_mask, hn_mask = hard_example_weights(base_dev, yd, HP_CONTEXT_MULT, HN_CONTEXT_MULT, hp_cut, hn_cut)
    model_revision = HfApi().model_info(MODEL_ID).sha
    print("Resolved contextual model revision:", model_revision, flush=True)
    tokenizer, context_model, context_train_meta = fine_tune_contextual(dev, context_w, model_revision)
    context_val = contextual_scores(tokenizer, context_model, val["context"].tolist())
    context_th = threshold_at_fpr(yv, context_val)
    context_m = metrics(yv, context_val, context_th)
    context_m.update(name="minilm_hard_rescue", family="contextual")
    rows.append(context_m); score_map["minilm_hard_rescue"] = context_val
    print("VAL contextual", json.dumps(context_m), flush=True)

    cascade_rows = []
    pair_sets = [
        ["nb_logreg_base", best_hard_name],
        ["nb_logreg_base", "minilm_hard_rescue"],
        [best_hard_name, "minilm_hard_rescue"],
    ]
    for names in pair_sets:
        m = constrained_union_search(yv, score_map, names)
        name = "or|" + "+".join(names)
        row = {**m, "name":name, "family":"or_pair", "members":"|".join(names)}
        cascade_rows.append(row)
        print("VAL", name, json.dumps(m), flush=True)

    tri_names = ["nb_logreg_base", best_hard_name, "minilm_hard_rescue"]
    tri_m = constrained_union_search(yv, score_map, tri_names)
    tri_name = "or3|" + "+".join(tri_names)
    cascade_rows.append({**tri_m, "name":tri_name, "family":"or_three", "members":"|".join(tri_names)})
    print("VAL", tri_name, json.dumps(tri_m), flush=True)

    all_df = pd.concat([pd.DataFrame(rows), pd.DataFrame(cascade_rows)], ignore_index=True, sort=False)
    all_df = all_df.sort_values(["recall","precision","fpr"], ascending=[False,False,True]).reset_index(drop=True)
    all_df.to_csv(RESULT_DIR / "assessment_v16_validation.csv", index=False)
    winner = all_df.iloc[0].to_dict()
    winner_name = winner["name"]
    print("VALIDATION WINNER", json.dumps(winner, indent=2, default=str), flush=True)

    t0 = time.time()
    audit = frame(train, audit_idx)
    ya = audit.y.to_numpy()
    amat = sparse_transform(audit, vectorizers).multiply(r).tocsr()
    audit_scores = {
        "nb_logreg_base": base.predict_proba(amat)[:,1],
        best_hard_name: models[best_hard_name].predict_proba(amat)[:,1],
        "minilm_hard_rescue": contextual_scores(tokenizer, context_model, audit["context"].tolist()),
    }
    audit_seconds = time.time()-t0

    if str(winner.get("family")) in {"or_pair", "or_three"}:
        members = str(winner["members"]).split("|")
        thresholds = winner["thresholds"]
        audit_m = evaluate_union(ya, audit_scores, {m: float(thresholds[m]) for m in members})
        audit_spec = {"type":str(winner["family"]), "members":members, "thresholds":{m:float(thresholds[m]) for m in members}}
    else:
        score = audit_scores["minilm_hard_rescue"] if winner_name == "minilm_hard_rescue" else audit_scores[winner_name]
        audit_m = metrics(ya, score, float(winner["threshold"]))
        audit_spec = {"type":"single", "name":winner_name, "threshold":float(winner["threshold"])}

    audit_m["recall_ci95"] = wilson(audit_m["tp"], audit_m["tp"] + audit_m["fn"])
    audit_m["fpr_ci95"] = wilson(audit_m["fp"], audit_m["fp"] + audit_m["tn"])
    print("COMPARATIVE AUDIT", json.dumps(audit_m, indent=2), flush=True)

    evidence = {
        "protocol_file":"agentshield/ASSESSMENT_V16_HARD_RESCUE_PROTOCOL.md",
        "research_only":True,
        "seed":SEED,
        "max_observed_validation_fpr":MAX_FPR,
        "benchmark_labels_accessed":False,
        "audit_is_pristine":False,
        "audit_role":"comparative only; previously observed in earlier experiments",
        "dataset":"perplexity-ai/browsesafe-bench",
        "dataset_fingerprints":{"train_raw":train_fp, "test_content_source":test_fp},
        "removed_internal_duplicates":dup_count,
        "removed_train_test_overlap":overlap_count,
        "splits":{"development":len(dev_idx), "validation":len(val_idx), "comparative_audit":len(audit_idx)},
        "hard_mining":{
            "hard_positive_quantile":0.45,
            "hard_negative_quantile":0.95,
            "hard_positive_cutoff":hp_cut,
            "hard_negative_cutoff":hn_cut,
            "hard_positive_count":int(hp_mask.sum()),
            "hard_negative_count":int(hn_mask.sum()),
            "sparse_grid":{"C":[0.5,1.0,2.0], "hp_mult":[2,4,6], "hn_mult":[1,2,4]},
        },
        "contextual":{
            "model_id":MODEL_ID, "revision":model_revision, "max_length":MAX_LENGTH,
            "epochs":EPOCHS, "learning_rate":LR, "weight_decay":WEIGHT_DECAY,
            "batch_size":BATCH_SIZE, "grad_accum":GRAD_ACCUM,
            "hard_positive_multiplier":HP_CONTEXT_MULT, "hard_negative_multiplier":HN_CONTEXT_MULT,
            **context_train_meta,
        },
        "best_hard_sparse":best_hard_name,
        "validation_winner":winner,
        "audit_spec":audit_spec,
        "comparative_audit":audit_m,
        "gates":{
            "B_70pct":bool(audit_m["recall"] >= .70 and audit_m["fpr"] <= .01),
            "C_85pct":bool(audit_m["recall"] >= .85 and audit_m["fpr"] <= .01),
            "D_90pct":bool(audit_m["recall"] >= .90 and audit_m["fpr"] <= .01),
            "stretch_99_9pct":bool(audit_m["recall"] >= .999 and audit_m["fpr"] <= .01),
        },
        "timing":{"frame_dev_val_s":frame_seconds, "audit_representation_scoring_s":audit_seconds},
        "runtime":{"python":sys.version, "platform":platform.platform(), "torch":torch.__version__},
    }
    with open(RESULT_DIR / "assessment_v16_evidence.json", "w") as f:
        json.dump(evidence, f, indent=2, default=str)

    assert len(dev_idx) == 7725 and len(val_idx) == 1656 and len(audit_idx) == 1656
    assert not evidence["benchmark_labels_accessed"]
    assert 0 <= audit_m["recall"] <= 1 and 0 <= audit_m["fpr"] <= 1
    print("AGENTSHIELD_ASSESSMENT_V16=COMPLETE", flush=True)
    print("GATES", json.dumps(evidence["gates"]), flush=True)


if __name__ == "__main__":
    main()
