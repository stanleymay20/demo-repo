"""AgentShield assessment v22 OOF taxonomy-rescue experiment.

Research-only successor to verified v18 champion.
BrowseSafe benchmark/test labels are never accessed.
Comparative audit is non-pristine and evaluated only after validation freeze.
"""
from __future__ import annotations

import base64
import html
import json
import math
import platform
import re
import sys
import time
import unicodedata
import urllib.parse
from collections import Counter
from itertools import product
from pathlib import Path

import numpy as np
import pandas as pd
from datasets import load_dataset
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.svm import LinearSVC

from assessment_v16_hard_rescue import (
    LAB, SEED, clean_training_split, fit_sparse, frame, make_views, metrics,
    nb_log_count_ratio, sparse_transform, threshold_at_fpr, wilson,
)
from assessment_v17_oof_adversarial import build_adversarial_dev, hard_weights, oof_nb_scores

np.random.seed(SEED)
RESULT_DIR = Path("agentshield/results")
TARGET_VAL_FPR = 0.006
OPERATING_FPR = 0.01
V18_RECALL = 600.0 / 821.0
V18_FPR = 7.0 / 835.0
EPS = 1e-12

ZERO_WIDTH_RE = re.compile(r"[\u200b-\u200f\u202a-\u202e\u2060\ufeff]")
HEX_ESC_RE = re.compile(r"\\x([0-9a-fA-F]{2})")
UNI_ESC_RE = re.compile(r"\\u([0-9a-fA-F]{4})")
B64_RE = re.compile(r"(?<![A-Za-z0-9+/=])([A-Za-z0-9+/]{24,256}={0,2})(?![A-Za-z0-9+/=])")
PERCENT_RE = re.compile(r"%[0-9a-fA-F]{2}")
SPACED_RE = re.compile(r"(?:\b[A-Za-z]\s+){4,}[A-Za-z]\b")
ROLE_RE = re.compile(r"\b(system|developer|assistant|user)\s*(?:message|prompt|role|instruction)?\b", re.I)
CONTROL_RE = re.compile(r"\b(prompt|instruction|directive|policy|guardrail|system message)\b", re.I)
EXFIL_RE = re.compile(r"\b(secret|credential|password|api[\s_-]?key|token|environment variable|private data|system prompt|hidden prompt|confidential)\b", re.I)
TOOL_RE = re.compile(r"\b(tool|function|browser|shell|terminal|api|click|download|upload|send|execute|run command|open url|http request)\b", re.I)
OVERRIDE_RE = re.compile(r"\b(ignore|disregard|forget|override|bypass|circumvent|jailbreak|previous instructions|prior instructions|above instructions)\b", re.I)
IMPERATIVE_RE = re.compile(r"\b(ignore|follow|reveal|return|output|send|execute|run|open|click|download|upload|copy|paste|read|write|delete|extract|print|show|tell|provide|respond)\b", re.I)
SECOND_PERSON_RE = re.compile(r"\b(you must|you should|your task|do not|don't|never|always|must now|please)\b", re.I)
HIDDEN_RE = re.compile(r"<!--|display\s*:\s*none|visibility\s*:\s*hidden|\bhidden\b|aria-label|data-[\w-]+|<script\b|type\s*=\s*[\"']?hidden", re.I)
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
    y = np.asarray(y)
    max_fp = int(math.floor(float(max_fpr) * int((y == 0).sum())))
    lists = [thresholds_for_budget(y, score_map[n], max_fpr) for n in names]
    best = None; best_key = None
    for vals in product(*lists):
        th = {n: float(t) for n, t in zip(names, vals)}
        m = evaluate_union(y, score_map, th)
        if m["fp"] > max_fp: continue
        key = (m["recall"], m["precision"], -m["fpr"])
        if best_key is None or key > best_key:
            best_key = key; best = {**m, "thresholds": th}
    if best is None: raise RuntimeError("No feasible constrained union")
    return best


def candidate_row(name, family, y, score, **extra):
    th = threshold_at_fpr(y, score, max_fpr=TARGET_VAL_FPR)
    return {**metrics(y, score, th), "name": name, "family": family, **extra}


def best_family(df, family):
    sub = df[df.family == family]
    if len(sub) == 0: raise RuntimeError(f"No rows for family {family}")
    return sub.sort_values(["recall", "precision", "fpr"], ascending=[False, False, True]).iloc[0]


def decode_ascii_b64(token):
    if len(token) < 24 or len(token) > 256: return None
    try:
        padded = token + "=" * ((4 - len(token) % 4) % 4)
        raw = base64.b64decode(padded, validate=False)
        if not raw or len(raw) > 256: return None
        text = raw.decode("utf-8", "ignore")
        printable = sum(ch.isprintable() or ch.isspace() for ch in text) / max(1, len(text))
        return text if printable >= 0.85 else None
    except Exception:
        return None


def canonicalize(raw):
    raw = "" if raw is None else str(raw)
    text, evidence, script_text, _ = make_views(raw)
    s = unicodedata.normalize("NFKC", html.unescape(raw))
    for _ in range(2):
        nxt = urllib.parse.unquote(s)
        if nxt == s: break
        s = nxt
    s = ZERO_WIDTH_RE.sub("", s)
    s = HEX_ESC_RE.sub(lambda m: chr(int(m.group(1), 16)), s)
    s = UNI_ESC_RE.sub(lambda m: chr(int(m.group(1), 16)), s)
    decoded = []
    for tok in B64_RE.findall(s)[:8]:
        d = decode_ascii_b64(tok)
        if d: decoded.append(d)
    s = re.sub(r"[|_~`^*=<>\\{}\[\]]+", " ", s)
    s = WS.sub(" ", s).strip()
    return f"{s} [VISIBLE] {text} [HIDDEN] {evidence} [SCRIPT] {script_text} [DECODED] {' '.join(decoded)}"


def category_flags(raw):
    raw = "" if raw is None else str(raw)
    text, evidence, script_text, _ = make_views(raw)
    suspicious_hits = (
        len(ROLE_RE.findall(raw)) + len(CONTROL_RE.findall(raw)) + len(EXFIL_RE.findall(raw)) +
        len(TOOL_RE.findall(raw)) + len(OVERRIDE_RE.findall(raw)) + len(IMPERATIVE_RE.findall(raw))
    )
    return {
        "role_control": bool(ROLE_RE.search(raw) and CONTROL_RE.search(raw)),
        "exfiltration": bool(EXFIL_RE.search(raw)),
        "tool_action": bool(TOOL_RE.search(raw)),
        "jailbreak_override": bool(OVERRIDE_RE.search(raw)),
        "encoding_obfuscation": bool(
            PERCENT_RE.search(raw) or HEX_ESC_RE.search(raw) or UNI_ESC_RE.search(raw) or
            ZERO_WIDTH_RE.search(raw) or B64_RE.search(raw) or SPACED_RE.search(raw)
        ),
        "hidden_markup": bool(HIDDEN_RE.search(raw) or len(evidence) > 40 or len(script_text) > 80),
        "instructional": bool(IMPERATIVE_RE.search(raw) or SECOND_PERSON_RE.search(raw)),
        "long_diluted": bool(len(raw) >= 8000 and suspicious_hits <= 6),
    }


def taxonomy_features(raw):
    raw = "" if raw is None else str(raw)
    text, evidence, script_text, _ = make_views(raw)
    flags = category_flags(raw)
    length = max(1, len(raw))
    words = max(1, len(WS.split(text.strip()))) if text.strip() else 1
    counts = [
        len(ROLE_RE.findall(raw)), len(CONTROL_RE.findall(raw)), len(EXFIL_RE.findall(raw)),
        len(TOOL_RE.findall(raw)), len(OVERRIDE_RE.findall(raw)), len(IMPERATIVE_RE.findall(raw)),
        len(SECOND_PERSON_RE.findall(raw)), len(PERCENT_RE.findall(raw)), len(HEX_ESC_RE.findall(raw)),
        len(UNI_ESC_RE.findall(raw)), len(B64_RE.findall(raw)), len(SPACED_RE.findall(raw)),
        len(HIDDEN_RE.findall(raw)),
    ]
    return [
        *[float(x) for x in counts], *[float(flags[k]) for k in sorted(flags)],
        math.log1p(length), math.log1p(words), math.log1p(len(evidence)), math.log1p(len(script_text)),
        float(len(evidence) / length), float(len(script_text) / length), float(sum(counts) / words),
    ]


def build_raw_views(dataset, ids):
    subset = dataset.select([int(i) for i in ids])
    raws = ["" if x is None else str(x) for x in subset["content"]]
    canonical = [canonicalize(x) for x in raws]
    tax = np.asarray([taxonomy_features(x) for x in raws], dtype=np.float64)
    flags = [category_flags(x) for x in raws]
    return raws, canonical, tax, flags


def count_taxonomy(flags, mask):
    mask = np.asarray(mask, dtype=bool)
    c = Counter()
    for use, row in zip(mask, flags):
        if use:
            for k, v in row.items():
                if v: c[k] += 1
    return dict(sorted(c.items()))


def main():
    RESULT_DIR.mkdir(parents=True, exist_ok=True)
    print("Loading BrowseSafe...", flush=True)
    ds = load_dataset("perplexity-ai/browsesafe-bench", token=False)
    train_raw, test = ds["train"], ds["test"]
    train_fp = getattr(train_raw, "_fingerprint", None); test_fp = getattr(test, "_fingerprint", None)
    train, dup_count, overlap_count = clean_training_split(train_raw, test)

    y = np.array([LAB[x] for x in train["label"]], dtype=np.int8)
    idx = np.arange(len(train))
    work, audit_idx = train_test_split(idx, test_size=0.15, stratify=y, random_state=SEED)
    dev_idx, val_idx = train_test_split(work, test_size=0.1764706, stratify=y[work], random_state=SEED)
    print("Development / validation / comparative audit:", len(dev_idx), len(val_idx), len(audit_idx), flush=True)

    t0 = time.time()
    dev, val = frame(train, dev_idx), frame(train, val_idx)
    _, dev_canon, dev_tax, dev_flags = build_raw_views(train, dev_idx)
    _, val_canon, val_tax, _ = build_raw_views(train, val_idx)
    frame_seconds = time.time() - t0
    yd, yv = dev.y.to_numpy(), val.y.to_numpy()

    vectorizers, dmat, vmat = fit_sparse(dev, val)
    oof = oof_nb_scores(dmat, yd, folds=5)
    oof_threshold = threshold_at_fpr(yd, oof, max_fpr=TARGET_VAL_FPR)
    oof_m = metrics(yd, oof, oof_threshold)
    residual_pos = (yd == 1) & (oof < oof_threshold)
    high_benign_cut = float(np.quantile(oof[yd == 0], 0.95))
    hard_benign = (yd == 0) & (oof >= high_benign_cut)
    print("OOF residual discovery", json.dumps(json_safe({
        "threshold": oof_threshold, "metrics": oof_m,
        "residual_positive_count": int(residual_pos.sum()),
        "high_benign_cutoff": high_benign_cut, "hard_benign_count": int(hard_benign.sum()),
    })), flush=True)
    tax_all_pos = count_taxonomy(dev_flags, yd == 1)
    tax_residual = count_taxonomy(dev_flags, residual_pos)
    print("DEV TAXONOMY ALL POS", json.dumps(tax_all_pos), flush=True)
    print("DEV TAXONOMY RESIDUAL", json.dumps(tax_residual), flush=True)

    hp_cut = float(np.quantile(oof[yd == 1], 0.45)); hn_cut = float(np.quantile(oof[yd == 0], 0.95))
    _, hp_mask, hn_mask = hard_weights(oof, yd, 1, 1, hp_cut, hn_cut)
    r = nb_log_count_ratio(dmat, yd); d_nb, v_nb = dmat.multiply(r).tocsr(), vmat.multiply(r).tocsr()
    rows, score_map, hard_models = [], {}, {}
    for c in [0.5, 1.0, 2.0]:
        for hp_mult in [1.0, 2.0, 4.0]:
            for hn_mult in [4.0, 6.0, 8.0]:
                w, _, _ = hard_weights(oof, yd, hp_mult, hn_mult, hp_cut, hn_cut)
                name = f"v22_hard|C={c:g}|hp={hp_mult:g}|hn={hn_mult:g}"
                clf = LogisticRegression(C=c, max_iter=1800, solver="liblinear", random_state=SEED)
                clf.fit(d_nb, yd, sample_weight=w); s = clf.predict_proba(v_nb)[:, 1]
                rows.append(candidate_row(name, "hard", yv, s)); score_map[name] = s; hard_models[name] = clf
    hard_name = str(best_family(pd.DataFrame(rows), "hard")["name"])

    adv_dev = build_adversarial_dev(dev, hp_mask); adv_y = adv_dev.y.to_numpy(dtype=np.int8)
    adv_vec, adv_dmat, adv_vmat = fit_sparse(adv_dev, val); adv_r = nb_log_count_ratio(adv_dmat, adv_y)
    adv_dnb, adv_vnb = adv_dmat.multiply(adv_r).tocsr(), adv_vmat.multiply(adv_r).tocsr()
    adv_weights = np.ones(len(adv_dev), dtype=np.float64); original_n = len(dev)
    adv_weights[:original_n][hp_mask] *= 2.0; adv_weights[:original_n][hn_mask] *= 4.0; adv_weights[original_n:] *= 1.5
    adv_models = {}
    for c in [0.5, 1.0, 2.0, 4.0]:
        name = f"v22_adv|C={c:g}"
        clf = LogisticRegression(C=c, max_iter=1800, solver="liblinear", random_state=SEED)
        clf.fit(adv_dnb, adv_y, sample_weight=adv_weights); s = clf.predict_proba(adv_vnb)[:, 1]
        rows.append(candidate_row(name, "adv", yv, s)); score_map[name] = s; adv_models[name] = clf
    adv_name = str(best_family(pd.DataFrame(rows), "adv")["name"])
    print("ANCHOR FAMILY WINNERS", hard_name, adv_name, flush=True)

    canon_vec = TfidfVectorizer(analyzer="char", ngram_range=(3, 6), min_df=2, max_features=140000,
                                sublinear_tf=True, strip_accents="unicode", dtype=np.float32)
    xdc = canon_vec.fit_transform(dev_canon).tocsr(); xvc = canon_vec.transform(val_canon).tocsr()
    canon_models = {}
    for c in [0.05, 0.1, 0.25, 0.5]:
        for rp_mult in [2.0, 4.0, 8.0]:
            for hb_mult in [2.0, 4.0]:
                w = np.ones(len(dev), dtype=np.float64); w[residual_pos] *= rp_mult; w[hard_benign] *= hb_mult
                name = f"canon_svc|C={c:g}|rp={rp_mult:g}|hb={hb_mult:g}"
                clf = LinearSVC(C=c, random_state=SEED, max_iter=5000); clf.fit(xdc, yd, sample_weight=w)
                s = clf.decision_function(xvc)
                rows.append(candidate_row(name, "canonical", yv, s, c=c, residual_mult=rp_mult, hard_benign_mult=hb_mult))
                score_map[name] = s; canon_models[name] = clf
    canon_name = str(best_family(pd.DataFrame(rows), "canonical")["name"])

    scaler = StandardScaler(); xdt = scaler.fit_transform(dev_tax); xvt = scaler.transform(val_tax)
    tax_models = {}
    for c in [0.1, 1.0, 10.0]:
        for rp_mult in [2.0, 4.0, 8.0]:
            for hb_mult in [2.0, 4.0]:
                w = np.ones(len(dev), dtype=np.float64); w[residual_pos] *= rp_mult; w[hard_benign] *= hb_mult
                name = f"tax_lr|C={c:g}|rp={rp_mult:g}|hb={hb_mult:g}"
                clf = LogisticRegression(C=c, max_iter=2000, solver="liblinear", random_state=SEED)
                clf.fit(xdt, yd, sample_weight=w); s = clf.predict_proba(xvt)[:, 1]
                rows.append(candidate_row(name, "taxonomy", yv, s, c=c, residual_mult=rp_mult, hard_benign_mult=hb_mult))
                score_map[name] = s; tax_models[name] = clf
    tax_name = str(best_family(pd.DataFrame(rows), "taxonomy")["name"])
    print("SPECIALIST WINNERS", canon_name, tax_name, flush=True)

    combos = [("anchor_or", [hard_name, adv_name]), ("anchor_canon", [hard_name, adv_name, canon_name]),
              ("anchor_tax", [hard_name, adv_name, tax_name]),
              ("anchor_canon_tax", [hard_name, adv_name, canon_name, tax_name])]
    for family, names in combos:
        m = constrained_union_search(yv, score_map, names, TARGET_VAL_FPR)
        row = {**m, "name": family + "|" + "+".join(names), "family": family,
               "members": names, "threshold": np.nan, "roc_auc": np.nan}
        rows.append(row); print("VAL UNION", family, json.dumps(json_safe(m)), flush=True)

    all_df = pd.DataFrame(rows).sort_values(["recall", "precision", "fpr"], ascending=[False, False, True]).reset_index(drop=True)
    all_df.to_csv(RESULT_DIR / "assessment_v22_validation.csv", index=False)
    winner = all_df.iloc[0].to_dict(); winner_name = str(winner["name"])
    print("VALIDATION WINNER", json.dumps(json_safe(winner), indent=2), flush=True)

    t0 = time.time(); audit = frame(train, audit_idx); ya = audit.y.to_numpy()
    _, audit_canon, audit_tax, _ = build_raw_views(train, audit_idx)
    amat = sparse_transform(audit, vectorizers).multiply(r).tocsr(); adv_amat = sparse_transform(audit, adv_vec).multiply(adv_r).tocsr()
    xac = canon_vec.transform(audit_canon).tocsr(); xat = scaler.transform(audit_tax)

    def audit_score(name):
        if name.startswith("v22_hard"): return hard_models[name].predict_proba(amat)[:, 1]
        if name.startswith("v22_adv"): return adv_models[name].predict_proba(adv_amat)[:, 1]
        if name.startswith("canon_svc"): return canon_models[name].decision_function(xac)
        if name.startswith("tax_lr"): return tax_models[name].predict_proba(xat)[:, 1]
        raise KeyError(name)

    family = str(winner["family"])
    if family.startswith("anchor_"):
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
        "protocol_file": "agentshield/ASSESSMENT_V22_OOF_TAXONOMY_RESCUE_PROTOCOL.md", "research_only": True, "seed": SEED,
        "target_validation_fpr": TARGET_VAL_FPR, "operating_fpr_ceiling": OPERATING_FPR,
        "reference_champion": {"version": "v18", "commit": "92b5e23d143397d8732673ee2e5715b5c81e82c1",
                               "tp": 600, "fn": 221, "fp": 7, "tn": 828, "recall_exact": V18_RECALL, "fpr_exact": V18_FPR},
        "benchmark_labels_accessed": False, "audit_is_pristine": False,
        "audit_role": "comparative only; previously observed in earlier experiments",
        "dataset": "perplexity-ai/browsesafe-bench", "dataset_fingerprints": {"train_raw": train_fp, "test_content_source": test_fp},
        "removed_internal_duplicates": int(dup_count), "removed_train_test_overlap": int(overlap_count),
        "splits": {"development": len(dev_idx), "validation": len(val_idx), "comparative_audit": len(audit_idx)},
        "development_oof_residual_discovery": {"folds": 5, "threshold": oof_threshold, "metrics": oof_m,
            "residual_positive_count": int(residual_pos.sum()), "hard_benign_cutoff": high_benign_cut,
            "hard_benign_count": int(hard_benign.sum()), "taxonomy_all_development_positives": tax_all_pos,
            "taxonomy_oof_residual_positives": tax_residual},
        "specialists": {"canonical": {"winner": canon_name, "view": "NFKC+HTML/URL/escape/base64 canonicalization + hidden/script evidence",
                                       "vectorizer": "char TF-IDF 3-6", "max_features": 140000},
                        "taxonomy": {"winner": tax_name, "categories": sorted(category_flags("").keys()),
                                     "feature_count": int(dev_tax.shape[1])}},
        "anchor_family_winners": {"hard": hard_name, "adversarial": adv_name}, "validation_winner": winner,
        "audit_spec": audit_spec, "comparative_audit": audit_m, "promotion": promotion,
        "gates": {"B_70pct": bool(audit_m["recall"] >= .70 and audit_m["fpr"] <= .01),
                  "C_85pct": bool(audit_m["recall"] >= .85 and audit_m["fpr"] <= .01),
                  "D_90pct": bool(audit_m["recall"] >= .90 and audit_m["fpr"] <= .01),
                  "E_95pct": bool(audit_m["recall"] >= .95 and audit_m["fpr"] <= .01)},
        "timing": {"frame_and_view_build_s": frame_seconds, "audit_representation_scoring_s": audit_seconds},
        "runtime": {"python": sys.version, "platform": platform.platform()},
    })
    with open(RESULT_DIR / "assessment_v22_evidence.json", "w") as f: json.dump(evidence, f, indent=2, allow_nan=False)
    print("V22 EVIDENCE", json.dumps(evidence, indent=2), flush=True)


if __name__ == "__main__": main()
