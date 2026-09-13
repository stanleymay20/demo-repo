"""Frozen AgentShield v18 external validation.

This script MUST NOT tune v18 on external labels. Stage 1 reconstructs v18,
verifies the exact internal champion confusion matrix, performs contamination
screening, generates external predictions, and seals them. Stage 2 reloads the
sealed predictions, verifies row identities, then reads labels and scores.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import re
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd
import requests
from datasets import DatasetDict, concatenate_datasets, load_dataset
from huggingface_hub import HfApi
from sklearn.feature_extraction.text import HashingVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import confusion_matrix, roc_auc_score
from sklearn.model_selection import train_test_split
from sklearn.neighbors import NearestNeighbors

from assessment_v16_hard_rescue import (
    LAB,
    SEED,
    clean_training_split,
    fit_sparse,
    frame,
    make_views,
    metrics,
    nb_log_count_ratio,
    sparse_transform,
    threshold_at_fpr,
    wilson,
)
from assessment_v17_oof_adversarial import build_adversarial_dev, hard_weights, oof_nb_scores
from assessment_v18_fpr_stable import (
    TARGET_VAL_FPR,
    candidate_row,
    constrained_union_search,
    evaluate_union,
    logit,
    sigmoid,
)

PROTOCOL = Path("agentshield/V18_EXTERNAL_VALIDATION_PROTOCOL.md")
V18_COMMIT = "92b5e23d143397d8732673ee2e5715b5c81e82c1"
EXPECTED_AUDIT = {"tp": 600, "fn": 221, "fp": 7, "tn": 828}
OPERATING_FPR = 0.01
NEAR_DUP_THRESHOLD = 0.92
INJECAGENT_COMMIT = "f19c9f2c79a41046eb13c03c51a24c567a8ffa07"
HF_DATASETS = ["v1adam/Comparison_Dataset", "deepset/prompt-injections"]
TEXT_CANDIDATES = ["text", "prompt", "content", "instruction", "input", "query"]
LABEL_CANDIDATES = ["label", "class", "category", "type", "is_malicious", "malicious", "target"]
WS = re.compile(r"\s+")


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def norm_text(x: Any) -> str:
    return WS.sub(" ", "" if x is None else str(x).lower()).strip()


def text_digest(x: Any) -> str:
    return hashlib.sha256(norm_text(x).encode("utf-8", "ignore")).hexdigest()


def rows_digest(rows: pd.DataFrame) -> str:
    h = hashlib.sha256()
    for row in rows.sort_values(["dataset", "split", "row_index", "variant"]).itertuples(index=False):
        for value in (row.dataset, row.split, row.row_index, row.variant, row.text_sha256, int(row.prediction)):
            b = str(value).encode("utf-8")
            h.update(len(b).to_bytes(8, "little")); h.update(b)
    return h.hexdigest()


def external_frame(raws: list[str]) -> pd.DataFrame:
    rows = []
    for raw in raws:
        text, evidence, script, combined = make_views(raw)
        rows.append({"text": text, "evidence": evidence, "script": script, "combined": combined})
    return pd.DataFrame(rows)


def reconstruct_v18():
    print("Reconstructing frozen v18", flush=True)
    ds = load_dataset("perplexity-ai/browsesafe-bench", token=False)
    train_raw, test = ds["train"], ds["test"]
    train, dup_count, overlap_count = clean_training_split(train_raw, test)
    y = np.array([LAB[x] for x in train["label"]], dtype=np.int8)
    idx = np.arange(len(train))
    work, audit_idx = train_test_split(idx, test_size=0.15, stratify=y, random_state=SEED)
    dev_idx, val_idx = train_test_split(work, test_size=0.1764706, stratify=y[work], random_state=SEED)
    if (len(dev_idx), len(val_idx), len(audit_idx)) != (7725, 1656, 1656):
        raise RuntimeError("v18 split sizes changed")
    dev, val = frame(train, dev_idx), frame(train, val_idx)
    yd, yv = dev.y.to_numpy(), val.y.to_numpy()
    vectorizers, dmat, vmat = fit_sparse(dev, val)
    oof = oof_nb_scores(dmat, yd, folds=5)
    hp_cut = float(np.quantile(oof[yd == 1], 0.45))
    hn_cut = float(np.quantile(oof[yd == 0], 0.95))
    _, hp_mask, hn_mask = hard_weights(oof, yd, 1, 1, hp_cut, hn_cut)
    r = nb_log_count_ratio(dmat, yd)
    d_nb, v_nb = dmat.multiply(r).tocsr(), vmat.multiply(r).tocsr()

    rows, score_map, models = [], {}, {}
    for c in [0.5, 1.0, 2.0]:
        for hp_mult in [1.0, 2.0, 4.0]:
            for hn_mult in [4.0, 6.0, 8.0]:
                w, _, _ = hard_weights(oof, yd, hp_mult, hn_mult, hp_cut, hn_cut)
                name = f"stable_hard_nb|C={c:g}|hp={hp_mult:g}|hn={hn_mult:g}"
                clf = LogisticRegression(C=c, max_iter=1800, solver="liblinear", random_state=SEED)
                clf.fit(d_nb, yd, sample_weight=w)
                s = clf.predict_proba(v_nb)[:, 1]
                rows.append(candidate_row(name, "stable_hard_nb", yv, s))
                score_map[name] = s; models[name] = clf

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
        name = f"stable_adv_nb|C={c:g}"
        clf = LogisticRegression(C=c, max_iter=1800, solver="liblinear", random_state=SEED)
        clf.fit(adv_dnb, adv_y, sample_weight=adv_weights)
        s = clf.predict_proba(adv_vnb)[:, 1]
        rows.append(candidate_row(name, "stable_adv_nb", yv, s))
        score_map[name] = s; adv_models[name] = clf

    cdf = pd.DataFrame(rows)
    hard_name = str(cdf[cdf.family == "stable_hard_nb"].sort_values(
        ["recall", "precision", "fpr"], ascending=[False, False, True]).iloc[0]["name"])
    adv_name = str(cdf[cdf.family == "stable_adv_nb"].sort_values(
        ["recall", "precision", "fpr"], ascending=[False, False, True]).iloc[0]["name"])

    union = constrained_union_search(yv, score_map, [hard_name, adv_name], TARGET_VAL_FPR)
    rows.append({**union, "name": f"stable_or|{hard_name}+{adv_name}", "family": "stable_or",
                 "members": [hard_name, adv_name], "threshold": np.nan, "roc_auc": np.nan})
    for alpha in np.linspace(0.1, 0.9, 9):
        fused = sigmoid(alpha * logit(score_map[hard_name]) + (1.0 - alpha) * logit(score_map[adv_name]))
        name = f"logit_fusion|alpha={alpha:.1f}|hard={hard_name}|adv={adv_name}"
        rows.append(candidate_row(name, "logit_fusion", yv, fused, alpha=float(alpha),
                                  hard_member=hard_name, adv_member=adv_name))
        score_map[name] = fused

    all_df = pd.DataFrame(rows).sort_values(
        ["recall", "precision", "fpr"], ascending=[False, False, True]).reset_index(drop=True)
    winner = all_df.iloc[0].to_dict()

    audit = frame(train, audit_idx); ya = audit.y.to_numpy()
    amat = sparse_transform(audit, vectorizers).multiply(r).tocsr()
    adv_amat = sparse_transform(audit, adv_vec).multiply(adv_r).tocsr()

    def score_member(name: str, x_main, x_adv):
        if name.startswith("stable_hard_nb"): return models[name].predict_proba(x_main)[:, 1]
        if name.startswith("stable_adv_nb"): return adv_models[name].predict_proba(x_adv)[:, 1]
        raise KeyError(name)

    family = str(winner["family"])
    if family == "stable_or":
        thresholds = winner["thresholds"]
        members = list(thresholds.keys())
        amap = {m: score_member(m, amat, adv_amat) for m in members}
        audit_m = evaluate_union(ya, amap, {m: float(thresholds[m]) for m in members})
        audit_spec = {"type": "or_pair", "members": members, "thresholds": {m: float(thresholds[m]) for m in members}}
    elif family == "logit_fusion":
        alpha = float(winner["alpha"]); hname = str(winner["hard_member"]); aname = str(winner["adv_member"])
        fused = sigmoid(alpha * logit(score_member(hname, amat, adv_amat)) + (1.0 - alpha) * logit(score_member(aname, amat, adv_amat)))
        audit_m = metrics(ya, fused, float(winner["threshold"]))
        audit_spec = {"type": "logit_fusion", "alpha": alpha, "hard_member": hname, "adv_member": aname,
                      "threshold": float(winner["threshold"])}
    else:
        name = str(winner["name"])
        audit_m = metrics(ya, score_member(name, amat, adv_amat), float(winner["threshold"]))
        audit_spec = {"type": "single", "name": name, "threshold": float(winner["threshold"])}

    got = {k: int(audit_m[k]) for k in EXPECTED_AUDIT}
    if got != EXPECTED_AUDIT:
        raise RuntimeError(f"Frozen v18 reconstruction mismatch: {got} != {EXPECTED_AUDIT}")
    print("Verified exact v18 audit", got, flush=True)
    return {
        "train_raw": train_raw, "test_raw": test, "train": train,
        "dataset_fingerprints": {"train_raw": getattr(train_raw, "_fingerprint", None), "test": getattr(test, "_fingerprint", None)},
        "cleanup": {"duplicates": int(dup_count), "train_test_overlap": int(overlap_count)},
        "winner": winner, "audit": audit_m, "audit_spec": audit_spec,
        "vectorizers": vectorizers, "r": r, "adv_vec": adv_vec, "adv_r": adv_r,
        "models": models, "adv_models": adv_models,
    }


def predict_v18(raws: list[str], state: dict) -> tuple[np.ndarray, np.ndarray]:
    df = external_frame(raws)
    x_main = sparse_transform(df, state["vectorizers"]).multiply(state["r"]).tocsr()
    x_adv = sparse_transform(df, state["adv_vec"]).multiply(state["adv_r"]).tocsr()
    winner = state["winner"]; family = str(winner["family"])

    def member(name: str):
        if name.startswith("stable_hard_nb"): return state["models"][name].predict_proba(x_main)[:, 1]
        if name.startswith("stable_adv_nb"): return state["adv_models"][name].predict_proba(x_adv)[:, 1]
        raise KeyError(name)

    if family == "stable_or":
        thresholds = winner["thresholds"]
        margins = [member(n) - float(t) for n, t in thresholds.items()]
        margin = np.max(np.vstack(margins), axis=0)
        pred = margin >= 0.0
    elif family == "logit_fusion":
        alpha = float(winner["alpha"]); h = member(str(winner["hard_member"])); a = member(str(winner["adv_member"]))
        score = sigmoid(alpha * logit(h) + (1.0 - alpha) * logit(a))
        margin = score - float(winner["threshold"]); pred = margin >= 0.0
    else:
        score = member(str(winner["name"])); margin = score - float(winner["threshold"]); pred = margin >= 0.0
    return pred.astype(np.int8), margin.astype(np.float64)


def pick_text_column(columns: list[str]) -> str:
    matches = [c for c in TEXT_CANDIDATES if c in columns]
    if not matches:
        raise RuntimeError(f"No recognized text column in {columns}")
    return matches[0]


def resolve_hf_revision(dataset_id: str) -> str:
    return HfApi().dataset_info(dataset_id).sha


def load_hf_rows_text_only(dataset_id: str, revision: str) -> tuple[list[dict], dict]:
    obj = load_dataset(dataset_id, revision=revision)
    if not isinstance(obj, DatasetDict):
        raise RuntimeError(f"Expected DatasetDict for {dataset_id}")
    rows, schema = [], {}
    for split in sorted(obj.keys()):
        d = obj[split]; cols = list(d.column_names); text_col = pick_text_column(cols)
        schema[split] = {"columns": cols, "text_column": text_col, "rows": len(d)}
        texts = d[text_col]
        for i, text in enumerate(texts):
            raw = "" if text is None else str(text)
            rows.append({"dataset": dataset_id, "split": split, "row_index": int(i), "variant": "native",
                         "text": raw, "text_sha256": text_digest(raw), "pair_id": "", "attack_type": ""})
    return rows, schema


def load_injecagent_rows() -> list[dict]:
    rows = []
    for fname in ["test_cases_dh_base.json", "test_cases_ds_base.json"]:
        url = f"https://raw.githubusercontent.com/uiuc-kang-lab/InjecAgent/{INJECAGENT_COMMIT}/data/{fname}"
        r = requests.get(url, timeout=60); r.raise_for_status(); payload = r.json()
        for i, item in enumerate(payload):
            attack = "" if item.get("Tool Response") is None else str(item.get("Tool Response"))
            template = "" if item.get("Tool Response Template") is None else str(item.get("Tool Response Template"))
            clean = template.replace("<Attacker Instruction>", "")
            pair_id = f"{fname}:{i}"
            attack_type = str(item.get("Attack Type", ""))
            for variant, text in [("attack", attack), ("clean_control", clean)]:
                rows.append({"dataset": "uiuc-kang-lab/InjecAgent", "split": fname, "row_index": int(i),
                             "variant": variant, "text": text, "text_sha256": text_digest(text),
                             "pair_id": pair_id, "attack_type": attack_type})
    return rows


def contamination_screen(external: pd.DataFrame, state: dict) -> pd.DataFrame:
    reference = ["" if x is None else str(x) for x in state["train_raw"]["content"]]
    reference += ["" if x is None else str(x) for x in state["test_raw"]["content"]]
    ref_norm = [norm_text(x) for x in reference]
    ref_hashes = {hashlib.sha256(x.encode("utf-8", "ignore")).hexdigest() for x in ref_norm}
    ext_norm = [norm_text(x) for x in external["text"].tolist()]
    external["exact_overlap"] = [hashlib.sha256(x.encode("utf-8", "ignore")).hexdigest() in ref_hashes for x in ext_norm]

    hv = HashingVectorizer(analyzer="char", ngram_range=(4, 6), n_features=2**18,
                           alternate_sign=False, norm="l2", lowercase=False)
    ref_x = hv.transform(ref_norm); ext_x = hv.transform(ext_norm)
    nn = NearestNeighbors(n_neighbors=1, metric="cosine", algorithm="brute", n_jobs=-1)
    nn.fit(ref_x); distance, _ = nn.kneighbors(ext_x, return_distance=True)
    sim = 1.0 - distance[:, 0]
    external["max_browsesafe_similarity"] = sim
    external["near_overlap"] = sim >= NEAR_DUP_THRESHOLD
    external["contaminated"] = external["exact_overlap"] | external["near_overlap"]
    return external


def stage1(out_dir: Path):
    out_dir.mkdir(parents=True, exist_ok=True)
    state = reconstruct_v18()
    hf_revisions = {d: resolve_hf_revision(d) for d in HF_DATASETS}
    rows, schemas = [], {}
    for d in HF_DATASETS:
        got, schema = load_hf_rows_text_only(d, hf_revisions[d]); rows.extend(got); schemas[d] = schema
    rows.extend(load_injecagent_rows())
    ext = pd.DataFrame(rows)
    ext = contamination_screen(ext, state)
    pred, margin = predict_v18(ext["text"].tolist(), state)
    ext["prediction"] = pred; ext["decision_margin"] = margin
    # Do not persist raw text in the sealed prediction artifact; row identity is text SHA-256.
    sealed = ext.drop(columns=["text"])
    pred_path = out_dir / "sealed_predictions.csv"; sealed.to_csv(pred_path, index=False)
    manifest = {
        "protocol_sha256": sha256_file(PROTOCOL),
        "v18_commit": V18_COMMIT,
        "verified_internal_audit": {k: int(state["audit"][k]) for k in ["tp", "fn", "fp", "tn"]},
        "v18_validation_winner": state["winner"],
        "v18_audit_spec": state["audit_spec"],
        "browsesafe_fingerprints": state["dataset_fingerprints"],
        "browsesafe_cleanup": state["cleanup"],
        "hf_revisions": hf_revisions,
        "injecagent_commit": INJECAGENT_COMMIT,
        "schemas_without_label_access": schemas,
        "near_duplicate_threshold": NEAR_DUP_THRESHOLD,
        "prediction_file_sha256": sha256_file(pred_path),
        "prediction_rows_digest": rows_digest(sealed),
        "counts": {
            "total": int(len(sealed)),
            "exact_overlap": int(sealed.exact_overlap.sum()),
            "near_overlap": int(sealed.near_overlap.sum()),
            "contaminated": int(sealed.contaminated.sum()),
        },
        "external_labels_used_for_model_or_threshold": False,
    }
    (out_dir / "stage1_manifest.json").write_text(json.dumps(manifest, indent=2, default=str), encoding="utf-8")
    print(json.dumps(manifest, indent=2, default=str), flush=True)


def pick_label_column(columns: list[str]) -> str:
    matches = [c for c in LABEL_CANDIDATES if c in columns]
    if not matches:
        raise RuntimeError(f"No recognized label column in {columns}")
    return matches[0]


def map_labels(values: list[Any]) -> np.ndarray:
    out = []
    for v in values:
        if isinstance(v, (bool, np.bool_)):
            out.append(int(v)); continue
        if isinstance(v, (int, np.integer)) and int(v) in (0, 1):
            out.append(int(v)); continue
        if isinstance(v, (float, np.floating)) and float(v) in (0.0, 1.0):
            out.append(int(v)); continue
        s = str(v).strip().lower().replace("-", "_").replace(" ", "_")
        if s in {"0", "benign", "safe", "normal", "legit", "legitimate", "negative", "clean"}:
            out.append(0); continue
        if s in {"1", "injection", "prompt_injection", "jailbreak", "malicious", "attack", "unsafe", "positive", "sensitive_data_exposure"}:
            out.append(1); continue
        if any(tok in s for tok in ["injection", "jailbreak", "malicious", "attack", "unsafe", "sensitive"]):
            out.append(1); continue
        raise RuntimeError(f"Unrecognized external label value: {v!r}")
    return np.asarray(out, dtype=np.int8)


def fixed_metrics(y: np.ndarray, pred: np.ndarray, margin: np.ndarray) -> dict:
    y = np.asarray(y, dtype=np.int8); pred = np.asarray(pred, dtype=np.int8)
    tn, fp, fn, tp = confusion_matrix(y, pred, labels=[0, 1]).ravel()
    precision = tp / max(1, tp + fp); recall = tp / max(1, tp + fn); fpr = fp / max(1, fp + tn)
    f1 = 2 * precision * recall / max(1e-12, precision + recall)
    auc = float(roc_auc_score(y, margin)) if len(np.unique(y)) == 2 else None
    return {"tp": int(tp), "fn": int(fn), "fp": int(fp), "tn": int(tn),
            "precision": float(precision), "recall": float(recall), "fpr": float(fpr), "f1": float(f1),
            "roc_auc_union_margin": auc,
            "recall_ci95": wilson(int(tp), int(tp + fn)) if tp + fn else None,
            "fpr_ci95": wilson(int(fp), int(fp + tn)) if fp + tn else None}


def reload_hf_labels(dataset_id: str, revision: str, pred_rows: pd.DataFrame) -> np.ndarray:
    obj = load_dataset(dataset_id, revision=revision)
    labels = []
    for row in pred_rows.itertuples(index=False):
        d = obj[row.split]; text_col = pick_text_column(list(d.column_names)); label_col = pick_label_column(list(d.column_names))
        text = "" if d[int(row.row_index)][text_col] is None else str(d[int(row.row_index)][text_col])
        if text_digest(text) != row.text_sha256:
            raise RuntimeError(f"External row hash mismatch {dataset_id} {row.split} {row.row_index}")
        labels.append(d[int(row.row_index)][label_col])
    return map_labels(labels)


def paired_injecagent_metrics(df: pd.DataFrame) -> dict:
    attacks = df[df.variant == "attack"].set_index("pair_id")
    cleans = df[df.variant == "clean_control"].set_index("pair_id")
    common = attacks.index.intersection(cleans.index)
    a = attacks.loc[common, "prediction"].astype(int); c = cleans.loc[common, "prediction"].astype(int)
    pairs = {
        "detected_attack_clean_accepted": int(((a == 1) & (c == 0)).sum()),
        "detected_both": int(((a == 1) & (c == 1)).sum()),
        "missed_attack_clean_accepted": int(((a == 0) & (c == 0)).sum()),
        "missed_attack_clean_flagged": int(((a == 0) & (c == 1)).sum()),
    }
    return {"pairs": int(len(common)), "attack_detection_rate": float(a.mean()) if len(a) else None,
            "matched_clean_fpr": float(c.mean()) if len(c) else None, "paired_outcomes": pairs}


def stage2(stage1_dir: Path, out_dir: Path):
    out_dir.mkdir(parents=True, exist_ok=True)
    manifest = json.loads((stage1_dir / "stage1_manifest.json").read_text(encoding="utf-8"))
    if manifest["protocol_sha256"] != sha256_file(PROTOCOL): raise RuntimeError("Protocol SHA mismatch")
    pred_path = stage1_dir / "sealed_predictions.csv"
    if sha256_file(pred_path) != manifest["prediction_file_sha256"]: raise RuntimeError("Prediction SHA mismatch")
    pred = pd.read_csv(pred_path, keep_default_na=False)
    if rows_digest(pred) != manifest["prediction_rows_digest"]: raise RuntimeError("Prediction rows digest mismatch")

    evidence = {"protocol_sha256": manifest["protocol_sha256"], "stage1_prediction_sha256": manifest["prediction_file_sha256"],
                "v18_commit": V18_COMMIT, "verified_internal_audit": manifest["verified_internal_audit"],
                "datasets": {}, "injecagent": {}, "interpretation": None}
    native_independent_supported = False; transfer_supported = False
    for dataset_id in HF_DATASETS:
        sub = pred[(pred.dataset == dataset_id) & (pred.variant == "native")].copy()
        y = reload_hf_labels(dataset_id, manifest["hf_revisions"][dataset_id], sub)
        sub["y"] = y
        all_m = fixed_metrics(y, sub.prediction.to_numpy(int), sub.decision_margin.to_numpy(float))
        clean = sub[~sub.contaminated.astype(bool)]
        clean_y = clean.y.to_numpy(int)
        clean_m = fixed_metrics(clean_y, clean.prediction.to_numpy(int), clean.decision_margin.to_numpy(float)) if len(clean) else None
        evidence["datasets"][dataset_id] = {
            "revision": manifest["hf_revisions"][dataset_id], "rows": int(len(sub)),
            "contaminated_rows": int(sub.contaminated.astype(bool).sum()), "all_rows_metrics": all_m,
            "clean_screened_rows": int(len(clean)), "clean_screened_metrics": clean_m,
        }
        if dataset_id == "v1adam/Comparison_Dataset" and clean_m is not None and clean_m["fpr"] <= OPERATING_FPR and clean_m["recall"] >= 0.50:
            native_independent_supported = True
        if clean_m is not None and clean_m["fpr"] <= OPERATING_FPR and clean_m["recall"] >= 0.50:
            transfer_supported = True

    inj = pred[pred.dataset == "uiuc-kang-lab/InjecAgent"].copy()
    inj_clean = inj[~inj.contaminated.astype(bool)].copy()
    evidence["injecagent"] = {
        "commit": INJECAGENT_COMMIT,
        "all_rows": paired_injecagent_metrics(inj),
        "clean_screened_rows": paired_injecagent_metrics(inj_clean),
        "contaminated_rows": int(inj.contaminated.astype(bool).sum()),
    }

    if native_independent_supported:
        interpretation = "GENERALIZATION_SUPPORTED"
    elif transfer_supported or (evidence["injecagent"]["clean_screened_rows"]["attack_detection_rate"] or 0) >= 0.50:
        interpretation = "TRANSFER_SUPPORTED_ONLY"
    else:
        interpretation = "GENERALIZATION_NOT_SUPPORTED"
    evidence["interpretation"] = interpretation
    out = out_dir / "v18_external_validation_evidence.json"
    out.write_text(json.dumps(evidence, indent=2, default=str), encoding="utf-8")
    print(json.dumps(evidence, indent=2, default=str), flush=True)


def main():
    ap = argparse.ArgumentParser(); sp = ap.add_subparsers(dest="cmd", required=True)
    a = sp.add_parser("predict"); a.add_argument("--out", type=Path, required=True)
    b = sp.add_parser("score"); b.add_argument("--stage1", type=Path, required=True); b.add_argument("--out", type=Path, required=True)
    args = ap.parse_args()
    if args.cmd == "predict": stage1(args.out)
    else: stage2(args.stage1, args.out)


if __name__ == "__main__":
    main()
