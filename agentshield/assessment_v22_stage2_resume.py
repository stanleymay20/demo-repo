"""AgentShield v22 infrastructure-resume stage 2.

Loads the stage-1 checkpoint and continues the frozen v22 computation from the
canonical/taxonomy specialist section through validation freeze and one comparative audit.
Scientific logic is inherited unchanged from assessment_v22_oof_taxonomy_rescue.py.
"""
from __future__ import annotations

import hashlib
import json
import platform
import sys
import time
from pathlib import Path

import joblib
import numpy as np
import pandas as pd

import assessment_v22_oof_taxonomy_rescue as v22


CHECKPOINT = v22.RESULT_DIR / "v22_stage1_checkpoint.joblib"
MANIFEST = v22.RESULT_DIR / "v22_stage1_checkpoint_manifest.json"
RESUME_MANIFEST = v22.RESULT_DIR / "v22_stage2_resume_manifest.json"


def fail(msg):
    raise RuntimeError("v22 resume integrity failure: " + msg)


def main():
    v22.RESULT_DIR.mkdir(parents=True, exist_ok=True)
    if not CHECKPOINT.is_file() or not MANIFEST.is_file():
        fail("checkpoint or checkpoint manifest missing")
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    digest = hashlib.sha256(CHECKPOINT.read_bytes()).hexdigest()
    if digest != manifest.get("sha256"):
        fail("checkpoint SHA-256 mismatch")

    state = joblib.load(CHECKPOINT)
    if state.get("schema") != 1:
        fail("unsupported checkpoint schema")
    if state.get("base_v22_commit") != "51603f42b0a73b0612c645b5627e12987214ce2f":
        fail("unexpected frozen v22 base commit")
    if int(state.get("seed")) != int(v22.SEED):
        fail("seed mismatch")

    t_reload = time.time()
    print("Reloading BrowseSafe for fail-closed resume verification...", flush=True)
    ds = v22.load_dataset("perplexity-ai/browsesafe-bench", token=False)
    train_raw, test = ds["train"], ds["test"]
    train_fp = getattr(train_raw, "_fingerprint", None)
    test_fp = getattr(test, "_fingerprint", None)
    train, dup_count, overlap_count = v22.clean_training_split(train_raw, test)
    if train_fp != state["train_fp"] or test_fp != state["test_fp"]:
        fail("dataset fingerprint mismatch")
    if int(dup_count) != int(state["dup_count"]) or int(overlap_count) != int(state["overlap_count"]):
        fail("cleanup-count mismatch")

    y = np.array([v22.LAB[x] for x in train["label"]], dtype=np.int8)
    idx = np.arange(len(train))
    work, audit_idx_check = v22.train_test_split(
        idx, test_size=0.15, stratify=y, random_state=v22.SEED
    )
    dev_idx_check, val_idx_check = v22.train_test_split(
        work, test_size=0.1764706, stratify=y[work], random_state=v22.SEED
    )
    for key, got in [
        ("dev_idx", dev_idx_check),
        ("val_idx", val_idx_check),
        ("audit_idx", audit_idx_check),
    ]:
        if not np.array_equal(np.asarray(state[key]), np.asarray(got)):
            fail(key + " mismatch")

    dev_idx = np.asarray(state["dev_idx"])
    val_idx = np.asarray(state["val_idx"])
    audit_idx = np.asarray(state["audit_idx"])
    dev, val = v22.frame(train, dev_idx), v22.frame(train, val_idx)
    yd, yv = dev.y.to_numpy(), val.y.to_numpy()
    if not np.array_equal(yd, np.asarray(state["yd"])) or not np.array_equal(yv, np.asarray(state["yv"])):
        fail("development/validation label mismatch")

    dev_canon = state["dev_canon"]
    val_canon = state["val_canon"]
    dev_tax = np.asarray(state["dev_tax"])
    val_tax = np.asarray(state["val_tax"])
    residual_pos = np.asarray(state["residual_pos"], dtype=bool)
    hard_benign = np.asarray(state["hard_benign"], dtype=bool)
    rows = list(state["rows"])
    score_map = dict(state["score_map"])
    hard_models = dict(state["hard_models"])
    adv_models = dict(state["adv_models"])
    hard_name = str(state["hard_name"])
    adv_name = str(state["adv_name"])
    vectorizers = state["vectorizers"]
    r = state["r"]
    adv_vec = state["adv_vec"]
    adv_r = state["adv_r"]
    data_reload_seconds = time.time() - t_reload

    # Frozen v22 canonical specialist grid — unchanged.
    canon_vec = v22.TfidfVectorizer(
        analyzer="char", ngram_range=(3, 6), min_df=2, max_features=140000,
        sublinear_tf=True, strip_accents="unicode", dtype=np.float32,
    )
    xdc = canon_vec.fit_transform(dev_canon).tocsr()
    xvc = canon_vec.transform(val_canon).tocsr()
    canon_models = {}
    for c in [0.05, 0.1, 0.25, 0.5]:
        for rp_mult in [2.0, 4.0, 8.0]:
            for hb_mult in [2.0, 4.0]:
                w = np.ones(len(dev), dtype=np.float64)
                w[residual_pos] *= rp_mult
                w[hard_benign] *= hb_mult
                name = f"canon_svc|C={c:g}|rp={rp_mult:g}|hb={hb_mult:g}"
                clf = v22.LinearSVC(C=c, random_state=v22.SEED, max_iter=5000)
                clf.fit(xdc, yd, sample_weight=w)
                s = clf.decision_function(xvc)
                rows.append(v22.candidate_row(
                    name, "canonical", yv, s,
                    c=c, residual_mult=rp_mult, hard_benign_mult=hb_mult,
                ))
                score_map[name] = s
                canon_models[name] = clf
    canon_name = str(v22.best_family(pd.DataFrame(rows), "canonical")["name"])

    # Frozen v22 taxonomy specialist grid — unchanged.
    scaler = v22.StandardScaler()
    xdt = scaler.fit_transform(dev_tax)
    xvt = scaler.transform(val_tax)
    tax_models = {}
    for c in [0.1, 1.0, 10.0]:
        for rp_mult in [2.0, 4.0, 8.0]:
            for hb_mult in [2.0, 4.0]:
                w = np.ones(len(dev), dtype=np.float64)
                w[residual_pos] *= rp_mult
                w[hard_benign] *= hb_mult
                name = f"tax_lr|C={c:g}|rp={rp_mult:g}|hb={hb_mult:g}"
                clf = v22.LogisticRegression(
                    C=c, max_iter=2000, solver="liblinear", random_state=v22.SEED
                )
                clf.fit(xdt, yd, sample_weight=w)
                s = clf.predict_proba(xvt)[:, 1]
                rows.append(v22.candidate_row(
                    name, "taxonomy", yv, s,
                    c=c, residual_mult=rp_mult, hard_benign_mult=hb_mult,
                ))
                score_map[name] = s
                tax_models[name] = clf
    tax_name = str(v22.best_family(pd.DataFrame(rows), "taxonomy")["name"])
    print("SPECIALIST WINNERS", canon_name, tax_name, flush=True)

    combos = [
        ("anchor_or", [hard_name, adv_name]),
        ("anchor_canon", [hard_name, adv_name, canon_name]),
        ("anchor_tax", [hard_name, adv_name, tax_name]),
        ("anchor_canon_tax", [hard_name, adv_name, canon_name, tax_name]),
    ]
    for family, names in combos:
        m = v22.constrained_union_search(yv, score_map, names, v22.TARGET_VAL_FPR)
        row = {
            **m,
            "name": family + "|" + "+".join(names),
            "family": family,
            "members": names,
            "threshold": np.nan,
            "roc_auc": np.nan,
        }
        rows.append(row)
        print("VAL UNION", family, json.dumps(v22.json_safe(m)), flush=True)

    all_df = pd.DataFrame(rows).sort_values(
        ["recall", "precision", "fpr"], ascending=[False, False, True]
    ).reset_index(drop=True)
    all_df.to_csv(v22.RESULT_DIR / "assessment_v22_validation.csv", index=False)
    winner = all_df.iloc[0].to_dict()
    winner_name = str(winner["name"])
    print("VALIDATION WINNER", json.dumps(v22.json_safe(winner), indent=2), flush=True)

    # Comparative audit is touched once, only after the validation winner is frozen.
    t0 = time.time()
    audit = v22.frame(train, audit_idx)
    ya = audit.y.to_numpy()
    _, audit_canon, audit_tax, _ = v22.build_raw_views(train, audit_idx)
    amat = v22.sparse_transform(audit, vectorizers).multiply(r).tocsr()
    adv_amat = v22.sparse_transform(audit, adv_vec).multiply(adv_r).tocsr()
    xac = canon_vec.transform(audit_canon).tocsr()
    xat = scaler.transform(audit_tax)

    def audit_score(name):
        if name.startswith("v22_hard"):
            return hard_models[name].predict_proba(amat)[:, 1]
        if name.startswith("v22_adv"):
            return adv_models[name].predict_proba(adv_amat)[:, 1]
        if name.startswith("canon_svc"):
            return canon_models[name].decision_function(xac)
        if name.startswith("tax_lr"):
            return tax_models[name].predict_proba(xat)[:, 1]
        raise KeyError(name)

    family = str(winner["family"])
    if family.startswith("anchor_"):
        thresholds = winner["thresholds"]
        members = list(thresholds.keys())
        amap = {m: audit_score(m) for m in members}
        audit_m = v22.evaluate_union(
            ya, amap, {m: float(thresholds[m]) for m in members}
        )
        audit_spec = {
            "type": family,
            "members": members,
            "thresholds": {m: float(thresholds[m]) for m in members},
        }
    else:
        audit_m = v22.metrics(ya, audit_score(winner_name), float(winner["threshold"]))
        audit_spec = {
            "type": "single",
            "family": family,
            "name": winner_name,
            "threshold": float(winner["threshold"]),
        }
    audit_seconds = time.time() - t0
    audit_m["recall_ci95"] = v22.wilson(audit_m["tp"], audit_m["tp"] + audit_m["fn"])
    audit_m["fpr_ci95"] = v22.wilson(audit_m["fp"], audit_m["fp"] + audit_m["tn"])

    promotion = {
        "reference_v18_recall_exact": v22.V18_RECALL,
        "reference_v18_fpr_exact": v22.V18_FPR,
        "strictly_beats_v18_recall": bool(audit_m["recall"] > v22.V18_RECALL + 1e-12),
        "within_operating_fpr": bool(audit_m["fpr"] <= v22.OPERATING_FPR),
    }
    promotion["promotable_over_v18"] = bool(
        promotion["strictly_beats_v18_recall"] and promotion["within_operating_fpr"]
    )

    evidence = v22.json_safe({
        "protocol_file": "agentshield/ASSESSMENT_V22_OOF_TAXONOMY_RESCUE_PROTOCOL.md",
        "research_only": True,
        "seed": v22.SEED,
        "target_validation_fpr": v22.TARGET_VAL_FPR,
        "operating_fpr_ceiling": v22.OPERATING_FPR,
        "reference_champion": {
            "version": "v18",
            "commit": "92b5e23d143397d8732673ee2e5715b5c81e82c1",
            "tp": 600, "fn": 221, "fp": 7, "tn": 828,
            "recall_exact": v22.V18_RECALL,
            "fpr_exact": v22.V18_FPR,
        },
        "benchmark_labels_accessed": False,
        "audit_is_pristine": False,
        "audit_role": "comparative only; previously observed in earlier experiments",
        "dataset": "perplexity-ai/browsesafe-bench",
        "dataset_fingerprints": {"train_raw": train_fp, "test_content_source": test_fp},
        "removed_internal_duplicates": int(dup_count),
        "removed_train_test_overlap": int(overlap_count),
        "splits": {
            "development": len(dev_idx),
            "validation": len(val_idx),
            "comparative_audit": len(audit_idx),
        },
        "development_oof_residual_discovery": {
            "folds": 5,
            "threshold": state["oof_threshold"],
            "metrics": state["oof_m"],
            "residual_positive_count": int(residual_pos.sum()),
            "hard_benign_cutoff": state["high_benign_cut"],
            "hard_benign_count": int(hard_benign.sum()),
            "taxonomy_all_development_positives": state["tax_all_pos"],
            "taxonomy_oof_residual_positives": state["tax_residual"],
        },
        "specialists": {
            "canonical": {
                "winner": canon_name,
                "view": "NFKC+HTML/URL/escape/base64 canonicalization + hidden/script evidence",
                "vectorizer": "char TF-IDF 3-6",
                "max_features": 140000,
            },
            "taxonomy": {
                "winner": tax_name,
                "categories": sorted(v22.category_flags("").keys()),
                "feature_count": int(dev_tax.shape[1]),
            },
        },
        "anchor_family_winners": {"hard": hard_name, "adversarial": adv_name},
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
        "timing": {
            "frame_and_view_build_s": state["frame_seconds"],
            "stage2_data_reload_verification_s": data_reload_seconds,
            "audit_representation_scoring_s": audit_seconds,
        },
        "runtime": {"python": sys.version, "platform": platform.platform()},
        "infrastructure_resume": {
            "used": True,
            "scientific_logic_changed": False,
            "base_v22_commit": state["base_v22_commit"],
            "checkpoint_sha256": digest,
            "repair_note": "agentshield/ASSESSMENT_V22_INFRA_REPAIR.md",
            "prior_interrupted_attempts": [1, 2],
        },
    })
    with open(v22.RESULT_DIR / "assessment_v22_evidence.json", "w", encoding="utf-8") as f:
        json.dump(evidence, f, indent=2, allow_nan=False)

    resume_manifest = {
        "checkpoint_sha256": digest,
        "dataset_fingerprints_verified": True,
        "cleanup_counts_verified": True,
        "split_indices_verified": True,
        "development_validation_labels_verified": True,
        "benchmark_labels_accessed": False,
        "scientific_logic_changed": False,
        "validation_winner": v22.json_safe(winner),
        "comparative_audit": v22.json_safe(audit_m),
        "promotion": promotion,
    }
    RESUME_MANIFEST.write_text(json.dumps(resume_manifest, indent=2), encoding="utf-8")
    print("V22 EVIDENCE", json.dumps(evidence, indent=2), flush=True)


if __name__ == "__main__":
    main()
