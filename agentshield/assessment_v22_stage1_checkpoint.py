"""AgentShield v22 infrastructure-resume stage 1.

Scientific logic is inherited unchanged from assessment_v22_oof_taxonomy_rescue.py.
This stage stops immediately after the existing ANCHOR FAMILY WINNERS boundary and
serializes the state required for stage 2.
"""
from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path

import joblib
import numpy as np
import pandas as pd

import assessment_v22_oof_taxonomy_rescue as v22


CHECKPOINT = v22.RESULT_DIR / "v22_stage1_checkpoint.joblib"
MANIFEST = v22.RESULT_DIR / "v22_stage1_checkpoint_manifest.json"


def main():
    v22.RESULT_DIR.mkdir(parents=True, exist_ok=True)
    print("Loading BrowseSafe...", flush=True)
    ds = v22.load_dataset("perplexity-ai/browsesafe-bench", token=False)
    train_raw, test = ds["train"], ds["test"]
    train_fp = getattr(train_raw, "_fingerprint", None)
    test_fp = getattr(test, "_fingerprint", None)
    train, dup_count, overlap_count = v22.clean_training_split(train_raw, test)

    y = np.array([v22.LAB[x] for x in train["label"]], dtype=np.int8)
    idx = np.arange(len(train))
    work, audit_idx = v22.train_test_split(
        idx, test_size=0.15, stratify=y, random_state=v22.SEED
    )
    dev_idx, val_idx = v22.train_test_split(
        work, test_size=0.1764706, stratify=y[work], random_state=v22.SEED
    )
    print(
        "Development / validation / comparative audit:",
        len(dev_idx), len(val_idx), len(audit_idx), flush=True,
    )

    t0 = time.time()
    dev, val = v22.frame(train, dev_idx), v22.frame(train, val_idx)
    _, dev_canon, dev_tax, dev_flags = v22.build_raw_views(train, dev_idx)
    _, val_canon, val_tax, _ = v22.build_raw_views(train, val_idx)
    frame_seconds = time.time() - t0
    yd, yv = dev.y.to_numpy(), val.y.to_numpy()

    vectorizers, dmat, vmat = v22.fit_sparse(dev, val)
    oof = v22.oof_nb_scores(dmat, yd, folds=5)
    oof_threshold = v22.threshold_at_fpr(yd, oof, max_fpr=v22.TARGET_VAL_FPR)
    oof_m = v22.metrics(yd, oof, oof_threshold)
    residual_pos = (yd == 1) & (oof < oof_threshold)
    high_benign_cut = float(np.quantile(oof[yd == 0], 0.95))
    hard_benign = (yd == 0) & (oof >= high_benign_cut)
    print(
        "OOF residual discovery",
        json.dumps(v22.json_safe({
            "threshold": oof_threshold,
            "metrics": oof_m,
            "residual_positive_count": int(residual_pos.sum()),
            "high_benign_cutoff": high_benign_cut,
            "hard_benign_count": int(hard_benign.sum()),
        })),
        flush=True,
    )
    tax_all_pos = v22.count_taxonomy(dev_flags, yd == 1)
    tax_residual = v22.count_taxonomy(dev_flags, residual_pos)
    print("DEV TAXONOMY ALL POS", json.dumps(tax_all_pos), flush=True)
    print("DEV TAXONOMY RESIDUAL", json.dumps(tax_residual), flush=True)

    hp_cut = float(np.quantile(oof[yd == 1], 0.45))
    hn_cut = float(np.quantile(oof[yd == 0], 0.95))
    _, hp_mask, hn_mask = v22.hard_weights(oof, yd, 1, 1, hp_cut, hn_cut)
    r = v22.nb_log_count_ratio(dmat, yd)
    d_nb, v_nb = dmat.multiply(r).tocsr(), vmat.multiply(r).tocsr()

    rows, score_map, hard_models = [], {}, {}
    for c in [0.5, 1.0, 2.0]:
        for hp_mult in [1.0, 2.0, 4.0]:
            for hn_mult in [4.0, 6.0, 8.0]:
                w, _, _ = v22.hard_weights(
                    oof, yd, hp_mult, hn_mult, hp_cut, hn_cut
                )
                name = f"v22_hard|C={c:g}|hp={hp_mult:g}|hn={hn_mult:g}"
                clf = v22.LogisticRegression(
                    C=c, max_iter=1800, solver="liblinear", random_state=v22.SEED
                )
                clf.fit(d_nb, yd, sample_weight=w)
                s = clf.predict_proba(v_nb)[:, 1]
                rows.append(v22.candidate_row(name, "hard", yv, s))
                score_map[name] = s
                hard_models[name] = clf
    hard_name = str(v22.best_family(pd.DataFrame(rows), "hard")["name"])

    adv_dev = v22.build_adversarial_dev(dev, hp_mask)
    adv_y = adv_dev.y.to_numpy(dtype=np.int8)
    adv_vec, adv_dmat, adv_vmat = v22.fit_sparse(adv_dev, val)
    adv_r = v22.nb_log_count_ratio(adv_dmat, adv_y)
    adv_dnb, adv_vnb = (
        adv_dmat.multiply(adv_r).tocsr(),
        adv_vmat.multiply(adv_r).tocsr(),
    )
    adv_weights = np.ones(len(adv_dev), dtype=np.float64)
    original_n = len(dev)
    # Intentionally preserved exactly from the frozen v22 implementation.
    adv_weights[:original_n][hp_mask] *= 2.0
    adv_weights[:original_n][hn_mask] *= 4.0
    adv_weights[original_n:] *= 1.5
    adv_models = {}
    for c in [0.5, 1.0, 2.0, 4.0]:
        name = f"v22_adv|C={c:g}"
        clf = v22.LogisticRegression(
            C=c, max_iter=1800, solver="liblinear", random_state=v22.SEED
        )
        clf.fit(adv_dnb, adv_y, sample_weight=adv_weights)
        s = clf.predict_proba(adv_vnb)[:, 1]
        rows.append(v22.candidate_row(name, "adv", yv, s))
        score_map[name] = s
        adv_models[name] = clf
    adv_name = str(v22.best_family(pd.DataFrame(rows), "adv")["name"])
    print("ANCHOR FAMILY WINNERS", hard_name, adv_name, flush=True)

    state = {
        "schema": 1,
        "base_v22_commit": "51603f42b0a73b0612c645b5627e12987214ce2f",
        "seed": int(v22.SEED),
        "train_fp": train_fp,
        "test_fp": test_fp,
        "dup_count": int(dup_count),
        "overlap_count": int(overlap_count),
        "dev_idx": np.asarray(dev_idx),
        "val_idx": np.asarray(val_idx),
        "audit_idx": np.asarray(audit_idx),
        "yd": np.asarray(yd),
        "yv": np.asarray(yv),
        "dev_canon": dev_canon,
        "val_canon": val_canon,
        "dev_tax": np.asarray(dev_tax),
        "val_tax": np.asarray(val_tax),
        "frame_seconds": float(frame_seconds),
        "oof_threshold": float(oof_threshold),
        "oof_m": oof_m,
        "residual_pos": np.asarray(residual_pos),
        "high_benign_cut": float(high_benign_cut),
        "hard_benign": np.asarray(hard_benign),
        "tax_all_pos": tax_all_pos,
        "tax_residual": tax_residual,
        "vectorizers": vectorizers,
        "r": r,
        "rows": rows,
        "score_map": score_map,
        "hard_models": hard_models,
        "hard_name": hard_name,
        "adv_vec": adv_vec,
        "adv_r": adv_r,
        "adv_models": adv_models,
        "adv_name": adv_name,
    }
    joblib.dump(state, CHECKPOINT, compress=3)
    digest = hashlib.sha256(CHECKPOINT.read_bytes()).hexdigest()
    manifest = {
        "checkpoint": str(CHECKPOINT),
        "sha256": digest,
        "base_v22_commit": state["base_v22_commit"],
        "scientific_logic_changed": False,
        "stage_boundary": "after ANCHOR FAMILY WINNERS",
        "split_sizes": {
            "development": len(dev_idx),
            "validation": len(val_idx),
            "comparative_audit": len(audit_idx),
        },
        "anchor_family_winners": {"hard": hard_name, "adversarial": adv_name},
    }
    MANIFEST.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    print("STAGE1 CHECKPOINT", json.dumps(manifest, indent=2), flush=True)


if __name__ == "__main__":
    main()
