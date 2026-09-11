"""AgentShield high-recall research v1.

Scientific scope:
- Uses ONLY BrowseSafe training split for model development/validation/audit.
- Does NOT read the BrowseSafe benchmark/test labels or score the benchmark.
- Removes normalized duplicates from the training split and removes any training rows
  overlapping the benchmark by normalized content hash before splitting.
- Selects model + threshold on validation only.
- Evaluates the selected configuration exactly once on the internal audit split.

Primary metric: attack recall subject to observed FPR <= 1%.
No result is promoted unless the audit evidence supports it.
"""

import gc, hashlib, json, os, re, time, warnings
import numpy as np
import pandas as pd
from bs4 import BeautifulSoup, Comment
from datasets import load_dataset
from scipy.sparse import hstack
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import confusion_matrix, precision_score, recall_score, f1_score, roc_auc_score, roc_curve
from sklearn.model_selection import train_test_split
from sklearn.svm import LinearSVC

warnings.filterwarnings("ignore")
SEED = 42
np.random.seed(SEED)
LAB = {"no": 0, "yes": 1}
WS = re.compile(r"\s+")


def normalized_digest(s):
    s = "" if s is None else str(s)
    z = WS.sub(" ", s.lower()).strip()
    return hashlib.sha256(z.encode("utf-8", "ignore")).digest()


def clean_training_split(train, test):
    # Test CONTENT hashes are used only to remove overlap; test labels are never read.
    test_hashes = {normalized_digest(x) for x in test["content"]}
    seen, keep = set(), []
    internal_dups = overlap = 0
    for i, s in enumerate(train["content"]):
        h = normalized_digest(s)
        if h in seen:
            internal_dups += 1
            continue
        if h in test_hashes:
            overlap += 1
            continue
        seen.add(h)
        keep.append(i)
    return train.select(keep), internal_dups, overlap


def views(raw):
    raw = "" if raw is None else str(raw)
    soup = BeautifulSoup(raw, "lxml")
    comments = [str(x) for x in soup.find_all(string=lambda t: isinstance(t, Comment))]
    hidden, attrs = [], []
    interesting = {"aria-label", "title", "alt", "value", "style", "hidden", "placeholder", "onclick", "role"}
    for tag in soup.find_all(True):
        style = str(tag.get("style", "")).lower().replace(" ", "")
        if (tag.has_attr("hidden") or "display:none" in style or "visibility:hidden" in style
                or (tag.name == "input" and str(tag.get("type", "")).lower() == "hidden")):
            hidden.append(tag.get_text(" ", strip=True))
        for k, v in tag.attrs.items():
            if k.startswith("data-") or k in interesting:
                if isinstance(v, list):
                    v = " ".join(map(str, v))
                attrs.append(f"{k} {v}")
    for tag in soup(["script", "style"]):
        tag.decompose()
    text = " ".join(soup.stripped_strings)
    evidence = " ".join(comments + hidden + attrs)
    # Markers let the model distinguish parsed text from hidden/attribute evidence.
    combined = f"[TEXT] {text} [HIDDEN] {evidence}"
    return text, evidence, combined


def frame(dataset, ids):
    rows = []
    subset = dataset.select([int(i) for i in ids])
    for batch in subset.iter(batch_size=16):
        for raw, label in zip(batch["content"], batch["label"]):
            text, evidence, combined = views(raw)
            rows.append({"text": text, "evidence": evidence, "combined": combined, "y": LAB[label]})
    return pd.DataFrame(rows)


def metrics(y, score, threshold):
    pred = (score >= threshold).astype(np.int8)
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


def threshold_at_fpr(y, score, max_fpr=0.01):
    fpr, tpr, thresholds = roc_curve(y, score)
    ok = np.where(fpr <= max_fpr)[0]
    # Highest TPR; for ties, use the highest threshold (more conservative).
    best_tpr = tpr[ok].max()
    tied = ok[tpr[ok] == best_tpr]
    return float(np.max(thresholds[tied]))


def wilson(k, n, z=1.96):
    p = k / n
    d = 1 + z*z/n
    c = (p + z*z/(2*n)) / d
    h = z*np.sqrt(p*(1-p)/n + z*z/(4*n*n)) / d
    return [float(c-h), float(c+h)]


def fit_vectorizers(dev, val, audit):
    # Word semantics + character robustness. Keep representations sparse and CPU-feasible.
    word = TfidfVectorizer(
        ngram_range=(1, 2), min_df=2, max_df=.995, max_features=50000,
        sublinear_tf=True, strip_accents="unicode", dtype=np.float32,
    )
    char = TfidfVectorizer(
        analyzer="char_wb", ngram_range=(3, 5), min_df=2, max_features=70000,
        sublinear_tf=True, dtype=np.float32,
    )
    evidence = TfidfVectorizer(
        analyzer="char", ngram_range=(3, 5), min_df=2, max_features=25000,
        sublinear_tf=True, dtype=np.float32,
    )
    t0 = time.time()
    Dw = word.fit_transform(dev["combined"])
    Dc = char.fit_transform(dev["combined"])
    De = evidence.fit_transform(dev["evidence"])
    V = hstack([word.transform(val["combined"]), char.transform(val["combined"]), evidence.transform(val["evidence"])], format="csr")
    A = hstack([word.transform(audit["combined"]), char.transform(audit["combined"]), evidence.transform(audit["evidence"])], format="csr")
    D = hstack([Dw, Dc, De], format="csr")
    return D, V, A, {"word_features": Dw.shape[1], "char_features": Dc.shape[1], "evidence_features": De.shape[1], "fit_transform_s": time.time()-t0}


def main():
    os.makedirs("agentshield/results", exist_ok=True)
    print("Loading BrowseSafe...")
    ds = load_dataset("perplexity-ai/browsesafe-bench", token=False)
    train, test = ds["train"], ds["test"]
    # IMPORTANT: benchmark labels are deliberately never accessed in this script.
    train, dup_count, overlap_count = clean_training_split(train, test)
    print("Removed internal normalized duplicates:", dup_count)
    print("Removed train/benchmark normalized overlap:", overlap_count)

    y = np.array([LAB[x] for x in train["label"]], dtype=np.int8)
    idx = np.arange(len(train))
    work, audit_idx = train_test_split(idx, test_size=.15, stratify=y, random_state=SEED)
    dev_idx, val_idx = train_test_split(work, test_size=.1764706, stratify=y[work], random_state=SEED)
    print("Development / validation / audit:", len(dev_idx), len(val_idx), len(audit_idx))

    t0 = time.time()
    dev, val, audit = frame(train, dev_idx), frame(train, val_idx), frame(train, audit_idx)
    print("Representation extraction seconds:", round(time.time()-t0, 2))

    D, V, A, feature_meta = fit_vectorizers(dev, val, audit)
    yd, yv, ya = dev.y.to_numpy(), val.y.to_numpy(), audit.y.to_numpy()
    print("Feature metadata:", feature_meta)

    rows = []
    fitted = {}

    # Linear SVM is a strong sparse-text ranking model. We tune only on validation.
    for C in [0.05, 0.1, 0.25, 0.5, 1.0, 2.0, 4.0]:
        for pos_weight in [1.0, 1.5, 2.0, 3.0]:
            name = f"LinearSVC_C{C:g}_pw{pos_weight:g}"
            clf = LinearSVC(C=C, class_weight={0: 1.0, 1: pos_weight}, random_state=SEED)
            t = time.time(); clf.fit(D, yd); fit_s = time.time()-t
            score = clf.decision_function(V)
            th = threshold_at_fpr(yv, score)
            m = metrics(yv, score, th)
            m.update(model=name, fit_s=float(fit_s))
            rows.append(m); fitted[name] = clf
            print("VAL", name, json.dumps({k: round(v, 6) if isinstance(v,float) else v for k,v in m.items() if k not in {"model"}}))

    # Logistic models provide a probabilistic comparison on identical features.
    for C in [0.25, 0.5, 1.0, 2.0]:
        for pos_weight in [1.0, 2.0]:
            name = f"LogReg_C{C:g}_pw{pos_weight:g}"
            clf = LogisticRegression(C=C, class_weight={0:1.0,1:pos_weight}, max_iter=1500, solver="liblinear", random_state=SEED)
            t = time.time(); clf.fit(D, yd); fit_s = time.time()-t
            score = clf.predict_proba(V)[:,1]
            th = threshold_at_fpr(yv, score)
            m = metrics(yv, score, th)
            m.update(model=name, fit_s=float(fit_s))
            rows.append(m); fitted[name] = clf
            print("VAL", name, json.dumps({k: round(v, 6) if isinstance(v,float) else v for k,v in m.items() if k not in {"model"}}))

    results = pd.DataFrame(rows).sort_values(["recall", "roc_auc", "precision"], ascending=False).reset_index(drop=True)
    results.to_csv("agentshield/results/high_recall_linear_v1_validation.csv", index=False)
    winner = results.iloc[0].to_dict()
    winner_name = winner["model"]
    winner_model = fitted[winner_name]
    print("VALIDATION WINNER", json.dumps(winner, indent=2))

    # One-shot internal audit with frozen model and validation-selected threshold.
    if winner_name.startswith("LinearSVC"):
        audit_score = winner_model.decision_function(A)
    else:
        audit_score = winner_model.predict_proba(A)[:,1]
    audit_m = metrics(ya, audit_score, float(winner["threshold"]))
    audit_m["recall_ci95"] = wilson(audit_m["tp"], audit_m["tp"] + audit_m["fn"])
    audit_m["fpr_ci95"] = wilson(audit_m["fp"], audit_m["fp"] + audit_m["tn"])
    print("AUDIT RESULT", json.dumps(audit_m, indent=2))

    evidence = {
        "protocol": "BrowseSafe train-only development/validation/audit; benchmark labels never accessed",
        "seed": SEED,
        "removed_internal_duplicates": dup_count,
        "removed_train_benchmark_overlap": overlap_count,
        "splits": {"development": len(dev), "validation": len(val), "audit": len(audit)},
        "feature_meta": feature_meta,
        "validation_winner": winner,
        "audit": audit_m,
        "promotion_gate_A_50pct_recall_at_1pct_fpr": bool(audit_m["recall"] >= .50 and audit_m["fpr"] <= .01),
    }
    with open("agentshield/results/high_recall_linear_v1_evidence.json", "w") as f:
        json.dump(evidence, f, indent=2)

    # Integrity assertions only; do not assert desired performance.
    assert len(dev) > 7000 and len(val) > 1500 and len(audit) > 1500
    assert 0 <= audit_m["recall"] <= 1 and 0 <= audit_m["fpr"] <= 1
    print("AGENTSHIELD_HIGH_RECALL_LINEAR_V1=COMPLETE")
    print("Gate A passed:", evidence["promotion_gate_A_50pct_recall_at_1pct_fpr"])


if __name__ == "__main__":
    main()
