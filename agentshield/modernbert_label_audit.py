"""Read-only configuration audit for the external ModernBERT specialist.

This script does not load BrowseSafe and does not evaluate any examples. Its sole
purpose is to verify the classifier's label semantics before any score is interpreted.
"""
from transformers import AutoConfig, AutoTokenizer

MODEL_ID = "dannyliv/agent-guard-modernbert-base"

cfg = AutoConfig.from_pretrained(MODEL_ID)
tok = AutoTokenizer.from_pretrained(MODEL_ID)
print("MODEL_ID", MODEL_ID)
print("architecture", getattr(cfg, "architectures", None))
print("num_labels", cfg.num_labels)
print("id2label", cfg.id2label)
print("label2id", cfg.label2id)
print("problem_type", getattr(cfg, "problem_type", None))
print("tokenizer_class", tok.__class__.__name__)
print("model_max_length", tok.model_max_length)

labels = {int(k): str(v).lower() for k, v in cfg.id2label.items()}
positive_terms = ("injection", "attack", "malicious", "unsafe", "positive", "yes")
candidates = [i for i, name in labels.items() if any(t in name for t in positive_terms)]
print("injection_label_candidates", candidates)
if len(candidates) != 1:
    raise RuntimeError("Injection label is not uniquely identifiable from config; do not score the model until semantics are verified from an authoritative source.")
print("VERIFIED_INJECTION_LABEL_ID", candidates[0])
print("AGENTSHIELD_MODERNBERT_LABEL_AUDIT=PASS")
