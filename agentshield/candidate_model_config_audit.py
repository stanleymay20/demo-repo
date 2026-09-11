"""Audit candidate prompt-injection classifiers before any evaluation.

No BrowseSafe data is loaded. The purpose is to verify that label semantics and
sequence-length assumptions are explicit enough to support scientifically valid scoring.
"""
from transformers import AutoConfig, AutoTokenizer

MODELS = [
    "siberiancat/modernbert-prompt-injection",
    "patronus-studio/wolf-defender-prompt-injection",
    "protectai/deberta-v3-base-prompt-injection-v2",
]
TERMS=("injection","attack","malicious","unsafe","benign","safe","legit","normal","jailbreak")

for mid in MODELS:
    print("\n===",mid,"===")
    try:
        cfg=AutoConfig.from_pretrained(mid)
        tok=AutoTokenizer.from_pretrained(mid)
        print("architectures",getattr(cfg,"architectures",None))
        print("num_labels",cfg.num_labels)
        print("problem_type",getattr(cfg,"problem_type",None))
        print("id2label",cfg.id2label)
        print("label2id",cfg.label2id)
        print("tokenizer",tok.__class__.__name__)
        print("model_max_length",tok.model_max_length)
        semantic=[(int(k),str(v)) for k,v in cfg.id2label.items() if any(t in str(v).lower() for t in TERMS)]
        print("semantic_label_candidates",semantic)
        valid=(cfg.num_labels in (1,2)) and len(semantic)>=1
        print("CONFIG_SEMANTICS_USABLE",valid)
    except Exception as e:
        print("AUDIT_ERROR",type(e).__name__,str(e))

print("AGENTSHIELD_CANDIDATE_CONFIG_AUDIT=COMPLETE")
