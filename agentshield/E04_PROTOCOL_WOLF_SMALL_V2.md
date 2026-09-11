# AgentShield E04 — Wolf Defender Small v2

Status: **predeclared before execution**

## Hypothesis
A longer-context prompt-injection specialist, evaluated with transparent multi-window document coverage, can materially improve attack recall over E03 while keeping observed false-positive rate (FPR) at or below 1%.

## Model
- Repository: `patronus-studio/wolf-defender-prompt-injection-small`
- Family: Wolf Defender Small v2 / ModernBERT
- Runtime artifact: `onnx/int8_int4_embeddings/model.onnx`
- The exact Hugging Face repository revision and downloaded ONNX SHA-256 MUST be resolved once at run start, then recorded in evidence and used for all model/config/tokenizer downloads in that run.
- Runtime MUST verify binary semantics from the model config: `0=BENIGN`, `1=INJECTION`. Any mismatch invalidates the run.

## Why the small ONNX variant
This experiment is designed for a CPU GitHub Actions runner. The small deployment checkpoint makes a longer-context evaluation operationally feasible while remaining a separately identifiable model/runtime artifact. Quantization is therefore part of E04 and must be reported explicitly; E04 is not treated as numerically interchangeable with the full Transformers checkpoint.

## Data and split
- Dataset: `perplexity-ai/browsesafe-bench`.
- BrowseSafe benchmark/test **labels MUST NOT be accessed**.
- Benchmark/test **content hashes only** may be used to remove exact normalized train/benchmark overlap.
- Remove exact normalized duplicates from the training split.
- Reuse seed `42` and the same deterministic validation/internal-audit split procedure used by E03 for comparability.
- The internal audit is reused across model families and is therefore corroborating evidence, not a pristine final holdout.

## Input representation
Reuse the E03 `combined_view` parser unchanged so E04 changes model/context treatment rather than silently changing the input representation. Visible text, comments, hidden-element text and selected HTML attributes are retained; script/style bodies remain excluded as in E03.

## Windowing
- Total model input length: 2,048 tokens, including special tokens.
- Content payload per window: 2,046 tokens when CLS/SEP are present.
- Sliding-window overlap target: 64 content tokens.
- Maximum scored windows per document: **3**.
- If a document produces more than three sliding-window candidates, choose three deterministically and approximately evenly across the document, preserving first/middle/last coverage.
- Record token counts, number of candidate windows, number of scored windows, percentage of documents requiring sampling, and approximate sampled token coverage.

This is intentionally a compute-bounded long-document test. It does **not** claim to reproduce Patronus' full-document benchmark protocol when a document needs more than three windows.

## Aggregation and threshold selection
Validation only may choose among these transparent document aggregations:
1. `first`
2. `max`
3. `top2mean`
4. `mean`

The vendor model card references normalized Smooth-Max, but E04 MUST NOT invent an unpublished formula or temperature. Unless an authoritative exact formula is available in the runtime dependency, E04 does not implement or claim normalized Smooth-Max reproduction.

For each aggregation, choose the threshold on validation to maximize recall subject to observed FPR <=1%. Break ties by the stricter/higher threshold. Select the winning aggregation by validation recall, then ROC-AUC, then precision.

After the aggregation and threshold are frozen, score the internal audit **once**. No audit threshold retuning is permitted.

## Metrics and evidence
Preserve at minimum:
- precision, recall, F1, ROC-AUC, observed FPR;
- TP, FP, FN, TN;
- 95% Wilson intervals for audit recall and FPR;
- model repository revision;
- ONNX artifact SHA-256;
- config label map and injection index;
- dataset fingerprints;
- duplicate/overlap removal counts;
- validation winner and frozen threshold;
- window/token coverage metadata;
- inference duration;
- Python/package/runtime versions;
- promotion gates.

## Promotion gates
All gates additionally require observed audit FPR <=1% and clean integrity checks:
- Gate A: >=50% recall
- Gate B: >=70% recall
- Gate C: >=85% recall
- Gate D: >=90% recall
- Gate E: >=95% recall
- Gate F: >=99% recall
- Stretch: >=99.9% recall

These are milestones, not quotas. Failed or disappointing results must be preserved exactly.

## Integrity rules
- No benchmark-label access.
- No post-hoc audit tuning.
- No result inferred from workflow success alone.
- Any unexpectedly strong result triggers explicit leakage/contamination review before promotion.
- E04 results do not modify the frozen M508 academic submission.
- A breakthrough claim still requires a genuinely untouched external holdout and reproducibility.
