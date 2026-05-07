# Implementation Plan: Cost-Stratified Multi-Pipeline Threat Classification

> **Audience**: This plan is written to be handed to a fresh Claude Code session. It assumes no prior context. Read this entire document before writing code.

---

## 1. Context You Need

### 1.1 The Project

You are working on `cowrie-log-analysis` at `/opt/cowrie-log-analysis` on the server `jake1@honeypot-data`. It is a cybersecurity research project comparing automated threat classification approaches on SSH honeypot session data collected from six globally distributed Cowrie sensors (~11.7M sessions total, dual-labeled subset of ~8,514 sessions).

Two pipelines already exist and have produced labels:

- **Pipeline A (rule-based)**: Deterministic regex + static thresholds + MITRE ATT&CK pattern matching. Produces `label_rule` field on each session.
- **Pipeline B (LLM-agent)**: Two-stage agentic system (Hunter filters noise → Analyst classifies), gated by a Welford-algorithm anomaly detector. Currently runs **Gemini 2.5 Flash** via Vertex AI. Produces `label_agent` field.

A third-party annotation pass has been completed using Claude Sonnet 4 over a stratified sample of 345 sessions (`annotation_results_reference.jsonl`). Human annotation is in progress separately — treat human labels as arriving later.

### 1.2 Key Files and Paths

| Path | Purpose |
|---|---|
| `src/labeled_sessions.jsonl` | Master dataset; each line is one session with both pipeline labels |
| `src/anomaly_stats.json` | Welford running stats for the anomaly detector |
| `annotation_sample_blind.jsonl` | The 345 stratified sessions presented blind to annotators |
| `annotation_sample_full.jsonl` | Same sessions with both pipeline labels visible (answer key) |
| `annotation_results_reference.jsonl` | Claude Sonnet 4 annotations on the blind sample |
| `scripts/run_agent_pipeline.py` | Pipeline B runner |
| `scripts/annotate_with_llm.py` | Third-party LLM annotation script |
| `scripts/analyze_disagreements.py` | Existing disagreement analysis |
| `scripts/index_to_elastic.py` | Elasticsearch sink |
| `scripts/compute_ground_truth_metrics.py` | (Exists; needs refactor — see Phase 1) |

Elasticsearch is at `http://192.168.3.130:9200`, index `cowrie-sessions`. Long-running jobs should use **tmux sessions** — never run a multi-hour job in the foreground.

### 1.3 Existing Schema (must be preserved)

Each session record contains, at minimum:

```json
{
  "session_id": "abc123",
  "start_ts": "2025-...",
  "sensor": "amsterdam|bangalore|london|new_york|singapore|toronto",
  "label_rule": {
    "primary_tactic": "Discovery|Execution|...|No Action|Unknown Activity",
    "threat_level": 1|2|3,
    "confidence": "high|medium|low",
    "matched_rules": [...]
  },
  "label_agent": {
    "primary_tactic": "...",
    "threat_level": 1|2|3,
    "confidence": 0.0-1.0,
    "reasoning": "...",
    "is_anomaly": bool
  },
  "features": {
    "F1_keyword_bash": ...,
    "...": "...",
    "F38_messages_per_sec": ...
  }
}
```

Any new pipeline you build must produce a `label_<name>` block compatible with the metrics framework (Phase 1).

### 1.4 The Research Story

**Headline finding so far**: Pipeline A is more precise *when its rules fire* but has a catastrophic silent-failure mode (`No Action` / `Unknown Activity` on real attacks). Pipeline B closes that blind spot but systematically undercalls severity and overuses `Initial Access` as a default.

**The paper's contribution** will be a **cost-stratified comparison across the rule/ML/LLM design space**, with cost-quality Pareto plots and a failure-mode taxonomy. The implementation work below builds the artifacts needed to support that paper.

### 1.5 Critical Methodological Constraints

1. **Do not modify Pipeline A or Pipeline B's classification logic.** Their outputs are the locked baseline. If you find a bug, document it, do not silently fix.
2. **Annotators (human or LLM) work on the blind sample.** Never let annotation code see `label_rule` or `label_agent`.
3. **Inter-pipeline agreement is not accuracy.** Only human ground truth (and validated LLM annotations) can be used to make accuracy claims.
4. **False negatives cost more than false positives in security contexts.** Metrics must reflect this.
5. **Preserve raw outputs.** Every pipeline run writes to a separate file; do not overwrite `labeled_sessions.jsonl` with new pipeline outputs — write a new sidecar JSONL keyed by `session_id`.

---

## 2. Research Goal (write code in service of this)

Produce the artifacts required to publish a paper structured roughly as:

1. **Methods**: three pipeline families compared on identical session data
   - Pipeline A: rule-based (existing)
   - Pipeline B: agentic LLM at multiple cost tiers (existing Flash + new Pro/Sonnet/local)
   - Pipeline C: classical ML on engineered features (new)
2. **Evaluation**: human ground truth + LLM-annotator with measured inter-annotator agreement
3. **Results**:
   - Per-pipeline precision/recall/F1, separated for tactic vs threat-level
   - Cost-quality Pareto frontier ($/session vs F1)
   - Failure-mode taxonomy with named categories
   - Confidence calibration analysis
4. **Discussion**: when does the LLM premium pay off; what does a deployable hybrid look like

Every phase below produces an artifact that will appear in the paper.

---

## 3. Phase 1 — Metrics Framework Refactor

**Why first**: Every later phase outputs labels that need to be evaluated. Without a clean metrics framework, you'll re-implement evaluation logic in five places.

### 3.1 Target module

Create `src/cowrie_dataset/eval/metrics.py` with the following public surface:

```python
def load_annotations(path: str) -> dict[str, Annotation]: ...
def load_pipeline_labels(path: str, pipeline_name: str) -> dict[str, Label]: ...

def confusion_matrix(
    truth: dict[str, Annotation],
    predictions: dict[str, Label],
    axis: Literal["tactic", "level", "joint"],
) -> pd.DataFrame: ...

def per_class_metrics(...) -> pd.DataFrame:
    """Returns precision, recall, F1, support per class."""

def agreement_metrics(
    annot1: dict, annot2: dict, axis: str,
) -> dict:
    """Returns Cohen's kappa (nominal), weighted kappa (ordinal),
    raw agreement %, and McNemar's test result."""

def bootstrap_f1_diff(
    truth, pred_a, pred_b, axis, n_iter=10_000,
) -> tuple[float, tuple[float, float]]:
    """Returns mean F1(A) - F1(B) and 95% CI."""

def calibration_curve(
    truth, predictions_with_confidence,
) -> pd.DataFrame: ...

def false_negative_rate(
    truth, predictions,
    fn_definition: Callable[[Annotation, Label], bool],
) -> float: ...
```

### 3.2 Critical design choices

- **Tactic and level are evaluated separately.** This is the single most important refactor. Existing metrics conflate them. A session where both pipelines say "Discovery" but one says L2 and the other L3 is a level-only disagreement, not a tactic disagreement.
- **Use weighted kappa for level**, plain Cohen's kappa for tactic. Levels are ordinal (1 < 2 < 3); tactics are nominal.
- **`No Action` and `Unknown Activity` are treated as a separate class**, not silently mapped to "no label." The whole point of the silent-failure analysis is preserving these as distinct outcomes.
- **All metric functions accept `dict[session_id -> X]`**, not parallel lists. Aligning by session_id is the only correct way given pipelines may emit different subsets.

### 3.3 Build a CLI

`python -m cowrie_dataset.cli evaluate --truth <ann.jsonl> --pred <pipeline.jsonl> --pipeline-name <name> --output <metrics.json>`

It should write:
- `metrics_<pipeline>.json` (machine-readable)
- `metrics_<pipeline>.md` (human-readable summary table)
- `confusion_<pipeline>_tactic.csv`
- `confusion_<pipeline>_level.csv`

### 3.4 Acceptance criteria

- Run `evaluate` against `annotation_results_reference.jsonl` (Claude annotator) as truth and existing `label_rule` predictions. Verify the **tactic confusion matrix matches the existing analysis** (same cells, same counts) — this proves no regression vs. existing analyzer.
- Verify that for the level-only disagreement bucket, the level confusion shows the L3→L2 miscalibration; the tactic confusion shows perfect agreement on Discovery.
- Bootstrap CI test: when comparing `label_rule` vs itself, the F1 difference must be 0 with CI tight around 0 (sanity check).

### 3.5 Output artifacts to commit

- `src/cowrie_dataset/eval/metrics.py`
- `src/cowrie_dataset/eval/__init__.py`
- `tests/test_metrics.py` (must include the self-comparison sanity check)
- `analysis/baseline_metrics/` with `metrics_rule.{json,md}`, `metrics_agent.{json,md}`, and confusion CSVs

---

## 4. Phase 2 — Pipeline C: Classical ML

**Why this matters for the paper**: Without a classical ML baseline, the comparison is "old rules vs new LLMs" — readers will rightly ask whether a basic ML approach captures most of the LLM gains at a fraction of the cost. A clean Pipeline C answers that.

### 4.1 Training data strategy

Train on **two label sources** in parallel and report both:

- **Pipeline C-Human**: trained on human-annotated labels (when available). This is the gold version that goes in the paper headline.
- **Pipeline C-Claude**: trained on `annotation_results_reference.jsonl`. This is the "LLM-distilled cheap classifier" — directly tests whether an ML model can recover LLM behavior from feature data. Available now; build first.

**Do NOT train on cases where Pipeline A and B agree.** That's selection bias on the easy subset.

### 4.2 Feature pipeline

Features F1–F38 are already engineered and stored in `labeled_sessions.jsonl`. Build:

- `src/cowrie_dataset/ml/features.py`: function `extract_features(session: dict) -> np.ndarray` that pulls the 38 features in a fixed, documented order. Save the feature ordering to `models/feature_schema.json`.
- Handle missing features explicitly (impute with median; record imputation rate).

### 4.3 Model

- **Two heads**: one classifier for tactic (multi-class), one ordinal regressor for threat level (use either ordered logistic regression or a regression-then-round approach). Don't train one giant joint classifier — separating them matches Phase 1's evaluation structure.
- **Algorithm**: XGBoost or LightGBM. Use whichever is already installed; install LightGBM if neither is. Document the choice.
- **Cross-validation**: 5-fold stratified by tactic. **Stratify by sensor as well** to prevent geographic leakage.
- **Output schema**: emit `label_ml` blocks with the same shape as `label_rule` and `label_agent`, including a `confidence` field (use predict_proba).

### 4.4 CLI

```
python -m cowrie_dataset.cli train_ml \
  --train-data src/labeled_sessions.jsonl \
  --labels annotation_results_reference.jsonl \
  --model-out models/pipeline_c_claude.pkl \
  --cv-folds 5

python -m cowrie_dataset.cli predict_ml \
  --model models/pipeline_c_claude.pkl \
  --input src/labeled_sessions.jsonl \
  --output src/labels_pipeline_c_claude.jsonl
```

### 4.5 Sanity checks before celebrating

- **Feature importance dump**: top-20 features by SHAP value. Save to `analysis/pipeline_c/feature_importance.csv`. If `F1_keyword_bash` is the only feature that matters, you have a degenerate model.
- **Held-out fold metrics must match cross-val mean** within ~2 F1 points. Larger gaps signal leakage.
- **Run on agreement-bucket sessions**: ML model should classify them with >95% accuracy — these are the easy cases.

### 4.6 Output artifacts

- `src/cowrie_dataset/ml/{features.py, train.py, predict.py}`
- `models/pipeline_c_claude.pkl`, `models/feature_schema.json`
- `src/labels_pipeline_c_claude.jsonl`
- `analysis/pipeline_c/{feature_importance.csv, cv_results.json, confusion_*.csv}`

---

## 5. Phase 3 — Pipeline B Variants Across LLMs

**Why**: The headline question for the paper is "does paying more for a frontier model give you proportionally better security classification, or do diminishing returns kick in?" That requires running the same prompts through multiple models.

### 5.1 Models to run

Run Pipeline B (Hunter + Analyst, identical prompts) through each of:

| Variant | Model | Provider | Notes |
|---|---|---|---|
| B-Flash | Gemini 2.5 Flash | Vertex AI | Already exists; baseline |
| B-Pro | Gemini 2.5 Pro | Vertex AI | Same provider, larger model |
| B-Sonnet | Claude Sonnet (current) | Anthropic API | Different family |
| B-Opus | Claude Opus (current) | Anthropic API | Frontier tier |
| B-GPT | GPT-class frontier | OpenAI or Azure | Cross-provider check |
| B-Local | Local model on 5080 | Ollama or vLLM | See Phase 4 |

For each variant, run on **the same stratified 345-session sample**, not the full dataset. Full-dataset runs would cost too much and aren't needed for comparison; the stratified sample is the evaluation set.

### 5.2 Refactor for model-agnostic execution

Currently `run_agent_pipeline.py` is Vertex-specific. Refactor:

- Extract a `LLMClient` protocol with methods `complete(prompt, max_tokens, temperature) -> Response`.
- Implementations: `VertexClient`, `AnthropicClient`, `OpenAIClient`, `OllamaClient`.
- A factory: `make_client(provider: str, model: str) -> LLMClient`.
- The pipeline takes a client; prompts are unchanged.

This must not change Pipeline B-Flash output. **Re-run B-Flash through the new client and verify byte-equivalent outputs against the existing JSONL.** If outputs drift, your refactor introduced a bug.

### 5.3 Cost and latency tracking

Every LLM call records to a sidecar log:

```json
{"session_id": "...", "variant": "B-Pro",
 "input_tokens": 1234, "output_tokens": 567,
 "latency_ms": 2300, "cost_usd": 0.0042,
 "model": "gemini-2.5-pro", "stage": "hunter|analyst"}
```

Cost calculation uses a static price table at `config/llm_costs.json`. Update it manually when prices change — don't try to fetch live pricing.

### 5.4 CLI

```
python scripts/run_agent_pipeline.py \
  --provider <vertex|anthropic|openai|ollama> \
  --model <model_id> \
  --variant-name B-Pro \
  --input annotation_sample_blind.jsonl \
  --output src/labels_b_pro.jsonl \
  --cost-log analysis/cost_logs/b_pro.jsonl \
  --concurrency 10
```

### 5.5 Acceptance

- Each variant produces a label JSONL with the same schema.
- Cost log is non-empty and totals are sane (Flash should be ~10x cheaper than Pro, etc.).
- Phase 1 metrics framework runs cleanly against each variant's labels.

### 5.6 Output artifacts

- `src/cowrie_dataset/llm/clients.py` (the protocol + implementations)
- `src/labels_b_<variant>.jsonl` for each variant
- `analysis/cost_logs/b_<variant>.jsonl`
- `analysis/multi_llm/cost_summary.csv`

---

## 6. Phase 4 — Local LLM Variant

**Why**: For SOC teams that can't pipe internal logs to a third-party API (regulated industries, classified contexts), only local models are deployable. The paper needs to answer: how much performance do you give up by going local?

### 6.1 Hardware

Target: NVIDIA RTX 5080, 16GB VRAM. With 16GB you can comfortably run:
- 7B–8B models at BF16
- 12B–14B models at INT8
- ~30B models at INT4 (slow but possible)

### 6.2 Candidate models

Run at least two; pick from:
- Qwen 2.5 7B Instruct
- Llama 3.1 8B Instruct
- Mistral Nemo 12B
- Phi-4 14B
- Gemma 2 9B

Choose based on which has the best instruction-following on JSON output (Pipeline B's Analyst stage requires structured JSON). Test with a 10-session smoke run before committing to a full 345-run.

### 6.3 Inference stack

Use **Ollama** for ease of setup unless throughput is poor. Fall back to **vLLM** if Ollama can't keep up; vLLM has much better batching but more setup overhead.

The `OllamaClient` from Phase 3 should already work. Just point it at `http://localhost:11434`.

### 6.4 Acceptance

- B-Local produces structured JSON output on at least 90% of sessions (parse rate). If it's lower, the model can't handle the prompt and is unsuitable; pick a different one.
- Cost log records latency only (cost = 0); record GPU power draw if `nvidia-smi --query-gpu=power.draw` is available, for an "energy cost" footnote.

---

## 7. Phase 5 — Comprehensive Evaluation

**Why**: Phases 2-4 produced labels. This phase produces the tables and figures that go in the paper.

### 7.1 The headline table

`analysis/headline_table.md`: rows are pipelines (A, B-Flash, B-Pro, B-Sonnet, B-Opus, B-Local, C-Claude, C-Human), columns are:
- Tactic accuracy (vs human truth)
- Tactic macro-F1
- Level MAE (ordinal)
- Level weighted kappa
- False-negative rate (using project-specific definition: human says any tactic, pipeline says No Action / Unknown / null)
- $/1000 sessions
- Median latency (ms)

This single table is the most-referenced artifact in the paper. Build it last, after all variants are done.

### 7.2 Cost-quality Pareto plot

`analysis/figures/cost_quality_pareto.{png,pdf}`:
- X axis: log $/1000 sessions
- Y axis: macro-F1
- One point per pipeline variant
- Pareto frontier highlighted
- Pipelines that are dominated (worse on both axes than another point) explicitly labeled as such

### 7.3 Confidence calibration

For pipelines that emit confidence (B-* and C-*), compute reliability diagrams. Bin predictions by confidence (10 bins), plot empirical accuracy vs predicted confidence. Report Brier score and Expected Calibration Error.

`analysis/figures/calibration_<variant>.png` for each.

A miscalibrated LLM is itself a finding. Don't bury it.

### 7.4 McNemar's tests

Pairwise McNemar's tests on **paired correctness**: for each session, did pipeline X get tactic right? did pipeline Y? Compare. Output a triangular matrix of p-values:

`analysis/pairwise_mcnemar_tactic.csv`

This is what answers "is B-Pro statistically better than B-Flash?"

### 7.5 Bootstrap F1 confidence intervals

For every pairwise comparison in the paper, report a 95% CI on the F1 difference using paired bootstrap (resample sessions with replacement, recompute both F1s, take 2.5th and 97.5th percentile of the diff). 10,000 iterations is plenty.

### 7.6 LLM ensemble (bonus pipeline)

Build **Pipeline E (Ensemble)**: majority vote across B-Flash, B-Pro, B-Sonnet on each session. Ties broken by highest mean confidence. This often outperforms any single model and is essentially free given the runs are already done.

Evaluate it the same way as the others. If it wins, include it. If not, include it anyway with a "did it win? no" sentence — null results are also publishable.

---

## 8. Phase 6 — Failure Mode Taxonomy

**Why**: Quantitative metrics tell readers *that* pipelines differ. A failure mode taxonomy tells them *how* and *why* — and that's what makes the paper useful for practitioners.

### 8.1 Approach

- For sessions where any pipeline disagrees with human truth, extract: session features, both pipeline labels, human label, and pipeline B's reasoning text (when available).
- Cluster these failure cases. Two reasonable approaches:
  - **Cheap**: TF-IDF on Pipeline B's reasoning text + KMeans (k=8 to 12).
  - **Better**: sentence embeddings (use any local embedding model) + HDBSCAN.
- For each cluster, sample 5 representative sessions and write a 2-sentence description by hand. The named categories from this manual labeling are the taxonomy.

### 8.2 Expected categories (based on Claude-annotator findings — verify, don't assume)

- Silent FN on stdin payload drop (A says No Action; real C2)
- MikroTik /system scheduler exploit (A misses; B catches)
- Command typo / failed exec (A flags as Execution L1; truly No Action)
- Severity overcalls on plain recon (B's L3→L2 issue)
- Severity undercalls on credential drops (B's "Initial Access" overuse)

The first three give a "where A fails" story; the last two give a "where B fails" story. Symmetric reporting.

### 8.3 Output

`analysis/failure_taxonomy/`:
- `categories.md` — taxonomy with descriptions and per-category counts
- `examples_<category>.jsonl` — representative sessions
- `figures/category_distribution.png` — bar chart, one bar per pipeline showing what fraction of its errors fall in each category

This becomes a paper figure and likely a full table.

---

## 9. Phase 7 — Reproducibility Artifacts

The paper will get rejected if reviewers can't reproduce it. Build these alongside everything else:

- `Makefile` with targets `train_ml`, `run_b_variants`, `evaluate`, `paper_artifacts`. Each target runs end-to-end and is idempotent.
- `requirements.lock` (use `pip freeze` or `uv pip compile`).
- `data/README.md` describing how to obtain the dataset (or, if private, what fields are released).
- `analysis/paper_artifacts/` — final destination for every table and figure that appears in the paper. Nothing goes in the paper unless it's regenerable from this directory.

---

## 10. Sequencing and Dependencies

```
Phase 1 (metrics) ─┬─> Phase 2 (Pipeline C)
                   ├─> Phase 3 (multi-LLM)
                   │      └─> Phase 4 (local LLM)
                   └─> Phase 5 (evaluation)  <── needs all label sources
                          └─> Phase 6 (taxonomy)
                                 └─> Phase 7 (reproducibility)
```

Phase 1 blocks everything else. **Do not start Phase 2 or Phase 3 until Phase 1 is locked and tested**, or you'll re-do their evaluation when the framework changes.

Phases 2 and 3 can run in parallel — different code paths, different data outputs.

Phase 5 onwards is sequential and depends on all label sources existing.

---

## 11. Working Style Expectations

The user prefers:

1. **tmux for any long-running process.** A single Pipeline B variant on 345 sessions takes 30–60 minutes; a Pipeline C cross-validation can take 20+ minutes. Always launch in tmux, name the session sensibly, document the session name in the relevant log.
2. **Confirm at each step.** Before moving to the next phase, run the acceptance criteria and report results. Don't chain phases without verification.
3. **Concise status reports.** When summarizing what was done, give numbers and file paths, not narration. The user iterates toward shorter explanations.
4. **Preserve raw outputs.** Every pipeline run gets its own JSONL file. Never overwrite. If you need to rerun, write to a `_v2` suffix and document why.
5. **Surface errors loudly.** The `max_tokens` bug previously caused 93% silent parse failures. Every LLM-output-parsing step must log parse failures with counts and never default to "Unknown" without flagging.

---

## 12. What Not to Do

- Do not modify Pipeline A or Pipeline B's classification logic.
- Do not train Pipeline C on agreement-only sessions.
- Do not let any annotator (LLM or human) see existing pipeline labels.
- Do not run multi-LLM variants on the full 11.7M sessions — only on the 345-session evaluation sample.
- Do not skip Phase 1; you will regret it in Phase 5.
- Do not silently fix bugs in upstream pipelines; document and report.
- Do not over-engineer: the goal is paper artifacts, not a production system.

---

## 13. Definition of Done for the Whole Plan

When all of the following exist and are reproducible from the `Makefile`:

1. `analysis/headline_table.md` — eight-pipeline comparison table
2. `analysis/figures/cost_quality_pareto.png` — Pareto frontier figure
3. `analysis/failure_taxonomy/categories.md` — named failure modes with counts per pipeline
4. `analysis/calibration/` — reliability diagrams for every confidence-emitting pipeline
5. `analysis/pairwise_mcnemar_tactic.csv` — significance testing across pipelines
6. `analysis/paper_artifacts/` — every figure and table that will appear in the paper

…the user has the artifacts they need to write the paper.

---

## 14. Start Here

When you take over this plan, your first response should be:

1. Confirm you've read this document end-to-end.
2. List the three things you would start with (should be Phase 1 sub-tasks).
3. Identify any ambiguities or constraints you want resolved before writing code.
4. Propose a tmux session naming convention for this plan's runs.

Do not write code in your first response. Confirm understanding first.
