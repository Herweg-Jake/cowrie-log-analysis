# Operator's Guide: Cost-Stratified Multi-Pipeline Threat Classification

> Step-by-step instructions for running the implementation. Pair with
> `IMPLEMENTATION_PLAN (1).md` for the design rationale; this doc covers
> what to actually type and what to look at when something goes wrong.

This guide assumes you're on the host where the data lives
(`jake1@honeypot-data` per the plan, working directory
`/opt/cowrie-log-analysis`). Adjust paths if your local copy differs.

---

## 0. Mental model

Three pipeline families produce labels on the same SSH-honeypot session
data, then everything is scored against a held-out annotation set.

| Family | Pipeline | What it is | Status |
|---|---|---|---|
| Rules | A | Deterministic regex + MITRE patterns | exists, frozen |
| LLM agents (Hunter -> Analyst) | B-Flash | Gemini 2.5 Flash via Vertex | exists |
| | B-Pro | Gemini 2.5 Pro | run in step 3 |
| | B-Sonnet | Claude Sonnet 4 | run in step 3 |
| | B-Opus | Claude Opus 4 | run in step 3 |
| | B-GPT | GPT-4o or similar | run in step 3 |
| | B-Local | Ollama on RTX 5080 | run in step 4 |
| Classical ML | C-Claude | LightGBM trained on Claude annotations | run in step 2 |
| | C-Human | Same, trained on human annotations | run when human labels arrive |
| Bonus | E (Ensemble) | Majority vote across B-* | run in step 5 |

The truth labels come from `annotation_results_reference.jsonl` (Claude
Sonnet 4 annotations) for now, and switch to a human resolved-truth
file once the human annotation pass is complete.

The metrics framework (`src/cowrie_dataset/eval/metrics.py`) is the
single source of truth for evaluation. Every comparison reads pipeline
labels through the same loader, so adding a variant only means adding a
row to `analysis/pipelines.spec.json`.

---

## 1. One-time setup

### 1.1 Pull the branch

```bash
cd /opt/cowrie-log-analysis
git fetch origin
git checkout claude/implement-plan-PZBbR
git pull
```

### 1.2 Install Python deps

```bash
pip install -e ".[ml,agents]"
pip install matplotlib pandas pytest tabulate
```

The `ml` extra brings in `lightgbm`, `scikit-learn`, `matplotlib`,
`seaborn`. The `agents` extra brings in `anthropic`, `openai`,
`google-genai`. `tabulate` is needed for `pandas.to_markdown()` in the
metrics CLI.

If you get `ModuleNotFoundError: No module named 'lightgbm'` later,
you skipped this step.

### 1.3 Run the test suite

```bash
python -m pytest tests/ -x
```

Expected: 22 passed (17 metrics tests + 5 phase-2-5 smoke tests).
If anything fails here, **stop**. Do not run downstream phases.

### 1.4 Make sure your secrets are in `.env`

`scripts/run_agent_pipeline.py` loads `.env` at startup. Required keys
depending on which providers you'll run:

```
GOOGLE_CLOUD_PROJECT=...   # for Vertex (B-Flash, B-Pro)
ANTHROPIC_API_KEY=...      # for B-Sonnet, B-Opus
OPENAI_API_KEY=...         # for B-GPT
OLLAMA_BASE_URL=http://localhost:11434  # only if non-default
```

`.env.example` shows the full list.

---

## 2. Phase 1 acceptance: baseline metrics

Phase 1 (the metrics framework) is already coded and tested. The only
remaining acceptance step is to run it against the real labels and
confirm we don't drift from the existing analyzer.

```bash
make baseline_metrics \
    TRUTH=annotation_results_reference.jsonl \
    SESSIONS=src/labeled_sessions.jsonl
```

This writes:

- `analysis/baseline_metrics/metrics_rule.{json,md}`
- `analysis/baseline_metrics/metrics_agent.{json,md}`
- `analysis/baseline_metrics/confusion_{rule,agent}_{tactic,level}.csv`

### 2.1 What to verify

1. **Tactic confusion matches the existing analyzer.** The legacy
   script is `scripts/compute_ground_truth_metrics.py`. Run it with the
   same inputs and diff the tactic-confusion section. They should match
   cell-for-cell. If they don't, the loader is interpreting your label
   files differently than the legacy script -- pipe the discrepancy
   back to me before continuing.

2. **Per-tactic Discovery row is intact** in
   `metrics_rule.md`. Pipeline A is the strongest on Discovery (recon
   commands), so it should show high precision and high recall there.

3. **No level-only disagreements show up as tactic disagreements.** If
   you compare `metrics_rule.md` to `metrics_agent.md` and see Pipeline
   A and B disagreeing on tactic for sessions where the legacy analyzer
   reports them as agreeing on tactic but disagreeing on level,
   something is wrong. The whole point of the refactor is to keep these
   axes separate.

### 2.2 If something looks off

- **`No overlap between annotations and pipeline labels`** -- the truth
  file's IDs (`session_id` or `annotation_id`) don't match the
  prediction file's IDs. Check both with `head -1 | python -m json.tool`.
- **`KeyError: 'primary_tactic'`** -- the loader didn't find a
  recognized label block. The pipeline name passed to `--pipeline-name`
  must correspond to either a `label_<name>` key or one of the legacy
  keys (`rule_based_label`, `agent_label`).

---

## 3. Phase 2: train Pipeline C-Claude

This trains a classical ML baseline (LightGBM) on the Claude
annotations, so we can answer "does an ML model recover most of the
LLM's signal at a fraction of the cost?".

### 3.1 Run training + importance + prediction

```bash
mkdir -p analysis/pipeline_c models
python -m cowrie_dataset.cli train_ml \
    --train-data src/labeled_sessions.jsonl \
    --labels annotation_results_reference.jsonl \
    --model-out models/pipeline_c_claude.pkl \
    --cv-folds 5

python -m cowrie_dataset.cli ml_importance \
    --model models/pipeline_c_claude.pkl \
    --output analysis/pipeline_c/feature_importance.csv

python -m cowrie_dataset.cli predict_ml \
    --model models/pipeline_c_claude.pkl \
    --input src/labeled_sessions.jsonl \
    --output src/labels_pipeline_c_claude.jsonl \
    --pipeline-name ml_claude
```

CV results land at `models/pipeline_c_claude.cv.json` (or override with
`--cv-out`).

### 3.2 Sanity checks before celebrating

The plan calls these out explicitly. Don't skip them.

- **Feature importance.** Open
  `analysis/pipeline_c/feature_importance.csv`. The top 5 should be a
  mix of features (e.g. message-length, base64 count, command-rate,
  some keyword counts). If `F1_keyword_bash` is alone at the top with
  the rest near zero, the model is degenerate -- training data is too
  small or features aren't carrying signal. Flag this.

- **CV consistency.** In `models/pipeline_c_claude.cv.json`, the
  per-fold `tactic_accuracy` should be within ~2 points of the mean.
  Larger spread = leakage somewhere; check whether sensor stratification
  is actually splitting (look at `tactic_distribution` and counts per
  fold).

- **Easy-case accuracy.** Build a slice of sessions where Pipeline A
  and Pipeline B already agree, run `predict_ml` on it, score against
  the agreed label. ML should be >95% accurate -- these are the easy
  ones. If it's lower, your features and the upstream extractor have
  drifted apart.

### 3.3 When human labels arrive

Re-run with the human file as truth and a different model output:

```bash
python -m cowrie_dataset.cli train_ml \
    --train-data src/labeled_sessions.jsonl \
    --labels annotation_results_human.jsonl \
    --model-out models/pipeline_c_human.pkl --cv-folds 5
python -m cowrie_dataset.cli predict_ml \
    --model models/pipeline_c_human.pkl \
    --input src/labeled_sessions.jsonl \
    --output src/labels_pipeline_c_human.jsonl \
    --pipeline-name ml_human
```

Pipeline C-Human is the headline ML number for the paper.

---

## 4. Phase 3: multi-LLM variants

Each variant runs Pipeline B (Hunter -> Analyst, identical prompts)
through a different model. **Always launch in tmux** -- a single
variant on the 345-session sample takes 30-60 minutes.

### 4.1 tmux session naming convention

`b-<variant>-<YYMMDD>` so old runs are easy to clean up:

```bash
tmux ls
# b-pro-260507    1 windows ...
# b-sonnet-260507 1 windows ...
```

Document the session name in any log you produce so a future you can
find the right tmux window.

### 4.2 Run each variant

```bash
mkdir -p analysis/cost_logs logs

# B-Pro (Vertex AI / Google Cloud credits)
tmux new -s b-pro-$(date +%y%m%d) -d \
  "python scripts/run_agent_pipeline.py \
     --provider vertex --model gemini-2.5-pro \
     --variant-name B-Pro \
     --input annotation_sample_blind.jsonl \
     --output src/labels_b_pro.jsonl \
     --cost-log analysis/cost_logs/b_pro.jsonl \
     --concurrency 10 2>&1 | tee logs/b_pro.log"

# B-Sonnet
tmux new -s b-sonnet-$(date +%y%m%d) -d \
  "python scripts/run_agent_pipeline.py \
     --provider anthropic --model claude-sonnet-4-20250514 \
     --variant-name B-Sonnet \
     --input annotation_sample_blind.jsonl \
     --output src/labels_b_sonnet.jsonl \
     --cost-log analysis/cost_logs/b_sonnet.jsonl \
     --concurrency 10 2>&1 | tee logs/b_sonnet.log"

# B-Opus (lower concurrency - more expensive, lower RPM)
tmux new -s b-opus-$(date +%y%m%d) -d \
  "python scripts/run_agent_pipeline.py \
     --provider anthropic --model claude-opus-4-20250514 \
     --variant-name B-Opus \
     --input annotation_sample_blind.jsonl \
     --output src/labels_b_opus.jsonl \
     --cost-log analysis/cost_logs/b_opus.jsonl \
     --concurrency 5 2>&1 | tee logs/b_opus.log"

# B-GPT (cross-provider check)
tmux new -s b-gpt-$(date +%y%m%d) -d \
  "python scripts/run_agent_pipeline.py \
     --provider openai --model gpt-4o \
     --variant-name B-GPT \
     --input annotation_sample_blind.jsonl \
     --output src/labels_b_gpt.jsonl \
     --cost-log analysis/cost_logs/b_gpt.jsonl \
     --concurrency 10 2>&1 | tee logs/b_gpt.log"
```

Attach with `tmux attach -t b-pro-260507`, detach with `Ctrl+b d`.

### 4.3 The B-Flash equivalence check

The Phase 3 acceptance test is that B-Flash output is **byte-equivalent**
when re-run through the new client layer. Run it the same way as the
others:

```bash
tmux new -s b-flash-recheck-$(date +%y%m%d) -d \
  "python scripts/run_agent_pipeline.py \
     --provider vertex --model gemini-2.5-flash \
     --variant-name B-Flash \
     --input annotation_sample_blind.jsonl \
     --output src/labels_b_flash_recheck.jsonl \
     --cost-log analysis/cost_logs/b_flash_recheck.jsonl \
     --concurrency 10 2>&1 | tee logs/b_flash_recheck.log"
```

Then diff against the existing B-Flash output:

```bash
python - <<'PY'
import json
def load(p):
    return {r["session_id"]: r.get("labels_agentic", {}).get("analyst_verdict")
            for r in (json.loads(l) for l in open(p) if l.strip())}
old = load("src/labels_b_flash.jsonl")  # whatever the existing path is
new = load("src/labels_b_flash_recheck.jsonl")
diffs = [(sid, old[sid], new[sid])
         for sid in (set(old) & set(new)) if old[sid] != new[sid]]
print(f"{len(diffs)}/{len(set(old) & set(new))} sessions differ")
for sid, o, n in diffs[:5]:
    print(sid, o, "->", n)
PY
```

Latency and token counts will differ; `primary_tactic` and
`threat_level` should not. If they do, the Ollama branch I added to
`BaseAgent` or the cost-log writer is leaking back into the Vertex
path -- tell me what you see.

### 4.4 Costs

Update `config/llm_costs.json` if any provider's pricing has shifted
since I checked the file in. Format:

```json
{"<exact-model-id>": {"input_per_1k": 0.0X, "output_per_1k": 0.0X}}
```

The cost log records latency and token counts unconditionally; the
$/session figure in the headline table is computed from the static
price table at evaluation time, so updating prices doesn't require
re-running the variants.

### 4.5 Common failures

- **Quota / 429 errors** -- the runner backs off automatically, but if
  you see them on every session check the rate-limit config in
  `src/cowrie_dataset/agents/base.py` (provider-specific RPM defaults
  there).
- **Empty `analyst_verdict`** -- this is what the original "max_tokens"
  bug looked like. The script logs parse failures with counts; check
  `logs/<variant>.log` for the failure rate. Anything above ~5% means
  the prompt+model combo isn't producing parseable JSON.
- **Stuck at session N** -- check the tmux window. If the API is
  hanging, kill the session, increase `--concurrency` to compensate
  for slow tail latencies, and resume by cropping the input file to
  unprocessed IDs.

---

## 5. Phase 4: local LLM (B-Local)

### 5.1 Pull a candidate model

The 16GB VRAM target on the RTX 5080 fits 7B-8B at BF16 comfortably,
12B-14B at INT8, ~30B at INT4. Start small and scale up if quality is
poor.

```bash
ollama pull qwen2.5:7b-instruct
# alternates if Qwen's parse rate is bad:
# ollama pull llama3.1:8b-instruct
# ollama pull mistral-nemo:12b-instruct
```

### 5.2 Smoke test (10 sessions)

```bash
python scripts/local_llm_smoke.py \
    --model qwen2.5:7b-instruct \
    --input annotation_sample_blind.jsonl --n 10
```

Output ends with `verdict: OK (>= 90%)` or `FAIL`. If it fails, try a
different model -- don't try to coax a model that can't produce JSON
into producing JSON, the comparison isn't fair.

### 5.3 Full run

```bash
tmux new -s b-local-$(date +%y%m%d) -d \
  "python scripts/run_agent_pipeline.py \
     --provider ollama --model qwen2.5:7b-instruct \
     --variant-name B-Local \
     --input annotation_sample_blind.jsonl \
     --output src/labels_b_local.jsonl \
     --cost-log analysis/cost_logs/b_local.jsonl \
     --concurrency 4 2>&1 | tee logs/b_local.log"
```

Concurrency is capped by the GPU, not the API. 4 is a reasonable start;
push higher only if `nvidia-smi` shows headroom.

### 5.4 Optional energy footnote

The plan suggests recording GPU power for an "energy cost" footnote.
Run this in a separate tmux window during the B-Local run:

```bash
tmux new -s b-local-power -d \
  "nvidia-smi --query-gpu=power.draw --format=csv -l 30 \
     > analysis/cost_logs/b_local_power.csv"
```

Stop it when the run finishes.

---

## 6. Phase 5: produce paper artifacts

This is where everything comes together into the headline table, the
Pareto plot, calibration diagrams, and the McNemar matrix.

### 6.1 Build the pipelines spec

The spec drives every Phase 5 target. Start from the example:

```bash
cp analysis/pipelines.spec.example.json analysis/pipelines.spec.json
```

Open `analysis/pipelines.spec.json` and **delete any rows whose
JSONL doesn't exist on disk yet**. The Makefile won't gracefully skip
missing files -- it'll throw a `FileNotFoundError`.

A minimum viable spec, after Phase 1 and Phase 2 only:

```json
[
  {"name": "A",        "predictions": "src/labeled_sessions.jsonl",
                       "pipeline_name": "rule"},
  {"name": "B-Flash",  "predictions": "src/labeled_sessions.jsonl",
                       "pipeline_name": "agent"},
  {"name": "C-Claude", "predictions": "src/labels_pipeline_c_claude.jsonl",
                       "pipeline_name": "ml_claude"}
]
```

Add B-Pro, B-Sonnet, B-Opus, B-GPT, B-Local rows as those runs
finish. Cost logs are optional -- omit `cost_log` for pipelines you
don't want a $/session number for.

### 6.2 Generate the artifacts

```bash
make headline      # analysis/headline_table.{md,csv}
make pareto        # analysis/figures/cost_quality_pareto.{png,pdf}
make pairwise      # analysis/pairwise_mcnemar_tactic.csv
```

### 6.3 Calibration diagrams (one per confidence-emitting variant)

```bash
mkdir -p analysis/figures
for v in b_flash b_pro b_sonnet b_opus b_gpt b_local; do
  test -f src/labels_${v}.jsonl || continue
  python -m cowrie_dataset.cli figures calibration \
      --truth annotation_results_reference.jsonl \
      --predictions src/labels_${v}.jsonl \
      --pipeline-name agent \
      --output analysis/figures/calibration_${v}.png
done

python -m cowrie_dataset.cli figures calibration \
    --truth annotation_results_reference.jsonl \
    --predictions src/labels_pipeline_c_claude.jsonl \
    --pipeline-name ml_claude \
    --output analysis/figures/calibration_c_claude.png
```

Each command prints the ECE (Expected Calibration Error) so you can
quickly see which variants are well-calibrated.

A miscalibrated LLM is a finding worth keeping -- don't bury it.

### 6.4 Pipeline E (ensemble)

Bonus pipeline; majority vote across multiple B-* runs. Often
outperforms any single model.

```bash
python -m cowrie_dataset.cli ensemble \
    --inputs src/labels_b_flash.jsonl:agent \
             src/labels_b_pro.jsonl:agent \
             src/labels_b_sonnet.jsonl:agent \
             src/labels_b_opus.jsonl:agent \
             src/labels_b_gpt.jsonl:agent \
    --output src/labels_ensemble.jsonl --name ensemble
```

The `:agent` suffix tells the loader which label block to read inside
each variant's file. Then add the ensemble row to
`analysis/pipelines.spec.json` and re-run `make headline pareto pairwise`.

If the ensemble doesn't win, **include it in the paper anyway** with
a one-sentence "tested, did not improve" note. Null results are also
publishable.

---

## 7. Phase 6: failure-mode taxonomy

Quantitative metrics tell readers *that* pipelines differ. The
taxonomy tells them *how* and *why*.

### 7.1 Cluster the failures

```bash
make taxonomy
```

This writes:

- `analysis/failure_taxonomy/categories.md` -- skeleton table with
  cluster numbers, top TF-IDF terms, and a TODO column for human
  titles.
- `analysis/failure_taxonomy/examples/cluster_NN.jsonl` -- 5 sample
  failures per cluster.
- `analysis/failure_taxonomy/category_distribution.csv` -- per-pipeline
  per-cluster failure counts (input to the bar chart in the paper).
- `analysis/failure_taxonomy/summary.json` -- totals.

### 7.2 Human label the clusters

Open `categories.md` and the `examples/` files side by side. For each
cluster, read the 5 examples and write a 2-sentence description.
The plan suggests these likely categories (verify, don't assume):

1. Silent FN on stdin payload drop -- A says "No Action", really C2.
2. MikroTik /system scheduler exploit -- A misses, B catches.
3. Command typo / failed exec -- A flags as Execution L1; truly No Action.
4. Severity overcalls on plain recon -- B's L3 -> L2 issue.
5. Severity undercalls on credential drops -- B's "Initial Access" overuse.

Replace each `_TODO_` cell in the table with a human-readable title.
Adjust the `--k` flag (`make taxonomy K=12`) and rerun if 10 clusters
collapses too aggressively.

### 7.3 What the bar chart should show

For each pipeline, a stacked or grouped bar showing what fraction of
its errors fall in each named category. Build it from
`category_distribution.csv` -- any plotting tool works; the format is
tidy enough for a one-liner in pandas/matplotlib.

---

## 8. Phase 7: lock the environment

```bash
pip freeze > requirements.lock
git add requirements.lock data/README.md
git commit -m "Lock environment for paper reproducibility"
```

I deliberately didn't check in a lockfile -- pin it from your actual
working environment so the lock matches what produced the figures.

For the paper-artifacts directory:

```bash
mkdir -p analysis/paper_artifacts
cp analysis/headline_table.md \
   analysis/figures/cost_quality_pareto.{png,pdf} \
   analysis/pairwise_mcnemar_tactic.csv \
   analysis/failure_taxonomy/categories.md \
   analysis/failure_taxonomy/category_distribution.csv \
   analysis/figures/calibration_*.png \
   analysis/paper_artifacts/
```

Anything that ends up in the paper goes in this directory, and only
this directory; that's the rule that keeps the paper reproducible.

---

## 9. Resuming after the human-annotation pass lands

When you have a human resolved-truth file (built from
`scripts/compute_ground_truth_metrics.py` over the multiple annotator
JSONLs), do all of the following:

1. **Re-run baseline metrics** with the human file as truth.
2. **Train Pipeline C-Human** (section 3.3) -- this is the headline ML
   number.
3. **Re-run Phase 5** with `TRUTH=annotation_results_human.jsonl` for
   the headline, pareto, calibration, and pairwise targets.
4. **Re-run the taxonomy** -- failure clusters change when the truth
   changes.
5. **Inter-annotator agreement** is computed by the existing
   `scripts/compute_ground_truth_metrics.py` script. The metrics
   framework also has `agreement_metrics(annot1, annot2, axis)` if you
   want kappa numbers from Python instead.

The pipelines.spec.json doesn't change between Claude-truth and
human-truth runs -- only `TRUTH` does.

---

## 10. Troubleshooting checklist

When something doesn't work, walk this list before asking for help.

- [ ] **Did `python -m pytest tests/` pass?** If not, the env is broken.
- [ ] **Are you on `claude/implement-plan-PZBbR`?** `git branch` to check.
- [ ] **Does the input file exist and have the IDs the loader expects?**
      `head -1 file.jsonl | python -m json.tool` to inspect a record.
- [ ] **Is `pipelines.spec.json` listing only files that exist?**
      `for p in $(jq -r '.[].predictions' analysis/pipelines.spec.json); do test -f $p || echo MISSING $p; done`
- [ ] **For LLM runs: is `.env` loaded?**
      `python scripts/run_agent_pipeline.py --help` -- if the env-loader
      crashes, you'll see it.
- [ ] **For LLM runs: is the cost log path's parent dir created?** The
      script appends, it doesn't create dirs.
- [ ] **For ML runs: is `lightgbm` installed?**
      `python -c "import lightgbm; print(lightgbm.__version__)"`
- [ ] **Are you accidentally pointing at `labeled_sessions.jsonl` for
      everything?** It's the master file -- it carries Pipeline A's and
      Pipeline B-Flash's labels embedded. New variants live in
      `src/labels_b_<variant>.jsonl`.

---

## 11. What this scaffolding does not do

In case a future-chat picks this up and assumes too much:

- **Does not modify Pipeline A or Pipeline B classification logic.**
  Their outputs are the locked baseline. If you find a bug, document
  it; do not silently fix.
- **Does not let annotators (LLM or human) see existing pipeline
  labels.** The annotation workflow uses `annotation_sample_blind.jsonl`
  for that reason.
- **Does not run multi-LLM variants on the full 11.7M sessions.** Only
  the stratified 345-session sample. Full-corpus LLM runs are not part
  of the comparison.
- **Does not auto-fetch live LLM pricing.** Update
  `config/llm_costs.json` by hand.
- **Does not produce the paper.** The artifacts directory has the
  inputs; the prose is human work.

---

## 12. File map

The places to look when something is unclear.

| Thing | Where |
|---|---|
| Metrics framework | `src/cowrie_dataset/eval/metrics.py` |
| Eval CLI | `src/cowrie_dataset/eval/cli.py` |
| Headline table builder | `src/cowrie_dataset/eval/headline.py` |
| Pareto + calibration plots | `src/cowrie_dataset/eval/figures.py` |
| McNemar matrix | `src/cowrie_dataset/eval/pairwise.py` |
| Ensemble | `src/cowrie_dataset/eval/ensemble.py` |
| Failure taxonomy | `src/cowrie_dataset/eval/taxonomy.py` |
| ML feature ordering | `src/cowrie_dataset/ml/features.py` |
| ML training | `src/cowrie_dataset/ml/train.py` |
| ML prediction | `src/cowrie_dataset/ml/predict.py` |
| Feature importance dump | `src/cowrie_dataset/ml/importance.py` |
| LLM client protocol | `src/cowrie_dataset/llm/clients.py` |
| Provider price table | `config/llm_costs.json` |
| Multi-LLM runner | `scripts/run_agent_pipeline.py` |
| Local-LLM smoke test | `scripts/local_llm_smoke.py` |
| End-to-end glue | `Makefile` |
| Pipelines spec example | `analysis/pipelines.spec.example.json` |
| Tests | `tests/test_metrics.py`, `tests/test_phases.py` |

---

## 13. Asking another chat for help

If you hand this doc to another chat and need them to pick up where
you are, also include:

- the output of `git log --oneline -10` so they know the latest commit;
- the contents of `analysis/pipelines.spec.json` if it exists;
- the **most recent** `make` target you ran and any error message;
- a list of which `src/labels_b_*.jsonl` files exist (`ls src/labels_*.jsonl`).

The chat doesn't need access to the data files to advise on logic
issues -- the failure modes are usually visible from the spec, the
error message, and the file listing.
