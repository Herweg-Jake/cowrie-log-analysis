# Dataset notes

This directory is intentionally empty in version control. The honeypot
data and intermediate artifacts live outside the repo - see paths below.
The Makefile assumes the layout described here; override with
`make TRUTH=... SESSIONS=...` if your local copy differs.

## Inputs

| Path | What | Source |
|---|---|---|
| `src/labeled_sessions.jsonl` | Master dataset, ~11.7M sessions, both pipelines' labels embedded | Cowrie sensors (Amsterdam, Bangalore, London, New York, Singapore, Toronto) |
| `src/anomaly_stats.json` | Welford running stats used by Pipeline B's gate | `scripts/train_anomaly_detector.py` |
| `annotation_sample_blind.jsonl` | 345 stratified sessions, no labels | `scripts/extract_annotation_sample.py` |
| `annotation_sample_full.jsonl` | Same sessions, both pipeline labels visible | same |
| `annotation_results_reference.jsonl` | Claude Sonnet 4 annotations on the blind sample | `scripts/annotate_with_llm.py` |

The full event-level Cowrie logs (per-day JSON files per sensor) are not
released. Aggregated session records and labels can be made available on
request - contact the project maintainers.

## Outputs

Re-runnable from the Makefile:

| Target | Produces |
|---|---|
| `make baseline_metrics` | `analysis/baseline_metrics/metrics_{rule,agent}.{json,md}` + confusion CSVs |
| `make train_ml predict_ml` | `models/pipeline_c_claude.pkl`, `src/labels_pipeline_c_claude.jsonl`, importance CSV |
| `make headline pareto` | `analysis/headline_table.md`, `analysis/figures/cost_quality_pareto.{png,pdf}` |
| `make pairwise` | `analysis/pairwise_mcnemar_tactic.csv` |
| `make taxonomy` | `analysis/failure_taxonomy/{categories.md,examples/,category_distribution.csv}` |

## The pipelines spec

Phase 5 evaluation reads `analysis/pipelines.spec.json`. Format:

```json
[
  {"name": "A",        "predictions": "src/labeled_sessions.jsonl", "pipeline_name": "rule"},
  {"name": "B-Flash",  "predictions": "src/labeled_sessions.jsonl", "pipeline_name": "agent",
                       "cost_log": "analysis/cost_logs/b_flash.jsonl"},
  {"name": "B-Pro",    "predictions": "src/labels_b_pro.jsonl",     "pipeline_name": "agent",
                       "cost_log": "analysis/cost_logs/b_pro.jsonl"},
  {"name": "B-Sonnet", "predictions": "src/labels_b_sonnet.jsonl",  "pipeline_name": "agent",
                       "cost_log": "analysis/cost_logs/b_sonnet.jsonl"},
  {"name": "B-Opus",   "predictions": "src/labels_b_opus.jsonl",    "pipeline_name": "agent",
                       "cost_log": "analysis/cost_logs/b_opus.jsonl"},
  {"name": "B-Local",  "predictions": "src/labels_b_local.jsonl",   "pipeline_name": "agent",
                       "cost_log": "analysis/cost_logs/b_local.jsonl"},
  {"name": "C-Claude", "predictions": "src/labels_pipeline_c_claude.jsonl", "pipeline_name": "ml_claude"},
  {"name": "Ensemble", "predictions": "src/labels_ensemble.jsonl",  "pipeline_name": "ensemble"}
]
```

Drop or add rows as variants come online; everything downstream
(headline, Pareto, McNemar, taxonomy) reads this single file.
