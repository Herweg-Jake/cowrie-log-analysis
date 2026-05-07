# End-to-end paper artifacts. Each target is idempotent - reruns won't
# clobber upstream pipeline outputs, just refresh derived analysis.
#
# Override paths from the command line, e.g.:
#   make evaluate TRUTH=annotations/jake.jsonl
#
# Default paths assume the project layout described in the implementation
# plan; adjust if your local data lives elsewhere.

PYTHON ?= python
TRUTH  ?= annotation_results_reference.jsonl
SESSIONS ?= src/labeled_sessions.jsonl
ANALYSIS ?= analysis
SPEC ?= $(ANALYSIS)/pipelines.spec.json

.PHONY: all evaluate baseline_metrics train_ml predict_ml run_b_variants \
        headline pareto calibration pairwise ensemble taxonomy paper_artifacts \
        test clean

all: paper_artifacts

# ---- Phase 1: baseline metrics (rule + agent) ----------------------------
baseline_metrics:
	mkdir -p $(ANALYSIS)/baseline_metrics
	$(PYTHON) -m cowrie_dataset.cli evaluate \
	    --truth $(TRUTH) --pred $(SESSIONS) --pipeline-name rule \
	    --output $(ANALYSIS)/baseline_metrics/
	$(PYTHON) -m cowrie_dataset.cli evaluate \
	    --truth $(TRUTH) --pred $(SESSIONS) --pipeline-name agent \
	    --output $(ANALYSIS)/baseline_metrics/

# ---- Phase 2: ML pipeline ------------------------------------------------
train_ml:
	mkdir -p models
	$(PYTHON) -m cowrie_dataset.cli train_ml \
	    --train-data $(SESSIONS) --labels $(TRUTH) \
	    --model-out models/pipeline_c_claude.pkl \
	    --cv-folds 5
	$(PYTHON) -m cowrie_dataset.cli ml_importance \
	    --model models/pipeline_c_claude.pkl \
	    --output $(ANALYSIS)/pipeline_c/feature_importance.csv

predict_ml:
	$(PYTHON) -m cowrie_dataset.cli predict_ml \
	    --model models/pipeline_c_claude.pkl \
	    --input $(SESSIONS) \
	    --output src/labels_pipeline_c_claude.jsonl \
	    --pipeline-name ml_claude

# ---- Phase 3: multi-LLM variants ----------------------------------------
# These are templates; uncomment as needed. Each variant is gated behind a
# real API key, so the Makefile won't run them by accident.
run_b_variants:
	@echo "See scripts/run_agent_pipeline.py --help. Examples:"
	@echo "  python scripts/run_agent_pipeline.py --provider anthropic \\"
	@echo "    --model claude-sonnet-4-20250514 --variant-name B-Sonnet \\"
	@echo "    --input annotation_sample_blind.jsonl \\"
	@echo "    --output src/labels_b_sonnet.jsonl \\"
	@echo "    --cost-log $(ANALYSIS)/cost_logs/b_sonnet.jsonl --concurrency 10"

# ---- Phase 5: evaluation artifacts --------------------------------------
headline:
	mkdir -p $(ANALYSIS)
	$(PYTHON) -m cowrie_dataset.cli headline \
	    --spec $(SPEC) --truth $(TRUTH) \
	    --out-md $(ANALYSIS)/headline_table.md \
	    --out-csv $(ANALYSIS)/headline_table.csv

pareto: headline
	$(PYTHON) -m cowrie_dataset.cli figures pareto \
	    --headline-csv $(ANALYSIS)/headline_table.csv \
	    --output $(ANALYSIS)/figures/cost_quality_pareto.png

calibration:
	@echo "Run for each confidence-emitting variant, e.g.:"
	@echo "  python -m cowrie_dataset.cli figures calibration \\"
	@echo "    --truth $(TRUTH) --predictions src/labels_b_sonnet.jsonl \\"
	@echo "    --pipeline-name agent --output $(ANALYSIS)/figures/calibration_b_sonnet.png"

pairwise:
	$(PYTHON) -m cowrie_dataset.cli pairwise_mcnemar \
	    --spec $(SPEC) --truth $(TRUTH) \
	    --output $(ANALYSIS)/pairwise_mcnemar_tactic.csv

ensemble:
	@echo "python -m cowrie_dataset.cli ensemble --inputs \\"
	@echo "  src/labels_b_flash.jsonl:agent src/labels_b_pro.jsonl:agent \\"
	@echo "  src/labels_b_sonnet.jsonl:agent --output src/labels_ensemble.jsonl"

taxonomy:
	$(PYTHON) -m cowrie_dataset.cli taxonomy \
	    --truth $(TRUTH) --sessions $(SESSIONS) \
	    --spec $(SPEC) --out-dir $(ANALYSIS)/failure_taxonomy --k 10

paper_artifacts: baseline_metrics headline pareto pairwise taxonomy
	@echo ""
	@echo "Artifacts ready under $(ANALYSIS)/"
	@echo "  - headline_table.md"
	@echo "  - figures/cost_quality_pareto.png"
	@echo "  - pairwise_mcnemar_tactic.csv"
	@echo "  - failure_taxonomy/categories.md"

# ---- Tests ---------------------------------------------------------------
test:
	$(PYTHON) -m pytest tests/ -x

clean:
	find . -name "__pycache__" -type d -exec rm -rf {} +
	rm -rf $(ANALYSIS)/figures $(ANALYSIS)/baseline_metrics
