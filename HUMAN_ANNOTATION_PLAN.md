# Human Annotation & Evaluation Implementation Plan

## Overview

This plan covers everything needed to create human-annotated ground truth for 8,514 dual-labeled sessions, compute per-pipeline accuracy metrics, and frame the results using your professors' suggested frameworks. The external dataset validation step is excluded — this plan ends when you have finalized accuracy numbers for both pipelines against human ground truth on your own Cowrie data.

---

## Prerequisite: Re-Index to Elasticsearch

Everything below depends on being able to query and filter sessions efficiently. The re-indexing was already scoped as your next step.

**On the server (`jake1@honeypot-data`):**

```bash
tmux new -s reindex

cd /opt/cowrie-log-analysis

python scripts/index_to_elastic.py \
  --input src/labeled_sessions.jsonl \
  --create-index --delete-index \
  --bulk-size 200
```

Use `--bulk-size 200` if you see memory pressure. This will take several hours. Verify afterward:

```bash
curl -u "$ES_USER:$ES_PASSWORD" "http://192.168.3.130:9200/cowrie-sessions/_count" | jq .
```

Expected: ~11.7M documents. Spot-check that `label_comparison.tactics_agree` fields are populated on the dual-labeled subset.

---

## Phase 1: Deeper Pattern Analysis

Before sampling, do a deeper dive into *what* the pipelines agree and disagree on. Your professors specifically called this out — look for interesting patterns. This informs both your sampling strategy and your paper's narrative.

### 1.1 What to Investigate

Your existing `disagreement_results.json` already has the confusion matrices. The key patterns to examine more closely:

**Biggest disagreement buckets (by count):**

| Rule-Based Says | Agent Says | Count | What's Happening |
|---|---|---|---|
| Discovery | Initial Access | 1,405 | Agent thinks these are login-only sessions; rules see recon commands |
| Command and Control | Initial Access | 1,169 | Agent downgrades C2 to just "they logged in"; rules see download commands |
| No Action | Initial Access | 885 | Rules see nothing; agent at least recognizes the successful auth |
| Command and Control | Execution | 358 | Agent sees command execution where rules see C2 |
| Unknown Activity (Low) | Initial Access | 267 | Rules don't know what to make of it; agent says it's just initial access |

**Level disagreement (the big one):**

| Rule Level | Agent Level | Count | Interpretation |
|---|---|---|---|
| 3 (Low) | 2 (Medium) | 3,500 | Agent upgrades 66% of rule-level-3 sessions to medium |
| 3 (Low) | 1 (High) | 977 | Agent upgrades 18% of rule-level-3 sessions to high |
| 1 (High) | 2 (Medium) | 518 | Agent downgrades 16% of rule-level-1 sessions |

**Questions to answer before sampling:**

1. Are the 1,405 "Discovery → Initial Access" sessions mostly `success_no_commands` type? If so, the agent may be right — they're just logins, not discovery.
2. For the 3,500 sessions upgraded from level 3 → level 2: what commands are present? Is the agent seeing real medium-severity activity the rules miss, or is it being overly cautious?
3. The 977 sessions upgraded from level 3 → level 1: are these genuine high-severity sessions? This is where false negatives from Pipeline A would show up.
4. Agreement sessions (3,532 tactic, 3,504 level): are these trivially obvious cases, or do they include ambiguous ones where both pipelines could plausibly be wrong?

### 1.2 Script: `scripts/analyze_patterns.py`

Build a script that reads `labeled_sessions.jsonl` and produces deeper breakdowns. For each major confusion matrix cell, extract:

- `session_type` distribution (failed_auth_only / success_no_commands / success_with_commands)
- Command count distribution (0, 1-5, 5-20, 20+)
- Most common commands seen
- Agent confidence distribution
- Agent sophistication labels
- Location distribution (are certain sensors over-represented?)

This tells you whether disagreements are systematic (one pipeline consistently mishandles a session type) or scattered. Systematic patterns are the interesting research finding.

---

## Phase 2: Stratified Sampling

You don't need to annotate all 8,514 sessions. A stratified sample gives you statistical power with manageable effort.

### 2.1 Sample Size

Target: **400 sessions total** (adjustable). This gives you roughly ±5% margin of error at 95% confidence for per-cell accuracy estimates, which is standard for annotation studies.

If you have multiple annotators available, increase to 500 — the extra 100 are for computing inter-annotator agreement on a shared overlap set.

### 2.2 Stratification Strategy

Sample proportionally from these buckets to ensure you cover the full landscape of agreement/disagreement:

**Bucket A — Tactic Agreements (sample ~120)**

Both pipelines agree on tactic. You still need to check these because they could both be wrong. Sample proportionally by the agreed-upon tactic:

| Agreed Tactic | Population | Sample |
|---|---|---|
| Discovery | ~2,200 | 30 |
| Command and Control | ~1,000 (est.) | 20 |
| Execution | ~50 (est.) | 10 |
| Persistence | ~40 (est.) | 10 |
| Initial Access | variable | 20 |
| Impact / Other | variable | 15 |
| *Mixed/rare* | — | 15 |

**Bucket B — Tactic Disagreements (sample ~220)**

These are where the interesting findings live. Over-sample the large disagreement cells and ensure rare-but-important cells are represented:

| Rule Tactic | Agent Tactic | Population | Sample |
|---|---|---|---|
| Discovery | Initial Access | 1,405 | 40 |
| Command and Control | Initial Access | 1,169 | 35 |
| No Action | Initial Access | 885 | 30 |
| Command and Control | Execution | 358 | 25 |
| Unknown Activity (Low) | Initial Access | 267 | 20 |
| Unknown Activity (High) | Persistence | 124 | 15 |
| No Action | Execution | 74 | 10 |
| Impact | Persistence | 48 | 10 |
| Discovery | various other | ~10 | 10 |
| All other cells | — | remaining | 25 |

**Bucket C — Novel Detections (sample ~40)**

Sessions where Pipeline A matched no rule patterns but Pipeline B assigned level 1 or 2. These directly test the "does the LLM find things rules miss?" hypothesis.

**Bucket D — Level-Only Disagreements (sample ~20)**

Tactic agrees but level disagrees. Interesting for the severity calibration question.

### 2.3 Script: `scripts/extract_annotation_sample.py`

This script reads `labeled_sessions.jsonl`, applies the stratification logic, and exports a clean annotation-ready dataset. It should:

1. Scan the full JSONL to identify which bucket each dual-labeled session falls into
2. Randomly sample the target count from each bucket (with a fixed random seed for reproducibility)
3. Export each sampled session as a JSON record containing:
   - `annotation_id` (sequential, 1-400)
   - `session_id`
   - `bucket` (which stratum it came from)
   - `session_type`, `location`, `duration_s`, `auth_success`
   - `commands` (full list with timestamps)
   - `downloads`, `uploads`
   - `login_attempts`
   - `ssh_version`, `hassh`
   - `features` (the computed features)
   - `rule_based_label` (tactic, level, matched_patterns)
   - `agent_label` (tactic, level, reasoning, confidence, sophistication, technique_ids)
4. Also export a separate "blind" version for annotators that **strips both pipeline labels** — annotators should see only raw session data and make independent judgments. The labels are kept in a separate answer-key file for later comparison.

Output files:
- `annotation_sample_blind.jsonl` — what annotators see (no pipeline labels)
- `annotation_sample_full.jsonl` — full data with pipeline labels (for analysis after annotation)
- `annotation_sample_metadata.json` — bucket counts, random seed, population sizes

---

## Phase 3: Annotation Interface & Guidelines

### 3.1 Annotation Format

Each annotator reviews a session and records:

| Field | Type | Description |
|---|---|---|
| `annotation_id` | int | Links back to the sample |
| `annotator` | string | Who did this annotation (e.g., "jake", "partner1") |
| `primary_tactic` | enum | MITRE ATT&CK tactic (from the standard set: Initial Access, Execution, Persistence, Privilege Escalation, Defense Evasion, Credential Access, Discovery, Lateral Movement, Collection, Command and Control, Exfiltration, Impact, Resource Hijacking) OR "No Action" / "Unknown" |
| `threat_level` | 1/2/3 | 1=High, 2=Medium, 3=Low (matching your existing scheme) |
| `confidence` | 1-5 | How confident the annotator is (1=guessing, 5=certain) |
| `notes` | text | Free-form reasoning, especially for ambiguous cases |
| `is_false_negative_risk` | bool | "Would missing this session be dangerous?" (addresses the false negative concern) |

### 3.2 Annotation Codebook

Create a 1-2 page reference document for annotators. It needs to define:

**Tactic definitions with honeypot-specific examples:**

- **Initial Access**: Session authenticated successfully but took no further action. The "attack" was just getting in. *Example: brute-forced credentials, logged in, disconnected.*
- **Discovery**: Ran commands to learn about the system (uname, cat /etc/passwd, ls, ifconfig, whoami). Did NOT take action beyond looking around.
- **Command and Control**: Downloaded tools/payloads from external servers (wget, curl, tftp to external IPs). The session established communication with attacker infrastructure.
- **Execution**: Ran downloaded payloads or executed commands meant to do something (./malware, sh script.sh, python -c ...). Distinguished from Discovery by *intent to act*, not just look.
- **Persistence**: Modified system to maintain access (crontab, authorized_keys, rc.local, added users).
- **Impact**: Destructive actions (rm -rf, kill processes, reboot, disk wiping).
- **Resource Hijacking**: Cryptomining or using system resources for attacker benefit.

**The "primary tactic" rule**: If a session spans multiple tactics (recon then download then execute), pick the *most advanced/severe* tactic in the kill chain. A session that does Discovery → C2 → Execution gets labeled "Execution" as primary.

**Level definitions:**
- **Level 1 (High)**: Could damage the system or achieve attacker objectives. Execution, Impact, C2 with payload delivery, Resource Hijacking.
- **Level 2 (Medium)**: Establishes persistence or escalates privileges without immediate damage. Persistence, Privilege Escalation, Credential Access.
- **Level 3 (Low)**: Reconnaissance only, or no meaningful action taken. Discovery, Initial Access with no follow-up, No Action.

**The false negative flag**: Mark `is_false_negative_risk = true` if this session represents real attacker activity that a security team should NOT miss. This directly feeds your professors' point about false negatives being more costly than false positives.

### 3.3 Annotation Workflow Options

**Option A — Spreadsheet (simplest)**

Export the blind sample to CSV/XLSX. Each row = one session. Annotators fill in columns for tactic, level, confidence, notes. Works well for 2-3 annotators and ~400 sessions.

Drawback: Reading raw command lists in a spreadsheet cell is painful.

**Option B — Simple Web Viewer (recommended if you have time)**

A lightweight local HTML/JS page that:
- Loads `annotation_sample_blind.jsonl`
- Displays one session at a time with formatted commands, timing, auth info
- Has dropdown selects for tactic, level, confidence
- Has a text box for notes and a checkbox for false-negative risk
- Saves annotations to localStorage or exports as JSON
- Tracks progress (124/400 complete)

This is maybe 2-3 hours to build and saves significant time during the actual annotation. The formatted view of commands with timestamps is much easier to read than raw JSON in a spreadsheet.

**Option C — Kibana + Spreadsheet Hybrid**

Use Kibana to browse sessions visually (filter by session_id from your sample list), then record annotations in a spreadsheet. Requires the ES re-index to be done.

### 3.4 Inter-Annotator Agreement

If you have 2+ annotators, have them independently annotate the same overlap set (~50-100 sessions). Then compute:

- **Cohen's Kappa** for tactic agreement (categorical)
- **Cohen's Kappa** for level agreement (ordinal — use weighted kappa)
- **Percent agreement** as a simpler supplementary metric

Kappa > 0.6 is generally considered "substantial agreement" and publishable. If kappa is low, review the disagreements together, refine the codebook, and re-annotate the overlap set. This calibration loop is normal and expected.

For sessions where annotators disagree, use majority vote (if 3+ annotators) or discussion-to-consensus (if 2 annotators). Document which approach you used.

---

## Phase 4: Computing Results

Once annotations are complete, you have three datasets to compare:
- **H** = Human ground truth (your answer key)
- **A** = Pipeline A labels (rule-based)
- **B** = Pipeline B labels (agentic/LLM)

### 4.1 Confusion Matrices (Against Ground Truth)

Build two confusion matrices:

1. **Pipeline A vs. Human** — rows = Pipeline A tactic, columns = Human tactic
2. **Pipeline B vs. Human** — rows = Pipeline B tactic, columns = Human tactic

Same for threat levels. This replaces your current A-vs-B confusion matrix (which only measures agreement, not correctness) with two matrices that measure actual accuracy.

### 4.2 Per-Pipeline Metrics

For each pipeline, compute:

**Per-tactic metrics:**
- **Precision** = of all sessions the pipeline labeled as tactic X, what fraction did the human also label X?
- **Recall** = of all sessions the human labeled as tactic X, what fraction did the pipeline also label X?
- **F1** = harmonic mean of precision and recall

**Overall metrics:**
- **Macro-averaged F1** = average F1 across all tactics (treats each tactic equally)
- **Weighted-averaged F1** = average F1 weighted by tactic frequency (treats common tactics as more important)
- **Overall accuracy** = fraction of sessions where pipeline tactic matches human tactic

**Level metrics:**
- Same precision/recall/F1 per level
- **Mean Absolute Error** on levels (since 1/2/3 are ordinal)

### 4.3 False Negative Analysis

Using the `is_false_negative_risk` annotations:

- **Pipeline A false negative rate** = of sessions marked as high false-negative risk by humans, what fraction did Pipeline A assign level 3 (low) or "No Action"?
- **Pipeline B false negative rate** = same for Pipeline B

This directly addresses your professors' concern: "we can't let any false negatives through." A pipeline that has higher overall precision but misses more dangerous sessions is worse for security purposes.

### 4.4 Superiority / Non-Inferiority Framing

This is how you frame your statistical claims:

**Superiority test**: "Pipeline B's F1 score is statistically significantly higher than Pipeline A's." Use McNemar's test (for paired categorical data) or a bootstrap confidence interval on the F1 difference. If the 95% CI for (F1_B - F1_A) is entirely above zero, B is superior.

**Non-inferiority test**: "Pipeline B is at least as good as Pipeline A (within a margin δ)." You pre-specify a margin (e.g., δ = 5% F1). If the 95% CI lower bound for (F1_B - F1_A) is above -δ, B is non-inferior. This is the right framing if your argument is "the LLM pipeline matches rule-based accuracy while also providing reasoning, novel detections, and adaptability."

**Which to use?** Depends on your results. If B clearly wins, claim superiority. If it's close, claim non-inferiority and argue that the additional benefits (reasoning, adaptability, novel detections) make B valuable even without a clear accuracy advantage.

### 4.5 Script: `scripts/compute_ground_truth_metrics.py`

This script takes:
- `annotation_results.jsonl` (human annotations)
- `annotation_sample_full.jsonl` (pipeline labels)

And outputs:
- Per-pipeline confusion matrices (tactic and level)
- Per-tactic precision, recall, F1 for each pipeline
- Overall accuracy, macro F1, weighted F1 for each pipeline
- False negative rates
- McNemar's test p-value for pipeline comparison
- Bootstrap 95% CI for F1 difference
- Inter-annotator agreement (kappa) if multiple annotators

---

## Phase 5: Novel Detection Validation

The 1,617 novel detections (where Pipeline B flagged something Pipeline A missed entirely) are a separate analysis. For the ~40 of these in your sample:

- What fraction did the human agree are real threats? This is Pipeline B's "value-add" precision.
- What types of threats are these? (Tactic distribution)
- Could Pipeline A's rules reasonably be extended to catch these? Or do they require the contextual reasoning the LLM provides?

This feeds the paper's narrative about whether LLM pipelines find genuinely new things or just generate false positives.

---

## Execution Timeline

| Step | Dependency | Estimated Time |
|---|---|---|
| 1. Re-index to Elasticsearch | None | ~4-6 hours (hands-off) |
| 2. Run deeper pattern analysis | Step 1 (or direct JSONL) | ~1 day to write script + analyze |
| 3. Build sampling script | Step 2 results inform buckets | ~1 day |
| 4. Write annotation codebook | Step 2 patterns | ~half day |
| 5. Build annotation interface | Step 3 output | ~half day (spreadsheet) to 2 days (web viewer) |
| 6. Annotate (per person) | Steps 3-5 | ~3-5 days for 400 sessions |
| 7. Compute inter-annotator agreement | Step 6 (if multiple annotators) | ~half day |
| 8. Resolve disagreements | Step 7 | ~1 day |
| 9. Compute final metrics | Step 8 | ~1 day to write script + analyze |
| 10. Interpret results + framing | Step 9 | ~1-2 days |

**Total: roughly 2-3 weeks** with one annotator working part-time, less if you have partners helping.

---

## Summary: What You're Building

```
labeled_sessions.jsonl (38GB, 11.7M sessions)
        │
        ▼
  ┌─────────────────────┐
  │  Deeper Pattern      │ ← Phase 1: understand WHAT disagrees and WHY
  │  Analysis Script     │
  └──────────┬──────────┘
             ▼
  ┌─────────────────────┐
  │  Stratified Sampler  │ ← Phase 2: pick ~400 representative sessions
  │  (4 buckets)         │
  └──────────┬──────────┘
             ▼
  ┌─────────────────────┐
  │  Blind Annotation    │ ← Phase 3: humans label without seeing pipeline output
  │  Interface           │
  └──────────┬──────────┘
             ▼
  ┌─────────────────────┐
  │  Ground Truth        │ ← Phase 4: grade both pipelines against human labels
  │  Metrics Script      │
  └──────────┬──────────┘
             ▼
  Pipeline A: Precision / Recall / F1 per tactic
  Pipeline B: Precision / Recall / F1 per tactic
  Superiority / Non-inferiority conclusion
  False negative rates
  Novel detection value-add
```
