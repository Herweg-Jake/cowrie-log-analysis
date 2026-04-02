#!/usr/bin/env python3
"""
Analyze disagreements between rule-based and agentic labels.

Works in two modes:
  - JSONL mode: reads labeled_sessions.jsonl directly (no ES needed)
  - ES mode: queries Elasticsearch index

Usage:
    # From JSONL file (default)
    python scripts/analyze_disagreements.py --input src/labeled_sessions.jsonl

    # From Elasticsearch
    python scripts/analyze_disagreements.py --es --es-host http://192.168.3.130:9200

    # Save full results
    python scripts/analyze_disagreements.py --input src/labeled_sessions.jsonl --output disagreements.json
"""

import argparse
import json
import os
from collections import Counter, defaultdict
from pathlib import Path

try:
    from tqdm import tqdm
except ImportError:
    def tqdm(iterable, **kwargs):
        total = kwargs.get('total', 0)
        for i, item in enumerate(iterable):
            if i % 1000 == 0:
                print(f"Progress: {i}/{total}")
            yield item


def _load_env():
    env_path = Path(__file__).resolve().parent.parent / ".env"
    if not env_path.exists():
        return
    with open(env_path) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, value = line.partition("=")
            if key.strip() not in os.environ:
                os.environ[key.strip()] = value.strip()


_load_env()


def normalize_tactic(tactic):
    """Normalize tactic names for comparison."""
    if not tactic:
        return ""
    return tactic.strip().lower().replace("(failed)", "").strip()


def analyze_from_jsonl(input_path, sample_size=50):
    """Analyze disagreements directly from JSONL file."""
    line_count = sum(1 for _ in open(input_path))

    # Counters
    total = 0
    anomalous = 0
    hunter_processed = 0
    hunter_noise = 0
    hunter_relevant = 0
    hunter_errored = 0
    analyst_processed = 0

    # Comparison stats (only for sessions with analyst verdicts)
    dual_labeled = 0
    tactic_agree = 0
    level_agree = 0

    # Distributions
    rule_tactic_dist = Counter()
    agent_tactic_dist = Counter()
    rule_level_dist = Counter()
    agent_level_dist = Counter()
    level_confusion = defaultdict(lambda: Counter())  # rule_level -> agent_level -> count
    tactic_confusion = defaultdict(lambda: Counter())  # rule_tactic -> agent_tactic -> count

    # Disagreement samples
    tactic_disagreements = []
    level_disagreements = []
    agent_only_detections = []  # H2: agent found threat, rules found nothing

    # H3: Hunter filter effectiveness
    hunter_verdicts = Counter()

    # Sophistication distribution (H5)
    sophistication_dist = Counter()

    with open(input_path) as f:
        for line in tqdm(f, total=line_count, desc="Analyzing"):
            d = json.loads(line)
            total += 1

            sa = d.get("statistical_anomaly", {})
            la = d.get("labels_agentic", {})
            lr = d.get("labels_rule_based", {})

            if not sa.get("is_anomaly"):
                continue
            anomalous += 1

            hv = la.get("hunter_verdict")
            if hv is None:
                hunter_errored += 1
                continue

            hunter_processed += 1
            hunter_verdicts[hv] += 1

            if hv == "NOISE":
                hunter_noise += 1
                continue

            hunter_relevant += 1

            # Check analyst verdict
            av = la.get("analyst_verdict")
            if not av or not isinstance(av, dict):
                continue
            analyst_processed += 1

            # Now we have both labels - compare
            dual_labeled += 1

            rule_tactic = lr.get("primary_tactic", "")
            agent_tactic = av.get("primary_tactic", "")
            rule_level = lr.get("level")
            agent_level = av.get("level")

            rule_tactic_dist[rule_tactic] += 1
            agent_tactic_dist[agent_tactic] += 1
            if rule_level is not None:
                rule_level_dist[rule_level] += 1
            if agent_level is not None:
                agent_level_dist[agent_level] += 1

            # Tactic agreement
            rt_norm = normalize_tactic(rule_tactic)
            at_norm = normalize_tactic(agent_tactic)
            if rt_norm == at_norm:
                tactic_agree += 1
            else:
                tactic_confusion[rule_tactic][agent_tactic] += 1
                if len(tactic_disagreements) < sample_size:
                    tactic_disagreements.append({
                        "session_id": d.get("session_id"),
                        "rule_tactic": rule_tactic,
                        "agent_tactic": agent_tactic,
                        "agent_reasoning": av.get("reasoning", ""),
                        "agent_confidence": av.get("confidence"),
                        "commands": d.get("commands", [])[:10],
                        "rule_matched_patterns": lr.get("matched_patterns", []),
                    })

            # Level agreement
            if rule_level is not None and agent_level is not None:
                level_confusion[rule_level][agent_level] += 1
                if rule_level == agent_level:
                    level_agree += 1
                elif len(level_disagreements) < sample_size:
                    level_disagreements.append({
                        "session_id": d.get("session_id"),
                        "rule_level": rule_level,
                        "agent_level": agent_level,
                        "rule_tactic": rule_tactic,
                        "agent_tactic": agent_tactic,
                        "agent_reasoning": av.get("reasoning", ""),
                    })

            # H2: Agent-only detections
            rule_patterns = lr.get("matched_patterns", [])
            if (not rule_patterns and agent_level is not None and agent_level <= 2
                    and len(agent_only_detections) < sample_size):
                agent_only_detections.append({
                    "session_id": d.get("session_id"),
                    "agent_level": agent_level,
                    "agent_tactic": agent_tactic,
                    "agent_reasoning": av.get("reasoning", ""),
                    "technique_ids": av.get("technique_ids", []),
                    "commands": d.get("commands", [])[:10],
                })

            # H5: Sophistication
            soph = av.get("sophistication")
            if soph:
                sophistication_dist[soph] += 1

    return {
        "summary": {
            "total_sessions": total,
            "anomalous": anomalous,
            "hunter_processed": hunter_processed,
            "hunter_errored": hunter_errored,
            "hunter_noise": hunter_noise,
            "hunter_relevant": hunter_relevant,
            "analyst_processed": analyst_processed,
            "dual_labeled": dual_labeled,
        },
        "agreement": {
            "tactic_agreement_rate": tactic_agree / dual_labeled if dual_labeled else 0,
            "tactic_agree": tactic_agree,
            "tactic_disagree": dual_labeled - tactic_agree,
            "level_agreement_rate": level_agree / dual_labeled if dual_labeled else 0,
            "level_agree": level_agree,
            "level_disagree": dual_labeled - level_agree,
        },
        "hypotheses": {
            "H1_tactic_disagreement_rate": 1 - (tactic_agree / dual_labeled) if dual_labeled else None,
            "H2_agent_only_detections": len(agent_only_detections),
            "H2_agent_only_rate": len(agent_only_detections) / dual_labeled if dual_labeled else 0,
            "H3_hunter_filter_rate": hunter_noise / hunter_processed if hunter_processed else 0,
            "H5_sophistication_distribution": dict(sophistication_dist.most_common()),
        },
        "distributions": {
            "rule_tactic": dict(rule_tactic_dist.most_common(20)),
            "agent_tactic": dict(agent_tactic_dist.most_common(20)),
            "rule_level": dict(sorted(rule_level_dist.items())),
            "agent_level": dict(sorted(agent_level_dist.items())),
            "hunter_verdicts": dict(hunter_verdicts.most_common()),
        },
        "confusion_matrices": {
            "level": {str(k): dict(v) for k, v in sorted(level_confusion.items())},
            "tactic": {k: dict(v.most_common(5)) for k, v in
                       sorted(tactic_confusion.items(), key=lambda x: -sum(x[1].values()))[:15]},
        },
        "samples": {
            "tactic_disagreements": tactic_disagreements,
            "level_disagreements": level_disagreements,
            "agent_only_detections": agent_only_detections,
        },
    }


def print_results(results):
    """Pretty-print the analysis results."""
    s = results["summary"]
    a = results["agreement"]
    h = results["hypotheses"]

    print("=" * 70)
    print("LABEL DISAGREEMENT ANALYSIS")
    print("=" * 70)

    print(f"\n## Pipeline Summary")
    print(f"Total sessions: {s['total_sessions']:,}")
    print(f"Statistical anomalies: {s['anomalous']:,} ({s['anomalous']/s['total_sessions']:.2%})")
    print(f"Hunter processed: {s['hunter_processed']:,}")
    print(f"Hunter errored (null verdict): {s['hunter_errored']:,}")
    print(f"Hunter NOISE: {s['hunter_noise']:,}")
    print(f"Hunter RELEVANT: {s['hunter_relevant']:,}")
    print(f"Analyst processed: {s['analyst_processed']:,}")
    print(f"Dual-labeled (comparable): {s['dual_labeled']:,}")

    print(f"\n## Agreement Rates")
    print(f"Tactic agreement: {a['tactic_agree']}/{s['dual_labeled']} = {a['tactic_agreement_rate']:.1%}")
    print(f"Level agreement: {a['level_agree']}/{s['dual_labeled']} = {a['level_agreement_rate']:.1%}")

    print(f"\n## Research Hypotheses")
    print(f"H1 (Tactic accuracy): {a['tactic_disagree']} disagreements to review")
    print(f"H2 (Novel detections): {h['H2_agent_only_detections']} agent-only detections "
          f"({h['H2_agent_only_rate']:.1%} of dual-labeled)")
    print(f"H3 (Hunter filter): {h['H3_hunter_filter_rate']:.1%} filtered as noise")
    print(f"H5 (Sophistication): {h['H5_sophistication_distribution']}")

    print(f"\n## Level Confusion Matrix (rule -> agent)")
    cm = results["confusion_matrices"]["level"]
    if cm:
        agent_levels = sorted({al for counts in cm.values() for al in counts})
        header = "Rule\\Agent | " + " | ".join(f"L{l}" for l in agent_levels)
        print(header)
        print("-" * len(header))
        for rl in sorted(cm.keys()):
            row = f"    L{rl}    | " + " | ".join(
                f"{cm[rl].get(al, 0):>3}" for al in agent_levels
            )
            print(row)

    print(f"\n## Top Tactic Disagreements")
    tc = results["confusion_matrices"]["tactic"]
    for rule_tactic, agent_tactics in list(tc.items())[:10]:
        for agent_tactic, count in list(agent_tactics.items())[:3]:
            print(f"  {rule_tactic} -> {agent_tactic}: {count}")

    print(f"\n## Disagreement Samples")
    for i, sample in enumerate(results["samples"]["tactic_disagreements"][:5]):
        print(f"\n--- Example {i+1} ---")
        print(f"Session: {sample['session_id']}")
        print(f"Rule: {sample['rule_tactic']}")
        print(f"Agent: {sample['agent_tactic']}")
        print(f"Agent reasoning: {sample['agent_reasoning'][:200]}")
        if sample.get("commands"):
            print(f"Commands: {sample['commands'][:5]}")

    print(f"\n## Agent-Only Detections (H2)")
    for i, sample in enumerate(results["samples"]["agent_only_detections"][:5]):
        print(f"\n--- Detection {i+1} ---")
        print(f"Session: {sample['session_id']}")
        print(f"Agent level: {sample['agent_level']}, Tactic: {sample['agent_tactic']}")
        print(f"Techniques: {sample.get('technique_ids', [])}")
        print(f"Reasoning: {sample['agent_reasoning'][:200]}")


def main():
    parser = argparse.ArgumentParser(description="Analyze label disagreements")
    parser.add_argument("--input", "-i", help="Input JSONL file (labeled sessions)")
    parser.add_argument("--es", action="store_true", help="Query from Elasticsearch instead")
    parser.add_argument("--es-host", default=None, help="ES host (default from .env)")
    parser.add_argument("--index", default=None, help="ES index name")
    parser.add_argument("--sample-size", type=int, default=50, help="Max samples per category")
    parser.add_argument("--output", "-o", help="Save full results to JSON file")
    args = parser.parse_args()

    if args.es:
        from elasticsearch import Elasticsearch
        from cowrie_dataset.config import Settings
        settings = Settings()
        es_host = args.es_host or settings.es_host
        index = args.index or settings.get_index_name()
        es = Elasticsearch(es_host,
                           basic_auth=(settings.es_user, settings.es_password)
                           if settings.es_user else None)
        print(f"ES mode not yet implemented for JSONL-first analysis. Use --input instead.")
        return 1
    elif args.input:
        input_path = Path(args.input)
        if not input_path.exists():
            print(f"Error: {input_path} not found")
            return 1
        results = analyze_from_jsonl(input_path, args.sample_size)
    else:
        parser.error("Provide --input or --es")
        return 1

    print_results(results)

    if args.output:
        with open(args.output, 'w') as f:
            json.dump(results, f, indent=2, default=str)
        print(f"\nFull results saved to {args.output}")

    return 0


if __name__ == "__main__":
    exit(main())
