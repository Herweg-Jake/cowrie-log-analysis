#!/usr/bin/env python3
"""
Cost-Benefit Analysis for Rule-Based vs Agentic Pipeline.

Compares processing speed, cost per session, detection coverage,
and false positive reduction. Works from JSONL or Elasticsearch.

Usage:
    # From JSONL
    python scripts/cost_benefit_analysis.py --input src/labeled_sessions.jsonl

    # Save report
    python scripts/cost_benefit_analysis.py --input src/labeled_sessions.jsonl --output cost_report.json
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


def analyze_from_jsonl(input_path):
    """Compute cost-benefit metrics from JSONL file."""
    line_count = sum(1 for _ in open(input_path))

    total = 0
    anomalous = 0

    # Agent pipeline metrics
    sent_to_hunter = 0
    sent_to_analyst = 0
    hunter_noise = 0
    hunter_relevant = 0
    hunter_errored = 0

    total_cost = 0.0
    total_latency_ms = 0
    hunter_only_cost = 0.0
    analyst_cost = 0.0

    # Rule-based coverage
    rule_levels = Counter()
    rule_with_patterns = 0
    rule_no_patterns = 0

    # Agent coverage
    agent_levels = Counter()
    agent_novel_findings = 0  # agent found something rules missed

    # Per-session costs for distribution
    session_costs = []

    with open(input_path) as f:
        for line in tqdm(f, total=line_count, desc="Analyzing costs"):
            d = json.loads(line)
            total += 1

            lr = d.get("labels_rule_based", {})
            la = d.get("labels_agentic", {})
            sa = d.get("statistical_anomaly", {})
            pm = la.get("pipeline_metrics", {})

            # Rule-based stats
            rl = lr.get("level")
            if rl is not None:
                rule_levels[rl] += 1
            patterns = lr.get("matched_patterns", [])
            if patterns:
                rule_with_patterns += 1
            else:
                rule_no_patterns += 1

            if not sa.get("is_anomaly"):
                continue
            anomalous += 1

            # Agent pipeline stats
            cost = pm.get("total_cost_usd", 0.0)
            latency = pm.get("total_latency_ms", 0)
            total_cost += cost
            total_latency_ms += latency

            if pm.get("sent_to_hunter"):
                sent_to_hunter += 1

            hv = la.get("hunter_verdict")
            if hv is None and pm.get("sent_to_hunter"):
                hunter_errored += 1
                continue

            if hv == "NOISE":
                hunter_noise += 1
                hunter_only_cost += cost
            elif hv == "RELEVANT":
                hunter_relevant += 1
                if pm.get("sent_to_analyst"):
                    sent_to_analyst += 1
                    analyst_cost += cost

                    # Check agent verdict
                    av = la.get("analyst_verdict")
                    if av and isinstance(av, dict):
                        al = av.get("level")
                        if al is not None:
                            agent_levels[al] += 1
                        # Novel finding: agent found high/medium threat but rules had no patterns
                        if al is not None and al <= 2 and not patterns:
                            agent_novel_findings += 1

                if cost > 0:
                    session_costs.append(cost)

    # Cost distribution
    cost_percentiles = {}
    if session_costs:
        session_costs.sort()
        n = len(session_costs)
        cost_percentiles = {
            "p25": session_costs[int(n * 0.25)],
            "p50": session_costs[int(n * 0.50)],
            "p75": session_costs[int(n * 0.75)],
            "p95": session_costs[int(n * 0.95)],
            "max": session_costs[-1],
            "min": session_costs[0],
        }

    return {
        "dataset": {
            "total_sessions": total,
            "anomalous": anomalous,
            "anomaly_rate": anomalous / total if total else 0,
        },
        "rule_based": {
            "coverage": {
                "with_patterns": rule_with_patterns,
                "no_patterns": rule_no_patterns,
                "pattern_rate": rule_with_patterns / total if total else 0,
            },
            "level_distribution": dict(sorted(rule_levels.items())),
            "cost_usd": 0.0,
            "speed_estimate_sessions_per_sec": 10000,
        },
        "agent_pipeline": {
            "sent_to_hunter": sent_to_hunter,
            "hunter_noise": hunter_noise,
            "hunter_relevant": hunter_relevant,
            "hunter_errored": hunter_errored,
            "sent_to_analyst": sent_to_analyst,
            "hunter_filter_rate": hunter_noise / (hunter_noise + hunter_relevant)
                if (hunter_noise + hunter_relevant) else 0,
            "level_distribution": dict(sorted(agent_levels.items())),
            "novel_findings": agent_novel_findings,
            "novel_finding_rate": agent_novel_findings / sent_to_analyst if sent_to_analyst else 0,
        },
        "cost": {
            "total_cost_usd": round(total_cost, 4),
            "hunter_only_cost_usd": round(hunter_only_cost, 4),
            "analyst_cost_usd": round(analyst_cost, 4),
            "avg_cost_per_anomalous_session": round(total_cost / anomalous, 6) if anomalous else 0,
            "avg_cost_per_hunter_call": round(total_cost / sent_to_hunter, 6) if sent_to_hunter else 0,
            "avg_cost_per_analyst_call": round(analyst_cost / sent_to_analyst, 6) if sent_to_analyst else 0,
            "cost_per_novel_finding": round(total_cost / agent_novel_findings, 4) if agent_novel_findings else None,
            "cost_distribution": cost_percentiles,
        },
        "latency": {
            "total_latency_s": total_latency_ms / 1000,
            "avg_latency_per_session_ms": total_latency_ms / sent_to_hunter if sent_to_hunter else 0,
        },
        "projections": {
            "cost_1m_sessions": round(
                (total_cost / anomalous if anomalous else 0)
                * (anomalous / total if total else 0)
                * 1_000_000, 2
            ) if total else 0,
            "time_1m_sessions_hours": round(
                (total_latency_ms / sent_to_hunter if sent_to_hunter else 0)
                * (anomalous / total if total else 0)
                * 1_000_000 / 1000 / 3600, 1
            ) if total else 0,
        },
        "h4_cost_per_insight": {
            "cost_per_novel_finding_usd": round(total_cost / agent_novel_findings, 4) if agent_novel_findings else None,
            "threshold_met": (total_cost / agent_novel_findings < 1.0) if agent_novel_findings else None,
            "description": "H4: Agent cost is acceptable if < $1 per novel finding",
        },
    }


def print_results(results):
    """Pretty-print cost-benefit analysis."""
    d = results["dataset"]
    rb = results["rule_based"]
    ap = results["agent_pipeline"]
    c = results["cost"]
    l = results["latency"]
    p = results["projections"]
    h4 = results["h4_cost_per_insight"]

    print("=" * 70)
    print("COST-BENEFIT ANALYSIS: Rule-Based vs Agentic Pipeline")
    print("=" * 70)

    print(f"\n## Dataset Summary")
    print(f"Total sessions: {d['total_sessions']:,}")
    print(f"Statistical anomalies: {d['anomalous']:,} ({d['anomaly_rate']:.2%})")

    print(f"\n## Rule-Based Pipeline (Free, ~10K sessions/sec)")
    print(f"Sessions with pattern matches: {rb['coverage']['with_patterns']:,} "
          f"({rb['coverage']['pattern_rate']:.2%})")
    print(f"Level distribution: {rb['level_distribution']}")

    print(f"\n## Agent Pipeline")
    print(f"Sent to Hunter: {ap['sent_to_hunter']:,}")
    print(f"  -> NOISE: {ap['hunter_noise']:,}")
    print(f"  -> RELEVANT: {ap['hunter_relevant']:,}")
    print(f"  -> Errored: {ap['hunter_errored']:,}")
    print(f"Hunter filter rate: {ap['hunter_filter_rate']:.1%}")
    print(f"Sent to Analyst: {ap['sent_to_analyst']:,}")
    print(f"Agent level distribution: {ap['level_distribution']}")
    print(f"Novel findings (agent-only): {ap['novel_findings']:,} "
          f"({ap['novel_finding_rate']:.1%} of analyzed)")

    print(f"\n## Cost Metrics")
    print(f"Total API cost: ${c['total_cost_usd']:.4f}")
    print(f"  Hunter-only cost: ${c['hunter_only_cost_usd']:.4f}")
    print(f"  Analyst cost: ${c['analyst_cost_usd']:.4f}")
    print(f"Avg cost per anomalous session: ${c['avg_cost_per_anomalous_session']:.6f}")
    print(f"Avg cost per hunter call: ${c['avg_cost_per_hunter_call']:.6f}")
    print(f"Avg cost per analyst call: ${c['avg_cost_per_analyst_call']:.6f}")
    if c['cost_distribution']:
        cd = c['cost_distribution']
        print(f"Cost distribution: p25=${cd['p25']:.6f} p50=${cd['p50']:.6f} "
              f"p75=${cd['p75']:.6f} p95=${cd['p95']:.6f} max=${cd['max']:.6f}")

    print(f"\n## Speed Metrics")
    print(f"Total agent time: {l['total_latency_s']:.1f}s")
    print(f"Avg latency per session: {l['avg_latency_per_session_ms']:.0f}ms")

    print(f"\n## Projections (1M sessions)")
    print(f"Projected cost: ${p['cost_1m_sessions']:,.2f}")
    print(f"Projected time: {p['time_1m_sessions_hours']:,.1f} hours")

    print(f"\n## H4: Cost Per Novel Insight")
    if h4['cost_per_novel_finding_usd'] is not None:
        status = "PASS" if h4['threshold_met'] else "FAIL"
        print(f"Cost per novel finding: ${h4['cost_per_novel_finding_usd']:.4f} [{status}]")
        print(f"Threshold: < $1.00 per novel finding")
    else:
        print(f"No novel findings yet — cannot evaluate")


def main():
    parser = argparse.ArgumentParser(description="Cost-benefit analysis")
    parser.add_argument("--input", "-i", help="Input JSONL file")
    parser.add_argument("--output", "-o", help="Save results to JSON")
    args = parser.parse_args()

    if not args.input:
        parser.error("Provide --input")
        return 1

    input_path = Path(args.input)
    if not input_path.exists():
        print(f"Error: {input_path} not found")
        return 1

    results = analyze_from_jsonl(input_path)
    print_results(results)

    if args.output:
        with open(args.output, 'w') as f:
            json.dump(results, f, indent=2, default=str)
        print(f"\nFull results saved to {args.output}")

    return 0


if __name__ == "__main__":
    exit(main())
