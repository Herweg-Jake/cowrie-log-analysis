#!/usr/bin/env python3
"""
Analyze disagreements between rule-based and agentic labels.

This script queries Elasticsearch for sessions that have been labeled by both
Pipeline A (rule-based) and Pipeline B (agentic), then computes agreement
statistics and surfaces interesting disagreement cases for manual review.

Usage:
    python scripts/analyze_disagreements.py --es-host http://localhost:9200

    # Save full results to JSON
    python scripts/analyze_disagreements.py --es-host http://localhost:9200 \
        --output disagreements.json

    # Use a different index
    python scripts/analyze_disagreements.py --index cowrie-sessions-v2
"""

import argparse
import json
import sys
from collections import Counter

from elasticsearch import Elasticsearch


def query_disagreements(es: Elasticsearch, index: str, size: int = 100) -> list:
    """Find sessions where pipelines disagree on primary tactic."""

    query = {
        "query": {
            "bool": {
                "must": [
                    {"exists": {"field": "labels_rule_based.primary_tactic"}},
                    {"exists": {"field": "labels_agentic.analyst_verdict.primary_tactic"}},
                ],
                "must_not": [
                    {
                        "script": {
                            "script": {
                                "source": (
                                    "doc['labels_rule_based.primary_tactic'].size() > 0 && "
                                    "doc['labels_agentic.analyst_verdict.primary_tactic'].size() > 0 && "
                                    "doc['labels_rule_based.primary_tactic'].value == "
                                    "doc['labels_agentic.analyst_verdict.primary_tactic'].value"
                                )
                            }
                        }
                    }
                ]
            }
        },
        "size": size,
        "_source": [
            "session_id",
            "commands",
            "labels_rule_based",
            "labels_agentic",
            "label_comparison",
            "timing",
            "connection",
            "authentication",
        ],
    }

    response = es.search(index=index, body=query)
    return [hit["_source"] for hit in response["hits"]["hits"]]


def query_level_disagreements(es: Elasticsearch, index: str, size: int = 100) -> list:
    """Find sessions where pipelines disagree on threat level."""

    query = {
        "query": {
            "bool": {
                "must": [
                    {"exists": {"field": "label_comparison.levels_agree"}},
                    {"term": {"label_comparison.levels_agree": False}},
                ]
            }
        },
        "size": size,
        "sort": [
            {"label_comparison.level_difference": {"order": "desc"}},
        ],
        "_source": [
            "session_id",
            "commands",
            "labels_rule_based",
            "labels_agentic",
            "label_comparison",
        ],
    }

    response = es.search(index=index, body=query)
    return [hit["_source"] for hit in response["hits"]["hits"]]


def query_agent_only_detections(es: Elasticsearch, index: str, size: int = 100) -> list:
    """
    Find high-threat sessions where rules said low/no threat but agent
    flagged as significant.

    These are the most interesting cases — potential novel attacks that
    rule-based detection missed entirely.
    """

    query = {
        "query": {
            "bool": {
                "must": [
                    # Rule-based said level 3 (low threat) or no level
                    {"term": {"labels_rule_based.level": 3}},
                    # Agent said level 1 (high threat)
                    {"term": {"labels_agentic.analyst_verdict.level": 1}},
                ]
            }
        },
        "size": size,
        "_source": [
            "session_id",
            "commands",
            "labels_rule_based",
            "labels_agentic",
            "label_comparison",
            "connection",
        ],
    }

    response = es.search(index=index, body=query)
    return [hit["_source"] for hit in response["hits"]["hits"]]


def calculate_agreement_stats(es: Elasticsearch, index: str) -> dict:
    """Calculate overall agreement statistics between the two pipelines."""

    # Total sessions with both labels
    total_query = {
        "query": {
            "bool": {
                "must": [
                    {"exists": {"field": "labels_rule_based"}},
                    {"exists": {"field": "labels_agentic.analyst_verdict"}},
                ]
            }
        }
    }
    total = es.count(index=index, body=total_query)["count"]

    if total == 0:
        return {
            "total_dual_labeled": 0,
            "tactic_agreement_rate": 0,
            "level_agreement_rate": 0,
            "tactic_disagreements": 0,
            "level_disagreements": 0,
        }

    # Tactic agreements (using the pre-computed label_comparison field)
    tactic_agree_query = {
        "query": {"term": {"label_comparison.tactics_agree": True}}
    }
    tactic_agree = es.count(index=index, body=tactic_agree_query)["count"]

    # Level agreements
    level_agree_query = {
        "query": {"term": {"label_comparison.levels_agree": True}}
    }
    level_agree = es.count(index=index, body=level_agree_query)["count"]

    return {
        "total_dual_labeled": total,
        "tactic_agreement_rate": tactic_agree / total if total > 0 else 0,
        "level_agreement_rate": level_agree / total if total > 0 else 0,
        "tactic_disagreements": total - tactic_agree,
        "level_disagreements": total - level_agree,
    }


def calculate_confusion_matrix(es: Elasticsearch, index: str) -> dict:
    """
    Build a confusion-style matrix: rule_level vs agent_level.

    Returns a nested dict where matrix[rule_level][agent_level] = count.
    """

    query = {
        "size": 0,
        "query": {
            "bool": {
                "must": [
                    {"exists": {"field": "label_comparison.rule_level"}},
                    {"exists": {"field": "label_comparison.agent_level"}},
                ]
            }
        },
        "aggs": {
            "by_rule_level": {
                "terms": {"field": "label_comparison.rule_level", "size": 10},
                "aggs": {
                    "by_agent_level": {
                        "terms": {"field": "label_comparison.agent_level", "size": 10}
                    }
                }
            }
        }
    }

    response = es.search(index=index, body=query)
    matrix = {}
    for rule_bucket in response["aggregations"]["by_rule_level"]["buckets"]:
        rule_level = rule_bucket["key"]
        matrix[rule_level] = {}
        for agent_bucket in rule_bucket["by_agent_level"]["buckets"]:
            agent_level = agent_bucket["key"]
            matrix[rule_level][agent_level] = agent_bucket["doc_count"]

    return matrix


def calculate_tactic_distribution(es: Elasticsearch, index: str) -> dict:
    """Get tactic distribution for both pipelines."""

    query = {
        "size": 0,
        "aggs": {
            "rule_tactics": {
                "terms": {"field": "labels_rule_based.primary_tactic", "size": 50}
            },
            "agent_tactics": {
                "terms": {"field": "labels_agentic.analyst_verdict.primary_tactic", "size": 50}
            },
        }
    }

    response = es.search(index=index, body=query)

    rule_dist = {
        b["key"]: b["doc_count"]
        for b in response["aggregations"]["rule_tactics"]["buckets"]
    }
    agent_dist = {
        b["key"]: b["doc_count"]
        for b in response["aggregations"]["agent_tactics"]["buckets"]
    }

    return {"rule_based": rule_dist, "agentic": agent_dist}


def print_session_summary(session: dict, index: int) -> None:
    """Print a compact summary of a disagreement case."""

    rule = session.get("labels_rule_based", {})
    agent = session.get("labels_agentic", {})
    verdict = agent.get("analyst_verdict", {})

    print(f"\n--- Example {index} ---")
    print(f"  Session:      {session.get('session_id', 'N/A')}")
    print(f"  Rule tactic:  {rule.get('primary_tactic', 'N/A')} (level {rule.get('level', '?')})")
    print(f"  Agent tactic: {verdict.get('primary_tactic', 'N/A')} (level {verdict.get('level', '?')})")
    print(f"  Agent confidence: {verdict.get('confidence', 'N/A')}")

    reasoning = verdict.get("reasoning", "")
    if reasoning:
        # Truncate long reasoning
        if len(reasoning) > 200:
            reasoning = reasoning[:200] + "..."
        print(f"  Agent reasoning: {reasoning}")

    commands = session.get("commands", {})
    if isinstance(commands, dict):
        inputs = commands.get("inputs", [])
    elif isinstance(commands, list):
        inputs = [c.get("input", str(c)) if isinstance(c, dict) else str(c) for c in commands]
    else:
        inputs = []

    if inputs:
        print(f"  Commands ({len(inputs)} total): {inputs[:5]}")


def main():
    parser = argparse.ArgumentParser(
        description="Analyze disagreements between rule-based and agentic labels"
    )
    parser.add_argument("--es-host", default="http://localhost:9200",
                        help="Elasticsearch host URL")
    parser.add_argument("--es-user", help="Elasticsearch username")
    parser.add_argument("--es-password", help="Elasticsearch password")
    parser.add_argument("--index", default="cowrie-sessions",
                        help="Elasticsearch index name")
    parser.add_argument("--sample-size", type=int, default=50,
                        help="Number of disagreement examples to fetch")
    parser.add_argument("--output", "-o",
                        help="Output file for full JSON results")
    args = parser.parse_args()

    # Connect to Elasticsearch
    es_kwargs = {"hosts": [args.es_host]}
    if args.es_user and args.es_password:
        es_kwargs["basic_auth"] = (args.es_user, args.es_password)
    es_kwargs["verify_certs"] = False

    es = Elasticsearch(**es_kwargs)

    # Verify connection
    try:
        info = es.info()
        print(f"Connected to Elasticsearch {info['version']['number']}")
    except Exception as e:
        print(f"Error: Could not connect to Elasticsearch at {args.es_host}: {e}")
        return 1

    print()
    print("=" * 60)
    print("LABEL DISAGREEMENT ANALYSIS")
    print("=" * 60)

    # --- Overall Agreement Stats ---
    print("\n[1/5] Computing agreement statistics...")
    stats = calculate_agreement_stats(es, args.index)

    print(f"\n  Overall Statistics:")
    print(f"    Total dual-labeled sessions: {stats['total_dual_labeled']}")
    if stats["total_dual_labeled"] == 0:
        print("\n  No dual-labeled sessions found. Make sure you have indexed")
        print("  data with both labels_rule_based and labels_agentic fields.")
        return 1

    print(f"    Tactic agreement rate: {stats['tactic_agreement_rate']:.1%}")
    print(f"    Level agreement rate:  {stats['level_agreement_rate']:.1%}")
    print(f"    Tactic disagreements:  {stats['tactic_disagreements']}")
    print(f"    Level disagreements:   {stats['level_disagreements']}")

    # --- Confusion Matrix ---
    print(f"\n[2/5] Building level confusion matrix...")
    matrix = calculate_confusion_matrix(es, args.index)

    if matrix:
        all_levels = sorted(set(list(matrix.keys()) + [
            lv for row in matrix.values() for lv in row.keys()
        ]))
        level_names = {1: "High(1)", 2: "Med(2)", 3: "Low(3)"}

        print(f"\n  Rule \\ Agent  ", end="")
        for lv in all_levels:
            print(f"  {level_names.get(lv, str(lv)):>8}", end="")
        print()
        print("  " + "-" * (16 + 10 * len(all_levels)))

        for rule_lv in all_levels:
            print(f"  {level_names.get(rule_lv, str(rule_lv)):>14}", end="")
            for agent_lv in all_levels:
                count = matrix.get(rule_lv, {}).get(agent_lv, 0)
                print(f"  {count:>8}", end="")
            print()

    # --- Tactic Distribution ---
    print(f"\n[3/5] Computing tactic distributions...")
    tactic_dist = calculate_tactic_distribution(es, args.index)

    print(f"\n  Rule-based tactic distribution:")
    for tactic, count in sorted(tactic_dist["rule_based"].items(), key=lambda x: -x[1]):
        print(f"    {tactic:<30} {count:>6}")

    print(f"\n  Agentic tactic distribution:")
    for tactic, count in sorted(tactic_dist["agentic"].items(), key=lambda x: -x[1]):
        print(f"    {tactic:<30} {count:>6}")

    # --- Tactic Disagreement Samples ---
    print(f"\n[4/5] Sampling tactic disagreements (up to {args.sample_size})...")
    disagreements = query_disagreements(es, args.index, args.sample_size)
    print(f"  Found {len(disagreements)} tactic disagreements")

    if disagreements:
        print(f"\n  Top Disagreement Examples:")
        for i, session in enumerate(disagreements[:5], 1):
            print_session_summary(session, i)

    # --- Level Disagreement Samples ---
    level_disagreements = query_level_disagreements(es, args.index, args.sample_size)

    # --- Agent-Only Detections ---
    print(f"\n[5/5] Finding agent-only detections (rules missed)...")
    agent_only = query_agent_only_detections(es, args.index, args.sample_size)
    print(f"  Found {len(agent_only)} sessions where agent found high threats rules missed")

    if agent_only:
        print(f"\n  Agent-Only Detection Examples:")
        for i, session in enumerate(agent_only[:5], 1):
            print_session_summary(session, i)

    # --- Summary ---
    print(f"\n{'='*60}")
    print("SUMMARY")
    print(f"{'='*60}")
    print(f"  Dual-labeled sessions:      {stats['total_dual_labeled']}")
    print(f"  Tactic agreement:           {stats['tactic_agreement_rate']:.1%}")
    print(f"  Level agreement:            {stats['level_agreement_rate']:.1%}")
    print(f"  Tactic disagreements:       {len(disagreements)} sampled")
    print(f"  Level disagreements:        {len(level_disagreements)} sampled")
    print(f"  Agent-only high-threat:     {len(agent_only)}")

    # --- Save Results ---
    if args.output:
        results = {
            "stats": stats,
            "confusion_matrix": {
                str(k): {str(k2): v2 for k2, v2 in v.items()}
                for k, v in matrix.items()
            },
            "tactic_distributions": tactic_dist,
            "tactic_disagreements": disagreements,
            "level_disagreements": level_disagreements,
            "agent_only_detections": agent_only,
        }

        with open(args.output, 'w') as f:
            json.dump(results, f, indent=2, default=str)
        print(f"\n  Full results saved to {args.output}")

    print()
    return 0


if __name__ == "__main__":
    sys.exit(main())
