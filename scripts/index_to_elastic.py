#!/usr/bin/env python3
"""
Index labeled sessions to Elasticsearch.

This script takes the output from the agent pipeline (labeled_sessions.jsonl)
and indexes it to Elasticsearch, merging both rule-based and agentic labels.

Usage:
    python scripts/index_to_elastic.py --input labeled_sessions.jsonl

    # With custom ES settings
    python scripts/index_to_elastic.py --input labeled_sessions.jsonl \
        --es-host http://localhost:9200 \
        --index cowrie-sessions

    # Create fresh index
    python scripts/index_to_elastic.py --input labeled_sessions.jsonl --create-index
"""

import argparse
import json
import os
from pathlib import Path
from datetime import datetime

try:
    from tqdm import tqdm
except ImportError:
    def tqdm(iterable, **kwargs):
        total = kwargs.get('total', 0)
        for i, item in enumerate(iterable):
            if i % 100 == 0:
                print(f"Progress: {i}/{total}")
            yield item

from cowrie_dataset.sinks.elasticsearch_sink import ElasticsearchSink
from cowrie_dataset.config import Settings


def compute_label_comparison(rule_labels: dict, agent_labels: dict) -> dict:
    """
    Compute comparison metrics between rule-based and agentic labels.
    
    Returns dict with comparison flags for Kibana filtering.
    """
    # Get levels
    rule_level = rule_labels.get("level")
    
    analyst_verdict = agent_labels.get("analyst_verdict")
    agent_level = analyst_verdict.get("level") if analyst_verdict else None
    
    # Get tactics
    rule_tactic = rule_labels.get("primary_tactic", "").lower()
    agent_tactic = ""
    if analyst_verdict:
        agent_tactic = analyst_verdict.get("primary_tactic", "").lower()
    
    return {
        "tactics_agree": rule_tactic == agent_tactic if agent_tactic else None,
        "levels_agree": rule_level == agent_level if agent_level else None,
        "rule_level": rule_level,
        "agent_level": agent_level,
        "level_difference": (
            abs(rule_level - agent_level) 
            if rule_level is not None and agent_level is not None else None
        ),
    }


def main():
    parser = argparse.ArgumentParser(description="Index labeled sessions to Elasticsearch")
    parser.add_argument("--input", "-i", required=True, help="Input JSONL file (output from agent pipeline)")
    parser.add_argument("--es-host", help="Elasticsearch host URL (overrides .env)")
    parser.add_argument("--es-user", help="Elasticsearch username")
    parser.add_argument("--es-password", help="Elasticsearch password")
    parser.add_argument("--index", help="Index name (default: from settings)")
    parser.add_argument("--create-index", "-c", action="store_true", help="Create index before indexing")
    parser.add_argument("--delete-index", action="store_true", help="Delete existing index first (DANGER!)")
    parser.add_argument("--bulk-size", type=int, default=500, help="Bulk index batch size")
    parser.add_argument("--limit", type=int, help="Limit number of sessions to index")
    args = parser.parse_args()
    
    # Load settings
    settings = Settings()
    
    # Override with args
    es_host = args.es_host or settings.es_host
    es_user = args.es_user or settings.es_user
    es_password = args.es_password or settings.es_password
    index_name = args.index or settings.get_index_name()
    
    # Check input file
    input_path = Path(args.input)
    if not input_path.exists():
        print(f"Error: Input file not found: {input_path}")
        return 1
    
    # Count lines
    line_count = sum(1 for _ in open(input_path))
    if args.limit:
        line_count = min(line_count, args.limit)
    
    print(f"Indexing {line_count} sessions to {es_host}/{index_name}")
    
    # Initialize sink
    sink = ElasticsearchSink(
        host=es_host,
        username=es_user,
        password=es_password,
        index_name=index_name,
        bulk_size=args.bulk_size,
    )
    
    if args.create_index:
        print(f"Creating index '{index_name}'...")
        sink.create_index(delete_existing=args.delete_index)
    
    # Process and index
    start_time = datetime.now()
    indexed = 0
    comparisons_added = 0
    
    try:
        with open(input_path) as f:
            for i, line in enumerate(tqdm(f, total=line_count)):
                if args.limit and i >= args.limit:
                    break
                
                doc = json.loads(line)
                
                # Add label comparison if both labels exist
                rule_labels = doc.get("labels_rule_based", {})
                agent_labels = doc.get("labels_agentic", {})
                
                if rule_labels and agent_labels and agent_labels.get("analyst_verdict"):
                    doc["label_comparison"] = compute_label_comparison(rule_labels, agent_labels)
                    comparisons_added += 1
                
                sink.add(doc)
                indexed += 1
        
        # Flush remaining
        sink.flush()
        sink.refresh()
        
    finally:
        sink.close()
    
    elapsed = datetime.now() - start_time
    stats = sink.get_stats()
    
    print(f"\n{'='*60}")
    print("INDEXING COMPLETE")
    print(f"{'='*60}")
    print(f"Time elapsed: {elapsed}")
    print(f"Sessions indexed: {stats['indexed']}")
    print(f"Errors: {stats['errors']}")
    print(f"Label comparisons added: {comparisons_added}")
    print(f"{'='*60}")
    
    return 0


if __name__ == "__main__":
    exit(main())
