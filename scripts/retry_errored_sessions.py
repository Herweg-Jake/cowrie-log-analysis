#!/usr/bin/env python3
"""
Retry errored sessions from a previous agent pipeline run.

Extracts sessions that were sent to the hunter but got no verdict (null hunter_verdict),
re-runs them through the pipeline at reduced concurrency, and merges the results
back into the original labeled_sessions.jsonl by session_id.

Usage:
    # Step 1: Re-run errored sessions
    python scripts/retry_errored_sessions.py --input src/errored_sessions.jsonl \
        --output src/retried_sessions.jsonl --concurrency 20

    # Step 2: Merge results back into the main file
    python scripts/retry_errored_sessions.py --merge \
        --original src/labeled_sessions.jsonl \
        --retried src/retried_sessions.jsonl \
        --output src/labeled_sessions_merged.jsonl
"""

import argparse
import json
import os
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

try:
    from tqdm import tqdm
except ImportError:
    def tqdm(iterable, **kwargs):
        total = kwargs.get('total', 0)
        for i, item in enumerate(iterable):
            if i % 100 == 0:
                print(f"Progress: {i}/{total}")
            yield item


def _load_env():
    """Load .env file from project root if it exists."""
    env_path = Path(__file__).resolve().parent.parent / ".env"
    if not env_path.exists():
        return
    with open(env_path) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, value = line.partition("=")
            key = key.strip()
            value = value.strip()
            if key not in os.environ:
                os.environ[key] = value


_load_env()


def _import_agents():
    from cowrie_dataset.agents import AgentConfig, AgentRunner, AnalystAgent
    return AgentConfig, AgentRunner, AnalystAgent


def process_session(runner, session):
    """Process a single session through the full pipeline."""
    result = runner.process(session)
    session["labels_agentic"] = result.to_dict()
    return session, result


def reanalyze_session(analyst, session):
    """Re-run only the analyst on a session that already passed hunter."""
    resp = analyst.analyze(session)
    la = session.get("labels_agentic", {})
    if resp.success:
        la["analyst_verdict"] = {
            "level": resp.result.get("threat_level", 2),
            "primary_tactic": resp.result.get("primary_tactic", "Unknown"),
            "all_tactics": resp.result.get("all_tactics", []),
            "technique_ids": resp.result.get("technique_ids", []),
            "sophistication": resp.result.get("sophistication", "UNKNOWN"),
            "intent": resp.result.get("intent", ""),
            "reasoning": resp.result.get("reasoning", ""),
            "confidence": resp.result.get("confidence", 0.5),
            "iocs": resp.result.get("iocs", []),
        }
    else:
        la["analyst_verdict"] = {"error": resp.error, "stage": "analyst_retry"}
    pm = la.get("pipeline_metrics", {})
    pm["total_cost_usd"] = round(pm.get("total_cost_usd", 0) + resp.estimated_cost, 6)
    pm["total_latency_ms"] = pm.get("total_latency_ms", 0) + resp.latency_ms
    la["pipeline_metrics"] = pm
    session["labels_agentic"] = la
    return session, resp


def run_retry(args):
    """Re-run errored sessions through the agent pipeline."""
    input_path = Path(args.input)
    output_path = Path(args.output)

    if not input_path.exists():
        print(f"Error: Input file not found: {input_path}")
        return 1

    line_count = sum(1 for _ in open(input_path))
    if args.limit:
        line_count = min(line_count, args.limit)

    print(f"Retrying {line_count} errored sessions at concurrency {args.concurrency}...")

    AgentConfig, AgentRunner, _ = _import_agents()
    config = AgentConfig(**({"model": args.model} if args.model else {}))
    runner = AgentRunner(config=config, skip_non_anomalous=False)
    print(f"Using {config.model} with {config.requests_per_minute} RPM limit")

    processed = 0
    succeeded = 0
    still_errored = 0
    relevant_count = 0
    write_lock = threading.Lock()

    with open(input_path) as f_in, open(output_path, 'w') as f_out:
        pbar = tqdm(total=line_count, desc="Retrying")
        pending = set()

        def handle_result(future):
            nonlocal processed, succeeded, still_errored, relevant_count
            try:
                session_out, result = future.result()
                with write_lock:
                    f_out.write(json.dumps(session_out) + '\n')
                if result.hunter_verdict is not None:
                    succeeded += 1
                    if result.hunter_verdict == "RELEVANT":
                        relevant_count += 1
                else:
                    still_errored += 1
                processed += 1
            except Exception as e:
                processed += 1
                still_errored += 1
                print(f"\nError: {e}")
            pbar.update(1)

        with ThreadPoolExecutor(max_workers=args.concurrency) as executor:
            for i, line in enumerate(f_in):
                if args.limit and i >= args.limit:
                    break

                session = json.loads(line)
                future = executor.submit(process_session, runner, session)
                pending.add(future)

                if len(pending) >= args.concurrency * 2:
                    done = {f for f in pending if f.done()}
                    for f in done:
                        handle_result(f)
                    pending -= done

            for f in as_completed(pending):
                handle_result(f)

        pbar.close()

    stats = runner.get_stats()
    print(f"\n{'='*60}")
    print(f"RETRY COMPLETE")
    print(f"{'='*60}")
    print(f"Processed: {processed}")
    print(f"Succeeded (got verdict): {succeeded}")
    print(f"Still errored: {still_errored}")
    print(f"Relevant: {relevant_count}")
    print(f"Total cost: ${stats['total_cost_usd']:.4f}")
    print(f"Errors: {stats['errors']}")
    print(f"Output: {output_path}")
    print(f"{'='*60}")
    return 0


def run_reanalyze(args):
    """Re-run only the analyst on sessions that passed hunter but had parse failures."""
    input_path = Path(args.input)
    output_path = Path(args.output)

    if not input_path.exists():
        print(f"Error: Input file not found: {input_path}")
        return 1

    line_count = sum(1 for _ in open(input_path))
    if args.limit:
        line_count = min(line_count, args.limit)

    print(f"Re-analyzing {line_count} sessions (analyst only) at concurrency {args.concurrency}...")

    AgentConfig, _, AnalystAgent = _import_agents()
    config = AgentConfig(**({"model": args.model} if args.model else {}))
    analyst = AnalystAgent(config)
    print(f"Using {config.model}")

    processed = 0
    succeeded = 0
    still_errored = 0
    write_lock = threading.Lock()

    with open(input_path) as f_in, open(output_path, 'w') as f_out:
        pbar = tqdm(total=line_count, desc="Re-analyzing")
        pending = set()

        def handle_result(future):
            nonlocal processed, succeeded, still_errored
            try:
                session_out, resp = future.result()
                with write_lock:
                    f_out.write(json.dumps(session_out) + '\n')
                if resp.success:
                    succeeded += 1
                else:
                    still_errored += 1
                processed += 1
            except Exception as e:
                processed += 1
                still_errored += 1
                print(f"\nError: {e}")
            pbar.update(1)

        with ThreadPoolExecutor(max_workers=args.concurrency) as executor:
            for i, line in enumerate(f_in):
                if args.limit and i >= args.limit:
                    break

                session = json.loads(line)
                future = executor.submit(reanalyze_session, analyst, session)
                pending.add(future)

                if len(pending) >= args.concurrency * 2:
                    done = {f for f in pending if f.done()}
                    for f in done:
                        handle_result(f)
                    pending -= done

            for f in as_completed(pending):
                handle_result(f)

        pbar.close()

    print(f"\n{'='*60}")
    print(f"RE-ANALYSIS COMPLETE")
    print(f"{'='*60}")
    print(f"Processed: {processed}")
    print(f"Succeeded: {succeeded}")
    print(f"Still errored: {still_errored}")
    print(f"Output: {output_path}")
    print(f"{'='*60}")
    return 0


def run_merge(args):
    """Merge retried results back into the original file by session_id."""
    original_path = Path(args.original)
    retried_path = Path(args.retried)
    output_path = Path(args.output)

    if not original_path.exists():
        print(f"Error: Original file not found: {original_path}")
        return 1
    if not retried_path.exists():
        print(f"Error: Retried file not found: {retried_path}")
        return 1

    # Load retried sessions into a dict keyed by session_id
    print("Loading retried sessions...")
    retried = {}
    with open(retried_path) as f:
        for line in f:
            d = json.loads(line)
            sid = d.get("session_id")
            if sid:
                retried[sid] = d
    print(f"Loaded {len(retried)} retried sessions")

    # Count original file
    original_count = sum(1 for _ in open(original_path))
    print(f"Merging into {original_count} sessions...")

    merged = 0
    unchanged = 0
    with open(original_path) as f_in, open(output_path, 'w') as f_out:
        for line in tqdm(f_in, total=original_count, desc="Merging"):
            d = json.loads(line)
            sid = d.get("session_id")

            if sid in retried:
                # Replace labels_agentic with retried version
                d["labels_agentic"] = retried[sid]["labels_agentic"]
                merged += 1
            else:
                unchanged += 1

            f_out.write(json.dumps(d) + '\n')

    print(f"\n{'='*60}")
    print(f"MERGE COMPLETE")
    print(f"{'='*60}")
    print(f"Total sessions: {merged + unchanged}")
    print(f"Merged (updated): {merged}")
    print(f"Unchanged: {unchanged}")
    print(f"Output: {output_path}")
    print(f"{'='*60}")

    # Verify
    if merged != len(retried):
        print(f"\nWARNING: {len(retried) - merged} retried sessions not found in original!")

    return 0


def main():
    parser = argparse.ArgumentParser(description="Retry errored sessions and merge results")
    subparsers = parser.add_subparsers(dest="command")

    # Retry subcommand
    retry_parser = subparsers.add_parser("retry", help="Re-run errored sessions")
    retry_parser.add_argument("--input", "-i", required=True, help="Input JSONL of errored sessions")
    retry_parser.add_argument("--output", "-o", required=True, help="Output JSONL")
    retry_parser.add_argument("--model", default=None, help="Override model")
    retry_parser.add_argument("--concurrency", type=int, default=20,
                              help="Concurrent workers (default 20, lower than normal for retries)")
    retry_parser.add_argument("--limit", type=int, help="Limit sessions to retry")

    # Reanalyze subcommand (analyst-only re-run)
    reanalyze_parser = subparsers.add_parser("reanalyze",
        help="Re-run analyst only on sessions with parse failures")
    reanalyze_parser.add_argument("--input", "-i", required=True, help="Input JSONL of parse-failed sessions")
    reanalyze_parser.add_argument("--output", "-o", required=True, help="Output JSONL")
    reanalyze_parser.add_argument("--model", default=None, help="Override model")
    reanalyze_parser.add_argument("--concurrency", type=int, default=20)
    reanalyze_parser.add_argument("--limit", type=int, help="Limit sessions")

    # Merge subcommand
    merge_parser = subparsers.add_parser("merge", help="Merge retried results back")
    merge_parser.add_argument("--original", required=True, help="Original labeled_sessions.jsonl")
    merge_parser.add_argument("--retried", required=True, help="Retried sessions output")
    merge_parser.add_argument("--output", "-o", required=True, help="Merged output file")

    args = parser.parse_args()

    if args.command == "retry":
        return run_retry(args)
    elif args.command == "reanalyze":
        return run_reanalyze(args)
    elif args.command == "merge":
        return run_merge(args)
    else:
        parser.print_help()
        return 1


if __name__ == "__main__":
    exit(main())
