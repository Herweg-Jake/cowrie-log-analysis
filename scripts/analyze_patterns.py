#!/usr/bin/env python3
"""
Phase 1 of the Human Annotation Plan: deeper pattern analysis.

For each major confusion matrix cell (rule_tactic x agent_tactic, rule_level x
agent_level), extract:
  - session_type distribution (failed_auth_only / success_no_commands / success_with_commands)
  - command count distribution (buckets: 0, 1-5, 6-20, 21+)
  - most common commands
  - agent confidence distribution
  - agent sophistication labels
  - location (sensor) distribution

The goal is to answer questions like:
  - Are the 1,405 "Discovery -> Initial Access" sessions mostly success_no_commands?
  - For sessions upgraded from level 3 -> level 2, what commands drive that call?
  - Are level 3 -> level 1 upgrades genuine high-severity sessions?
  - Are agreement sessions trivially obvious or ambiguous?

Usage:
    python scripts/analyze_patterns.py --input src/labeled_sessions.jsonl
    python scripts/analyze_patterns.py -i src/labeled_sessions.jsonl -o pattern_results.json

The script only inspects dual-labeled sessions (those with both rule-based and
agent analyst verdicts), which is what the sampling step cares about.
"""

import argparse
import json
from collections import Counter, defaultdict
from pathlib import Path

try:
    from tqdm import tqdm
except ImportError:
    def tqdm(iterable, **kwargs):
        total = kwargs.get("total", 0)
        for i, item in enumerate(iterable):
            if total and i % 1000 == 0:
                print(f"Progress: {i}/{total}")
            yield item


# Cells the plan explicitly calls out as worth a deep dive. Anything bigger
# than MIN_CELL_SIZE gets auto-included too.
FOCUS_TACTIC_CELLS = [
    ("Discovery", "Initial Access"),
    ("Command and Control", "Initial Access"),
    ("No Action", "Initial Access"),
    ("Command and Control", "Execution"),
    ("Unknown Activity (Low)", "Initial Access"),
    ("Unknown Activity (High)", "Persistence"),
    ("No Action", "Execution"),
    ("Impact", "Persistence"),
]

FOCUS_LEVEL_CELLS = [
    (3, 2),  # the "upgrade to medium" bucket
    (3, 1),  # the "upgrade to high" bucket
    (1, 2),  # the "downgrade from high" bucket
    (2, 1),
    (2, 3),
]

MIN_CELL_SIZE = 50  # auto-profile any cell with at least this many sessions


def _cmd_bucket(n: int) -> str:
    if n == 0:
        return "0"
    if n <= 5:
        return "1-5"
    if n <= 20:
        return "6-20"
    return "21+"


def _norm_tactic(t: str) -> str:
    if not t:
        return ""
    return t.strip()


def _blank_profile() -> dict:
    return {
        "count": 0,
        "session_type": Counter(),
        "command_bucket": Counter(),
        "top_commands": Counter(),
        "agent_confidence": Counter(),
        "agent_sophistication": Counter(),
        "rule_sophistication_score": Counter(),
        "location": Counter(),
        "auth_success": Counter(),
        "has_download": 0,
        "has_upload": 0,
        "avg_duration_s": 0.0,
        "_duration_sum": 0.0,
        "_duration_n": 0,
        "sample_session_ids": [],
    }


def _update_profile(profile: dict, d: dict, av: dict, lr: dict, max_samples: int = 10):
    profile["count"] += 1

    meta = d.get("meta", {})
    profile["session_type"][meta.get("session_type", "unknown")] += 1

    cmds_block = d.get("commands") or {}
    # commands can be either a list (old format) or a dict with total_count/inputs (new format)
    if isinstance(cmds_block, dict):
        cmd_count = cmds_block.get("total_count", 0)
        cmd_inputs = cmds_block.get("inputs", []) or []
    else:
        cmd_count = len(cmds_block)
        cmd_inputs = [c.get("input", "") if isinstance(c, dict) else str(c) for c in cmds_block]

    profile["command_bucket"][_cmd_bucket(cmd_count)] += 1
    for cmd in cmd_inputs[:20]:
        # first token is usually the command name; truncate long argv blobs
        head = (cmd or "").strip().split()[:1]
        if head:
            profile["top_commands"][head[0][:40]] += 1

    profile["agent_confidence"][str(av.get("confidence"))] += 1
    profile["agent_sophistication"][str(av.get("sophistication"))] += 1
    profile["rule_sophistication_score"][str(lr.get("sophistication_score"))] += 1
    profile["location"][d.get("location", "unknown")] += 1

    auth = d.get("authentication") or {}
    profile["auth_success"][str(bool(auth.get("success")))] += 1

    dl = d.get("downloads") or {}
    ul = d.get("uploads") or {}
    if isinstance(dl, dict) and dl.get("count"):
        profile["has_download"] += 1
    if isinstance(ul, dict) and ul.get("count"):
        profile["has_upload"] += 1

    timing = d.get("timing") or {}
    dur = timing.get("duration_s")
    if isinstance(dur, (int, float)):
        profile["_duration_sum"] += dur
        profile["_duration_n"] += 1

    if len(profile["sample_session_ids"]) < max_samples:
        profile["sample_session_ids"].append(d.get("session_id"))


def _finalize_profile(profile: dict, top_n: int = 15) -> dict:
    n = profile["_duration_n"]
    profile["avg_duration_s"] = (profile["_duration_sum"] / n) if n else None
    profile.pop("_duration_sum", None)
    profile.pop("_duration_n", None)

    # Convert Counters to ordered dicts, keeping only the top N for command lists
    return {
        "count": profile["count"],
        "session_type": dict(profile["session_type"].most_common()),
        "command_bucket": dict(profile["command_bucket"].most_common()),
        "top_commands": dict(profile["top_commands"].most_common(top_n)),
        "agent_confidence": dict(profile["agent_confidence"].most_common()),
        "agent_sophistication": dict(profile["agent_sophistication"].most_common()),
        "rule_sophistication_score": dict(profile["rule_sophistication_score"].most_common()),
        "location": dict(profile["location"].most_common()),
        "auth_success": dict(profile["auth_success"].most_common()),
        "has_download": profile["has_download"],
        "has_upload": profile["has_upload"],
        "avg_duration_s": profile["avg_duration_s"],
        "sample_session_ids": profile["sample_session_ids"],
    }


def analyze(input_path: Path, top_n_cells: int = 20) -> dict:
    total = 0
    dual = 0

    # Full confusion matrices (so we can look up cell sizes).
    tactic_matrix = defaultdict(Counter)
    level_matrix = defaultdict(Counter)

    # First pass: compute confusion matrix cell sizes so we know which ones
    # to deep-profile. We do this in a single streaming pass, so we profile
    # every cell we might care about eagerly and prune later.
    tactic_profiles = defaultdict(_blank_profile)  # key: (rule_tactic, agent_tactic)
    level_profiles = defaultdict(_blank_profile)   # key: (rule_level, agent_level)

    # Also profile "agreement" cells (so we can spot trivially obvious vs ambiguous
    # agreements) and "novel detection" cells (Pipeline A matched nothing but B flagged).
    agreement_profiles = defaultdict(_blank_profile)  # key: agreed_tactic
    novel_detection_profile = _blank_profile()

    line_count = sum(1 for _ in open(input_path))

    with open(input_path) as f:
        for line in tqdm(f, total=line_count, desc="Scanning"):
            try:
                d = json.loads(line)
            except json.JSONDecodeError:
                continue
            total += 1

            la = d.get("labels_agentic") or {}
            lr = d.get("labels_rule_based") or {}
            av = la.get("analyst_verdict")
            if not av or not isinstance(av, dict):
                continue
            if not lr:
                continue

            rule_tactic = _norm_tactic(lr.get("primary_tactic", ""))
            agent_tactic = _norm_tactic(av.get("primary_tactic", ""))
            rule_level = lr.get("level")
            agent_level = av.get("level")

            if not rule_tactic or not agent_tactic:
                continue

            dual += 1
            tactic_matrix[rule_tactic][agent_tactic] += 1
            if rule_level is not None and agent_level is not None:
                level_matrix[rule_level][agent_level] += 1

            _update_profile(tactic_profiles[(rule_tactic, agent_tactic)], d, av, lr)
            if rule_level is not None and agent_level is not None:
                _update_profile(level_profiles[(rule_level, agent_level)], d, av, lr)

            if rule_tactic.lower() == agent_tactic.lower():
                _update_profile(agreement_profiles[rule_tactic], d, av, lr)

            rule_patterns = lr.get("matched_patterns") or []
            if (not rule_patterns and agent_level is not None and agent_level <= 2):
                _update_profile(novel_detection_profile, d, av, lr)

    # Build confusion matrix summaries (cell size only, no per-cell detail yet).
    tactic_cells = []
    for rt, row in tactic_matrix.items():
        for at, c in row.items():
            tactic_cells.append({"rule": rt, "agent": at, "count": c, "agree": rt.lower() == at.lower()})
    tactic_cells.sort(key=lambda r: -r["count"])

    level_cells = []
    for rl, row in level_matrix.items():
        for al, c in row.items():
            level_cells.append({"rule": rl, "agent": al, "count": c, "agree": rl == al})
    level_cells.sort(key=lambda r: -r["count"])

    # Decide which profiles to keep detailed. Focus cells + any cell over MIN_CELL_SIZE
    # + top N overall.
    keep_tactic_keys = set()
    for rt, at in FOCUS_TACTIC_CELLS:
        keep_tactic_keys.add((rt, at))
    for cell in tactic_cells:
        if cell["count"] >= MIN_CELL_SIZE:
            keep_tactic_keys.add((cell["rule"], cell["agent"]))
    for cell in tactic_cells[:top_n_cells]:
        keep_tactic_keys.add((cell["rule"], cell["agent"]))

    keep_level_keys = set()
    for rl, al in FOCUS_LEVEL_CELLS:
        keep_level_keys.add((rl, al))
    for cell in level_cells:
        if cell["count"] >= MIN_CELL_SIZE:
            keep_level_keys.add((cell["rule"], cell["agent"]))

    tactic_detail = {
        f"{rt} -> {at}": _finalize_profile(tactic_profiles[(rt, at)])
        for (rt, at) in keep_tactic_keys
        if (rt, at) in tactic_profiles
    }
    level_detail = {
        f"L{rl} -> L{al}": _finalize_profile(level_profiles[(rl, al)])
        for (rl, al) in keep_level_keys
        if (rl, al) in level_profiles
    }
    agreement_detail = {
        tactic: _finalize_profile(prof)
        for tactic, prof in agreement_profiles.items()
        if prof["count"] > 0
    }

    return {
        "summary": {
            "total_sessions_scanned": total,
            "dual_labeled": dual,
        },
        "tactic_confusion_matrix": tactic_cells,
        "level_confusion_matrix": level_cells,
        "tactic_cell_profiles": tactic_detail,
        "level_cell_profiles": level_detail,
        "agreement_profiles": agreement_detail,
        "novel_detection_profile": _finalize_profile(novel_detection_profile),
    }


def _print_profile(name: str, prof: dict) -> None:
    print(f"\n--- {name}  (n={prof['count']}) ---")
    print(f"  session_type     : {prof['session_type']}")
    print(f"  command_bucket   : {prof['command_bucket']}")
    print(f"  top_commands     : {list(prof['top_commands'].items())[:8]}")
    print(f"  agent_confidence : {prof['agent_confidence']}")
    print(f"  agent_sophist.   : {prof['agent_sophistication']}")
    print(f"  rule_sophist.    : {prof['rule_sophistication_score']}")
    print(f"  has_download/up  : {prof['has_download']}/{prof['has_upload']}")
    print(f"  auth_success     : {prof['auth_success']}")
    print(f"  avg_duration_s   : {prof['avg_duration_s']}")
    loc_top = list(prof["location"].items())[:5]
    print(f"  location top 5   : {loc_top}")


def print_report(results: dict) -> None:
    s = results["summary"]
    print("=" * 70)
    print("DEEPER PATTERN ANALYSIS (Phase 1)")
    print("=" * 70)
    print(f"Sessions scanned : {s['total_sessions_scanned']:,}")
    print(f"Dual-labeled     : {s['dual_labeled']:,}")

    print("\n## Top tactic confusion cells")
    for cell in results["tactic_confusion_matrix"][:15]:
        flag = "=" if cell["agree"] else "!"
        print(f"  {flag} {cell['rule']:<30} -> {cell['agent']:<30} {cell['count']:>6}")

    print("\n## Tactic cell profiles (focus cells + large cells)")
    # Sort by count descending
    detailed = sorted(
        results["tactic_cell_profiles"].items(),
        key=lambda kv: -kv[1]["count"],
    )
    for name, prof in detailed:
        _print_profile(name, prof)

    print("\n## Level cell profiles")
    detailed_l = sorted(
        results["level_cell_profiles"].items(),
        key=lambda kv: -kv[1]["count"],
    )
    for name, prof in detailed_l:
        _print_profile(name, prof)

    print("\n## Agreement profiles (what do both pipelines agree on?)")
    agree = sorted(
        results["agreement_profiles"].items(),
        key=lambda kv: -kv[1]["count"],
    )
    for name, prof in agree[:10]:
        _print_profile(f"AGREE: {name}", prof)

    print("\n## Novel-detection profile (rules saw nothing, agent flagged level <=2)")
    _print_profile("NOVEL DETECTIONS", results["novel_detection_profile"])


def main():
    parser = argparse.ArgumentParser(description="Deeper pattern analysis for annotation planning")
    parser.add_argument("--input", "-i", required=True, help="labeled_sessions.jsonl")
    parser.add_argument("--output", "-o", help="Save full results to JSON")
    parser.add_argument("--top-n-cells", type=int, default=20)
    args = parser.parse_args()

    input_path = Path(args.input)
    if not input_path.exists():
        print(f"Error: {input_path} not found")
        return 1

    results = analyze(input_path, top_n_cells=args.top_n_cells)
    print_report(results)

    if args.output:
        with open(args.output, "w") as f:
            json.dump(results, f, indent=2, default=str)
        print(f"\nFull results saved to {args.output}")
    return 0


if __name__ == "__main__":
    exit(main())
