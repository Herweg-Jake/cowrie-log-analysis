#!/usr/bin/env python3
"""
Phase 2 of the Human Annotation Plan: stratified sampling.

Reads labeled_sessions.jsonl, classifies every dual-labeled session into one of
four buckets (Agreement / Disagreement / Novel / LevelOnly), and draws a
stratified sample with reproducible random seed.

Outputs three files:

  - annotation_sample_blind.jsonl
      Per-row record WITHOUT any pipeline labels (this is what annotators see).

  - annotation_sample_full.jsonl
      Per-row record WITH both pipeline labels (kept as the answer key for
      Phase 4 scoring).

  - annotation_sample_metadata.json
      Random seed, population sizes, sample sizes, target quotas, bucket rules.

The default quotas match the plan (400 total, heavy weight on disagreements).
Override per-bucket with CLI flags if desired.

Usage:
    python scripts/extract_annotation_sample.py \\
        --input src/labeled_sessions.jsonl \\
        --out-dir annotation_out \\
        --seed 42

The script makes two passes: one to classify and count, one to reservoir-sample
each bucket. Memory usage stays bounded even on the full 11.7M-session file
because we only retain session IDs per bucket until the sampling pass.
"""

import argparse
import json
import random
from collections import Counter, defaultdict
from pathlib import Path

try:
    from tqdm import tqdm
except ImportError:
    class _Tqdm:
        def __init__(self, iterable=None, total=0, desc=""):
            self.iterable = iterable
            self.total = total
            self.desc = desc
            self.n = 0
        def __iter__(self):
            for i, item in enumerate(self.iterable or []):
                self.n = i
                if self.total and i % 1000 == 0:
                    print(f"{self.desc}: {i}/{self.total}")
                yield item
        def update(self, k=1):
            self.n += k
            if self.total and self.n % 1000 == 0:
                print(f"{self.desc}: {self.n}/{self.total}")
        def close(self):
            pass
    def tqdm(iterable=None, **kwargs):
        return _Tqdm(iterable=iterable, **kwargs)


# ---------------------------------------------------------------------------
# Bucket definitions
# ---------------------------------------------------------------------------

# Bucket A (Tactic Agreements): quotas keyed by the agreed-upon tactic.
AGREEMENT_QUOTAS = {
    "Discovery": 30,
    "Command and Control": 20,
    "Execution": 10,
    "Persistence": 10,
    "Initial Access": 20,
    "Impact": 15,
    "_other": 15,  # mixed/rare
}

# Bucket B (Tactic Disagreements): quotas keyed by (rule_tactic, agent_tactic).
DISAGREEMENT_QUOTAS = {
    ("Discovery", "Initial Access"): 40,
    ("Command and Control", "Initial Access"): 35,
    ("No Action", "Initial Access"): 30,
    ("Command and Control", "Execution"): 25,
    ("Unknown Activity (Low)", "Initial Access"): 20,
    ("Unknown Activity (High)", "Persistence"): 15,
    ("No Action", "Execution"): 10,
    ("Impact", "Persistence"): 10,
    ("Discovery", "_other"): 10,  # Discovery -> anything not already listed
    ("_other", "_other"): 25,     # everything else
}

# Bucket C (Novel Detections): rules matched nothing, agent flagged level 1 or 2.
NOVEL_QUOTA = 40

# Bucket D (Level-Only Disagreements): tactic agrees but level differs.
LEVEL_ONLY_QUOTA = 20


def _norm_tactic(t: str) -> str:
    return (t or "").strip()


def _is_novel(lr: dict, av: dict) -> bool:
    rule_patterns = lr.get("matched_patterns") or []
    agent_level = av.get("level")
    return (not rule_patterns) and agent_level is not None and agent_level <= 2


def classify(rule_tactic: str, agent_tactic: str, rule_level, agent_level,
             lr: dict, av: dict):
    """
    Return a list of (bucket_name, key) tuples. A session can land in multiple
    buckets (e.g. "novel detection" and "disagreement").
    """
    out = []
    rt = _norm_tactic(rule_tactic)
    at = _norm_tactic(agent_tactic)
    tactic_agrees = rt.lower() == at.lower() and rt != ""
    level_agrees = (rule_level is not None and agent_level is not None
                    and rule_level == agent_level)

    # Bucket C first (these are standalone, don't care about tactic agreement).
    if _is_novel(lr, av):
        out.append(("novel", "novel"))

    if tactic_agrees:
        # Bucket A or Bucket D
        if level_agrees or rule_level is None or agent_level is None:
            key = rt if rt in AGREEMENT_QUOTAS else "_other"
            out.append(("agreement", key))
        else:
            out.append(("level_only", f"{rt}|L{rule_level}->L{agent_level}"))
    else:
        # Bucket B: tactic disagreement
        key = (rt, at)
        if key in DISAGREEMENT_QUOTAS:
            pass  # exact match
        elif rt == "Discovery":
            key = ("Discovery", "_other")
        else:
            key = ("_other", "_other")
        out.append(("disagreement", key))

    return out


def _extract_common_fields(d: dict) -> dict:
    """Fields shared by both the blind record and the full (answer-key) record."""
    cmds_block = d.get("commands") or {}
    if isinstance(cmds_block, dict):
        cmd_inputs = cmds_block.get("inputs", []) or []
        cmd_total = cmds_block.get("total_count", len(cmd_inputs))
        cmd_success = cmds_block.get("success_count")
        cmd_failed = cmds_block.get("failed_count")
    else:
        cmd_inputs = [c.get("input", "") if isinstance(c, dict) else str(c) for c in cmds_block]
        cmd_total = len(cmd_inputs)
        cmd_success = None
        cmd_failed = None

    dl = d.get("downloads") or {}
    ul = d.get("uploads") or {}
    auth = d.get("authentication") or {}
    client = d.get("client") or {}
    timing = d.get("timing") or {}
    meta = d.get("meta") or {}

    return {
        "session_id": d.get("session_id"),
        "location": d.get("location"),
        "session_type": meta.get("session_type"),
        "duration_s": timing.get("duration_s"),
        "start_ts": timing.get("start_ts"),
        "end_ts": timing.get("end_ts"),
        "auth_success": auth.get("success"),
        "login_attempts": {
            "attempts": auth.get("attempts"),
            "failed_count": auth.get("failed_count"),
            "success_count": auth.get("success_count"),
            "final_username": auth.get("final_username"),
            "final_password": auth.get("final_password"),
            "usernames_tried": auth.get("usernames_tried", [])[:20],
        },
        "ssh_version": client.get("ssh_version"),
        "hassh": client.get("hassh"),
        "commands": {
            "total_count": cmd_total,
            "success_count": cmd_success,
            "failed_count": cmd_failed,
            "inputs": cmd_inputs,
        },
        "downloads": dl,
        "uploads": ul,
        "features": d.get("features", {}),
    }


def build_blind_record(d: dict, annotation_id: int, bucket: str, bucket_key) -> dict:
    base = _extract_common_fields(d)
    base["annotation_id"] = annotation_id
    base["bucket"] = bucket
    base["bucket_key"] = (list(bucket_key) if isinstance(bucket_key, tuple) else bucket_key)
    return base


def build_full_record(d: dict, annotation_id: int, bucket: str, bucket_key) -> dict:
    base = build_blind_record(d, annotation_id, bucket, bucket_key)
    la = d.get("labels_agentic") or {}
    base["rule_based_label"] = d.get("labels_rule_based") or {}
    base["agent_label"] = la.get("analyst_verdict") or {}
    base["hunter_verdict"] = la.get("hunter_verdict")
    base["statistical_anomaly"] = d.get("statistical_anomaly", {})
    return base


# ---------------------------------------------------------------------------
# Two-pass sampler
# ---------------------------------------------------------------------------

def pass1_classify(input_path: Path):
    """
    First pass: walk the JSONL and for every dual-labeled session record its
    offset in each bucket. We store (byte_offset, session_id) so we can jump
    back on the second pass.
    """
    # bucket -> key -> list[(offset, session_id)]
    bucket_index = defaultdict(lambda: defaultdict(list))
    populations = defaultdict(Counter)

    total = 0
    dual = 0

    line_count = sum(1 for _ in open(input_path))

    with open(input_path, "rb") as f:
        offset = 0
        pbar = tqdm(total=line_count, desc="Classifying")
        while True:
            line = f.readline()
            if not line:
                break
            this_offset = offset
            offset += len(line)
            pbar.update(1)
            total += 1

            try:
                d = json.loads(line)
            except json.JSONDecodeError:
                continue

            la = d.get("labels_agentic") or {}
            lr = d.get("labels_rule_based") or {}
            av = la.get("analyst_verdict")
            if not av or not isinstance(av, dict) or not lr:
                continue

            dual += 1
            rule_tactic = _norm_tactic(lr.get("primary_tactic", ""))
            agent_tactic = _norm_tactic(av.get("primary_tactic", ""))
            rule_level = lr.get("level")
            agent_level = av.get("level")

            classifications = classify(
                rule_tactic, agent_tactic, rule_level, agent_level, lr, av
            )
            sid = d.get("session_id")
            for bucket, key in classifications:
                bucket_index[bucket][key].append((this_offset, sid))
                populations[bucket][key] += 1
        pbar.close()

    return {
        "total": total,
        "dual": dual,
        "bucket_index": bucket_index,
        "populations": populations,
    }


def _sample_ids(pop_list, quota, rng):
    if not pop_list:
        return []
    if quota >= len(pop_list):
        return list(pop_list)
    return rng.sample(pop_list, quota)


def pass2_sample(classify_result: dict, quotas: dict, rng: random.Random) -> dict:
    """
    Given the bucket index and quotas, randomly draw offsets for each
    (bucket, key). Returns a dict: offset -> (annotation_id, bucket, bucket_key).

    annotation_ids are assigned after all sampling so they're contiguous 1..N
    and in a deterministic order.
    """
    chosen = []  # list of (offset, session_id, bucket, bucket_key)
    bucket_index = classify_result["bucket_index"]

    # Bucket A
    for key, quota in quotas["agreement"].items():
        pool = bucket_index.get("agreement", {}).get(key, [])
        for offset, sid in _sample_ids(pool, quota, rng):
            chosen.append((offset, sid, "agreement", key))

    # Bucket B
    for key, quota in quotas["disagreement"].items():
        pool = bucket_index.get("disagreement", {}).get(key, [])
        for offset, sid in _sample_ids(pool, quota, rng):
            chosen.append((offset, sid, "disagreement", key))

    # Bucket C (single pool)
    novel_pool = bucket_index.get("novel", {}).get("novel", [])
    for offset, sid in _sample_ids(novel_pool, quotas["novel"], rng):
        chosen.append((offset, sid, "novel", "novel"))

    # Bucket D: spread the quota across whatever level-only keys exist.
    level_only_pool = bucket_index.get("level_only", {})
    # Flatten all level-only sessions into one pool with their key.
    flat = []
    for key, entries in level_only_pool.items():
        for e in entries:
            flat.append((e[0], e[1], key))
    if flat:
        picks = rng.sample(flat, min(quotas["level_only"], len(flat)))
        for offset, sid, key in picks:
            chosen.append((offset, sid, "level_only", key))

    # Dedup: a session can land in multiple buckets. Keep the first (most-specific)
    # bucket label per offset by preferring disagreement > novel > level_only > agreement.
    priority = {"disagreement": 0, "novel": 1, "level_only": 2, "agreement": 3}
    by_offset = {}
    for offset, sid, bucket, key in chosen:
        cur = by_offset.get(offset)
        if cur is None or priority[bucket] < priority[cur[2]]:
            by_offset[offset] = (offset, sid, bucket, key)

    deduped = list(by_offset.values())
    # Deterministic annotation_id assignment: sort by offset for stability.
    deduped.sort(key=lambda r: r[0])

    selection = {}
    for i, (offset, sid, bucket, key) in enumerate(deduped, start=1):
        selection[offset] = {
            "annotation_id": i,
            "session_id": sid,
            "bucket": bucket,
            "bucket_key": key,
        }
    return selection


def pass3_export(input_path: Path, selection: dict, out_dir: Path) -> dict:
    """
    Walk the JSONL a second time, pulling out the selected offsets.
    """
    out_dir.mkdir(parents=True, exist_ok=True)
    blind_path = out_dir / "annotation_sample_blind.jsonl"
    full_path = out_dir / "annotation_sample_full.jsonl"

    written = 0
    with open(input_path, "rb") as f, \
         open(blind_path, "w") as fb, \
         open(full_path, "w") as ff:
        offset = 0
        while True:
            line = f.readline()
            if not line:
                break
            this_offset = offset
            offset += len(line)
            if this_offset not in selection:
                continue
            info = selection[this_offset]
            try:
                d = json.loads(line)
            except json.JSONDecodeError:
                continue

            blind = build_blind_record(d, info["annotation_id"], info["bucket"], info["bucket_key"])
            full = build_full_record(d, info["annotation_id"], info["bucket"], info["bucket_key"])
            fb.write(json.dumps(blind, default=str) + "\n")
            ff.write(json.dumps(full, default=str) + "\n")
            written += 1

    return {"blind": str(blind_path), "full": str(full_path), "written": written}


def _default_quotas(args) -> dict:
    q = {
        "agreement": dict(AGREEMENT_QUOTAS),
        "disagreement": dict(DISAGREEMENT_QUOTAS),
        "novel": NOVEL_QUOTA,
        "level_only": LEVEL_ONLY_QUOTA,
    }
    # Simple scaling: if user passes --total, re-weight everything proportionally.
    if args.total:
        current = sum(q["agreement"].values()) + sum(q["disagreement"].values()) + q["novel"] + q["level_only"]
        scale = args.total / current
        q["agreement"] = {k: max(1, round(v * scale)) for k, v in q["agreement"].items()}
        q["disagreement"] = {k: max(1, round(v * scale)) for k, v in q["disagreement"].items()}
        q["novel"] = max(1, round(q["novel"] * scale))
        q["level_only"] = max(1, round(q["level_only"] * scale))
    return q


def main():
    parser = argparse.ArgumentParser(description="Extract stratified annotation sample")
    parser.add_argument("--input", "-i", required=True, help="labeled_sessions.jsonl")
    parser.add_argument("--out-dir", "-o", default="annotation_out",
                        help="Directory for blind/full/metadata outputs")
    parser.add_argument("--seed", type=int, default=42, help="Random seed")
    parser.add_argument("--total", type=int, default=None,
                        help="Scale all quotas to approximately this total (default: use plan's 400)")
    args = parser.parse_args()

    input_path = Path(args.input)
    if not input_path.exists():
        print(f"Error: {input_path} not found")
        return 1

    out_dir = Path(args.out_dir)
    quotas = _default_quotas(args)
    rng = random.Random(args.seed)

    print("Pass 1: classifying sessions into buckets...")
    classify_result = pass1_classify(input_path)
    populations = classify_result["populations"]

    print("\nPopulation sizes per bucket key:")
    for bucket, keys in populations.items():
        print(f"  [{bucket}]")
        for key, count in sorted(keys.items(), key=lambda kv: -kv[1])[:15]:
            print(f"    {key}: {count}")

    print("\nPass 2: drawing stratified sample...")
    selection = pass2_sample(classify_result, quotas, rng)
    print(f"  selected {len(selection)} sessions after dedup")

    print("\nPass 3: exporting to JSONL...")
    export_info = pass3_export(input_path, selection, out_dir)

    # Bucket composition of final sample
    final_counts = Counter()
    for info in selection.values():
        final_counts[info["bucket"]] += 1

    metadata = {
        "seed": args.seed,
        "input": str(input_path),
        "total_sessions_scanned": classify_result["total"],
        "dual_labeled_sessions": classify_result["dual"],
        "quotas": {
            "agreement": {str(k): v for k, v in quotas["agreement"].items()},
            "disagreement": {f"{k[0]} -> {k[1]}" if isinstance(k, tuple) else str(k): v
                             for k, v in quotas["disagreement"].items()},
            "novel": quotas["novel"],
            "level_only": quotas["level_only"],
        },
        "populations": {
            bucket: {
                (f"{k[0]} -> {k[1]}" if isinstance(k, tuple) else str(k)): v
                for k, v in keys.items()
            }
            for bucket, keys in populations.items()
        },
        "final_sample": {
            "total": len(selection),
            "by_bucket": dict(final_counts),
            "blind_path": export_info["blind"],
            "full_path": export_info["full"],
        },
    }

    meta_path = out_dir / "annotation_sample_metadata.json"
    with open(meta_path, "w") as f:
        json.dump(metadata, f, indent=2, default=str)

    print(f"\nWrote:")
    print(f"  {export_info['blind']}")
    print(f"  {export_info['full']}")
    print(f"  {meta_path}")
    print(f"\nFinal sample size: {len(selection)} sessions")
    print(f"By bucket: {dict(final_counts)}")
    return 0


if __name__ == "__main__":
    exit(main())
