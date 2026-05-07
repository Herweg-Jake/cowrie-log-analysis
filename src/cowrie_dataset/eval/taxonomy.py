"""Cluster pipeline disagreements with truth into named failure modes.

Approach: for sessions where any pipeline got the tactic wrong, gather
Pipeline B's reasoning text (when available) plus a short feature
summary. TF-IDF + KMeans, k from --k. Each cluster gets a sample of 5
sessions written to its own JSONL; the human writes the descriptive
title in categories.md afterwards.

The cheap path is intentional - the plan also allows sentence
embeddings + HDBSCAN, but that's an extra dep. KMeans on TF-IDF is
enough to surface the named categories listed in section 8.2.
"""

from __future__ import annotations

import argparse
import csv
import json
from collections import Counter
from pathlib import Path

from . import metrics as M


def _gather_failures(truth, pipeline_preds_by_name, sessions):
    """Yield (session_id, pipeline_name, summary) for tactic mismatches."""
    for name, preds in pipeline_preds_by_name.items():
        for sid in sorted(set(truth) & set(preds)):
            if truth[sid].tactic == preds[sid].tactic:
                continue
            sess = sessions.get(sid, {})
            agent = sess.get("label_agent") or sess.get("agent_label") or {}
            reasoning = ""
            verdict = (sess.get("labels_agentic") or {}).get("analyst_verdict") or {}
            if verdict.get("reasoning"):
                reasoning = verdict["reasoning"]
            elif agent.get("reasoning"):
                reasoning = agent["reasoning"]
            commands = " ".join(sess.get("commands", []) or [])[:600]
            yield {
                "session_id": sid,
                "pipeline": name,
                "truth_tactic": truth[sid].tactic,
                "pred_tactic": preds[sid].tactic,
                "truth_level": truth[sid].level,
                "pred_level": preds[sid].level,
                "reasoning": reasoning,
                "commands": commands,
            }


def _vectorize_and_cluster(corpus, k):
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.cluster import KMeans
    vec = TfidfVectorizer(max_features=2000, ngram_range=(1, 2),
                          min_df=2, stop_words="english")
    X = vec.fit_transform(corpus)
    km = KMeans(n_clusters=k, n_init=10, random_state=42)
    labels = km.fit_predict(X)
    # Top features per cluster (a hint for the human writing titles).
    terms = vec.get_feature_names_out()
    centers = km.cluster_centers_
    top_terms = []
    for c in range(k):
        idx = centers[c].argsort()[::-1][:8]
        top_terms.append([terms[i] for i in idx if centers[c][i] > 0])
    return labels.tolist(), top_terms


def build_taxonomy(truth_path, sessions_path, spec_path, out_dir, k=10):
    truth = M.load_annotations(truth_path)
    spec = json.loads(Path(spec_path).read_text())
    pipelines = {}
    for entry in spec:
        pipelines[entry["name"]] = M.load_pipeline_labels(
            entry["predictions"], pipeline_name=entry.get("pipeline_name"))

    sessions = {}
    with open(sessions_path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            r = json.loads(line)
            if r.get("session_id"):
                sessions[r["session_id"]] = r

    failures = list(_gather_failures(truth, pipelines, sessions))
    if not failures:
        raise SystemExit("no tactic mismatches found - nothing to cluster")

    corpus = [f"{f['reasoning']} {f['commands']}".strip() or f"{f['truth_tactic']}->{f['pred_tactic']}"
              for f in failures]
    labels, top_terms = _vectorize_and_cluster(corpus, k)

    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    examples_dir = out_dir / "examples"
    examples_dir.mkdir(exist_ok=True)

    # categories.md skeleton - the human fills in the description column
    by_cluster: dict[int, list[dict]] = {}
    for f, lab in zip(failures, labels):
        f["cluster"] = int(lab)
        by_cluster.setdefault(int(lab), []).append(f)

    md = ["# Failure-mode taxonomy",
          "",
          "Auto-clustered. Top terms are a hint - rename categories with",
          "human-readable titles after sampling the example files.",
          "",
          "| cluster | n | top terms | suggested title |",
          "|---|---|---|---|"]
    for c in sorted(by_cluster):
        terms = ", ".join(top_terms[c][:5])
        md.append(f"| {c} | {len(by_cluster[c])} | {terms} | _TODO_ |")
    (out_dir / "categories.md").write_text("\n".join(md) + "\n")

    # Per-cluster examples (capped at 5 sessions)
    for c, items in by_cluster.items():
        path = examples_dir / f"cluster_{c:02d}.jsonl"
        with open(path, "w") as f:
            for it in items[:5]:
                f.write(json.dumps(it) + "\n")

    # Pipeline x cluster distribution table
    dist_path = out_dir / "category_distribution.csv"
    pipelines_seen = sorted({f["pipeline"] for f in failures})
    with open(dist_path, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["pipeline"] + [f"cluster_{c}" for c in sorted(by_cluster)])
        for p in pipelines_seen:
            row = [p]
            for c in sorted(by_cluster):
                n = sum(1 for x in by_cluster[c] if x["pipeline"] == p)
                row.append(n)
            w.writerow(row)

    # Per-pipeline summary so the README/notebook can pull totals
    summary = {
        "n_failures": len(failures),
        "n_clusters": k,
        "by_pipeline": dict(Counter(f["pipeline"] for f in failures)),
    }
    (out_dir / "summary.json").write_text(json.dumps(summary, indent=2))


def cli(argv=None):
    ap = argparse.ArgumentParser(prog="cowrie_dataset.cli taxonomy")
    ap.add_argument("--truth", required=True)
    ap.add_argument("--sessions", required=True,
                    help="Master JSONL with reasoning + commands")
    ap.add_argument("--spec", required=True,
                    help="Same pipelines spec used by headline/pairwise")
    ap.add_argument("--out-dir", required=True)
    ap.add_argument("--k", type=int, default=10)
    args = ap.parse_args(argv)
    build_taxonomy(args.truth, args.sessions, args.spec, args.out_dir, k=args.k)
    print(f"wrote {args.out_dir}/categories.md and examples/")


if __name__ == "__main__":
    cli()
