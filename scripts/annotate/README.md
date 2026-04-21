# Annotation Web Viewer

A single-file static page for annotating sessions from `annotation_sample_blind.jsonl`.

## How to use

1. Generate the blind sample:

   ```bash
   python scripts/extract_annotation_sample.py \
       --input src/labeled_sessions.jsonl \
       --out-dir annotation_out
   ```

2. Open `scripts/annotate/index.html` in a browser. All processing is
   client-side; nothing is uploaded. You can simply double-click the file, or
   serve it locally:

   ```bash
   python -m http.server --directory scripts/annotate 8000
   # then open http://localhost:8000/
   ```

3. Click **Choose file** and select `annotation_out/annotation_sample_blind.jsonl`.

4. Enter your name in the `annotator` field (this goes into the exported
   records).

5. For each session, pick tactic / level / confidence, optionally flag
   false-negative risk, add notes, then **Save & Next** (or press `s`).
   Progress is auto-saved to `localStorage` keyed by filename+size, so closing
   and reopening the tab preserves your work.

6. When done, click **Export** to download
   `annotation_results_<annotator>.jsonl`. That file is what
   `scripts/compute_ground_truth_metrics.py` consumes.

## Keyboard shortcuts

| Key | Action |
|---|---|
| `s` | Save current annotation and move to next |
| `Shift+S` | Skip without saving |
| `j` | Previous session |
| `k` | Next session |

## Notes

- The viewer never sees pipeline labels — it reads `annotation_sample_blind.jsonl`,
  which was built for that purpose. Annotators making judgments here are
  independent of both Pipeline A and Pipeline B.
- Annotations live in `localStorage` until exported. Export frequently.
- The **Reset** button clears saved annotations for the currently loaded file
  only (scoped by filename + size).
- Consult `docs/ANNOTATION_CODEBOOK.md` for tactic definitions and the
  decision tree before starting.
