"""v0.9.5: end-to-end eval against the constructed share.

Companion to ``tools/build_constructed_share.py``. Runs the deployed
``truffler scan-files`` pipeline against the constructed-share file
list and compares predictions to the ground-truth manifest. Measures:

* Stage-1 (path-classifier) precision/recall on the constructed paths
* Stage-2 (content-classifier, when triggered by tier filter)
  precision/recall on flagged paths
* End-to-end precision/recall (path-AND-content stages combined)

This is the only test of the orchestration that the existing eval
scripts skip.

The path stage sees local-Linux paths (constructed share is on the
local filesystem) so it routes to the Linux model. Windows-path-shape
testing remains the writeup-realistic-share benchmark from v0.9.3,
which scores raw path strings without disk content.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_MANIFEST = REPO_ROOT / "data" / "external" / "constructed_share_manifest.jsonl"
DEFAULT_PATHS_LIST = REPO_ROOT / "data" / "eval" / "constructed_share_paths.txt"
DEFAULT_OUTPUT = REPO_ROOT / "reports" / "constructed_share_eval.json"


def _run_truffler_scan(
    paths_list: Path,
    content_model_dir: str | None,
    linux_model_dir: str | None = None,
    windows_model_dir: str | None = None,
) -> list[dict]:
    """Invoke `truffler scan-files --input` and collect the JSONL
    predictions."""
    cmd = ["uv", "run", "truffler", "scan-files", "--input", str(paths_list)]
    if content_model_dir:
        cmd.extend(["--content-model-dir", content_model_dir])
    if linux_model_dir:
        cmd.extend(["--linux-model-dir", linux_model_dir])
    if windows_model_dir:
        cmd.extend(["--windows-model-dir", windows_model_dir])
    env_extras = "PYTORCH_CUDA_ALLOC_CONF=expandable_segments:True "
    print(f"Running: {env_extras}{' '.join(cmd)}", file=sys.stderr)
    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        cwd=REPO_ROOT,
        env={
            **__import__("os").environ,
            "PYTORCH_CUDA_ALLOC_CONF": "expandable_segments:True",
        },
    )
    if result.returncode != 0:
        print(f"stderr tail: {result.stderr[-2000:]}", file=sys.stderr)
        raise RuntimeError(f"truffler scan-files returned {result.returncode}")
    predictions: list[dict] = []
    for line in result.stdout.splitlines():
        line = line.strip()
        if not line or not line.startswith("{"):
            continue
        try:
            predictions.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return predictions


def _prf(tp: int, fp: int, fn: int) -> dict:
    prec = tp / max(1, tp + fp)
    rec = tp / max(1, tp + fn)
    f1 = 2 * prec * rec / max(1e-9, prec + rec)
    return {"tp": tp, "fp": fp, "fn": fn, "precision": prec, "recall": rec, "f1": f1}


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    p.add_argument("--paths-list", type=Path, default=DEFAULT_PATHS_LIST)
    p.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    p.add_argument(
        "--content-model-dir",
        default=None,
        help="Override content classifier (default: runtime default = v0p5).",
    )
    p.add_argument(
        "--linux-model-dir",
        default=None,
        help="Override Linux path classifier.",
    )
    p.add_argument(
        "--windows-model-dir",
        default=None,
        help="Override Windows path classifier.",
    )
    p.add_argument(
        "--label",
        default="constructed_share_v0p9",
        help="Tag for the results JSON entry.",
    )
    args = p.parse_args(argv)

    if not args.manifest.exists():
        print(f"ERROR: {args.manifest} missing — run build_constructed_share.py first", file=sys.stderr)
        return 1
    if not args.paths_list.exists():
        print(f"ERROR: {args.paths_list} missing", file=sys.stderr)
        return 1

    manifest = {r["local_path"]: r for r in (
        json.loads(line) for line in args.manifest.read_text().splitlines() if line.strip()
    )}
    print(f"Manifest: {len(manifest)} records", file=sys.stderr)

    predictions = _run_truffler_scan(
        args.paths_list,
        args.content_model_dir,
        linux_model_dir=args.linux_model_dir,
        windows_model_dir=args.windows_model_dir,
    )
    print(f"Predictions: {len(predictions)} records", file=sys.stderr)

    # Ground truth is "salted" — the file actually contains a credential.
    # Note: is_juicy_label is the *path-shape* judgment (does this LOOK like
    # a path that might contain creds), salted is the *content* truth.
    # The end-to-end test compares Stage-2 predictions to salted.
    stage1_tp = stage1_fp = stage1_fn = 0  # path classifier (tier-flagged)
    stage2_tp = stage2_fp = stage2_fn = 0  # content classifier (yes prediction)
    e2e_tp = e2e_fp = e2e_fn = 0           # tier-flagged AND yes
    not_in_manifest = 0
    for pred in predictions:
        local_path = pred.get("path")
        gt = manifest.get(local_path)
        if gt is None:
            not_in_manifest += 1
            continue
        path_flagged = pred.get("path_tier") is not None
        content_yes = pred.get("content_check") == "yes"
        true_juicy_path = bool(gt.get("is_juicy_label"))
        true_salted = bool(gt.get("salted"))

        # Stage 1 metrics (path classifier vs path-shape label).
        if path_flagged and true_juicy_path:
            stage1_tp += 1
        elif path_flagged and not true_juicy_path:
            stage1_fp += 1
        elif not path_flagged and true_juicy_path:
            stage1_fn += 1

        # Stage 2 metrics (content classifier vs salt truth, only on
        # files where stage 1 flagged + content was actually scanned).
        if content_yes and true_salted:
            stage2_tp += 1
        elif content_yes and not true_salted:
            stage2_fp += 1
        elif content_yes is False and true_salted:
            stage2_fn += 1
        # content_check might be None if path stage didn't flag — that
        # falls under stage 1 recall, not stage 2.

        # End-to-end: flag and say yes vs ground-truth salted.
        e2e_yes = path_flagged and content_yes
        if e2e_yes and true_salted:
            e2e_tp += 1
        elif e2e_yes and not true_salted:
            e2e_fp += 1
        elif not e2e_yes and true_salted:
            e2e_fn += 1

    out = {
        "label": args.label,
        "n_predictions": len(predictions),
        "n_manifest": len(manifest),
        "n_not_in_manifest": not_in_manifest,
        "stage1_path_classifier_metrics": _prf(stage1_tp, stage1_fp, stage1_fn),
        "stage2_content_classifier_metrics": _prf(stage2_tp, stage2_fp, stage2_fn),
        "end_to_end_metrics": _prf(e2e_tp, e2e_fp, e2e_fn),
    }
    if args.content_model_dir:
        out["content_model_dir"] = args.content_model_dir

    args.output.parent.mkdir(parents=True, exist_ok=True)
    existing: dict = {}
    if args.output.exists():
        try:
            existing = json.loads(args.output.read_text())
            if not isinstance(existing, dict):
                existing = {}
        except json.JSONDecodeError:
            existing = {}
    existing[args.label] = out
    args.output.write_text(json.dumps(existing, indent=2))

    print(f"\n=== Constructed-share end-to-end eval ===", file=sys.stderr)
    for stage, key in [
        ("stage 1 (path classifier)", "stage1_path_classifier_metrics"),
        ("stage 2 (content classifier)", "stage2_content_classifier_metrics"),
        ("end-to-end", "end_to_end_metrics"),
    ]:
        m = out[key]
        print(
            f"  {stage}: P={m['precision']:.3f} R={m['recall']:.3f} "
            f"F1={m['f1']:.3f} (tp={m['tp']}, fp={m['fp']}, fn={m['fn']})",
            file=sys.stderr,
        )
    print(f"\nWrote results to {args.output.relative_to(REPO_ROOT)}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
