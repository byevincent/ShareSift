"""v0.14 — head-to-head eval of Truffler v0.14 vs Snaffler-alone.

Runs both rulesets independently against a labeled share file list and
reports precision / recall / F1 per tool plus a head-to-head diff
(files only in A, files only in B, files in both). Emits a final
BEAT/TIE/LOST decision per the v0.14 spec's success criteria.

Rulesets compared:
- **snaffler_only**: pysnaffler's bundled defaults (81 rules), no
  Truffler extras, no path classifier, no content classifier
- **truffler_v0p14**: pysnaffler defaults + 7 catch-up rules + 7
  blind-spot rules + binary preprocessor + Truffler path classifier
  + Truffler content classifier (v0p7, optional via --no-content)

Inputs:
- ``--file-list``: text file with one path per line (the enumeration
  of the target share, e.g. from Metasploitable 3 walk)
- ``--ground-truth``: JSONL from ``build_msf3_ground_truth.py`` with
  ``has_credential`` labels per path (manually verified or
  cross-check-labeled)

Decision criteria (per v0.14 spec):
- BEAT: Truffler recall >= Snaffler recall AND precision >= Snaffler + 0.30
- TIE: recall matches but precision delta < 0.30
- LOST: recall below Snaffler

Usage:
    uv run python tools/eval_v0p14_vs_snaffler.py \\
        --file-list data/external/metasploitable3/file_list.txt \\
        --ground-truth data/external/metasploitable3/ground_truth.jsonl \\
        --predictions reports/v0p14_vs_snaffler_predictions.jsonl \\
        --summary reports/v0p14_vs_snaffler_summary.json
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "references" / "pysnaffler"))
sys.path.insert(0, str(REPO_ROOT / "src"))

DEFAULT_FILE_LIST = REPO_ROOT / "data" / "external" / "metasploitable3" / "file_list.txt"
DEFAULT_GT = REPO_ROOT / "data" / "external" / "metasploitable3" / "ground_truth.jsonl"
DEFAULT_PREDICTIONS = REPO_ROOT / "reports" / "v0p14_vs_snaffler_predictions.jsonl"
DEFAULT_SUMMARY = REPO_ROOT / "reports" / "v0p14_vs_snaffler_summary.json"


def _load_jsonl(path: Path) -> list[dict]:
    records: list[dict] = []
    with path.open(encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return records


def _build_rulesets(include_content: bool, include_path: bool):
    """Construct (snaffler_only, truffler_v0p14) ruleset pair."""
    from pysnaffler.ruleset import SnafflerRuleSet
    from sharesift.rules import get_extra_rules

    snaffler_only = SnafflerRuleSet.load_default_ruleset()

    truffler = SnafflerRuleSet.load_default_ruleset()
    for rule in get_extra_rules():
        truffler.load_rule(rule)
    if include_path:
        try:
            from sharesift.pysnaffler_rule import ShareSiftPathRule
            truffler.load_rule(ShareSiftPathRule())
        except Exception as e:
            print(f"[warn] could not load ShareSiftPathRule: {e}", file=sys.stderr)
    if include_content:
        try:
            from sharesift.pysnaffler_content_rule import TrufflerContentRule
            truffler.load_rule(TrufflerContentRule())
        except Exception as e:
            print(f"[warn] could not load TrufflerContentRule: {e}", file=sys.stderr)
    return snaffler_only, truffler


def _classify_path(ruleset, path: str) -> tuple[bool, list[str]]:
    """Run pysnaffler's enum_file on a single path. Returns (kept, rule_names)."""
    import os
    name = path.replace("\\", "/").split("/")[-1] or path
    try:
        keep, rules = ruleset.enum_file(None, fullpath=path, name=name, size=1024)
    except Exception as e:
        return False, [f"<error: {e!s}>"]
    rule_names = [r.ruleName for r in rules] if isinstance(rules, list) else []
    return bool(keep) and bool(rule_names), rule_names


def _prf(tp: int, fp: int, fn: int) -> dict:
    prec = tp / max(1, tp + fp)
    rec = tp / max(1, tp + fn)
    f1 = 2 * prec * rec / max(1e-9, prec + rec)
    return {"tp": tp, "fp": fp, "fn": fn,
            "precision": round(prec, 4),
            "recall": round(rec, 4),
            "f1": round(f1, 4)}


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--file-list", type=Path, default=DEFAULT_FILE_LIST,
                   help="Newline-delimited paths to score")
    p.add_argument("--ground-truth", type=Path, default=DEFAULT_GT)
    p.add_argument("--predictions", type=Path, default=DEFAULT_PREDICTIONS)
    p.add_argument("--summary", type=Path, default=DEFAULT_SUMMARY)
    p.add_argument("--no-path", action="store_true",
                   help="Skip Truffler path classifier (avoids GPU dep for dry runs)")
    p.add_argument("--no-content", action="store_true",
                   help="Skip Truffler content classifier")
    args = p.parse_args(argv)

    if not args.file_list.exists():
        print(f"ERROR: --file-list missing: {args.file_list}", file=sys.stderr)
        return 2
    if not args.ground_truth.exists():
        print(f"ERROR: --ground-truth missing: {args.ground_truth}", file=sys.stderr)
        return 2

    paths = [
        line.strip() for line in args.file_list.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    print(f"[load] {len(paths)} paths from file list", file=sys.stderr)

    gt_records = _load_jsonl(args.ground_truth)
    gt = {r["path"].lower(): r for r in gt_records}
    labeled = {k: v for k, v in gt.items() if v.get("has_credential") is not None}
    n_positives = sum(1 for v in labeled.values() if v["has_credential"])
    print(f"[load] {len(gt_records)} GT records ({len(labeled)} labeled, "
          f"{n_positives} positives)", file=sys.stderr)

    snaffler_only, truffler = _build_rulesets(
        include_content=not args.no_content,
        include_path=not args.no_path,
    )
    print(f"[ruleset] snaffler_only: {len(snaffler_only.allRules)} rules", file=sys.stderr)
    print(f"[ruleset] truffler_v0p14: {len(truffler.allRules)} rules", file=sys.stderr)

    predictions: list[dict] = []
    s_tp = s_fp = s_fn = 0
    t_tp = t_fp = t_fn = 0
    truffler_only_catches = []  # files truffler caught and snaffler missed
    snaffler_only_catches = []  # files snaffler caught and truffler missed
    both_caught = []
    both_missed = []

    for path in paths:
        s_keep, s_rules = _classify_path(snaffler_only, path)
        t_keep, t_rules = _classify_path(truffler, path)
        label = gt.get(path.lower())
        has_cred = label.get("has_credential") if label else None
        predictions.append({
            "path": path,
            "snaffler_kept": s_keep,
            "snaffler_rules": s_rules,
            "truffler_kept": t_keep,
            "truffler_rules": t_rules,
            "has_credential": has_cred,
            "verified": (label.get("verified") if label else None),
        })
        # Only count toward metrics if we have a ground-truth label
        if has_cred is None:
            continue
        # Snaffler tally
        if has_cred and s_keep:
            s_tp += 1
        elif has_cred and not s_keep:
            s_fn += 1
        elif (not has_cred) and s_keep:
            s_fp += 1
        # Truffler tally
        if has_cred and t_keep:
            t_tp += 1
        elif has_cred and not t_keep:
            t_fn += 1
        elif (not has_cred) and t_keep:
            t_fp += 1
        # Diff
        if t_keep and not s_keep:
            truffler_only_catches.append({"path": path, "is_credential": has_cred,
                                          "truffler_rules": t_rules})
        elif s_keep and not t_keep:
            snaffler_only_catches.append({"path": path, "is_credential": has_cred,
                                          "snaffler_rules": s_rules})
        elif s_keep and t_keep:
            both_caught.append(path)
        else:
            both_missed.append({"path": path, "is_credential": has_cred})

    args.predictions.parent.mkdir(parents=True, exist_ok=True)
    with args.predictions.open("w", encoding="utf-8") as fh:
        for rec in predictions:
            fh.write(json.dumps(rec) + "\n")
    print(f"[predictions] {len(predictions)} → {args.predictions}", file=sys.stderr)

    snaffler_metrics = _prf(s_tp, s_fp, s_fn)
    truffler_metrics = _prf(t_tp, t_fp, t_fn)
    precision_delta = truffler_metrics["precision"] - snaffler_metrics["precision"]
    recall_delta = truffler_metrics["recall"] - snaffler_metrics["recall"]

    if truffler_metrics["recall"] < snaffler_metrics["recall"]:
        decision = "LOST: Truffler recall below Snaffler — debug rule port or new rules"
    elif precision_delta >= 0.30:
        decision = "BEAT: Truffler recall >= Snaffler AND precision +30pp absolute"
    elif precision_delta > 0:
        decision = f"TIE: matched Snaffler recall, precision +{precision_delta:.3f} (target +0.30)"
    else:
        decision = f"TIE: matched Snaffler recall but precision worse by {-precision_delta:.3f}"

    # FN files Truffler missed but should catch — flag for spec attention
    truffler_fns = [
        rec["path"] for rec in predictions
        if rec["has_credential"] is True and not rec["truffler_kept"]
    ]
    snaffler_fns = [
        rec["path"] for rec in predictions
        if rec["has_credential"] is True and not rec["snaffler_kept"]
    ]

    summary = {
        "n_paths_scored": len(paths),
        "n_labeled": len(labeled),
        "n_positives": n_positives,
        "snaffler_only": snaffler_metrics,
        "truffler_v0p14": truffler_metrics,
        "precision_delta": round(precision_delta, 4),
        "recall_delta": round(recall_delta, 4),
        "decision": decision,
        "diff": {
            "truffler_only_catches": truffler_only_catches[:50],
            "snaffler_only_catches": snaffler_only_catches[:50],
            "both_caught_count": len(both_caught),
            "both_missed_count": len(both_missed),
            "both_missed_credentials": [m for m in both_missed if m["is_credential"]][:20],
        },
        "truffler_false_negatives": truffler_fns[:30],
        "snaffler_false_negatives": snaffler_fns[:30],
    }
    args.summary.parent.mkdir(parents=True, exist_ok=True)
    args.summary.write_text(json.dumps(summary, indent=2))
    print(f"[summary] → {args.summary}", file=sys.stderr)

    print(f"\n=== v0.14 vs Snaffler head-to-head ===", file=sys.stderr)
    print(f"  Snaffler:   P={snaffler_metrics['precision']:.3f} "
          f"R={snaffler_metrics['recall']:.3f} F1={snaffler_metrics['f1']:.3f}",
          file=sys.stderr)
    print(f"  Truffler:   P={truffler_metrics['precision']:.3f} "
          f"R={truffler_metrics['recall']:.3f} F1={truffler_metrics['f1']:.3f}",
          file=sys.stderr)
    print(f"  Delta:      ΔP={precision_delta:+.3f} ΔR={recall_delta:+.3f}",
          file=sys.stderr)
    print(f"\n  >>> {decision} <<<", file=sys.stderr)
    print(f"\n  Truffler-only catches: {len(truffler_only_catches)} "
          f"(of which {sum(1 for d in truffler_only_catches if d['is_credential'])} are TPs)",
          file=sys.stderr)
    print(f"  Snaffler-only catches: {len(snaffler_only_catches)} "
          f"(of which {sum(1 for d in snaffler_only_catches if d['is_credential'])} are TPs)",
          file=sys.stderr)
    print(f"  Both caught: {len(both_caught)}", file=sys.stderr)
    print(f"  Both missed: {len(both_missed)} "
          f"(of which {sum(1 for d in both_missed if d['is_credential'])} are credential files)",
          file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
