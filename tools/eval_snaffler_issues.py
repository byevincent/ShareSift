"""v0.47 step 3: score ShareSift against the Snaffler-issues corpus.

Reads ``benchmarks/snaffler_issues/{corpus,heldout}.jsonl`` — one
probe per line, each with an expected tier — and reports how the
current cascade handles each one. Two probe types:

* ``probe_type: "path"`` — score via ``PathClassifier``, compare the
  returned tier to ``expected_tier``.
* ``probe_type: "content"`` — score via ``ContentRuleEngine``, take
  the highest-tier rule match against the synthetic content snippet,
  compare to ``expected_tier``.

The expected_tier semantics: for ``signal_type == "miss"`` probes,
ShareSift must return ``>= expected_tier`` to PASS (catching it at a
HIGHER tier is fine — that's the augmenter thesis). For
``signal_type == "fp"`` probes, ShareSift must return strictly LOWER
than ``expected_tier`` or no tier at all (we're trying NOT to flag).

Output: per-probe pass/fail to stdout, summary to stderr.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

# Allow `python tools/eval_snaffler_issues.py` from the repo root.
REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "src"))

from sharesift.content_rules import ContentRuleEngine
from sharesift.path import PathClassifier

CORPUS_PATH = REPO_ROOT / "benchmarks" / "snaffler_issues" / "corpus.jsonl"
HELDOUT_PATH = REPO_ROOT / "benchmarks" / "snaffler_issues" / "heldout.jsonl"

# Tier rank for compare. Higher = juicier.
_TIER_RANK = {"Black": 4, "Red": 3, "Yellow": 2, "Green": 1, None: 0}


def _tier_geq(actual: str | None, expected: str) -> bool:
    return _TIER_RANK.get(actual, 0) >= _TIER_RANK.get(expected, 0)


def _max_tier(a: str | None, b: str | None) -> str | None:
    return a if _TIER_RANK.get(a, 0) >= _TIER_RANK.get(b, 0) else b


def _tier_leq(actual: str | None, expected: str) -> bool:
    """For FP probes: PASS when actual is no HIGHER than expected.

    ``expected_tier == "Green"`` means "should not be elevated above the
    Green floor"; ``Green`` itself is fine because Green is operator
    parlance for "indexed but not actionable."
    """
    return _TIER_RANK.get(actual, 0) <= _TIER_RANK.get(expected, 0)


def main() -> int:
    import argparse

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--set",
        choices=("corpus", "heldout", "both"),
        default="corpus",
        help="Which probe set to score (default: corpus).",
    )
    args = parser.parse_args()

    probes: list[dict] = []
    if args.set in ("corpus", "both"):
        if not CORPUS_PATH.exists():
            print(f"ERROR: corpus not found at {CORPUS_PATH}", file=sys.stderr)
            return 1
        probes.extend(
            json.loads(line) for line in CORPUS_PATH.read_text().splitlines() if line.strip()
        )
        print(f"Loaded {len(probes)} probes from {CORPUS_PATH.name}", file=sys.stderr)
    if args.set in ("heldout", "both"):
        if not HELDOUT_PATH.exists():
            print(f"ERROR: heldout not found at {HELDOUT_PATH}", file=sys.stderr)
            return 1
        before = len(probes)
        probes.extend(
            json.loads(line) for line in HELDOUT_PATH.read_text().splitlines() if line.strip()
        )
        print(
            f"Loaded {len(probes) - before} probes from {HELDOUT_PATH.name}",
            file=sys.stderr,
        )

    path_clf = PathClassifier()
    content_eng = ContentRuleEngine()

    pass_count = 0
    fail_count = 0
    miss_pass = miss_fail = 0
    fp_pass = fp_fail = 0
    fails: list[tuple[str, str, str | None, str]] = []

    for probe in probes:
        probe_id = probe["id"]
        expected = probe["expected_tier"]
        signal = probe["signal_type"]
        actual_tier: str | None
        explanation = ""

        # Production cascade is Stage 1 (path classifier) + rule engine.
        # We take the MAX-tier verdict across both for path probes; for
        # content probes the rule engine sees the content, the path
        # classifier sees just the path, take MAX of both.
        path_res = path_clf.score_batch([probe["path"]])[0]
        rule_verdict = content_eng.evaluate(probe["path"], probe.get("content_snippet"))
        ml_tier = path_res.tier
        rule_tier = rule_verdict.tier
        actual_tier = _max_tier(ml_tier, rule_tier)
        explanation_bits = [f"p={path_res.probability:.3f}"]
        if rule_verdict.matches:
            rule_names = ",".join(m.rule_name for m in rule_verdict.matches[:3])
            explanation_bits.append(f"matches={rule_names}")
        else:
            explanation_bits.append("no-rule")
        explanation = " ".join(explanation_bits)

        if signal == "miss":
            ok = _tier_geq(actual_tier, expected)
            if ok:
                miss_pass += 1
            else:
                miss_fail += 1
        else:  # signal == "fp"
            ok = _tier_leq(actual_tier, expected)
            if ok:
                fp_pass += 1
            else:
                fp_fail += 1

        if ok:
            pass_count += 1
            marker = "PASS"
        else:
            fail_count += 1
            marker = "FAIL"
            fails.append((probe_id, expected, actual_tier, explanation))

        print(
            f"  [{marker}] {probe_id:42s} signal={signal:4s} "
            f"expected={expected:6s} actual={str(actual_tier):6s} {explanation}"
        )

    print(file=sys.stderr)
    print("=" * 70, file=sys.stderr)
    print(
        f"Total: {pass_count}/{len(probes)} passed ({fail_count} failed)",
        file=sys.stderr,
    )
    print(f"  miss probes: {miss_pass}/{miss_pass+miss_fail} passed", file=sys.stderr)
    print(f"  fp   probes: {fp_pass}/{fp_pass+fp_fail} passed", file=sys.stderr)
    if fails:
        print(file=sys.stderr)
        print("Failed probes (candidate rule additions for v0.47):", file=sys.stderr)
        for probe_id, expected, actual, why in fails:
            print(
                f"  {probe_id:42s} expected={expected:6s} actual={str(actual):6s} ({why})",
                file=sys.stderr,
            )

    return 0 if fail_count == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
