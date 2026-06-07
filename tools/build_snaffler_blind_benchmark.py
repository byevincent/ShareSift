"""Build the Snaffler-blind held-out benchmark for Phase 2 model evaluation.

Per ``docs/build_plan.md`` Phase 1, the path classifier needs a measurement
target — paths Snaffler's TOML rules WEREN'T designed for. Phase 2's
"did the ML model beat Snaffler" question is unanswerable without this set.

What this script does:

1. Walks Snaffler's default rule pack (``references/Snaffler/.../DefaultRules/``),
   parses every TOML rule, and keeps the path-applicable ones (MatchLocation
   in FileName / FilePath / FileExtension). Content-scan rules
   (FileContentAsString) are skipped — we're simulating path-level triage.
2. Implements pysnaffler's WordListType → regex conversion (Regex / EndsWith
   / StartsWith / Contains / Exact, all with case-insensitive flag) so the
   simulator matches what pysnaffler would actually do on the same path.
3. Classifies every record in ``data/eval/eval_set_claude.jsonl`` as
   Discard (Snaffler explicitly skips), Snaffle/Relay (Snaffler engages),
   or Silent (no rule fires). "Snaffler-blind" = Silent.
4. Samples 500 Snaffler-silent records, stratified by Truffler's juicy
   label so the benchmark measures both recall (juicy paths Snaffler
   missed) and specificity (not_juicy paths Snaffler skipped, where
   the ML model shouldn't false-positive).
5. Writes ``data/eval/snaffler_blind_benchmark.jsonl``.

Stats printed at the end include:
- Snaffler verdict breakdown over the full queue
- Snaffler's recall on Truffler-juicy paths (the "what Snaffler caught" number)
- Sample composition

Note on scope: this simulates Snaffler's *path-level* triage only. Snaffler
also runs content-scan rules (FileContentAsString) once a file is opened;
those are downstream of path triage and don't affect what's "Snaffler-blind"
at the candidate-selection stage.
"""

from __future__ import annotations

import argparse
import json
import random
import re
import sys
import tomllib
from dataclasses import dataclass
from pathlib import Path, PureWindowsPath

REPO_ROOT = Path(__file__).resolve().parent.parent
SNAFFLER_RULES_ROOT = (
    REPO_ROOT / "references" / "Snaffler" / "Snaffler" / "SnaffRules" / "DefaultRules"
)
LABELED_PATH = REPO_ROOT / "data" / "eval" / "eval_set_claude.jsonl"
DEFAULT_OUTPUT = REPO_ROOT / "data" / "eval" / "snaffler_blind_benchmark.jsonl"

_PATH_MATCH_LOCATIONS = frozenset({"FileName", "FilePath", "FileExtension"})
_SNAFFLE_ACTIONS = frozenset({"Snaffle", "Relay"})  # Snaffler engages
_DISCARD_ACTIONS = frozenset({"Discard"})


@dataclass(frozen=True)
class SnafflerRule:
    name: str
    action: str
    location: str  # FileName, FilePath, FileExtension
    patterns: tuple[re.Pattern, ...]
    triage: str | None


def _word_to_regex(word: str, word_list_type: str) -> str:
    """Mirror pysnaffler's WordListType → regex conversion (rules/rule.py
    __convert_wordlist). Same semantics so the simulator agrees with what
    pysnaffler would compute on the same path."""
    if word_list_type == "Regex":
        return word
    if word_list_type == "EndsWith":
        return word + "$"
    if word_list_type == "StartsWith":
        return "^" + word
    if word_list_type == "Contains":
        return ".*" + word + ".*"
    if word_list_type == "Exact":
        return "^" + word + "$"
    raise ValueError(f"unknown WordListType {word_list_type!r}")


def _load_rule_file(toml_path: Path) -> list[SnafflerRule]:
    with toml_path.open("rb") as f:
        data = tomllib.load(f)
    rules: list[SnafflerRule] = []
    for raw in data.get("ClassifierRules", []):
        location = raw.get("MatchLocation", "")
        if location not in _PATH_MATCH_LOCATIONS:
            continue
        word_list_type = raw.get("WordListType", "")
        if word_list_type not in {"Regex", "EndsWith", "StartsWith", "Contains", "Exact"}:
            continue
        patterns: list[re.Pattern] = []
        for word in raw.get("WordList", []):
            try:
                patterns.append(
                    re.compile(_word_to_regex(word, word_list_type), flags=re.IGNORECASE)
                )
            except re.error:
                # Snaffler regexes are .NET-flavored — a small fraction
                # use constructs Python's re module can't compile. Skip
                # those rather than crash; under-counting Snaffler's
                # coverage is the safer error direction (a benchmark
                # entry that Snaffler would actually catch ends up in
                # the "blind" set, which understates our blind-coverage
                # claim rather than overstating it).
                continue
        if not patterns:
            continue
        rules.append(
            SnafflerRule(
                name=raw.get("RuleName", toml_path.stem),
                action=raw.get("MatchAction", ""),
                location=location,
                patterns=tuple(patterns),
                triage=raw.get("Triage"),
            )
        )
    return rules


def load_snaffler_rules(rules_root: Path) -> list[SnafflerRule]:
    """Walk the DefaultRules tree and return every path-applicable rule."""
    rules: list[SnafflerRule] = []
    for toml_path in sorted(rules_root.rglob("*.toml")):
        rules.extend(_load_rule_file(toml_path))
    return rules


def classify_path(path: str, rules: list[SnafflerRule]) -> tuple[str, str | None]:
    """Return (verdict, rule_name) where verdict is 'Snaffle' (Snaffler
    would engage), 'Discard' (Snaffler would skip), or 'Silent' (no rule
    fires). For 'Snaffle' the highest-triage match wins; the rule_name
    is which one fired."""
    p = PureWindowsPath(path)
    name = p.name
    suffix = p.suffix
    # Per pysnaffler's file.py: strip a trailing .bak before extracting
    # the suffix (so foo.kdbx.bak still classifies as .kdbx).
    if path.endswith(".bak"):
        suffix = PureWindowsPath(path[:-4]).suffix

    # Discard wins over Snaffle per Snaffler evaluation order: if a path
    # is in a discarded directory or matches a discard rule, Snaffler
    # never gets to the keep rules.
    for rule in rules:
        if rule.action not in _DISCARD_ACTIONS:
            continue
        target = _target_for(rule.location, name, suffix, path)
        if any(rex.search(target) for rex in rule.patterns):
            return "Discard", rule.name

    # Then check Snaffle/Relay rules.
    triage_rank = {"Black": 0, "Red": 1, "Yellow": 2, "Green": 3, None: 4}
    best: tuple[int, SnafflerRule] | None = None
    for rule in rules:
        if rule.action not in _SNAFFLE_ACTIONS:
            continue
        target = _target_for(rule.location, name, suffix, path)
        if any(rex.search(target) for rex in rule.patterns):
            rank = triage_rank.get(rule.triage, 4)
            if best is None or rank < best[0]:
                best = (rank, rule)
    if best is not None:
        return "Snaffle", best[1].name
    return "Silent", None


def _target_for(
    location: str, name: str, suffix: str, full_path: str
) -> str:
    if location == "FileName":
        return name
    if location == "FileExtension":
        return suffix
    return full_path  # FilePath


def load_labeled_records(path: Path) -> list[dict]:
    return [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def stratified_sample(
    silent_records: list[dict], sample_size: int, seed: int
) -> list[dict]:
    """Sample with Truffler-label stratification. Aim for ~50/50 split
    of juicy / not_juicy when supply allows; if there aren't enough
    juicy candidates, take all juicy and fill remainder with not_juicy.
    """
    rng = random.Random(seed)
    juicy = [r for r in silent_records if r.get("label") == "juicy"]
    not_juicy = [r for r in silent_records if r.get("label") == "not_juicy"]
    target_juicy = min(sample_size // 2, len(juicy))
    target_not_juicy = sample_size - target_juicy
    if target_not_juicy > len(not_juicy):
        target_not_juicy = len(not_juicy)
    rng.shuffle(juicy)
    rng.shuffle(not_juicy)
    out = juicy[:target_juicy] + not_juicy[:target_not_juicy]
    rng.shuffle(out)
    return out


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    p.add_argument(
        "--input",
        type=Path,
        default=LABELED_PATH,
        help=f"Labeled queue JSONL (default {LABELED_PATH.relative_to(REPO_ROOT)}).",
    )
    p.add_argument(
        "--output",
        type=Path,
        default=DEFAULT_OUTPUT,
        help=f"Benchmark output JSONL (default {DEFAULT_OUTPUT.relative_to(REPO_ROOT)}).",
    )
    p.add_argument(
        "--rules-root",
        type=Path,
        default=SNAFFLER_RULES_ROOT,
        help="Snaffler DefaultRules directory.",
    )
    p.add_argument("--sample-size", type=int, default=500)
    p.add_argument("--seed", type=int, default=2026)
    args = p.parse_args(argv)

    rules = load_snaffler_rules(args.rules_root)
    print(
        f"Loaded {len(rules)} path-applicable Snaffler rules from "
        f"{args.rules_root.relative_to(REPO_ROOT)}",
        file=sys.stderr,
    )

    records = load_labeled_records(args.input)
    print(
        f"Loaded {len(records)} labeled records from "
        f"{args.input.relative_to(REPO_ROOT)}",
        file=sys.stderr,
    )

    verdict_counts = {"Snaffle": 0, "Discard": 0, "Silent": 0}
    juicy_by_verdict = {"Snaffle": 0, "Discard": 0, "Silent": 0}
    silent_records: list[dict] = []
    for r in records:
        verdict, rule_name = classify_path(r["path"], rules)
        verdict_counts[verdict] += 1
        if r.get("label") == "juicy":
            juicy_by_verdict[verdict] += 1
        if verdict == "Silent":
            silent_records.append(r)

    total = len(records)
    juicy_total = sum(juicy_by_verdict.values())

    print("\n=== Snaffler verdict breakdown (path-level rules only) ===")
    for v in ("Snaffle", "Discard", "Silent"):
        pct = 100 * verdict_counts[v] / total if total else 0
        j_pct = (
            100 * juicy_by_verdict[v] / juicy_total if juicy_total else 0
        )
        print(
            f"  {v:8s}: {verdict_counts[v]:6d} ({pct:5.1f}%) — "
            f"of which {juicy_by_verdict[v]:4d} Truffler-juicy "
            f"({j_pct:5.1f}% of all juicy)"
        )

    if juicy_total:
        snaffler_recall = 100 * juicy_by_verdict["Snaffle"] / juicy_total
        print(
            f"\nSnaffler recall on Truffler-juicy paths: "
            f"{snaffler_recall:.1f}% "
            f"({juicy_by_verdict['Snaffle']}/{juicy_total})"
        )
        snaffler_blind_on_juicy = juicy_by_verdict["Silent"]
        print(
            f"Truffler-juicy paths Snaffler missed (the recall gap "
            f"the ML model is supposed to close): "
            f"{snaffler_blind_on_juicy}"
        )

    sample = stratified_sample(silent_records, args.sample_size, args.seed)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", encoding="utf-8") as f:
        for rec in sample:
            f.write(json.dumps(rec) + "\n")

    sample_juicy = sum(1 for r in sample if r.get("label") == "juicy")
    print(
        f"\nWrote {len(sample)} records to "
        f"{args.output.relative_to(REPO_ROOT)} "
        f"({sample_juicy} juicy / {len(sample) - sample_juicy} not_juicy, "
        f"seed={args.seed})"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
