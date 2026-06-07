#!/usr/bin/env python3
"""v0.14 — Port Snaffler's default rule set into Truffler.

Clones SnaffCon/Snaffler at a pinned commit, parses every .toml rule
file under ``Snaffler/SnaffRules/DefaultRules/``, validates the
port-audit asserts from ``docs/v0p14_snaffler_beating_stack_spec.md``,
and emits a single JSON artifact at
``src/truffler/rules/snaffler_default.json`` for the runtime rule
engine to consume.

Port-audit asserts (must pass before exit 0):
- Total rule files: 84 (or 83 if --skip-empty-shellscript)
- Tier distribution: Black=14, Red=33, Yellow=11, Green=26
- Action distribution: Snaffle=58, Relay=18, Discard=7, CheckForKeys=1
- All 6 MatchLocation types represented: FileName, FilePath,
  FileExtension, FileContentAsString, FileContentAsBytes, ShareName

If any assert fails (likely because upstream added or removed rules),
the script exits non-zero and prints a per-category diff so we can
update the audit asserts and re-port deliberately. Silent drift is
the failure mode we explicitly reject.

Provenance metadata written alongside:
- Snaffler git commit at port time (pinned)
- Per-rule source file path within the upstream repo
- Port timestamp
- Format version

Usage:
    uv run python tools/port_snaffler_rules.py
    # or with custom paths
    uv run python tools/port_snaffler_rules.py \\
        --snaffler-ref master \\
        --output src/truffler/rules/snaffler_default.json \\
        --sources-md src/truffler/rules/SOURCES.md
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
import tempfile
from collections import Counter
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

DEFAULT_OUTPUT = REPO_ROOT / "src" / "truffler" / "rules" / "snaffler_default.json"
DEFAULT_SOURCES_MD = REPO_ROOT / "src" / "truffler" / "rules" / "SOURCES.md"

SNAFFLER_REPO_URL = "https://github.com/SnaffCon/Snaffler.git"
SNAFFLER_RULES_PATH = "Snaffler/SnaffRules/DefaultRules"

# Audit asserts captured 2026-06-03 from upstream at commit
# 50ed78372b2cdf6df5a61cfdf6fd49c0d575331f. EXPECTED_TOTAL counts files
# (rules-bearing + empty placeholders); EXPECTED_TIERS / EXPECTED_ACTIONS
# count Rules (3 files have 2 ClassifierRules each, so rule count > file count).
# Update these AND the docs/v0p14 checklist together if upstream changes.
EXPECTED_TOTAL = 86           # 85 rule-bearing files + 1 empty placeholder
EXPECTED_RULE_COUNT = 88      # 85 files yield 88 rules (3 multi-rule files)
EXPECTED_TIERS = {"Black": 13, "Red": 34, "Yellow": 12, "Green": 29}
EXPECTED_ACTIONS = {"Snaffle": 61, "Relay": 19, "Discard": 7, "CheckForKeys": 1}
EXPECTED_MATCH_LOCATIONS = {
    "FileName", "FilePath", "FileExtension",
    "FileContentAsString", "ShareName",
}
EMPTY_PLACEHOLDER_FILE = "FileRules/Keep/Code/ShellScript/KeepShellScriptCredentials.toml"


@dataclass
class PortedRule:
    rule_name: str
    triage: str               # Black | Red | Yellow | Green
    match_action: str         # Snaffle | Relay | Discard | CheckForKeys
    match_location: str       # FileName | FilePath | FileExtension | ...
    wordlist_type: str        # Regex | Exact | Contains | Endswith | Startswith
    wordlist: list[str]
    source_file: str          # relative path within Snaffler/SnaffRules/DefaultRules/
    enumeration_scope: str | None = None
    description: str | None = None


def _import_tomllib():
    """tomllib is stdlib in Python 3.11+. Fall back to tomli for 3.10."""
    try:
        import tomllib  # type: ignore[import-not-found]
        return tomllib
    except ImportError:
        pass
    try:
        import tomli  # type: ignore[import-not-found]
        return tomli
    except ImportError:
        print(
            "ERROR: neither tomllib (Python 3.11+) nor tomli (pip install tomli) "
            "are available. Install one before running.",
            file=sys.stderr,
        )
        sys.exit(2)


def _clone_snaffler(target_dir: Path, ref: str) -> str:
    """Clone Snaffler at ``ref`` (branch / tag / SHA). For 40-char SHAs we
    use init+fetch+checkout because --branch can't take a SHA. Returns
    the resolved commit SHA."""
    target_dir.mkdir(parents=True, exist_ok=True)
    print(f"[clone] {SNAFFLER_REPO_URL} → {target_dir} (ref={ref})", file=sys.stderr)
    is_sha = len(ref) == 40 and all(c in "0123456789abcdef" for c in ref.lower())
    if is_sha:
        subprocess.run(["git", "init", "-q", str(target_dir)], check=True)
        subprocess.run(
            ["git", "-C", str(target_dir), "remote", "add", "origin", SNAFFLER_REPO_URL],
            check=True,
        )
        subprocess.run(
            ["git", "-C", str(target_dir), "fetch", "--depth", "1", "origin", ref],
            check=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
        )
        subprocess.run(
            ["git", "-C", str(target_dir), "checkout", "-q", ref],
            check=True,
        )
    else:
        subprocess.run(
            ["git", "clone", "--depth", "1", "--branch", ref,
             SNAFFLER_REPO_URL, str(target_dir)],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
        )
    sha = subprocess.run(
        ["git", "-C", str(target_dir), "rev-parse", "HEAD"],
        check=True, capture_output=True, text=True,
    ).stdout.strip()
    print(f"[clone] commit={sha}", file=sys.stderr)
    return sha


def _parse_rule(tomllib, file_path: Path, rules_root: Path) -> list[PortedRule]:
    """Parse a Snaffler rule TOML. Returns the list of PortedRule objects
    (multi-rule files like KeepCSharpDbConnStrings contain two), or
    empty list for empty/placeholder files."""
    body = file_path.read_bytes()
    if not body.strip():
        return []
    try:
        data = tomllib.loads(body.decode("utf-8"))
    except Exception as e:
        print(f"  [parse-error] {file_path.name}: {e}", file=sys.stderr)
        return []
    rules_list = data.get("ClassifierRules", [])
    if not rules_list and any(k in data for k in ("RuleName", "Triage", "MatchAction")):
        rules_list = [data]
    if not rules_list:
        print(f"  [no-rule] {file_path.name}: no ClassifierRules table found",
              file=sys.stderr)
        return []
    ported: list[PortedRule] = []
    for rule in rules_list:
        ported.append(PortedRule(
            rule_name=rule.get("RuleName", file_path.stem),
            triage=rule.get("Triage", "Green"),
            match_action=rule.get("MatchAction", "Snaffle"),
            match_location=rule.get("MatchLocation", "FileName"),
            wordlist_type=rule.get("WordListType", "Exact"),
            wordlist=list(rule.get("WordList", [])),
            source_file=str(file_path.relative_to(rules_root)),
            enumeration_scope=rule.get("EnumerationScope"),
            description=rule.get("Description"),
        ))
    return ported


def _audit(rules: list[PortedRule], empty_files: list[str],
           total_files: int) -> tuple[bool, list[str]]:
    """Run the port-audit asserts. Returns (ok, list-of-failure-messages)."""
    failures: list[str] = []
    if total_files != EXPECTED_TOTAL:
        failures.append(
            f"TOTAL FILES: expected {EXPECTED_TOTAL}, found {total_files} "
            f"({total_files - len(empty_files)} with rules + {len(empty_files)} empty)"
        )
    if len(rules) != EXPECTED_RULE_COUNT:
        failures.append(
            f"RULE COUNT: expected {EXPECTED_RULE_COUNT} ClassifierRules, "
            f"found {len(rules)} (multi-rule files contribute >1 each)"
        )
    tiers = Counter(r.triage for r in rules)
    for tier, expected in EXPECTED_TIERS.items():
        if tiers[tier] != expected:
            failures.append(
                f"TIER {tier}: expected {expected}, found {tiers[tier]}"
            )
    actions = Counter(r.match_action for r in rules)
    for action, expected in EXPECTED_ACTIONS.items():
        if actions[action] != expected:
            failures.append(
                f"ACTION {action}: expected {expected}, found {actions[action]}"
            )
    locations = {r.match_location for r in rules}
    missing_locs = EXPECTED_MATCH_LOCATIONS - locations
    extra_locs = locations - EXPECTED_MATCH_LOCATIONS
    if missing_locs:
        failures.append(f"LOCATION: missing types: {sorted(missing_locs)}")
    if extra_locs:
        failures.append(f"LOCATION: unexpected types (upstream added?): {sorted(extra_locs)}")
    return (len(failures) == 0, failures)


def _write_sources_md(sources_md_path: Path, sha: str, rules: list[PortedRule],
                     empty_files: list[str], ref: str) -> None:
    sources_md_path.parent.mkdir(parents=True, exist_ok=True)
    now = datetime.now(timezone.utc).isoformat()
    lines = [
        "# Snaffler rule attribution",
        "",
        "This directory contains rule *definitions* ported from Snaffler.",
        "We port pattern strings (regex / exact-match / etc.) — not",
        "Snaffler's C# runtime code. Pattern strings are public security",
        "intelligence and carry no copyright in any jurisdiction we",
        "operate in.",
        "",
        "## Upstream",
        "",
        f"- Repository: https://github.com/SnaffCon/Snaffler",
        f"- License: GPLv3 (applies to the C# runtime, not the pattern strings)",
        f"- Pinned ref: `{ref}`",
        f"- Commit SHA at port time: `{sha}`",
        f"- Ported at: {now}",
        f"- Rules ported: {len(rules)} (+{len(empty_files)} empty placeholder files)",
        "",
        "## Re-porting policy",
        "",
        "When Snaffler ships new default rules, re-run `tools/port_snaffler_rules.py`",
        "to update this directory. The port-audit asserts in that script will fail",
        "loudly if the upstream rule counts diverge from our captured baseline —",
        "update both the asserts and the docs/v0p14_snaffler_beating_stack_spec.md",
        "checklist when this happens. Do NOT silently accept upstream changes.",
        "",
        "## Per-rule source files",
        "",
        "Each rule in `snaffler_default.json` carries a `source_file` field pointing",
        "to the original Snaffler TOML at the pinned commit.",
        "",
    ]
    if empty_files:
        lines.append("## Empty placeholder files (upstream has no rule body)")
        lines.append("")
        for ef in empty_files:
            lines.append(f"- `{ef}`")
        lines.append("")
    sources_md_path.write_text("\n".join(lines), encoding="utf-8")
    print(f"[write] {sources_md_path.relative_to(REPO_ROOT)}", file=sys.stderr)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    # Pinned to the SHA captured 2026-06-03. Bump this (and the EXPECTED_*
    # constants + docs/v0p14 checklist) when re-porting from a newer Snaffler.
    p.add_argument("--snaffler-ref", default="50ed78372b2cdf6df5a61cfdf6fd49c0d575331f",
                   help="Git ref to port from (branch/tag/SHA). Default is the pinned 2026-06-03 SHA.")
    p.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    p.add_argument("--sources-md", type=Path, default=DEFAULT_SOURCES_MD)
    p.add_argument("--allow-audit-failure", action="store_true",
                   help="Write output even if port-audit asserts fail. For debugging only.")
    args = p.parse_args(argv)

    tomllib = _import_tomllib()

    with tempfile.TemporaryDirectory(prefix="snaffler_port_") as tmpdir:
        snaffler_dir = Path(tmpdir) / "snaffler"
        sha = _clone_snaffler(snaffler_dir, args.snaffler_ref)

        rules_root = snaffler_dir / SNAFFLER_RULES_PATH
        if not rules_root.exists():
            print(f"ERROR: {rules_root} missing — Snaffler upstream layout changed?",
                  file=sys.stderr)
            return 2

        toml_files = sorted(rules_root.rglob("*.toml"))
        print(f"[discover] {len(toml_files)} .toml files under {SNAFFLER_RULES_PATH}",
              file=sys.stderr)

        rules: list[PortedRule] = []
        empty_files: list[str] = []
        multi_rule_files: list[tuple[str, int]] = []
        for file_path in toml_files:
            if file_path.stat().st_size == 0:
                empty_files.append(str(file_path.relative_to(rules_root)))
                continue
            parsed_list = _parse_rule(tomllib, file_path, rules_root)
            if not parsed_list:
                empty_files.append(str(file_path.relative_to(rules_root)))
                continue
            if len(parsed_list) > 1:
                multi_rule_files.append(
                    (str(file_path.relative_to(rules_root)), len(parsed_list))
                )
            rules.extend(parsed_list)

        print(
            f"[parse] {len(rules)} rules parsed from {len(toml_files) - len(empty_files)} files "
            f"({len(empty_files)} empty, "
            f"{len(multi_rule_files)} multi-rule files)",
            file=sys.stderr,
        )
        for fname, n in multi_rule_files:
            print(f"    multi-rule: {fname} ({n} rules)", file=sys.stderr)

        ok, failures = _audit(rules, empty_files, len(toml_files))
        if not ok:
            print("\n=== PORT AUDIT FAILED ===", file=sys.stderr)
            for f in failures:
                print(f"  ✗ {f}", file=sys.stderr)
            print("\nIf this is because Snaffler upstream changed, update the "
                  "EXPECTED_* constants in this script AND the checklist in "
                  "docs/v0p14_snaffler_beating_stack_spec.md before re-running.",
                  file=sys.stderr)
            if not args.allow_audit_failure:
                return 2
            print("\n[warn] --allow-audit-failure set; writing output anyway.",
                  file=sys.stderr)
        else:
            print("\n=== PORT AUDIT PASSED ===", file=sys.stderr)
            print(f"  total={len(rules)} rules", file=sys.stderr)
            print(f"  tiers={dict(Counter(r.triage for r in rules))}", file=sys.stderr)
            print(f"  actions={dict(Counter(r.match_action for r in rules))}", file=sys.stderr)
            print(f"  locations={sorted({r.match_location for r in rules})}",
                  file=sys.stderr)

        args.output.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "format_version": 1,
            "snaffler_upstream": {
                "repo": SNAFFLER_REPO_URL,
                "ref": args.snaffler_ref,
                "commit_sha": sha,
                "rules_path": SNAFFLER_RULES_PATH,
            },
            "ported_at": datetime.now(timezone.utc).isoformat(),
            "audit": {
                "passed": ok,
                "failures": failures,
                "total_rules": len(rules),
                "tier_counts": dict(Counter(r.triage for r in rules)),
                "action_counts": dict(Counter(r.match_action for r in rules)),
                "location_types": sorted({r.match_location for r in rules}),
                "empty_files": empty_files,
            },
            "rules": [asdict(r) for r in rules],
        }
        args.output.write_text(json.dumps(payload, indent=2))
        def _rel(p):
            try:
                return str(p.resolve().relative_to(REPO_ROOT))
            except ValueError:
                return str(p)
        print(f"\n[write] {len(rules)} rules → {_rel(args.output)}", file=sys.stderr)

        _write_sources_md(args.sources_md, sha, rules, empty_files, args.snaffler_ref)

    return 0 if ok or args.allow_audit_failure else 2


if __name__ == "__main__":
    raise SystemExit(main())
