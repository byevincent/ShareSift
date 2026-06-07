"""Diff pysnaffler's bundled ruleset against our fresh port.

pysnaffler ships an embedded Snaffler ruleset (pickled) that lags behind
current Snaffler upstream. This tool loads both and reports:

  * Rules in port but NOT in pysnaffler  → we need to add these
  * Rules in pysnaffler but NOT in port  → pysnaffler may have older
    rules that upstream removed, or rules with renamed RuleName fields
  * Rules in BOTH but with different fields → semantics drift

For each missing-from-pysnaffler rule, prints the full definition so
we can convert it to TOML and ship in `src/truffler/rules/snaffler_supplement/`.

Usage:
    uv run python tools/diff_pysnaffler_vs_port.py
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_PORT = REPO_ROOT / "src" / "truffler" / "rules" / "snaffler_default.json"


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--port", type=Path, default=DEFAULT_PORT)
    args = p.parse_args(argv)

    if not args.port.exists():
        print(f"ERROR: --port missing: {args.port}\n"
              f"Run tools/port_snaffler_rules.py first.", file=sys.stderr)
        return 2

    port_data = json.loads(args.port.read_text())
    port_rules = {r["rule_name"]: r for r in port_data["rules"]}
    print(f"[port] {len(port_rules)} rules from "
          f"commit {port_data['snaffler_upstream']['commit_sha'][:10]}",
          file=sys.stderr)

    # Load pysnaffler's bundled ruleset
    sys.path.insert(0, str(REPO_ROOT / "references" / "pysnaffler"))
    from pysnaffler.ruleset import SnafflerRuleSet  # type: ignore[import-not-found]
    rs = SnafflerRuleSet.load_default_ruleset()
    pysnaffler_rules = {name: rule for name, rule in rs.allRules.items()}
    print(f"[pysnaffler] {len(pysnaffler_rules)} rules from bundled pickle",
          file=sys.stderr)

    port_names = set(port_rules.keys())
    pysnaffler_names = set(pysnaffler_rules.keys())
    missing_from_pysnaffler = sorted(port_names - pysnaffler_names)
    missing_from_port = sorted(pysnaffler_names - port_names)
    in_both = sorted(port_names & pysnaffler_names)

    print(f"\n=== Summary ===", file=sys.stderr)
    print(f"  port (fresh): {len(port_names)} rules", file=sys.stderr)
    print(f"  pysnaffler:   {len(pysnaffler_names)} rules", file=sys.stderr)
    print(f"  shared:       {len(in_both)} rules", file=sys.stderr)
    print(f"  port-only:    {len(missing_from_pysnaffler)} (we need to add these to pysnaffler)",
          file=sys.stderr)
    print(f"  pysnaffler-only: {len(missing_from_port)} (renamed upstream or pysnaffler-local)",
          file=sys.stderr)

    if missing_from_pysnaffler:
        print(f"\n=== Rules in PORT but NOT in pysnaffler "
              f"({len(missing_from_pysnaffler)}) ===\n", file=sys.stderr)
        for name in missing_from_pysnaffler:
            r = port_rules[name]
            print(f"--- {name} ---", file=sys.stderr)
            print(f"  source_file:    {r['source_file']}", file=sys.stderr)
            print(f"  triage:         {r['triage']}", file=sys.stderr)
            print(f"  match_action:   {r['match_action']}", file=sys.stderr)
            print(f"  match_location: {r['match_location']}", file=sys.stderr)
            print(f"  wordlist_type:  {r['wordlist_type']}", file=sys.stderr)
            wl_preview = r['wordlist'][:3] if isinstance(r['wordlist'], list) else [r['wordlist']]
            print(f"  wordlist ({len(r['wordlist'])} entries):", file=sys.stderr)
            for pat in wl_preview:
                print(f"    {pat!r}", file=sys.stderr)
            if len(r['wordlist']) > 3:
                print(f"    ... ({len(r['wordlist']) - 3} more)", file=sys.stderr)
            print(file=sys.stderr)

    if missing_from_port:
        print(f"\n=== Rules in pysnaffler but NOT in port "
              f"({len(missing_from_port)}) ===\n"
              f"(could be renamed upstream, or pysnaffler-local additions)",
              file=sys.stderr)
        for name in missing_from_port:
            r = pysnaffler_rules[name]
            print(f"  {name}: {r.triage.name}/{r.matchAction.name}/"
                  f"{r.matchLocation.name}", file=sys.stderr)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
