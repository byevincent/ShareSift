# Snaffler rule attribution

This directory contains rule *definitions* ported from Snaffler.
We port pattern strings (regex / exact-match / etc.) — not
Snaffler's C# runtime code. Pattern strings are public security
intelligence and carry no copyright in any jurisdiction we
operate in.

## Upstream

- Repository: https://github.com/SnaffCon/Snaffler
- License: GPLv3 (applies to the C# runtime, not the pattern strings)
- Pinned ref: `50ed78372b2cdf6df5a61cfdf6fd49c0d575331f`
- Commit SHA at port time: `50ed78372b2cdf6df5a61cfdf6fd49c0d575331f`
- Ported at: 2026-06-03T20:11:05.363870+00:00
- Rules ported: 88 (+1 empty placeholder files)

## Re-porting policy

When Snaffler ships new default rules, re-run `tools/port_snaffler_rules.py`
to update this directory. The port-audit asserts in that script will fail
loudly if the upstream rule counts diverge from our captured baseline —
update both the asserts and the docs/v0p14_snaffler_beating_stack_spec.md
checklist when this happens. Do NOT silently accept upstream changes.

## Per-rule source files

Each rule in `snaffler_default.json` carries a `source_file` field pointing
to the original Snaffler TOML at the pinned commit.

## Empty placeholder files (upstream has no rule body)

- `FileRules/Keep/Code/ShellScript/KeepShellScriptCredentials.toml`
