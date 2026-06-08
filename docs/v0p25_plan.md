# v0.25 — more parsers + harness trajectory visualisation + CI fix

Drafted 2026-06-08. Continuing the architecturally-versatile-only
trajectory from v0.22-v0.24. Every item is documented-format-aware
(no training, no benchmark tuning).

## Phases

### Phase 0 — Fix the v0.24 CI gate YAML (urgent)

The v0.24 `eval_gate.yml` workflow embedded multi-line Python inside
a `run: |` block scalar at column 0, which YAML treated as exiting
the block — the workflow failed to parse. Fix: extract the
comparison logic to `tools/eval_gate_compare.py` and have the
workflow invoke it as a separate command.

Tested independently in `tests/test_eval_gate_compare.py`.

### Phase 1 — 4 more structured parsers (parser count 22 → 26)

| Parser | Filename | What it extracts |
|---|---|---|
| `pypirc` | `.pypirc`, `pypirc` | PyPI / TestPyPI upload tokens — `pypi:repository:username:password` INI sections |
| `gcloud_credentials` | `legacy_credentials/*.json`, `application_default_credentials.json` | GCP user/service-account refresh tokens + client_id/client_secret |
| `gh_cli_config` | `hosts.yml` (in `.config/gh/` dir or `gh` dir) | GitHub CLI OAuth tokens stored locally |
| `keyring_credentials` | `keyring*.cfg`, `keyringrc.cfg`, `keyring_credentials.json` | Python keyring backend config — sometimes carries password backend secrets |

Each parser uses synthetic test fixtures matching the documented
format, NOT real captures from any benchmark.

### Phase 2 — Harness trajectory visualisation

`tools/plot_harness_history.py` reads
`benchmarks/v0p22_eval/harness_history.jsonl` and emits a
text-mode chart (no matplotlib dep, no PNG) showing MIN top-10 and
MIN recall across every recorded release. Stdlib only.

Sample output:

```
ShareSift harness MIN trajectory
================================
              MIN top-10         MIN recall
v0.22.0     ▇▇▇▇░░░░░░ 0.20    ▇▇▇▇▇▇▇▇▇░ 0.90
v0.23.0     ▇▇▇▇░░░░░░ 0.20    ▇▇▇▇▇▇▇▇▇░ 0.90
v0.24.0     ▇▇▇▇░░░░░░ 0.20    ▇▇▇▇▇▇▇▇▇░ 0.90
v0.25.0     ▇▇▇▇░░░░░░ 0.20    ▇▇▇▇▇▇▇▇▇░ 0.90
```

If a release ever regresses, the chart shows the dip visually. If
a new component delivers measurable improvement, the chart shows
the jump.

### Phase 3 — Re-run harness + ship

Expected: same MIN (0.20 / 0.90). The new parsers, like v0.24's,
target file formats not present in MSF3 or CredData. Same honest
framing as v0.23/v0.24 — capacity grows independent of the harness
delta.

## Out of scope (carryover)

- Registry hive parser — need real `.reg` exports or live hive samples
- PuTTY `.ppk` parser — need real PPK files
- Stage 2 LoRA cross-distribution eval — weights still not tracked
- New held-out benchmark sets — until we have one we haven't tuned
  against, we can't validate broader generalization. v0.26+.

## Sprint accounting

| Sprint | Scope |
|---|---|
| 0 | Fix eval_gate.yml YAML + extract `tools/eval_gate_compare.py` |
| 1 | 4 new parsers (pypirc, gcloud, gh CLI, keyring) |
| 2 | `tools/plot_harness_history.py` |
| 3 | Re-run + ship |
