# v0.25 results — more parsers + harness trajectory + CI gate fix

Released 2026-06-08. Executes Phases 0-3 of `docs/v0p25_plan.md`.

## Headline (held flat, by design)

| Metric | v0.24 | v0.25 |
|---|---|---|
| MIN top-10 precision | 0.20 | 0.20 |
| MIN recall any-tier | 0.90 | 0.90 |

Same dynamic as v0.23 / v0.24 — the new parsers target file formats
that don't exist in MSF3 (paths only) or CredData (source-code
snippets).

```
ShareSift harness MIN trajectory
================================
            MIN top-10         MIN recall
v0.22.0     ▇▇░░░░░░░░ 0.20     ▇▇▇▇▇▇▇▇▇░ 0.90
v0.23.0     ▇▇░░░░░░░░ 0.20     ▇▇▇▇▇▇▇▇▇░ 0.90
v0.24.0     ▇▇░░░░░░░░ 0.20     ▇▇▇▇▇▇▇▇▇░ 0.90
v0.25.0     ▇▇░░░░░░░░ 0.20     ▇▇▇▇▇▇▇▇▇░ 0.90
```

Flat trajectory across 4 releases. The trajectory IS the
discipline working — we're adding capacity without claiming
unmeasured improvements, and the gate that would flag a regression
hasn't fired.

## What shipped

### Phase 0 — Eval-gate CI YAML fix

The v0.24 workflow embedded multi-line Python inside a `run: |`
block at column 0, which YAML treated as exiting the block scalar.
The workflow failed to parse on GitHub.

Fix: extracted the comparison logic to `tools/eval_gate_compare.py`
and made the workflow invoke it. The helper is now independently
testable (`tests/test_eval_gate_compare.py`, 5 tests covering
equal / improvement / top-10 regression / recall regression / empty
baseline).

### Phase 1 — 4 more structured parsers (22 → 26)

| Parser | Filenames | What it extracts |
|---|---|---|
| `pypirc` | `.pypirc`, `pypirc` | PyPI upload tokens — per-section username + password (PyPI uses `pypi-`-prefixed tokens) |
| `gcloud_credentials` | `application_default_credentials.json`, `adc.json`, `credentials.db.json` | GCP user-credential refresh token + client_secret. Skips service-account JSONs (already caught by v0.23 extractor). |
| `gh_cli_config` | `hosts.yml`, `hosts.yaml` | GitHub CLI OAuth tokens — per-host `oauth_token` + `user` |
| `keyring_credentials` | `keyring_pass.cfg`, `keyring_cryptfile_pass.cfg`, `keyringrc.cfg` | Python keyring file-backend storage — base64'd passwords in `keyring_pass.cfg`; flags encrypted blobs in cryptfile; flags risky backend choice in `keyringrc.cfg` |

Each parser uses synthetic fixtures matching the documented format,
not real captures.

### Phase 2 — Harness trajectory visualisation

`tools/plot_harness_history.py` reads
`benchmarks/v0p22_eval/harness_history.jsonl` and emits a text-mode
chart (no matplotlib, no PNG). Two side-by-side bars per release:
MIN top-10 and MIN recall, each over a 10-cell 0..1 axis.

The chart above shows the v0.22-v0.25 trajectory. A future
regression would show fewer filled cells; a future improvement
would show more.

### Phase 3 — Re-run + ship

Harness ran clean; MIN top-10 = 0.20 and MIN recall = 0.90 held.

## Tests

| Component | Tests added |
|---|---|
| `pypirc` + `gcloud_credentials` + `gh_cli_config` + `keyring_credentials` | 10 |
| `tools/eval_gate_compare.py` | 5 |
| `tools/plot_harness_history.py` | 6 |

Full suite: 811 passing, 8 skipped (was 790 — +21 new, 0 regressions).

## Sprint accounting

| Sprint | Status |
|---|---|
| 0 — fix eval_gate.yml + extract `eval_gate_compare.py` | ✅ |
| 1 — 4 new parsers | ✅ |
| 2 — `plot_harness_history.py` | ✅ |
| 3 — re-run + ship | ✅ (this doc) |

## What v0.25 explicitly didn't do

- **Registry hive parser** — still need real `.reg` exports or live
  hives to validate
- **PuTTY `.ppk` parser** — encrypted v2/v3 format non-trivial
- **Stage 2 LoRA cross-distribution eval** — weights still not tracked
- **New held-out benchmark** — until we have one we haven't tuned
  against, broader generalization claims aren't justified. The
  trajectory tracking lets a future new benchmark be plugged in and
  compared against the existing history.

## What's queued for v0.26

| Item |
|---|
| Registry hive parser when samples accessible |
| PuTTY `.ppk` parser when samples accessible |
| Stage 2 LoRA cross-distribution eval when weights tracked |
| Acquire a 4th independent held-out set (GOAD, a HTB box dump, or PoshC2 logs) |
| Verifiers for the v0.23 new credential types (Stripe, SendGrid, etc.) — read-only API calls to confirm "this token is valid" without touching state |

## Meta

Four releases (v0.22-v0.25) ago I had to back out an overconfident
"+46 pp" claim from v0.21 because the reranker overfit on synthetic
data. Since then: MIN top-10 has held flat at 0.20. That's not
exciting, but the trajectory chart says it honestly. The discipline
trades exciting numbers for trustworthy ones.

If v0.26 brings a NEW held-out set that ALSO shows 0.20 / 0.90,
we'll have evidence the stack generalizes. If the new set shows a
worse number, we'll learn what real cross-distribution looks like.
Either way the chart will show it.
