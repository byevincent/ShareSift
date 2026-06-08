# v0.24 results — 4 new structured parsers + harness tracking

Released 2026-06-08. Executes Phases 1-3 of the v0.24 plan
(`docs/v0p24_plan.md`).

## Headline numbers (held flat, by design)

| Metric | v0.23 | v0.24 |
|---|---|---|
| MIN top-10 precision (primary) | 0.20 | 0.20 |
| MIN recall any-tier (primary) | 0.90 | 0.90 |

Per-set: MSF3 recall 0.90, top-10 0.20. CredData recall 1.00,
top-10 0.70. engagement_corpus (supp) recall 0.90, top-10 0.60.

**Same dynamic as v0.23.** The new parsers don't fire on MSF3
(which is path-only) or CredData (which doesn't contain wp-config /
AWS credentials / .netrc / Maven settings files). The added
capacity is real and applies on real engagements; the held-out
sets just aren't shaped to reward it.

## What shipped

### Phase 1 — 4 new structured parsers

Pre-v0.24 parser count: 18. v0.24: **22**.

| Parser | Filenames matched | What it extracts |
|---|---|---|
| `wp_config_php` | `wp-config.php`, `wp-config.php.bak`, `wp-config.php.old` | DB_NAME / DB_USER / DB_PASSWORD / DB_HOST + 8 auth keys (AUTH_KEY, SECURE_AUTH_KEY, LOGGED_IN_KEY, NONCE_KEY + 4 salts). Skips boilerplate placeholders ("put your unique phrase here"). |
| `aws_cli_credentials` | `credentials`, `aws_credentials`, `credentials.bak` | Per-profile `aws_access_key_id` / `aws_secret_access_key` / `aws_session_token` across all INI sections. Fallback regex if the INI parser fails. |
| `netrc` | `.netrc`, `_netrc`, `netrc` | Per-machine `login` / `password` / `account` tokens. Handles both multi-line and single-line forms; supports the `default` block. |
| `maven_settings_xml` | `settings.xml` | Per-server `<id>` + `<username>` + `<password>` inside `<servers>` blocks. Walks by local-name so the standard Maven xmlns doesn't trip up extraction. Silent on non-Maven settings.xml files. |

Each parser yields `ExtractedField` records that integrate into
`ScanResult.extracted_fields`. Downstream consumers (verify
dispatch, ranker features, report rendering) all see the new
extractions automatically.

### Phase 2 — Harness baseline tracking

1. **`benchmarks/v0p22_eval/harness_history.jsonl`** — append-only
   record of `(version, date, MIN top-10, MIN recall)` per release.
   Lets us plot the trajectory across versions without depending on
   GitHub Actions artifact retention.
2. **Artifact upload in eval gate workflow** —
   `.github/workflows/eval_gate.yml` now uploads
   `harness_results.json` as a workflow artifact with 90-day
   retention. Each commit's full per-set metrics are inspectable
   after the fact.

## Did the new components help? (Honest, same as v0.23)

The harness MIN didn't move. The four new parsers target file
formats that don't exist in our held-out sets:

- **MSF3** has only path strings. No file content → no parser invocation.
- **CredData** is source-code-credential text snippets. wp-config /
  `.aws/credentials` / `.netrc` / `settings.xml` files don't appear in
  CredData's corpus shape.
- **engagement_corpus** has paths only — same as MSF3.

Why ship them anyway: these formats are documented and high-frequency
in real engagements. wp-config.php is on the majority of WordPress
sites; `.aws/credentials` is the default location for AWS CLI;
`.netrc` is touched by curl/wget/git CLI; `settings.xml` is on every
Maven build server.

The discipline says: **claim only what we measure, but ship what we
know is independently valuable**. Same line v0.23 drew.

## Tests

11 new in `tests/test_parsers_v0p24.py`:

- wp-config.php: DB creds, auth keys, placeholder skip
- AWS credentials: default + named profiles
- .netrc: multi-line, single-line, default block
- Maven settings.xml: passwords, namespace handling, silent on non-Maven

Full suite: 790 passing, 8 skipped (was 779 — +11 new, 0 regressions).

## What v0.24 explicitly didn't do

- **Registry hive parser** — need real `.reg` exports or live hives
  to validate. v0.25 if samples land.
- **PuTTY `.ppk` parser** — encrypted v2/v3 format non-trivial.
- **Stage 2 LoRA cross-distribution eval** — weights still not
  tracked. Plan E from v0.22 keeps slipping until weights are
  accessible.

## Sprint accounting

| Sprint | Status |
|---|---|
| 1 — 4 new parsers + dispatch wiring | ✅ |
| 2 — harness history + artifact upload | ✅ |
| 3 — re-run + ship | ✅ (this doc) |

## What's queued for v0.25

| Item |
|---|
| Registry hive parser when samples accessible |
| PuTTY `.ppk` parser when samples accessible |
| Stage 2 LoRA cross-distribution eval when weights tracked |
| More structured parsers — `.pypirc`, gcloud credentials, gh CLI auth, KeyringFile |
| `tools/plot_harness_history.py` — render the harness_history.jsonl as a chart |

## Meta

Same release shape as v0.23: ship versatile capacity, hold the
headline flat, document honestly. The harness history file (started
in this release) will eventually let us look back at "MIN top-10
trajectory v0.22 → v0.30" and see whether the discipline produced
incremental gains or merely defended against regressions. Both are
acceptable outcomes; the discipline just makes the trajectory
visible.
