# v0.24 — more structured parsers + harness tracking

Drafted 2026-06-08 from the v0.23 results
(`docs/v0p23_results.md`). v0.23 added 9 credential-format extractors
and OOXML text extraction; v0.24 adds 4 structured parsers and a
GitHub Action artifact upload so harness MIN can be tracked over time.

Every item is **architecturally versatile**: no training distribution,
no benchmark-specific tuning, applies identically on every share.

## Phases

### Phase 1 — 4 new structured parsers

Pre-v0.24 parser count: 18. v0.24: **22**.

| Parser | Filename pattern | Why useful |
|---|---|---|
| `wp_config_php` | `wp-config.php` | WordPress installs are everywhere; pre-v0.24 the cascade catches the filename but doesn't extract the 8 auth keys + DB creds inside |
| `aws_cli_credentials` | `~/.aws/credentials`, `credentials` (in `.aws/` dir) | AWS CLI default credentials format; high-frequency on engineering shares |
| `netrc` | `.netrc`, `_netrc` | curl/wget/git CLI auth; common on Linux user homes |
| `maven_settings_xml` | `settings.xml` (Maven) | Build servers and dev workstations; embedded server passwords |

Each parser yields `ExtractedField` records — `field_name`, `value`,
`confidence`, `parser`. Output integrates into the existing
`ScanResult.extracted_fields` pipeline.

### Phase 2 — Harness baseline tracking

`.github/workflows/eval_gate.yml` already exists and runs
`tools/eval_harness.py` on every push/PR, failing if MIN regresses.
v0.24 adds:

1. **Artifact upload** — the `harness_results.json` from each run is
   uploaded as a workflow artifact, so a history of MIN over time is
   queryable from the GitHub Actions UI.
2. **`benchmarks/v0p22_eval/harness_history.jsonl`** — append-only
   record of `(commit_sha, date, MIN top-10, MIN recall)` checked
   in to the repo. Lets us plot the MIN trajectory across releases
   in a single file without depending on Actions retention.

### Phase 3 — Measure + ship

Re-run harness, expect numbers identical to v0.23 (new parsers can't
fire on MSF3 path-only data and CredData doesn't contain wp-config /
AWS credentials / `.netrc` / Maven settings files).

The capacity added is real and applies on real engagements; the
harness just isn't shaped to reward it. This is the same dynamic as
v0.23 — discipline lets us ship capacity without claiming a number.

## Out of scope (carryover)

- **Registry hive parser** — need real `.reg` exports or live hives to validate
- **PuTTY `.ppk` parser** — need real PPK files (the encrypted v2/v3 format is non-trivial)
- **Stage 2 LoRA cross-distribution eval** — weights still not tracked

## Sprint accounting

| Sprint | Scope | Deliverable |
|---|---|---|
| 1 | `wp_config_php`, `aws_cli_credentials`, `netrc`, `maven_settings_xml` parsers + dispatch wiring | `src/sharesift/parsers/*.py` |
| 2 | Harness artifact upload + history file | `.github/workflows/eval_gate.yml` + `benchmarks/v0p22_eval/harness_history.jsonl` |
| 3 | Re-run harness + ship | `docs/v0p24_results.md` + release |

## Versatility honesty note

Each new parser COULD overfit on a specific file shape (e.g., a
specific WordPress version's wp-config format). Mitigation: parser
tests use synthetic fixtures matching the documented file format
(PHP `define()` calls for wp-config, INI for AWS credentials,
machine/login/password for .netrc, `<server>` blocks for Maven), NOT
real captured files from any benchmark. We're testing "parser
recognises documented format," not "parser happens to extract
benchmark X correctly."
