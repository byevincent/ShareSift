# v0.16 results — `--verify` + interactive HTML report

## Headline

**Two non-technical levers shipped that change the product's category, not
its margins.** v0.15.1 closed the technical pipeline (path classifier,
distilled content classifier, 44 extras, 13 parsers, three benchmark
BEATs vs Snaffler). v0.16 adds:

1. **`sharesift verify`** — live credential verification against 10
   credential types (7 HTTP-based SaaS + AWS STS + SSH bind + SMB/LDAP
   scaffolds). TruffleHog's `--only-verified` was the inspiration; this
   gives ShareSift the same precision lever.
2. **`sharesift render-report`** — single self-contained interactive
   HTML report. PowerHuntShares 2.0's actual moat is the report, not the
   parsers; this closes that operator-UX gap. No CDN calls — works in
   air-gapped engagement environments.

Both demo cleanly to a security audience and remove the two most
common "but does it ship like a real tool" objections.

## What shipped — `sharesift verify`

### Architecture

Six-file core + 10 verifier modules in `src/sharesift/verify/`:

| File | Purpose |
|---|---|
| `base.py` | `VerifyResult` dataclass + `BaseVerifier` ABC |
| `registry.py` | Lazy credential-type → verifier dispatch |
| `extractor.py` | Re-extract credentials from `content_excerpt` via regex |
| `rate_limiter.py` | Per-service token bucket |
| `_http.py` | Shared `requests`-based HTTP transport |
| `runner.py` | Orchestration + status aggregation |
| `anthropic.py`, `openai.py`, `huggingface.py`, `github.py`, `slack.py`, `databricks.py`, `aws.py` | HTTP verifiers (7) |
| `ssh.py`, `smb.py`, `ldap.py` | Network verifiers (3) |

### Coverage matrix

| Credential type | Verifier | Path |
|---|---|---|
| `anthropic_api_key` (+ admin) | Anthropic | `GET /v1/models` w/ `x-api-key` |
| `openai_api_key` (legacy + `sk-proj-`/`sk-svcacct-`/`sk-admin-`) | OpenAI | `GET /v1/models` w/ Bearer |
| `huggingface_token` (+ org) | HuggingFace | `GET /api/whoami-v2` |
| `github_pat_classic` / `_fine_grained` / `oauth` / `app_user` / `app` | GitHub | `GET /user` |
| `slack_bot_token` / `_user_token` / `_workspace_token` | Slack | `POST /api/auth.test` |
| `databricks_pat` | Databricks | `GET /clusters/list?max=1` (per-workspace) |
| `aws_access_key` | AWS | STS `GetCallerIdentity` via boto3 |
| `ssh_private_key` (OpenSSH / RSA / DSA / EC / Ed25519) | SSH | `paramiko` bind to target list |
| `smb_credential` | SMB | impacket SMB connect (scaffolded — needs parser hookup) |
| `ldap_credential` | LDAP | ldap3 simple bind (scaffolded — needs parser hookup) |

### CLI

```bash
uv run sharesift verify \
    --input hits.jsonl \
    --output verified.jsonl \
    [--target-file targets.yaml] \
    [--rate-limit 1.0] \
    [--dry-run] \
    [--only anthropic_api_key --only github_pat_classic] \
    [--no-banner]
```

Target file (YAML)::

```yaml
ssh:
  - host: build01.corp.local
    port: 22
    usernames: [root, deploy, ubuntu]
smb:
  - host: dc01.corp.local
ldap:
  - url: ldap://dc01.corp.local:389
    bind_dn_template: "{username}@corp.local"
databricks:
  - https://my-workspace.cloud.databricks.com
```

### Safety

- `--dry-run` reports what would be verified, sends no traffic.
- 3-second confirmation banner (suppressed with `--no-banner` for CI).
- Per-service token bucket; default 1 req/sec, configurable.
- Network verifiers (SSH/SMB/LDAP) refuse to run without `--target-file`
  — return `inconclusive` rather than firing into the void.
- `--only` filter restricts which credential types get dispatched.

### Status semantics (TruffleHog-compatible)

- `passed` — credential authenticated; metadata carries identity info
  (AWS account/ARN, GitHub login, Anthropic model count, etc.).
- `failed` — service rejected the credential (HTTP 401/403, AWS
  `InvalidClientTokenId`, SSH `AuthenticationException`).
- `inconclusive` — verification ran but result was ambiguous (timeout,
  network error, missing target file for SSH/SMB/LDAP).
- `skipped` — verification not attempted (dry-run, no verifier
  registered for the type, no extractable credential in excerpt).

Record-level `verification_status` rolls up: any `passed` wins,
otherwise any `failed`, otherwise inconclusive/skipped.

### Tests

37 tests passing across:
- `test_verify_extractor.py` — regex extraction for 8 cred formats + edge cases
- `test_verify_ssh_extractor.py` — SSH PEM block extraction
- `test_verify_rate_limiter.py` — token bucket timing
- `test_verify_runner.py` — orchestration + skip handling
- `test_verify_http.py` — mocked HTTP verifier responses

End-to-end smoke test: fake Anthropic + GitHub keys in a content
excerpt → both correctly mapped to `failed` (HTTP 401) by live verify.

## What shipped — `sharesift render-report`

### Architecture

| File | Purpose |
|---|---|
| `src/sharesift/report/html.py` | Jinja2 renderer + summary-stat computation |
| `src/sharesift/report/template.html.j2` | Self-contained HTML + inline CSS + vanilla JS |

Single self-contained `report.html` output — no CDN, no external
script/link tags. Works in air-gapped operator environments.

### Features

- **Summary banner**: total hits, by-tier counts (Black/Red/Yellow/Green
  with colored badges), by-verification-status (when `--verify` ran),
  top shares, top extensions.
- **Sortable table**: 7 columns (tier badge / path / probability /
  content check / verification badge / extension / snippet preview).
  Click column header → sort; click again → reverse.
- **Filter dropdowns**: tier, verification status, share, extension.
- **Search box**: full-text across path, snippet preview, and extracted
  credential types.
- **Row expand**: click any row to reveal extracted credential types,
  per-verification-attempt detail table, and full content excerpt in
  a monospace pre block.
- **Dark theme** sized for engagement-room demos. No JS framework
  dependency; ~250 lines of vanilla JS inline.

### CLI

```bash
uv run sharesift render-report \
    --input verified.jsonl \
    --output report.html \
    [--title "Acme Q3 2026 engagement"]
```

### Tests

7 tests passing covering structural HTML, summary-stat correctness,
share/extension extraction, and empty-record-list handling.

## Files added (v0.16)

```
src/sharesift/verify/         (16 files: __init__, base, registry, extractor,
                              rate_limiter, _http, runner, anthropic, openai,
                              huggingface, github, slack, databricks, aws,
                              ssh, smb, ldap)
src/sharesift/report/         (3 files: __init__, html, template.html.j2)
tests/test_verify_*.py       (5 files)
tests/test_report_html.py    (1 file)
docs/v0p16_results.md        (this doc)
```

## Files modified

- `src/sharesift/cli.py` — `verify` and `render-report` subcommands
- `pyproject.toml` — `verify`, `verify-cloud`, `report` dependency groups

## What's deferred to v0.17

- **SMB / LDAP credential extraction from parser output.** Today's
  hit-record schema doesn't carry `ExtractedField` records from the
  structured parsers (unattend.xml, my.cnf, etc.). The SMB and LDAP
  verifiers are scaffolded but return `inconclusive` until a future
  patch wires parser-extracted user/password pairs through to the
  verify runner.
- **Azure SP / GCP service-account verifiers.** azure-identity and
  google-auth are heavy SDKs; deferring to v0.17 keeps `verify-cloud`
  size manageable.
- **Charts in the HTML report.** Chart.js inline for hits-by-share,
  hits-by-tier histograms. Deferred — the v0.16 summary banner already
  surfaces the same data in text form.
- **Active-learning labeling UI in the report.** Click "true positive"
  / "false positive" → emit labels.jsonl for ranker retraining. The
  active-learning loop is the v0.17/v0.18 multiplier.

## Verification

End-to-end demo flow:

```bash
# 1. Build fixture share
mkdir -p /tmp/demo && cd /tmp/demo
echo "ANTHROPIC_API_KEY=sk-ant-api03-FAKE...AA" > .env
echo "aws_access_key_id=AKIAIOSFODNN7EXAMPLE" > aws_credentials.txt

# 2. Path triage
ls /tmp/demo/* | uv run sharesift score-paths --stdin --output /tmp/demo/triaged.jsonl

# 3. Full scan with content stage
ls /tmp/demo/* | uv run sharesift scan-files --stdin --output /tmp/demo/hits.jsonl

# 4. Verify (dry-run safety check first)
uv run sharesift verify --input /tmp/demo/hits.jsonl --dry-run --no-banner

# 5. Verify for real (against live APIs)
uv run sharesift verify --input /tmp/demo/hits.jsonl --output /tmp/demo/verified.jsonl --no-banner

# 6. Render the report
uv run sharesift render-report --input /tmp/demo/verified.jsonl --output /tmp/demo/report.html --title "Demo run"

# 7. Open the report
xdg-open /tmp/demo/report.html
```

## Sources

- [TruffleHog v3 verification model](https://trufflesecurity.com/blog/how-trufflehog-verifies-secrets) — status taxonomy + `--only-verified` UX
- [PowerHuntShares 2.0 HTML report](https://www.netspi.com/blog/technical-blog/network-pentesting/powerhuntshares-2-0-release/) — interactive report architecture
- [GitGuardian State of Secrets Sprawl 2026](https://thehackernews.com/2026/03/the-state-of-secrets-sprawl-2026-9.html) — coverage priorities for AI infrastructure leaks
