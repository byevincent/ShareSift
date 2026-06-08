# v0.26 results — read-only verifiers + PuTTY parser + honest deferral

Released 2026-06-08. Executes Phases 1-3 of `docs/v0p26_plan.md`.

## Headline (held flat across 5 releases)

| Metric | v0.25 | v0.26 |
|---|---|---|
| MIN top-10 precision | 0.20 | 0.20 |
| MIN recall any-tier | 0.90 | 0.90 |

```
ShareSift harness MIN trajectory
================================
            MIN top-10         MIN recall
v0.22.0     ▇▇░░░░░░░░ 0.20     ▇▇▇▇▇▇▇▇▇░ 0.90
v0.23.0     ▇▇░░░░░░░░ 0.20     ▇▇▇▇▇▇▇▇▇░ 0.90
v0.24.0     ▇▇░░░░░░░░ 0.20     ▇▇▇▇▇▇▇▇▇░ 0.90
v0.25.0     ▇▇░░░░░░░░ 0.20     ▇▇▇▇▇▇▇▇▇░ 0.90
v0.26.0     ▇▇░░░░░░░░ 0.20     ▇▇▇▇▇▇▇▇▇░ 0.90
```

## What shipped

### Phase 1 — 4 read-only verifiers

The v0.23 release added 9 credential extractors (Stripe, SendGrid,
Mailgun, Twilio, Azure storage, GCP service-account) but no
verifiers — the cascade could detect them but `sharesift verify`
couldn't confirm they were live. v0.26 closes that for the API-
verifiable ones:

| Verifier | Endpoint | Auth |
|---|---|---|
| `StripeVerifier` | `GET https://api.stripe.com/v1/account` | Bearer |
| `SendGridVerifier` | `GET https://api.sendgrid.com/v3/user/profile` | Bearer |
| `MailgunVerifier` | `GET https://api.mailgun.net/v3/domains` | Basic (`api:<key>`) |
| `TwilioVerifier` | `GET https://api.twilio.com/2010-04-01/Accounts/<sid>.json` | Basic (`<sid>:<token>`) |

All four are **read-only** — no POSTs, no write actions, no
side-effects on the operator's behalf. The discipline holds: we
confirm liveness, we don't perform actions.

Registry mappings:

| Extractor type | Verifier |
|---|---|
| `stripe_live_secret`, `stripe_live_restricted` | StripeVerifier |
| `sendgrid_api_key` | SendGridVerifier |
| `mailgun_api_key` | MailgunVerifier |
| `twilio_account_sid`, `twilio_api_key_sid` | TwilioVerifier (requires Account SID via context) |

Twilio's SID-as-URL-component requirement means the verifier
returns `skipped + no_account_sid_in_context` when the SID isn't
threaded through — same pattern v0.16's SMB/LDAP verifiers used.

### Phase 2 — PuTTY `.ppk` parser

PPK is the documented PuTTY/WinSCP key format. The parser yields:

- **Header line metadata**: PPK version (v2 / v3) + key algorithm
- **Encryption status**: `none` / `aes256-cbc` (v2) / `aes256-gcm` (v3)
- **Comment line**: usually a hostname / user identifier
- **Plaintext private body** (Encryption: none only) — base64 body
  for downstream offline reassembly

Encrypted PPKs surface the file's presence + algorithm but NOT the
body. Matches the v0.24 `ansible_vault` pattern — flag the
encrypted-blob, defer decryption to offline operator work.

Synthetic fixtures only; no real PPK files in the test set.

### Phase 3 — Re-run + ship

Harness MIN held at 0.20 / 0.90. Trajectory chart appended above.

## The 4th held-out set — honest deferral

v0.25's plan listed acquiring a 4th independent held-out benchmark
as the most interesting next move. v0.26 surveyed the disk for
candidates:

| Candidate | Verdict |
|---|---|
| `kingfisher_input/` (1044 files) | Real positives only — no matched negatives. Single-class. |
| `engagement_corpus/articles.jsonl` (1653 records) | Raw DFIR text bodies, not credential-labeled. Manual labeling needed. |
| `engagement_corpus/synthetic_paths.jsonl` (50,000 records) | Likely produced by the same generator we already validated against — overfit risk. |
| GOAD / HTB / PoshC2 logs | None on disk. Real acquisition projects. |
| SecretBench | Access still gated. |

**No clean candidate**. The discipline says don't fake a 4th set
just to pad the trajectory chart. The trajectory was always
allowed to be flat for honest reasons.

The 4th set defers to v0.27 with explicit acquisition plans:
acquire one of GOAD / HTB box dump / PoshC2 logs / SecretBench, with
documentation of which one was acquired + the licensing /
distribution constraints. Without a clean candidate, the discipline
beats the chart entry.

## Tests

| Component | Tests |
|---|---|
| 4 verifiers (mocked HTTP) | 7 (positive + negative + registry integration) |
| PuTTY .ppk parser | 3 (v2 unencrypted, v3 encrypted, non-PPK silent) |

Full suite: 821 passing, 8 skipped (was 811 — +10 new, 0 regressions).

## Sprint accounting

| Sprint | Status |
|---|---|
| 1 — 4 read-only verifiers | ✅ |
| 2 — PuTTY .ppk parser | ✅ |
| 3 — re-run + ship | ✅ (this doc) |

## What's queued for v0.27

| Item | Estimate |
|---|---|
| **Acquire a 4th held-out benchmark** — GOAD lab dump, HTB box, or PoshC2 logs; honest acquisition work | days, not one session |
| Azure storage account verifier | small (uses Storage REST API ListContainers) |
| GCP service-account verifier — `gcloud auth activate-service-account` shape, or direct OAuth token exchange | small |
| Registry hive parser when real samples accessible | needs samples |
| Stage 2 LoRA cross-distribution eval | needs tracked weights |

## Meta

5 releases (v0.22-v0.26) holding the MIN trajectory flat. Capacity
grew: parsers 18 → 27 (PPK added); extractors 21 → 30; verifiers
14 → 18. The eval gate hasn't fired against any release.

This is sustainable progress. Not exciting, but honest.
