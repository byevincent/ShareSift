# v0.26 — read-only verifiers + PuTTY parser

Drafted 2026-06-08. The v0.25 queue listed "acquire a 4th
independent held-out benchmark" as the highest-information next
move, but the disk audit shows the candidates are either
single-class (kingfisher_input has only positives, no matched
negatives) or carry overfit risk (`synthetic_paths.jsonl` was
likely produced by the same generator we already validated
against). **Faking a 4th set to pad the trajectory chart defeats
the whole discipline.** v0.26 ships what's honestly buildable now
and the 4th set is deferred to v0.27 with explicit acquisition
plans.

## Phases

### Phase 1 — Read-only verifiers for v0.23 credential types

The `sharesift verify` subcommand can validate a found credential
by making an authenticated call. We added 9 new credential
extractors in v0.23 but no verifiers — the cascade detects them but
can't confirm they're live.

v0.26 adds verifiers for the documented-API ones:

| Credential | Endpoint | Validation signal |
|---|---|---|
| Stripe (secret) | `GET https://api.stripe.com/v1/account` | 200 = valid; 401 = revoked |
| SendGrid | `GET https://api.sendgrid.com/v3/user/profile` | 200 = valid; 401 = revoked |
| Mailgun | `GET https://api.mailgun.net/v3/domains` (HTTP Basic with key) | 200 = valid |
| Twilio | `GET https://api.twilio.com/2010-04-01/Accounts/<sid>.json` | 200 = valid |

Each verifier is a small class registered via the existing
verifier registry (`sharesift/verify/registry.py`).

Implementation rule: **read-only endpoints ONLY**. No POSTs, no
write actions. The point is to confirm liveness, not perform any
real action on the operator's behalf.

Testing: all verifier tests mock the HTTP layer (`requests.get`
patched). We never make real outbound calls in CI. Live calls only
happen during operator-initiated `sharesift verify` runs.

### Phase 2 — PuTTY `.ppk` parser (format-only)

The PPK file is a documented format used by PuTTY / WinSCP. v2 is
the most common; v3 adds AES-GCM. Common shape:

    PuTTY-User-Key-File-2: ssh-rsa
    Encryption: none
    Comment: my-server-key
    Public-Lines: 6
    AAAAB3NzaC1yc2EAAAA...
    Private-Lines: 14
    AAABABCD...
    Private-MAC: a1b2c3d4...

Encrypted PPKs (Encryption: aes256-cbc) have the private body
ciphertext. We surface the file's presence + encryption status; the
operator decrypts offline.

Synthetic test fixtures only — we test "parser recognises the
PuTTY-User-Key-File-N header + extracts metadata", not "we have a
real PPK from any benchmark." Same fixtures-not-captures rule v0.24
+ v0.25 followed.

### Phase 3 — Re-run + ship

Harness MIN should hold at 0.20 / 0.90. Verifiers don't affect the
score (verify is a separate subcommand). PPK parser only fires on
`.ppk` files which don't exist in MSF3 / CredData.

## What's out of scope (deferred to v0.27)

- **Registry hive parser** — same blocker as v0.25; need real samples
- **4th independent held-out benchmark** — the realistic options are:
  - GOAD (would need to spin up the lab + dump shares)
  - HTB box dump (single-VM, possibly licensing-gated)
  - PoshC2 / Sliver logs (would need real engagement data)
  - SecretBench when access lands
  Each is a real acquisition project, not a one-session task.
- **Stage 2 LoRA cross-distribution eval** — weights still not tracked

## Sprint accounting

| Sprint | Scope |
|---|---|
| 1 | 4 read-only verifiers (Stripe, SendGrid, Mailgun, Twilio) |
| 2 | PuTTY `.ppk` parser |
| 3 | Re-run + ship |

## Versatility honesty

The verifiers are architecturally versatile — they're declarative
HTTP calls to documented endpoints. No training, no benchmark
tuning. The risk vector is that an endpoint's response shape
changes; we test against mocked responses, not the live API, so
this is a normal upstream-API-change concern, not an overfitting
concern.

The PPK parser is format-only — recognises the documented header
shape. Encrypted PPKs surface "encrypted" rather than the body,
matching the v0.24 `ansible_vault` pattern.
