# v0.32 results — half the GCP gap closed (extractor side)

Released 2026-06-08. v0.31 surfaced a real architectural finding: the
v0.23 `gcp_service_account_email` extractor caught only the email
field, but a real verifier needs the full SA JSON (private_key
included). v0.32 closes the extractor side of that gap; live OAuth
verification stays queued for v0.33+ pending a clean way to ship
JWT-signing capability.

## What "closing half" means

| Gap component | v0.31 status | v0.32 status |
|---|---|---|
| Extractor captures private_key + token_uri | ❌ Only email | ✅ Full JSON `{...}` block |
| Verifier knows what fields to check | (n/a — couldn't run) | ✅ Structural validation runs |
| Live OAuth — sign RS256 JWT, exchange for token, check API | ❌ Would need PyJWT | ❌ Deferred to v0.33+ — would add `pyjwt` as opt-in dep |

Concretely: a v0.32 operator scanning a share that contains a leaked
GCP SA JSON gets a `verification_status=passed` from the structural
verifier, telling them "this is a well-formed SA JSON ready for live
verification with `gcloud auth activate-service-account`." Not yet
"this SA is currently live and unrevoked" — that's a v0.33+ enhancement
that adds the JWT-signing path.

## Headline

| Metric | v0.31 | v0.32 |
|---|---|---|
| MIN top-10 precision (primary) | 0.20 | 0.20 |
| MIN recall any-tier (primary) | 0.90 | 0.90 |
| Verifier coverage | 19 cred types | **20** |
| Extractor patterns | 30 (1 GCP-email) | **31** (1 GCP-email + 1 GCP-JSON) |

The headline numbers are still flat. The capacity grew (extractor
expansion + verifier addition), the discipline held (no new code
without paired tests), and the v0.31 finding moved from "queued
architectural gap" to "half closed, the harder half explicitly
scoped."

## What shipped

### Phase 1 — Extractor expansion

`src/sharesift/verify/extractor.py` adds two new patterns:

```python
_GCP_SA_JSON_PATTERN     = re.compile(r'\{[^{}]*?"type":"service_account"[^{}]*?'
                                       r'"private_key":"-----BEGIN PRIVATE KEY-----[^{}]*?'
                                       r'"client_email":"[a-z0-9\-]+@[a-z0-9\-]+\.iam\.gserviceaccount\.com"[^{}]*?\}',
                                       re.DOTALL)
_GCP_SA_JSON_ALT_PATTERN = re.compile(r'\{[^{}]*?"client_email":...[^{}]*?'
                                       r'"private_key":"-----BEGIN PRIVATE KEY-----[^{}]*?'
                                       r'"type":"service_account"[^{}]*?\}',
                                       re.DOTALL)
```

Both patterns capture the entire `{...}` JSON object — no nested
braces allowed (real SA JSON is flat). The extractor produces a new
credential type `gcp_service_account_json` whose `value` is the full
JSON string the verifier can `json.loads`.

The v0.23 `gcp_service_account_email` matcher stays — older scan
outputs and downstream consumers (the cascade source distribution,
the v0.30 rule engine) keep working unchanged.

### Phase 2 — Structural verifier

`src/sharesift/verify/gcp_service_account.py`. Required fields
(per Google's documented SA schema), PEM-shaped `private_key`,
well-formed `client_email` matching the IAM service-account regex.
No external calls; no optional deps.

Verdict matrix:
- All required fields present + `type == service_account` + PEM-shaped
  private_key + well-formed email → `passed` with metadata
  `{client_email, project_id, private_key_id, validation_mode: "structural"}`
- Missing fields → `failed` with `missing_fields: <comma-list>`
- Wrong `type` (e.g. `authorized_user`) → `failed` with `wrong_type`
- Malformed email → `failed` with `malformed_client_email`
- Non-PEM private_key → `failed` with `private_key_not_pem_shaped`
- Not parseable JSON → `failed` with `not_valid_json`

### Phase 3 — Honest defer of live OAuth verification

The verifier docstring documents the v0.33+ path explicitly:

> Operator note: structural `passed` means the credential is
> syntactically valid and ready for live verification (`gcloud auth
> activate-service-account`). It does NOT confirm the key hasn't been
> revoked. Live OAuth verification is queued for v0.33+ when an
> operator workflow requests it.

The blocker isn't the architecture (now we have the private_key);
it's the dependency call — adding `pyjwt` or implementing RS256 from
scratch with `cryptography`. Both are reasonable but want explicit
operator demand before being locked in as opt-in deps.

## Why the harness is unchanged

The GCP extractor + verifier additions are content-side capacity;
the harness primary sets (MSF3, CredData, MSF2) don't contain GCP
SA JSON files, so neither the new extractor pattern nor the new
verifier fires. DiskForge supplementary also doesn't contain a SA
JSON plant — could add one in a future regen but isn't load-bearing
because the GCP tests in `test_gcp_v0p32.py` exhaustively cover the
verifier's behavior.

## Tests

| Component | Tests added | What's covered |
|---|---|---|
| Extractor expansion | 3 | Full JSON capture, legacy email-only still works, partial JSON doesn't match |
| Verifier | 7 | Pass on well-formed, fail on missing fields / wrong type / malformed email / non-PEM key / invalid JSON / registry integration |

Full suite: **849 passing, 8 skipped, 0 regressions** (was 839 — +10 GCP).

## Sprint accounting

| Sprint | Status |
|---|---|
| 1 — Extractor multi-field SA JSON pattern | ✅ |
| 2 — Structural verifier | ✅ |
| 3 — Register in verifier registry | ✅ |
| 4 — Tests (extractor + verifier + registry integration) | ✅ |
| 5 — Honest v0.33 deferral of live OAuth | ✅ documented in docstring + this doc |
| 6 — Ship | ✅ |

## What's queued for v0.33

| Item |
|---|
| **Live OAuth verification** — JWT signing (PyJWT or cryptography), token exchange, benign API call. Would convert SA verifier from `validation_mode: structural` to `validation_mode: live`. |
| Registry hive parser when samples accessible (standing carryover) |
| (Optional) DiskForge plant for GCP SA JSON — confirm extractor + verifier fire on a planted disk |

## Meta

v0.32 demonstrates what an "honest half-closure" looks like inside
the discipline:

- The v0.31 finding was concrete (extractor doesn't surface
  private_key, verifier can't run without it)
- v0.32 fixed the extractor half — measurable improvement in
  what gets captured
- The verifier ships in structural mode, which is genuinely useful
  for operator triage (well-formed SA JSON = ready for `gcloud
  activate-service-account`)
- Live OAuth is documented as v0.33+ with the specific blocker named
  (RS256 JWT signing dep) — not as a vague "future improvement"

The MIN trajectory still says 0.20 / 0.90. The capacity grew. The
v0.31 finding moved from "open architectural gap" to "half-closed
with the remaining work explicitly scoped." That's the iteration
the benchmark loop is supposed to produce.
