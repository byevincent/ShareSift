# v0.33 results — second half of the GCP gap closed (live OAuth)

Released 2026-06-08. The v0.31 finding came in two halves: the
extractor doesn't surface the private_key, and the verifier needs
JWT signing to actually verify. v0.32 closed the extractor half.
**v0.33 closes the verifier half.** Both halves of the v0.31 gap
are now on the record.

## Two halves, two releases

| v0.31 gap | v0.32 closure | v0.33 closure |
|---|---|---|
| Extractor surfaces only `client_email` | ✅ Multi-field regex captures whole `{...}` | (n/a — already closed) |
| Verifier can sign RS256 JWT | (n/a — needed extractor first) | ✅ pyjwt[crypto] integration + OAuth token exchange |

The verifier now has **two modes**:

| Mode | Trigger | What it confirms |
|---|---|---|
| `live` | pyjwt[crypto] installed (default in `verify` group) | This SA is currently live and unrevoked |
| `structural` | pyjwt[crypto] not installed | This SA is well-formed and ready for live verification |

Graceful fallback — operators who didn't install the optional
`pyjwt[crypto]` still get the structural verdict that was useful in
v0.32. Operators who did install it (the new `verify` group default)
get full liveness confirmation.

## Headline

| Metric | v0.32 | v0.33 |
|---|---|---|
| MIN top-10 precision (primary) | 0.20 | 0.20 |
| MIN recall any-tier (primary) | 0.90 | 0.90 |
| Verifier coverage | 20 cred types | 20 |
| **GCP verification mode** | structural only | **live + structural fallback** |

The verifier coverage count stays at 20 (same credential types
verified) but the depth grew — the GCP entry went from "is the JSON
well-formed" to "is the SA actually accepting JWTs right now."

## What shipped

### Phase 1 — pyjwt[crypto] in the verify dep group

`pyproject.toml`:

```toml
verify = [
    "requests>=2.31",
    "pyyaml>=6.0",
    "paramiko>=3.3",
    "ldap3>=2.9",
    "pyjwt[crypto]>=2.0",  # v0.33
]
```

PyJWT pulls `cryptography` for RS256 signing. ~3 MB additional
install size for the verify group; structural fallback means
operators without the dep still get a useful verdict.

### Phase 2 — Live OAuth helper

`src/sharesift/verify/gcp_service_account.py::_try_live_verification`.
Returns `(status, metadata, error)` or `None`:

- **`None`**: pyjwt unavailable → caller falls back to structural
- **`("passed", meta, None)`**: OAuth returned 200 + access_token →
  `validation_mode=live`, metadata carries `token_type`, `expires_in`
- **`("failed", meta, "oauth_token_exchange_<code>:<gcp_error>")`**:
  401 (revoked / invalid_grant) or 400 (malformed)
- **`("inconclusive", meta, "token_exchange_timeout")`**: network
  timeout — don't blame the SA for operator connectivity
- **`("inconclusive", meta, "token_exchange_connection_error:...")`**:
  DNS / TCP failure

JWT payload follows Google's documented format:

```python
{
    "iss": data["client_email"],
    "scope": "https://www.googleapis.com/auth/userinfo.email",  # read-only
    "aud": data["token_uri"],
    "iat": now,
    "exp": now + 300,  # 5 minutes
}
```

Read-only scope by design. The `userinfo.email` endpoint returns
public info about the SA itself; the verification doesn't enumerate
cloud resources or mutate state. Same discipline as the existing
read-only Stripe / SendGrid / Mailgun / Twilio / Azure verifiers.

### Phase 3 — Test coverage

Synthetic 2048-bit RSA key generated at test fixture time using
`cryptography.hazmat.primitives.asymmetric.rsa` — pyjwt actually
signs with it. The OAuth POST is mocked at `requests.post`. Tests
cover:

| Test | What it asserts |
|---|---|
| `test_live_verification_passes_on_oauth_200` | 200 + access_token → `passed` with `validation_mode=live` |
| `test_live_verification_returns_live_meta_when_oauth_succeeds` | Metadata carries project_id + validation_mode |
| `test_live_verification_fails_on_oauth_401_revoked_key` | 401 → `failed` with oauth_http_status |
| `test_live_verification_fails_on_oauth_400` | 400 → `failed` |
| `test_live_verification_inconclusive_on_oauth_timeout` | Timeout → `inconclusive`, not failed |
| `test_live_verification_inconclusive_on_connection_error` | Conn error → `inconclusive` |
| `test_jwt_payload_includes_correct_oauth_claims` | Decoded JWT has iss / scope / aud / iat / exp |
| `test_falls_back_to_structural_when_pyjwt_import_fails` | None from helper → structural verdict |

Full suite: **857 passing**, 8 skipped (was 849 — +8 v0.33 tests).

## Why the harness number is unchanged (and why that's correct)

Same reason as v0.32: none of the primary held-out sets (MSF3,
CredData, MSF2) contain GCP SA JSON files. The verifier behavior
is exhaustively covered in the test suite, not at the benchmark
level. **Adding a real GCP SA plant to DiskForge** would be a
nice end-to-end smoke but isn't load-bearing — the unit tests do
the actual coverage work.

The harness's job is to catch cross-distribution regressions in
the cascade (path / rules / content). It doesn't need to catch
every verifier behavior; verifiers run separately, off the cascade
path, and have their own coverage.

## What v0.31's finding fully cost vs. delivered

| | v0.31 documented | v0.33 delivered |
|---|---|---|
| Architectural understanding | Extractor → verifier data flow gap identified | Both sides closed |
| Documented blocker | "Needs pyjwt for RS256" | pyjwt installed, RS256 working |
| Operator-facing behavior | None (no verifier could run) | `validation_mode=live` confirms unrevoked SA |
| Sprint cost | (finding + defer) | One sprint each for v0.32 and v0.33 |

Two sprints to close. Probably right — v0.32 ships the extractor
expansion + a useful structural verifier as a checkpoint, v0.33 ships
the dep-bearing live half. Splitting them let v0.32 ship without the
pyjwt commitment.

## Sprint accounting

| Sprint | Status |
|---|---|
| 1 — Add pyjwt[crypto] to verify group | ✅ |
| 2 — `_try_live_verification` helper with JWT signing + OAuth exchange | ✅ |
| 3 — Adjust v0.32 happy-path test to monkeypatch the live helper (now that live tries to run) | ✅ |
| 4 — 8 new v0.33 tests for live OAuth behavior (success, 401, 400, timeout, conn error, JWT claims, structural fallback) | ✅ |
| 5 — Ship | ✅ |

## What's queued for v0.34

| Item |
|---|
| Registry hive parser when samples accessible (long-standing carryover) |
| Optional DiskForge GCP SA JSON plant for end-to-end cascade-to-verifier smoke (not load-bearing per above) |
| (Speculative) Generate a Sliver / PoshC2 / Mythic engagement-log corpus as a 4th primary set |

The standing carryover is registry hive parser. The DiskForge plant
is nice-to-have. The engagement-log set would be the most
informative new direction but needs real engagement data we don't
have on disk.

## Meta

v0.32 + v0.33 together closed the v0.31 finding completely. The
release shape worked: one sprint per half, ship what's done at each
checkpoint, document what's next with the specific blocker named.
Operators on v0.32 got structural verification (better than nothing);
operators on v0.33 get live verification (the full close).

The MIN trajectory still says 0.20 / 0.90. **The capacity grew
along the dimension the v0.31 finding pointed at.** That's exactly
the loop the benchmark discipline is designed to drive.
