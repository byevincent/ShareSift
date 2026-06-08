# v0.31 results — Azure verifier + bigger DiskForge + GCP honest defer

Released 2026-06-08. Three things attempted, two shipped, one
explicitly deferred. The discipline working as designed: when a piece
of work turned out to need more infrastructure than v0.31 scope, we
documented the gap honestly instead of shipping a half-built version.

## Headline (primary MIN unchanged, DiskForge realistic-density now)

| Metric | v0.30 | v0.31 |
|---|---|---|
| MIN top-10 precision (primary) | 0.20 | 0.20 |
| MIN recall any-tier (primary) | 0.90 | 0.90 |
| DiskForge records | 43 | **519** |
| DiskForge positive density | 28% (unrealistic) | **2.3%** (comparable to MSF3, MSF2) |
| DiskForge recall (supp) | 1.000 | 1.000 |
| DiskForge top-10 (supp) | 0.60 | 0.60 |
| Verifier coverage | 18 cred types | **19** (Azure added) |

## What shipped

### Phase 1 — Azure storage verifier

`src/sharesift/verify/azure_storage.py`. Read-only HTTP GET to the
List Containers endpoint, authenticated via the documented Shared
Key HMAC-SHA256 signing scheme.

```python
class AzureStorageVerifier(BaseVerifier):
    service = "azure_storage"
    credential_type = "azure_storage_connection_string"
```

* Parses `AccountName=...;AccountKey=...` connection string
* Builds canonicalized resource + signing string per Microsoft spec
* HMAC-SHA256 the signing string with the base64-decoded account key
* Headers: `Authorization: SharedKey <name>:<sig>` + `x-ms-date` + `x-ms-version`
* GET https://`<account>`.blob.core.windows.net/?comp=list — 200 = passed, 403 = failed

Verifier coverage: 18 → **19** credential types. Completes the
v0.23 extractor→verifier loop for `azure_storage_connection_string`
(one of the 9 extractors added in v0.23).

### Phase 2 — GCP service-account verifier — honest defer

Started; got blocked on what turned out to be a real architecture
gap. Documented and deferred to v0.32 (or further).

**The gap.** v0.23 added `gcp_service_account_email` as the GCP
extractor — it matches the `client_email` field in a service-account
JSON file. That's the credential's name, not the credential. To
actually verify the SA, we need:

1. Build a JWT (iss = service_account_email, scope, iat, exp)
2. Sign with the SA's private key (RS256)
3. POST to `https://oauth2.googleapis.com/token` for an access token
4. Use the access token to call a benign API (e.g., `tokeninfo`)

Step 2 needs the private key — which the v0.23 extractor doesn't
surface. The full SA JSON would have to either:

- (a) Be captured by an expanded extractor that grabs the whole
  JSON file content when it sees `client_email`, OR
- (b) Be threaded through the verify dispatcher as a separate
  "credential bundle" — the verify runner reads the file by path
  and passes its content to the verifier

Both options are larger than v0.31 scope. (a) requires extending
the extractor data model from "regex match in content" to "structured
file content"; (b) requires plumbing changes through the verify
runner's context dict. Either path is its own design pass.

**v0.31 ships the finding rather than a half-verifier.** Documented
in `CHANGELOG.md` and queued for v0.32+.

### Phase 3 — Bigger DiskForge image

`tools/diskforge_v0p31/build_manifest.py` programmatically generates
476 decoy negatives + the same 12 positives from v0.29-v0.30. The
decoys are synthetic stubs at realistic Windows paths:

| Decoy bucket | Count |
|---|---|
| System binaries (`.dll`, `.exe`, `.sys`) | 188 |
| Event logs (`.evtx`) + Prefetch (`.pf`) | 70 |
| Program Files clutter | 68 |
| User profile clutter (Documents / Downloads / Caches / Recent) | 91 |
| IIS logs, app configs, scheduled tasks, misc | 65 |
| **Total decoys** | **482** (actual on disk after dedup: 476) |

Result: **2.3% positive density, comparable to MSF3 (3.8%) and MSF2 (2.3%).** The DiskForge benchmark is now a realistic-density coverage
test for documented credential file shapes. Recall holds at 1.000
(all 12 plants caught) and top-10 precision holds at 0.60 — meaningful
now that random-baseline top-10 isn't already 28%.

DiskForge stays **supplementary**, not primary. The decoys are
synthetic stubs (text payloads with `.dll` / `.evtx` / `.lnk`
extensions), not real Windows binary files. Promoting to primary
would suggest the benchmark measures real-world precision, when it
actually measures "did we catch the credential file shapes we
intentionally planted, in the presence of realistic-density noise?"
Useful, but different from MSF3 / MSF2 / CredData.

## What this iteration tells us structurally

The Azure verifier and the GCP verifier looked equivalent on paper —
"add a small declarative HTTP-based verifier for a v0.23 cred type."
In practice they diverged sharply because of a difference in what
the v0.23 extractor produces:

| Extractor type | Output |
|---|---|
| `azure_storage_connection_string` | The full connection string — everything the verifier needs |
| `gcp_service_account_email` | Just the email — verifier needs the private key too |

The Azure verifier sails; the GCP verifier blocks on what the
extractor caught. That's the kind of architectural finding the
benchmark loop is supposed to surface. v0.32+ will either expand
the GCP extractor or thread file content through the verify
dispatcher.

## Tests

| Component | Tests added |
|---|---|
| Azure verifier (positive 200, fail 403, signature determinism, signature changes with date, garbage connection string, registry integration) | 6 |

Full suite: **839 passing, 8 skipped, 0 regressions** (was 833).

## Sprint accounting

| Sprint | Status |
|---|---|
| 1 — Azure storage verifier + tests | ✅ |
| 2 — GCP service-account verifier | ⚠️ honest deferral — extractor doesn't surface private_key |
| 3 — Bigger DiskForge image | ✅ 43 → 519 records, density 28% → 2.3% |
| 4 — Re-run + ship | ✅ |

## What's queued for v0.32

| Item |
|---|
| **Resolve the GCP gap** — expand the extractor to surface the full SA JSON, OR thread file content through the verify dispatcher |
| Registry hive parser when samples accessible |
| (Optional) Generate `Sliver` / `PoshC2` engagement log samples as a new held-out distribution |

## Meta

v0.31 is what shipping mid-iteration looks like when one of three
planned items hits a real architectural blocker:
- Ship what's done (Azure)
- Ship the unrelated work that came out clean (bigger DiskForge)
- Document the blocked item with the concrete gap, not a vague
  "needs more work" stub
- Don't fake the GCP verifier just to fill the "verifier shipped"
  slot — the harness wouldn't catch a verifier that's secretly
  no-op, but the discipline would.

The MIN trajectory still says 0.20 / 0.90. DiskForge is now a
realistic-density supplementary set. The architecture finding for
GCP is on the record. That's the iteration.
