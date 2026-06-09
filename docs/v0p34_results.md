# v0.34 results — end-to-end smoke for the GCP fix

Released 2026-06-08. Small release: the standing v0.31-v0.33
GCP-fix carryover gets an integration-test closure. The
v0.32 + v0.33 work is now exercised end-to-end by a planted file
on the DiskForge supplementary benchmark.

## Headline (unchanged primary)

| Metric | v0.33 | v0.34 |
|---|---|---|
| MIN top-10 (primary) | 0.20 | 0.20 |
| MIN recall (primary) | 0.90 | 0.90 |
| DiskForge plants (supp) | 12 | **13** (added GCP SA JSON) |
| DiskForge recall (supp) | 1.000 | 1.000 |

## What shipped

### Phase 1 — DiskForge GCP plant

`tools/diskforge_v0p31/build_manifest.py` now emits a 13th positive:
a synthetic 2048-bit RSA key + valid SA JSON shape, planted at
`/Users/Administrator/Documents/gcp_service_account.json`.

Generation happens at build time in
`tools/diskforge_v0p31/files/plant/gcp_service_account.json` so the
private key never lives in any committed credential payload other
than this benchmark's own synthetic-by-construction file.

### Phase 2 — Integration tests

`tests/test_gcp_diskforge_integration_v0p34.py` exercises the
v0.32 extractor + v0.33 verifier on the actual planted file
content (no mocking of those layers):

| Test | Asserts |
|---|---|
| `test_planted_sa_json_exists` | Build artifact present; reproducible from `build_manifest.py` |
| `test_planted_sa_json_is_caught_by_extractor` | v0.32 multi-field regex catches the planted JSON; `gcp_service_account_json` in extracted types |
| `test_planted_sa_json_passes_structural_verifier` | v0.33 verifier with live helper monkeypatched to None returns `validation_mode=structural` |
| `test_planted_sa_json_signs_real_jwt_in_live_path` | v0.33 verifier with real RSA key signs a >200-char JWT; mocked OAuth 200 returns `validation_mode=live` |

This is the end-to-end coverage I deferred in v0.32 + v0.33 (the
unit tests there cover behavior; this test closes the integration
loop using a real file).

### Phase 3 — Harness shows the plant works

```
--- diskforge_win10 (supplementary) ---
  records: 520 (positive: 13)  ← 12 → 13 (the new GCP plant)
  recall_any_tier: 1.0
  top-10/20/50 precision: 0.6 / 0.55 / None
```

The cascade catches all 13 plants. The new GCP plant lands at a path
that fires existing rules + the path classifier (filename matches
the `application_default_credentials.json` shape via the v0.30
`ShareSiftKeepGcloudCredentials` filename rule's siblings; the JSON
content matches the v0.32 multi-field extractor pattern).

## Tests

Full suite: **861 passing**, 8 skipped (was 857 — +4 integration).

## Sprint accounting

| Sprint | Status |
|---|---|
| 1 — Generate synthetic 2048-bit RSA key + SA JSON in `build_manifest.py` | ✅ |
| 2 — Rebuild DiskForge image; verify 13 plants present, recall holds 1.000 | ✅ |
| 3 — Integration tests (planted file → extractor → verifier, both modes) | ✅ |
| 4 — Ship | ✅ |

## v0.35 queue

The remaining standing carryover is the registry-hive parser, which
has been blocked on real `.reg` / hive samples since v0.26. No source
materialised yet; it stays on the queue but not as a v0.35 commitment.

| Item | Status |
|---|---|
| Registry hive parser | ❌ blocked on samples (10+ release carryover) |
| Engagement-log corpus (Sliver / PoshC2 / Mythic) as 4th primary | speculative; no source on disk |
| More parsers for credential file shapes we don't cover yet | possible (`.docker/config.json` is covered; gcloud is covered v0.34; what else?) |

## Meta — and the "how far" question Vincent asked

v0.34 is a clean checkpoint. The v0.31 finding is fully closed:
extractor expansion (v0.32), live verification (v0.33), end-to-end
smoke confirming both fire on a planted file (v0.34).

The trajectory chart has been flat at 0.20 / 0.90 for 13 releases.
That isn't a failure — it's the discipline working. The capacity
grew dramatically (extractors +10, parsers +9, verifiers +6,
held-out sets +1.5, declarative scoring fixes including one
falsified hypothesis), and the floor metric didn't move because
the harness wouldn't let it without honest evidence.

**The v0.22-v0.34 arc is the substantive product.** Continuing past
v0.35 without external input (real engagement data, real users)
becomes capacity expansion for its own sake. The discipline still
holds — the numbers stay honest — but the marginal value of each
release drops sharply. v0.34 is a fine point to slow down and
consider whether the next release should be a methodology
retrospective rather than another bundle.
