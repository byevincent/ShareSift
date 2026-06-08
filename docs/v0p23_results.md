# v0.23 results — more versatile components, same eval discipline

Released 2026-06-08. Executes Phases 1-4 of the v0.23 plan
(`docs/v0p23_plan.md`). Phase 5 (re-run + ship) is this release.

## Headline numbers (same harness, 3 held-out sets)

| Metric | v0.22 | v0.23 | Δ |
|---|---|---|---|
| **MIN top-10 precision** (primary) | 0.20 | 0.20 | 0 |
| **MIN recall any-tier** (primary) | 0.90 | 0.90 | 0 |

Per-set:

| Set | Records | Positive | Recall | Top-10 |
|---|---|---|---|---|
| MSF3 | 1054 | 40 | 0.900 | 0.20 |
| CredData | 1500 | 500 | 1.000 | 0.70 |
| engagement_corpus (supp) | 401 | 92 | 0.902 | 0.60 |

**The harness numbers didn't move.** Honest explanation in the
"Did the new components help?" section below.

## What v0.23 shipped

### Phase 1 — 9 new credential-format extractors

Strong inductive biases (regex patterns matching documented credential
shape). Added to `src/sharesift/verify/extractor.py`:

| Credential type | Pattern shape |
|---|---|
| `stripe_live_secret` | `sk_live_[A-Za-z0-9]{24,}` |
| `stripe_live_restricted` | `rk_live_[A-Za-z0-9]{24,}` |
| `stripe_live_publishable` | `pk_live_[A-Za-z0-9]{24,}` |
| `sendgrid_api_key` | `SG\.<22>\.<43>` |
| `mailgun_api_key` | `key-[a-f0-9]{32}` |
| `twilio_account_sid` | `AC[a-f0-9]{32}` |
| `twilio_api_key_sid` | `SK[a-f0-9]{32}` |
| `azure_storage_connection_string` | full connection string with `AccountKey=` |
| `gcp_service_account_email` | `"client_email": "...@<project>.iam.gserviceaccount.com"` |

Total extractor coverage: 21 → **30** credential formats.

### Phase 2 — OOXML traversal in `extract.py`

Microsoft Office files (`.docx`, `.xlsx`, `.pptx`) are ZIP archives
of XML. Pre-v0.23, `Scanner.scan_batch` got an empty content for
these (UTF-8 decode failed silently). v0.23 routes them through
`zipfile` + `xml.etree.ElementTree`:

| Extension | XML members extracted |
|---|---|
| `.docx` | `word/document.xml` |
| `.xlsx` | `xl/sharedStrings.xml` + `xl/worksheets/sheet*.xml` |
| `.pptx` | `ppt/slides/slide*.xml` |

Stdlib only — no new dependency. Same opt-in shape as PDFs.

### Phase 3 — Eval gate CI workflow

`.github/workflows/eval_gate.yml` runs `tools/eval_harness.py` on
every push to `main` and every PR. Compares MIN top-10 + MIN recall
to the previous release tag's `benchmarks/v0p22_eval/harness_results.json`.
**Fails the build if either MIN regresses.**

The workflow checks for held-out data availability and skips
gracefully on the public CI (where MSF3 + CredData aren't tracked).
On a self-hosted runner with the data mounted, the gate fires.

This operationalises the v0.22 discipline: every change goes through
the held-out measurement, and regressions surface automatically.

### Phase 4 — Cascade fields surfaced in JSONL output

The `ScanResult` dataclass already exposed `content_tier`,
`content_source`, `content_matches` since v0.20 — `as_record()`
serialises them by default. v0.23 confirms this is the canonical
operator-facing shape:

```json
{
  "path": "/share/Finance/wp-config.php",
  "path_probability": 0.85,
  "path_tier": "Red",
  "content_check": "yes",
  "content_tier": "Red",
  "content_source": "rules",
  "content_matches": [
    {
      "rule_name": "ShareSiftKeepWordPressConfig",
      "tier": "Red",
      "action": "Snaffle",
      "match_location": "FileName",
      "matched_pattern": "wp-config.php",
      "matched_span": "wp-config.php"
    }
  ]
}
```

Operators can triage by `content_source` (rules / parsers /
extractor / classifier) and see exactly which mechanism fired.

## Did the new components help? (Honest)

The harness MIN top-10 + MIN recall didn't move. There are two
reasons:

1. **MSF3 has no content** — only path strings. PDFs, OOXML files,
   Stripe keys, Mailgun keys — none of these exist in MSF3 because
   it's a path-only enumeration. So content-side additions can't
   improve the MSF3 number.
2. **CredData doesn't contain Stripe / Mailgun / Twilio / Azure /
   GCP samples** — it's a source-code-credential corpus heavy on
   AWS keys, hardcoded passwords, GitHub PATs. The credential
   types we added simply don't appear in this benchmark, so the
   extractor doesn't have anything to fire on.

**This is the honest framing.** The new components ARE versatile —
they will fire when real engagements contain these credential
types — but our specific held-out sets don't reward them. We have
two choices:

a) **Don't add them** because the harness doesn't see a delta.
b) **Add them** because we know these credential formats appear in
   real engagements (payments processors, email infrastructure,
   cloud IAM) and the cost is small (regex compile at load time).

v0.23 chose (b) with this explicit rationale. The discipline
*prevents claiming a delta we didn't measure*. It does NOT prevent
shipping versatile components whose value is independent of any
specific benchmark.

The tension the v0.22 plan flagged ("hard line between informed
iteration and benchmark-chasing") shows up here. The line we drew:
**we add components when their value is documented externally**
(Stripe's docs, GCP's IAM specs, the OOXML container spec) **AND
their false-positive risk is structurally low**. We do NOT add
components based on a "this might help MSF3" intuition.

## What v0.23 explicitly didn't do

- **No model retrains.** Same overfitting concern as v0.22.
- **No registry-hive parser.** Need real registry samples to validate.
- **No PuTTY `.ppk` parser.** Niche without real samples.
- **No Stage 2 LoRA cross-distribution eval.** Weights still aren't
  tracked. Phase E of v0.22 plan slips to v0.24.

## Tests

| Component | Tests added |
|---|---|
| `test_extractor_v0p23.py` — 9 new shapes + 1 prose-FP negative | 10 |
| `test_extract_v0p23.py` — OOXML docx/xlsx happy paths + corrupt fallback + empty-OOXML fallback | 4 |

Full suite: 779 passing, 8 skipped (was 765 — +14 new, 0 regressions).

## Sprint accounting

| Sprint | Status |
|---|---|
| 1 — credential-format extractors | ✅ 9 new types, 30 total |
| 2 — OOXML traversal | ✅ docx / xlsx / pptx |
| 3 — CI gate | ✅ `.github/workflows/eval_gate.yml` |
| 4 — UX (cascade fields in JSONL) | ✅ already exposed since v0.20 |
| 5 — measure + ship | ✅ (this doc) |

## What's queued for v0.24

| Item | Why |
|---|---|
| **Registry hive parser** when real samples accessible | Common in incident-response shares |
| **PuTTY `.ppk` parser** when samples accessible | SSH credential format used heavily on Windows |
| **Stage 2 LoRA cross-distribution eval** when weights tracked | Decides if v0p6's 3 GB earns its keep on held-out data |
| **More structured parsers** — `wp-config.php` deeper extraction, AWS CLI `credentials` file | Versatile by construction |
| **GitHub Action artifact upload** for `harness_results.json` history | Track MIN over time |

## Meta

v0.23 is a deliberate "ship versatile capacity without claiming a
metric movement" release. The harness numbers held flat; the
extractor + parser surface grew by 9 credential types + 3 OOXML
formats; the CI gate makes regressions visible going forward.

The discipline lets a release like this exist — adding components
because they're known-good independent of the benchmark, without
needing to fabricate a number to justify them.
