# v0.23 — more versatile components, same eval discipline

Drafted 2026-06-08 from the v0.22 results
(`docs/v0p22_results.md`). v0.22 established the eval harness and
declarative ranking fixes that put MIN top-10 at 0.20. v0.23 adds
architecturally-versatile components — extractors, parsers, an
operator-facing UX — and measures the delta through the same
harness.

Every item below is **architecturally versatile**: no training
distribution, no benchmark-specific tuning, applies identically on
every share.

## Phases

### Phase 1 — New credential-format extractors

Strong inductive biases — regex patterns that match credential
shape, not statistical properties of files. The existing
`verify/extractor.py` covers 21 patterns; v0.23 adds 6 more for
modern SaaS / payments / GCP / Azure.

| Credential type | Pattern shape | Why useful |
|---|---|---|
| Stripe (live + restricted) | `sk_live_[A-Za-z0-9]{24,}`, `rk_live_*` | Payments — high-impact creds |
| SendGrid | `SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}` | Email infra |
| Mailgun | `key-[a-f0-9]{32}` | Email infra |
| Twilio | `SK[a-f0-9]{32}`, `AC[a-f0-9]{32}` | SMS/voice infra |
| Azure storage connection string | `DefaultEndpointsProtocol=https;AccountName=...;AccountKey=...` | Cloud storage |
| GCP service account JSON | Heuristic: `"type": "service_account"` + `"private_key": "-----BEGIN PRIVATE KEY-----"` | Cloud IAM |

All shapes are well-published and stable. False-positive risk is
low because each pattern carries strong structural constraints
(known prefixes + specific length + character class).

### Phase 2 — OOXML traversal parser

Microsoft Office files (`.docx`, `.xlsx`, `.pptx`) are ZIP archives
of XML. The current `Scanner.scan_batch` calls
`load_content(path)` which tries `path.read_text(encoding="utf-8")`
on `.docx`/`.xlsx` and gets garbage — these are binary ZIPs.

v0.20 added PDF text extraction. v0.23 adds OOXML:

* `.docx` → extract paragraph text from `word/document.xml`
* `.xlsx` → extract cell values from `xl/sharedStrings.xml` + `xl/worksheets/sheet*.xml`
* `.pptx` → extract slide text from `ppt/slides/slide*.xml`

Implementation: stdlib `zipfile` + `xml.etree.ElementTree`. No new
dependency. Same opt-in shape as PDF (`pdf-extraction` group) —
new group `ooxml-extraction`, or just include in core since
stdlib-only.

### Phase 3 — CI gate

GitHub Actions workflow that runs `tools/eval_harness.py` on every
PR + push to main, fails if MIN top-10 precision OR MIN recall drops
below the previous release's value. Operationalizes the discipline
so future regressions surface automatically.

Implementation: read `benchmarks/v0p22_eval/harness_results.json`
from the previous tag (`git show v0.22.0:benchmarks/v0p22_eval/harness_results.json`),
compare to the current run, fail if either MIN regresses.

### Phase 4 — Calibrated abstention UX

The cascade already produces `tier`, `source`, `matches[]`. v0.23
surfaces these in the JSONL output so the operator can see exactly
which detection mechanism fired:

```json
{
  "path": "...",
  "content_check": "yes",
  "content_tier": "Red",
  "content_source": "rules",
  "content_matches": [
    {"rule_name": "KeepWP_Config", "tier": "Red", "action": "Snaffle"}
  ]
}
```

Already in the dataclass (since v0.20). v0.23 makes sure it's in
the `as_record()` output by default and documented as the canonical
shape.

### Phase 5 — Measure delta + ship

Re-run `tools/eval_harness.py`. Goal: hold MSF3 + CredData at v0.22
levels (no regression) while improving CredData precision via the
new extractors and surfacing previously-invisible content via
OOXML.

## What v0.23 explicitly does NOT do

- **No model retrains.** Same overfitting concern as v0.22.
- **No registry-hive parser.** Too few real test cases on this host
  to validate; better as v0.24 with real registry samples.
- **No PuTTY `.ppk` parser.** Niche; would require real PPK files
  to validate. v0.24.
- **No Stage 2 LoRA evaluation.** Weights still aren't tracked.

## Sprint accounting

| Sprint | Scope | Deliverable |
|---|---|---|
| 1 | 6 new credential-format extractors + tests | `src/sharesift/verify/extractor.py` |
| 2 | OOXML traversal in `extract.py` | `src/sharesift/extract.py` |
| 3 | CI gate workflow | `.github/workflows/eval_gate.yml` |
| 4 | UX: confirm cascade fields exposed in JSONL | doc-only change if dataclass already covers |
| 5 | Re-run harness + ship | `docs/v0p23_results.md` + release |

## Verification (after sprint 5)

```bash
uv run python tools/eval_harness.py
# Expected: MIN top-10 >= 0.20 (v0.22 floor); CredData
# precision-any-tier should improve from 0.33 thanks to new
# extractors firing on more specific credential formats.
```

## Out-of-scope honest note

Each new extractor and parser COULD overfit on a specific corpus
the patterns were tuned against. The risk is lower than learned
models because the patterns are declarative + their shape is
publicly documented (Stripe's key format is in their docs, not
discovered from CredData). But it's not zero.

Mitigation: every new extractor gets a test that verifies it fires
on a *synthetic* example matching the documented shape, not a real
CredData / MSF3 string. That way we're testing what we claim
("matches documented Stripe key shape"), not what happens to be in
our benchmark.
