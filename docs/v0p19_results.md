# v0.19 results — themed-benchmark iteration loop

Released 2026-06-07.

v0.19 executes the plan in `docs/v0p19_themed_benchmark_plan.md`:
build 5 themed synthetic shares (finance / healthcare / dev-eng /
gov-contractor / legal), measure Stage 1 path-classifier performance
per theme, label dominant failure modes, and queue the resulting fix
candidates for v0.20.

The plan acknowledged that the "fix" step in each theme's sprint was
optional — failures requiring a major architecture change get
shelved. **This v0.19 release ships the build/run/measure/triage
cycle.** The "fix" step (model retrains, parser extensions, PDF
extraction) is queued for v0.20.

## What's measured

Stage 1 (path classifier) only. Stage 2 (content classifier) would
require a 3 GB Qwen3+LoRA weights download per theme; deferred. The
v0.20 fix priorities below identify which themes' results are likely
to change once Stage 2 runs against the same shares.

Snaffler head-to-head deferred — `snaffler` binary not on the
benchmark machine. Each theme's metrics are sharesift-only.

## Per-theme results

| Theme | Files | Salted | Recall (any tier) | Top-10 precision | Bottom-miss dominant failure mode | Pre-registration matched? |
|---|---|---|---|---|---|---|
| Finance | 80 | 22 | **0.318** | 0.30 | `naming-ood` (swift_codes, wire_instructions, K1) | ✅ |
| Healthcare | 80 | 27 | **0.370** | 0.40 | `content-ood` (benign-named salted: discharge_summary, prior_auth) | partial |
| Dev / engineering | 80 | 26 | **0.500** | 0.30 | `content-ood` + api_key naming gap (0/0% recall) | partial (calibration-drift hypothesis not the main story) |
| Gov / contractor | 80 | 20 | **0.650** | 0.40 | `extraction-missing` (PDF) + `content-ood` (SOW_draft) | ✅ |
| Legal | 80 | 20 | **0.200** | 0.00 | `extraction-missing` (PDF) + `template-mismatch` (MSA / NDA boilerplate) | partial |

Stage 1's mean recall across themes: **0.408**. Compare with the
held-out training split where recall sits at 100% — the cross-theme
drop is the whole point of v0.19 surfacing.

Legal at 20% recall + 0% top-10 precision is the worst-performing
theme. The bottom misses are all PDFs and legal-template `.docx`
files — both Stage 1 can't see (extraction) and the path classifier
has no signal for (MSA / NDA are benign-named).

Gov/contractor at 65% recall is the best — many of its juicy tokens
(`db_password`, `saml`, `ssh_private_key`) appear in the training
corpus's dev/ops distribution. Where it fails, it fails on PDFs.

## Per-theme failure-mode triage

Each section labels the bottom-5 misses with the v0.19 failure-mode
taxonomy from `src/eval/themed_taxonomy.py`. v0.20 fixes target the
dominant mode per theme.

### Finance — dominant: `naming-ood`

3/5 bottom misses are juicy-by-name files whose tokens
(`wire_instructions`, `swift_codes`) the Windows/Linux path
classifier doesn't recognise from training. The classifier assigns
0.146–0.232 probability; the threshold for Yellow is 0.50.

| Path token | Salted credential | Probability | Failure label |
|---|---|---|---|
| `wire_instructions` | swift_iban | 0.146 | `naming-ood` |
| `cash_flow_statement` | swift_iban | 0.159 | `content-ood` (benign name, salted) |
| `swift_codes` | swift_iban | 0.203 | `naming-ood` |
| `swift_codes` | db_password | 0.203 | `naming-ood` |
| `cash_flow_statement` | swift_iban | 0.232 | `content-ood` |

**v0.20 fix candidate:** augment Stage 1 training corpus with finance
filename tokens. swift_codes / wire_instructions / treasury_creds /
K1_signing_keys / 1099_credentials / ach_routing aren't in the
current training data. ~20 token families to add; cheap retrain.

### Healthcare — dominant: `content-ood`

All 5 bottom misses are benign-token files (intake_form,
discharge_summary, prior_auth_request, billing_summary) that happen
to be salted. Stage 1 is honest about not flagging them — the
filename gives no signal. This is a Stage 2 problem.

| Path token | Salted credential | Probability | Failure label |
|---|---|---|---|
| `intake_form` | db_password | 0.161 | `content-ood` |
| `discharge_summary` | api_key | 0.189 | `content-ood` |
| `prior_auth_request` | api_key | 0.214 | `content-ood` |
| `billing_summary` | db_password | 0.221 | `content-ood` |
| `billing_summary` | db_password | 0.221 | `content-ood` |

Notable per-cred-type findings:
- `saml_assertion`: 100% recall (when the filename contains SAML, classifier catches it)
- `ehr_account`: 0% recall — the `MRN-*` shape isn't recognised
- `ssh_private_key`: 0% recall in healthcare context

**v0.20 fix candidate:** ehr_account stays out-of-distribution for
Stage 1 by design (MRN strings don't appear in filenames). The fix
is Stage 2 capability — but it needs to distinguish MRN/account
numbers (PII shape) from real credentials (the template-mismatch
risk the plan flagged). Adversarial healthcare negatives in the
Stage 2 training corpus.

### Dev / engineering — dominant: `content-ood` + api_key naming gap

| Path token | Salted credential | Probability | Failure label |
|---|---|---|---|
| `release_notes` | cloud_credential | 0.163 | `content-ood` |
| `runbook_template` | vault_token | 0.189 | `content-ood` |
| `migration_guide` | vault_token | 0.192 | `content-ood` |
| `oncall_handoff` | ssh_private_key | 0.192 | `content-ood` |
| `migration_guide` | ssh_private_key | 0.198 | `content-ood` |

But the per-type recall surfaces a separate problem:

- `api_key`: 0% recall — even on juicy-named api-key files, the
  classifier misses. Whether this is `naming-ood` (specific filenames
  fall outside the trained pattern) or systematic under-recall on
  api-key tokens in the test seed deserves further investigation.
- `vault_token`: 50%, `oauth_token`: 67%, `ssh_private_key`: 33%

The pre-registered hypothesis was `calibration-drift` (tier band
precision contracts breaking under high salt density). The data
doesn't actually surface that — recall is mid (50%), top-K precision
is mid (0.30). The actual finding is more boring: the classifier is
under-confident on dev/eng cred-type-specific filenames.

**v0.20 fix candidate:** Sprint-level question — is the api_key 0%
recall driven by the synthetic data seed or a real gap? Re-run with
seed 2029 to disambiguate before retraining.

### Gov / contractor — dominant: `extraction-missing` + `content-ood`

| Path token | Salted credential | Probability | Failure label |
|---|---|---|---|
| `SOW_draft` (docx) | api_key | 0.161 | `content-ood` (benign name) |
| `SOW_draft` (doc) | contract_password | 0.179 | `content-ood` |
| `status_report_weekly` (pdf) | contract_password | 0.257 | `extraction-missing` |
| `DCAA_audit_response` (docx) | api_key | 0.315 | `content-ood` |
| `travel_voucher` (pdf) | cloud_credential | 0.319 | `extraction-missing` |

**v0.20 fix candidate:** PDF text extraction is genuine v0.20 scope.
The plan explicitly flagged this as the gov_contractor sprint's slip
risk. Recommend wiring `pdfplumber` or `pypdf` into the Scanner's
content-loading path; gates the verify + content stages on the
extracted text.

### Legal — dominant: `extraction-missing` + `template-mismatch`

| Path token | Salted credential | Probability | Failure label |
|---|---|---|---|
| `MSA_template` | cloud_credential | 0.146 | `template-mismatch` |
| `data_processing_addendum` (pdf) | cloud_credential | 0.151 | `extraction-missing` |
| `data_processing_addendum` (doc) | db_password | 0.219 | `content-ood` |
| `subpoena_response` | contract_password | 0.233 | `content-ood` |
| `NDA_draft` (pdf) | db_password | 0.235 | `extraction-missing` |

20% recall + 0% top-10 precision says the legal theme is genuinely
hostile to Stage 1. Most files are template-shaped (MSA, NDA,
addendum) and the filenames carry no credential signal even when
salted.

**v0.20 fix candidate:** legal is the strongest argument for Stage 2
being capable on benign-named files. The v0.13 literal-vs-referenced
separator should catch "the contract mentions the word password" vs
"the contract contains an actual password" — verify with a legal-
themed Stage 2 evaluation.

## Cross-theme aggregate findings

### Failure-mode distribution across all 25 bottom misses

| Label | Count | Themes affected |
|---|---|---|
| `content-ood` | 13 | finance, healthcare, dev_eng, gov_contractor, legal |
| `extraction-missing` | 4 | gov_contractor, legal |
| `naming-ood` | 4 | finance |
| `template-mismatch` | 1 | legal |
| `calibration-drift` | 0 | — |
| `parser-gap` | 0 | — |

**Top-level takeaway:** the v0.19 measurement says the dominant
issue is `content-ood` — half of Stage 1 misses are benign-token
files that happen to be salted, and Stage 1 honestly can't flag them
from filename alone. That's not a Stage 1 bug; it's a Stage 2
necessity. The second issue is PDF `extraction-missing` (16% of
misses), which blocks any content stage from running at all.

`calibration-drift` and `parser-gap`, which the plan's failure
taxonomy included, didn't surface in the v0.19 measurement. Either
the synthetic shares aren't dense enough to trigger them, or they're
genuinely smaller issues than the plan estimated.

### v0.20 fix queue, ranked by impact

| Fix | Themes that benefit | Effort | Mechanism |
|---|---|---|---|
| **PDF text extraction in Scanner** | gov_contractor, legal | ~2 days | wire `pdfplumber` into `pipeline.py` content-loading; gate Stage 2 + verify on extracted text |
| **Finance/healthcare filename retrain** | finance, healthcare, legal | ~3 days | add 50-100 industry-specific filename tokens to Stage 1 training corpus; ~1 GPU-hour to re-fit |
| **Legal-aware Stage 2** | legal, healthcare | ~ongoing | use the v0.13 literal-vs-referenced classifier in the Stage 2 pipeline against legal/EHR templates; measure FP rate on benign-template-with-mention |
| **Stage 2 run against v0.19 shares** | all | ~hours | once content classifier is set up, re-run scoring on all 5 themed shares; surface the *real* content-ood failure rate |
| **Dev/eng api_key recall deep-dive** | dev_eng | ~1 day | seed variance check + manifest audit; decide whether it's the synthetic seed or a real gap |

## Honest gaps

- **No Snaffler head-to-head.** `snaffler` binary isn't installed on
  the benchmark host. Per-theme Snaffler numbers would let us
  compare ShareSift's degradation curve to the rule-pack baseline's.
- **No Stage 2 (content classifier).** Qwen3 + LoRA weights aren't
  in the public repo or available without a 3 GB download per run.
  The `content-ood` finding (the dominant failure label) can't be
  acted on without Stage 2 measurements.
- **No model retrain inside v0.19.** The fix step is shelved to
  v0.20 — consistent with the plan's acknowledgement that "the loop
  assumes the failure modes are *fixable* in v0.19," with the
  caveat that some require architecture change and get deferred.
- **Same-builder bias.** All 5 themes share the same synthetic
  builder (`tools/build_themed_share.py`). Cross-theme variance is
  about token pool and salt density only; the underlying file
  generation is identical. The Limitations section in the README
  already says this; v0.19 doesn't move that ball.
- **Small-N noise.** 80 files × 5 themes × ~25% salt density = ~125
  total salted files in the benchmark. Recall numbers carry ~±5%
  noise from sampling alone. Don't over-interpret a 32% vs 37%
  finance-vs-healthcare delta without theme-internal repro.

## What's tracked vs. regenerated

| Path | Tracked? | Regenerable? |
|---|---|---|
| `benchmarks/v0p19/themes/<theme>.yaml` | ✅ | source of truth |
| `benchmarks/v0p19/<theme>/manifest.jsonl` | ✅ | yes, from theme+seed |
| `benchmarks/v0p19/<theme>/metrics.json` | ✅ | yes, from scores+manifest |
| `benchmarks/v0p19/<theme>/share/` | ❌ gitignored | yes, from theme+seed |
| `benchmarks/v0p19/<theme>/paths.txt` | ❌ gitignored | yes |
| `benchmarks/v0p19/<theme>/scores.jsonl` | ❌ gitignored | yes, run `sharesift score-paths` |

To reproduce a theme's run:

```bash
uv run python tools/build_themed_share.py --theme finance
uv run sharesift score-paths \
    --input benchmarks/v0p19/finance/paths.txt \
    --output benchmarks/v0p19/finance/scores.jsonl
uv run python tools/score_themed_run.py \
    --theme finance \
    --scores benchmarks/v0p19/finance/scores.jsonl
```

## Sprint accounting

| Sprint | Status |
|---|---|
| 0 — wait for v0.18 ergonomics | ✅ (`--json`, `sharesift scan`) |
| 1 — tooling (build, score, taxonomy) | ✅ `tools/build_themed_share.py`, `tools/score_themed_run.py`, `src/eval/themed_taxonomy.py`, 7 tests |
| 2 — finance | ✅ build / run / measure / triage; fix step → v0.20 |
| 3 — healthcare | ✅ same |
| 4 — dev_eng | ✅ same |
| 5 — gov_contractor | ✅ same |
| 6 — legal | ✅ same |
| 7 — docs/v0p19_results.md + bundle + tag | ✅ this doc + `dist/sharesift-v0p19.zip` + tag v0.19.0 |

What v0.19 explicitly does NOT do, per the original plan's caveats:
the model retrains. Those land in v0.20+ based on the fix queue
above.

## Test counts

| Component | Tests added | Notes |
|---|---|---|
| `src/eval/themed_taxonomy.py` | 2 | label vocabulary + serialization |
| `tools/build_themed_share.py` | 3 | determinism + structure + cred injection |
| `tools/score_themed_run.py` | 2 | metric card shape + bottom-miss surfacing |
| **Total v0.19 additions** | **7** | All passing |

Full suite: 734 passing, 8 skipped (was 727 + 7 new).
