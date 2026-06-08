# v0.20 results — content determiner + dormant-infra wiring

Released 2026-06-08.

Executes the plan in `docs/v0p20_content_determiner_plan.md`. v0.19's
themed-benchmark surfaced `content-ood` (benign-named files hiding
credentials inside) as the dominant Stage-2 failure mode and showed
Stage-2 wasn't measurable because the heavy LoRA weights weren't
available. v0.20 fixes both by wiring already-vendored content-
detection infrastructure into the main Scanner — **no model retrain
required.**

## Headline numbers

Re-ran the 5 themed shares from v0.19 through the new pipeline
(path classifier + content cascade combined). Mean recall on salted
files went **0.408 → 0.640, +23 pp.**

| Theme | v0.19 recall | v0.20 recall | Δ | What caught the new positives |
|---|---|---|---|---|
| Finance | 0.318 | 0.455 | **+13.6 pp** | rules + cascade+path |
| Healthcare | 0.370 | 0.593 | **+22.2 pp** | rules + cascade+path |
| Dev / engineering | 0.500 | 0.846 | **+34.6 pp** | rules dominated |
| Gov / contractor | 0.650 | 0.700 | **+5.0 pp** | cascade+path |
| Legal | 0.200 | 0.600 | **+40.0 pp** | rules + cascade+path |
| **Mean** | **0.408** | **0.640** | **+23.2 pp** | rules + cascade+path |

Top-10 precision moved less consistently — finance / healthcare /
dev_eng held or improved slightly, gov_contractor held at 0.40,
legal dropped to 0.00 (the rule engine adds matches without
distinguishing top-10 ranking better than the v0.19 path classifier
did). Precision-side work is a known follow-up.

## What shipped

### Phase 1 — wire the dormant infrastructure

| Component | New file | Purpose |
|---|---|---|
| `ContentRuleEngine` — compile + execute 78 vendored Snaffler content/path rules | `src/sharesift/content_rules.py` | The biggest gap from the audit: 110 vendored rules existed but never ran inside the main Scanner. The engine now executes them per file. |
| PDF text extraction via `pypdf` | `src/sharesift/extract.py` | New optional `--group pdf-extraction`. Scanner's content load now routes PDFs through `pypdf.PdfReader` before falling back to UTF-8 text. |
| Base64 recursive decoder, optionally applied | `src/sharesift/extract.py` (wires existing `preprocess/base64_decode.py`) | Reveals credentials nested inside JSON/XML/PS1 configs. Opt-in (off by default) so legitimate base64 blobs in cert files don't double payload size. |

### Phase 2 — ContentDeterminer cascade

`src/sharesift/content_determiner.py` unifies the four content-side
mechanisms into one `ContentDeterminer.evaluate(path, content)` that
returns a single `ContentVerdict(tier, source, matches, confidence)`:

```
1. structured parsers  (existing — high precision, narrow recall)
2. content rule engine (new in v0.20 — medium precision, broad recall)
3. verify extractor    (existing — very high precision, narrow recall)
4. LoRA classifier     (existing — opt-in fallback only)
```

The cascade short-circuits on first hit. Callers without the 3 GB Qwen
download set `use_classifier=False` and still get useful results from
tiers 1-3. `Scanner.scan_batch` runs the cascade per file; the LoRA
fires only when the cheap tiers are inconclusive AND the path
classifier flagged the file OR `--force-content` was set.

`ScanResult` grows three new fields — `content_tier`,
`content_source`, `content_matches` — alongside the existing binary
`content_check`. Reports and downstream consumers now know which
cascade tier produced each verdict.

## Per-theme triage

### Finance — +13.6 pp

The v0.19 dominant failure mode was `naming-ood` (industry-specific
tokens like `swift_codes`, `wire_instructions` outside the path
classifier's training distribution). The cascade caught half of these
through the rule engine — `KeepNameContainsGreen` (matches `passw`,
`secret`, `credential`) fired on `treasury_creds` and `banking_passwords`
variants. swift_codes and pure wire_instructions remain `naming-ood`
unless retrained.

Caught-salted source distribution: `rules` 3, `cascade+path` 2, `path` 5.

### Healthcare — +22.2 pp

Rules fired on credential-bearing content the path classifier
couldn't see. `saml_assertion` and `ssh_private_key` content
patterns produce matches even when the filename
(`intake_form_0058.csv`, `discharge_summary`) gives no signal —
exactly the v0.19 `content-ood` failure mode the rules engine was
designed to address.

Caught-salted source distribution: `rules` 6, `cascade+path` 6,
`path` 4.

### Dev / engineering — +34.6 pp

The single largest improvement. Dev/eng has the densest credentials
and the most cred types the rule engine recognises (vault tokens,
SSH keys, AWS credentials, OAuth tokens). The combined
path+cascade has 0.846 recall, leaving only 4 misses out of 26
salted files.

Caught-salted source distribution: `cascade+path` 12, `rules` 9,
`path` 1.

### Gov / contractor — +5.0 pp

Smallest improvement because gov_contractor had the highest v0.19
recall (0.65) to start — the path classifier was already catching
most signal. The remaining gains are on `db_password` / `saml`-named
files where the rule engine's content-side patterns confirmed what
the path classifier guessed.

The 4 PDF misses from v0.19 weren't fixed by this run because the
synthetic PDFs in `benchmarks/v0p19/` are text-with-.pdf-extension,
not real PDFs (pypdf rejects them with "invalid pdf header"). Real
engagement PDFs would extract — this is a measurement artifact, not a
pipeline bug. v0.20 ships the wiring; v0.21 should regenerate the
themed shares with real PDFs to verify.

Caught-salted source distribution: `cascade+path` 8, `path` 5,
`rules` 1.

### Legal — +40 pp

Largest absolute improvement. v0.19's 20% recall was the floor —
legal filenames (`MSA_template`, `NDA_draft`, `data_processing_addendum`)
gave Stage 1 nothing. The rule engine looks INSIDE the file and
catches credential-shape strings regardless of filename. The cascade
+ path together identify 60% of salted files.

But top-10 precision dropped to 0.00, which means: the cascade
flagged a lot of files (some legitimately, some not), and ranking by
combined-tier didn't put the right files in the top 10. This is the
"precision risk from the rule engine" the v0.20 plan flagged —
legal NDAs use the words `password`, `credential`, `secret` in
boilerplate, and the rule engine can't tell semantic from literal use.
That's the v0.13 literal-vs-referenced classifier's job. Wiring it
into the cascade is queued for v0.21.

Caught-salted source distribution: `rules` 8, `cascade+path` 4.

## Honest gaps remaining

1. **Top-10 precision didn't move (legal regressed to 0.00).** The
   rule engine produces more matches; ranking by `max(path_prob,
   cascade_tier_pseudo)` isn't sophisticated enough. v0.21 should
   train a small reranker that uses cascade source + tier + path
   probability as features. The infrastructure is there — it's a
   ranking-model task, not a detection task.
2. **PDF extraction unverified on real PDFs.** v0.19 synthetic shares
   use `.pdf`-extensioned text files. Pypdf rejects them. Real-
   world PDF extraction works (pypdf is a well-tested library) but
   we don't have a metric until the shares are regenerated with
   real PDFs.
3. **No Stage 2 LoRA in the cascade benchmarks.** Weights still
   aren't tracked. The 23 pp improvement is from regex + parsers
   alone — adding the LoRA would push higher on hard cases (legal
   template boilerplate, healthcare PII shapes).
4. **`extra_rules.py` not loaded.** The 22 v0.12 blind-spot + Gitleaks-
   derived modern SaaS rules construct `SnaffleRule` instances tied
   to the pysnaffler dependency. Porting them to JSON for the
   `ContentRuleEngine` is a v0.20.1 candidate.
5. **The rule engine fires `KeepNameContainsGreen` (`passw`/
   `secret`/`credential`) widely.** Some apparent recall gains are
   really Green-tier matches that wouldn't survive a precision-tuned
   threshold. The v0.21 reranker should down-weight Green hits.

## What's tracked

```
src/sharesift/content_rules.py     — Phase 1 rule engine
src/sharesift/extract.py           — PDF + base64 wrapper
src/sharesift/content_determiner.py — Phase 2 cascade
benchmarks/v0p20/<theme>/metrics.json — per-theme delta vs v0.19
```

## Test counts

| Component | Tests added |
|---|---|
| `ContentRuleEngine` | 8 |
| `extract.load_content` | 6 |
| `ContentDeterminer` cascade | 6 |
| **Total v0.20 additions** | **20** |

Full suite: 754 passing, 8 skipped (was 734 + 20 new).

## Sprint accounting

| Sprint | Status |
|---|---|
| 1 — `ContentRuleEngine` + tests | ✅ `src/sharesift/content_rules.py`, 8 tests |
| 2 — PDF + base64 wiring | ✅ `src/sharesift/extract.py`, 6 tests |
| 3 — `ContentDeterminer` cascade + tests | ✅ `src/sharesift/content_determiner.py`, 6 tests |
| 4 — Re-run v0.19 benchmark | ✅ `benchmarks/v0p20/<theme>/metrics.json` × 5; mean recall +23 pp |
| 5 — Docs + bundle + tag | ✅ this doc + `dist/sharesift-v0p20.zip` + `v0.20.0` |

## What's deferred to v0.21

- Stage 1 retrain with v0.19 themed filename tokens (naming-ood gaps)
- Lightweight content classifier for the cascade's smart middle tier
  (runnable without the LoRA download)
- Reranker that uses cascade source + tier as features
- `extra_rules.py` → JSON port for the rule engine
- Regenerate v0.19 themed shares with real PDFs to verify pypdf wins
- Wire `literal_vs_referenced` (v0p7) into the cascade for legal/
  healthcare template false-positive control
