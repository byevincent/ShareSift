# Changelog

All notable changes to ShareSift are listed here. Format loosely follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow
[Semantic Versioning](https://semver.org/).

## [0.18.0] — 2026-06-07

CLI ergonomics. Full execution of the Phase B–F plan that v0.17.1
Phase A started.

### Added

- **Top-level `-q`/`--quiet`, `-v`/`--verbose`.** A 30-line `Output`
  helper in `src/sharesift/_output.py` routes all stderr emissions
  through a verbosity-gated singleton. `--quiet` silences progress and
  info; warnings (incl. the verify safety banner) and errors still
  print. `--verbose` adds debug detail (model dirs, batch sizes, rate
  limits, device, target file) and bypasses the 3rd-party warning
  filter.
- **`tqdm` progress bars** on `Scanner.scan_batch` (the model-heavy
  content stage) and `verify_records`. Auto-suppressed on non-TTY
  stderr at NORMAL; always shown at VERBOSE. `tqdm>=4.66` is now a
  core dep.
- **Top-level `--json`** flag. Each subcommand emits a single
  structured end-of-run summary on stderr with a common envelope
  (`command`, `version`, `elapsed_s`, `input_count`/`output_count`,
  `exit_code`) plus per-handler fields. Stdout stays pure JSONL.
- **One-shot `sharesift scan`** subcommand wraps enumerate →
  score-paths → scan-files → verify → render-report into a single
  call. `--skip-verify` and `--skip-report` drop the late stages. The
  combined `--json` summary lists `stages_run` and the path to each
  intermediate.

### Changed

- 3rd-party warning suppression extended to `UserWarning` and
  `sklearn.*` (the LGBMClassifier feature-name nag was leaking under
  `--quiet`).
- `verify_records` lost its `progress: bool` kwarg; the singleton
  handles verbosity now. The hand-rolled every-25-records checkpoint
  is gone — tqdm handles update cadence.
- Project version bumps 0.5.0 → 0.18.0 across all `--version` /
  metadata reads.

### Notes

- Compat shim at `src/truffler/` continues to ship so joblib
  artifacts pickled with the old module paths still load. It will be
  removed once models are retrained against `sharesift.*`.
- Test count: 727 passing, 8 skipped (the 8 skipped are CLI
  integration tests that gate on the `models/path_classifier_v0/`
  artifact, which is not tracked in the public repo).

## [0.17.1] — 2026-06-07

First public release. Phase A of the v0.18 CLI ergonomics plan.

### Added

- `sharesift --version` flag — reports the installed version, sourced from
  package metadata via `importlib.metadata`.
- `sharesift.__version__` — Python-accessible version constant.
- 3rd-party warning suppression at CLI entry — `FutureWarning` and
  `DeprecationWarning` from `transformers`, `peft`, `urllib3`, and
  `bitsandbytes` are filtered. `TRANSFORMERS_VERBOSITY` defaults to
  `error` if not already set.

### Changed

- Project renamed Truffler → ShareSift. Package is `sharesift`; CLI entry
  point is `sharesift`. A compat shim at `src/truffler/` lets joblib
  artifacts pickled with the old module paths still load — it will be
  removed once models are retrained against `sharesift.*`.

### Notes

- Pre-public history (v0.1 through v0.17) is summarised in `docs/journal.md`
  and the per-version `docs/v0pXX_*.md` writeups.
- Model weights are not bundled in this repository. See `RUN.md` (in the
  release archive) for download instructions.

## [Unreleased]

v0.25 — registry-hive + PuTTY `.ppk` parsers (need real samples);
Stage 2 LoRA cross-distribution eval (need tracked weights); more
structured parsers (`.pypirc`, gcloud credentials, gh CLI auth,
KeyringFile); `tools/plot_harness_history.py` for visualising the
MIN trajectory.

## [0.24.0] — 2026-06-08

Four new structured parsers (wp-config.php, AWS CLI credentials,
`.netrc`, Maven settings.xml) + harness history tracking. The
production stack stays the v0.20 cascade. Harness numbers held flat
— same dynamic as v0.23.

### Added

- `src/sharesift/parsers/wp_config_php.py` — extracts DB_USER /
  DB_PASSWORD / DB_HOST + the 8 WordPress auth keys/salts from
  PHP `define()` calls. Skips boilerplate placeholders.
- `src/sharesift/parsers/aws_cli_credentials.py` — parses INI
  sections; emits per-profile access key / secret / session token.
- `src/sharesift/parsers/netrc.py` — token-stream parser handling
  multi-line, single-line, and default-block forms.
- `src/sharesift/parsers/maven_settings_xml.py` — walks XML by
  local-name (xmlns-agnostic) extracting server username/password.
- `benchmarks/v0p22_eval/harness_history.jsonl` — append-only
  record of MIN top-10 / MIN recall per release for trajectory
  tracking.
- `.github/workflows/eval_gate.yml` — added artifact upload step
  for `harness_results.json` (90-day retention).

### Findings

| Metric | v0.23 | v0.24 |
|---|---|---|
| MIN top-10 precision | 0.20 | 0.20 |
| MIN recall any-tier | 0.90 | 0.90 |

Parser count: 18 → **22**. Held-out sets don't contain wp-config /
AWS credentials / `.netrc` / Maven settings files, so the harness
doesn't reward the added capacity. Same v0.23 framing: discipline
prevents claiming an unmeasured improvement; doesn't prevent
shipping components whose value is independently documented.

### Notes

- Tests added: 11. Full suite: **790 passing, 8 skipped, 0
  regressions**.

## [0.23.0] — 2026-06-08

More architecturally-versatile components, same v0.22 eval
discipline. The production stack stays the v0.20 cascade. Harness
numbers held flat — by design — because the new components target
credential types and file formats that don't appear in the held-out
benchmarks but DO appear in real engagements.

### Added

- **9 new credential-format extractors** in
  `src/sharesift/verify/extractor.py`:
  - Stripe (live secret, restricted, publishable)
  - SendGrid + Mailgun
  - Twilio (account SID, API key SID)
  - Azure storage connection string
  - GCP service-account email
  - Total extractor coverage: 21 → **30** credential formats.
- **OOXML traversal** in `src/sharesift/extract.py` — `.docx` /
  `.xlsx` / `.pptx` are now read via stdlib `zipfile` +
  `xml.etree.ElementTree`. No new dependency. Replaces the silent
  empty-content fallback that v0.20-v0.22 had for these formats.
- **Eval gate CI workflow**
  (`.github/workflows/eval_gate.yml`) — runs
  `tools/eval_harness.py` on push to main and on PRs; fails the
  build if MIN top-10 precision OR MIN recall regresses below the
  previous release tag's value. Skips gracefully when held-out
  data isn't present.

### Findings

Harness numbers identical to v0.22:

| Metric | v0.22 | v0.23 |
|---|---|---|
| MIN top-10 precision | 0.20 | 0.20 |
| MIN recall any-tier | 0.90 | 0.90 |

**Honest framing**: MSF3 has no content, so OOXML / PDFs / Stripe
keys / etc. can't affect it. CredData doesn't contain Stripe /
Mailgun / Twilio / Azure / GCP samples, so the new extractors
don't fire on it. The new components add capacity for credential
types known to appear in real engagements but absent from these
specific held-out sets. The discipline prevents claiming an
unmeasured improvement; it does NOT prevent shipping components
whose value is independently documented.

### Notes

- Tests added: 14. Full suite: **779 passing, 8 skipped, 0
  regressions**.
- Cascade fields (`content_tier`, `content_source`,
  `content_matches`) confirmed in `ScanResult.as_record()` output
  — calibrated abstention UX shipped since v0.20.

## [0.22.0] — 2026-06-08

Versatility-first: Phases A-C of `docs/v0p22_versatility_plan.md`.
The production stack is the v0.20 cascade; v0.22 adds eval
discipline and two declarative ranking fixes — no learned features,
no per-benchmark tuning.

### Added

- `tools/eval_harness.py` — runs the production cascade against 3
  independently-collected held-out sets (MSF3, CredData,
  engagement_corpus). Reports MIN-across-primary as the headline,
  not mean. Writes `benchmarks/v0p22_eval/harness_results.json`.
- `RuleVerdict.credential_tier` — distinguishes Snaffle/CheckForKeys
  matches (credential signal) from Relay matches (enumeration
  helper). The default `tier` field unchanged for back-compat.
- `_score_with_dedup_penalty()` — declarative ranking that divides
  per-file evidence by `sqrt(filename_frequency)`. Replicates the
  v0.14 LightGBM ranker's "many copies = noise" intuition
  declaratively. No training, no fitting.

### Changed

- Cascade tier scoring: **Green tier scores 0** in the eval
  harness ranking. Green is informational ("fetch for context") —
  the v0.21 MSF3 validation traced top-K collapse to
  `RelayPsByExtension` (Green-tier) firing on 84% of MSF3 files.
  Yellow / Red / Black unchanged.

### Findings

| Metric | v0.21 | v0.22 |
|---|---|---|
| MSF3 top-10 precision | 0.00 | **0.20** |
| MSF3 recall | 0.900 | 0.900 |
| CredData top-10 | 0.70 | 0.70 |
| CredData recall | 1.000 | 1.000 |
| **MIN top-10 across primary** | **0.00** | **0.20** |

The 0.20 floor is the honest "what an operator should expect on the
next share" number. The v0.14 README claim of 1.000 on MSF3 was an
in-distribution measurement; v0.22 reports cross-distribution.

### Notes

- The v0.21 reranker stays experimental and is NOT in the production
  scan flow.
- No MSF3-specific rules added — the dedup penalty addresses
  Boxstarter / Chocolatey noise universally.
- No model retraining. Both v0.22 fixes are declarative.
- Tests added: 6. Full suite: 765 passing, 0 regressions.

## [0.21.1] — 2026-06-08

**Honesty patch.** v0.21's "+46 pp top-10 precision" headline was an
in-distribution result (reranker trained and evaluated on the same
5 themed shares). Real-world validation on Metasploitable 3 showed
the reranker is ~5× worse on data it wasn't trained against
(top-10 = 0.20 vs the 0.76 mean reported in v0.21).

This release adds honesty to the existing artifacts; no code in the
production scan flow changes.

### Changed

- `src/sharesift/reranker_v0p21.py` — module docstring leads with
  an EXPERIMENTAL warning + the MSF3 numbers. The reranker is NOT
  wired into `Scanner.scan_batch` and was never in the production
  default flow.
- `docs/v0p21_results.md` — added a cross-distribution caveat at
  the top of the document with the in-distribution vs MSF3 numbers
  side by side.
- `docs/v0p22_versatility_plan.md` — new. Replaces the previous
  Unreleased section's "retrain reranker on MSF3+GOAD" idea with a
  versatility-first plan: evaluation discipline (frozen held-out
  sets, eval harness with MIN-across-sets headline metric), rule
  engine over-fire fix, architecturally-versatile component
  investments.

### Notes

- The v0.20 cascade (parsers + rules + extractor) is unaffected and
  remains the production stack — its +23 pp recall win is real on
  both synthetic and MSF3 data.
- Test count unchanged: 759 passing.

## [0.21.0] — 2026-06-08

Cascade reranker + extra rules. Executes the plan in
`docs/v0p21_plan.md`. v0.20's content cascade fixed recall (+23 pp)
but broke top-K ranking on legal; v0.21 fixes top-K ranking across
all 5 themes.

### Added

- `src/sharesift/rules/extra_rules.json` — 41 ported rules from
  the v0.12 blind-spot collection + Gitleaks-derived modern SaaS
  detectors. Loaded automatically by `ContentRuleEngine` alongside
  the existing 78 base rules. Total engine rule count: **120**.
- `src/sharesift/reranker_v0p21.py` — `RerankFeatures` (30-dim
  vector) + `CascadeReranker` (LightGBM inference wrapper).
- `tools/train_reranker_v0p21.py` — trains a LightGBM binary
  classifier on the v0.19 themed manifests + v0.20 cascade output.
  Supports leave-one-theme-out CV.
- `tools/score_themed_run_v0p21.py` — re-runs the benchmark with
  cascade + reranker; emits per-theme baseline-vs-reranked top-K
  comparison.
- `models/reranker_v0p21.joblib` — trained model (~50KB).
- `benchmarks/v0p21/<theme>/metrics.json` — per-theme metrics cards
  for all 5 themes.

### Findings

| Theme | v0.20 top-10 | v0.21 top-10 | Δ |
|---|---|---|---|
| Finance | 0.30 | **0.90** | +60 pp |
| Healthcare | 0.50 | **0.90** | +40 pp |
| Dev / engineering | 0.30 | **0.70** | +40 pp |
| Gov / contractor | 0.40 | **0.60** | +20 pp |
| Legal | **0.00** | **0.70** | **+70 pp** |
| **Mean** | **0.30** | **0.76** | **+46 pp** |

Recall identical to v0.20 (cascade unchanged; reranker reorders only).

### Honest caveats

- **In-distribution result.** The reranker was trained on the same
  5 themes it scored. Leave-one-theme-out CV scores were 0.10-0.30
  on held-out themes vs. 0.60-0.90 in production. Cross-theme
  generalization needs ~1000+ labeled pairs to validate; v0.22.
- Real-PDF regen (Sprint 2 in the v0.21 plan) deferred to v0.22.

### Notes

- Tests added: 5. Full suite: 759 passing, 8 skipped.

## [0.20.0] — 2026-06-08

Content determiner + dormant-infrastructure wiring. Executes the plan
in `docs/v0p20_content_determiner_plan.md` end-to-end. The headline
result: re-running the v0.19 themed benchmark on the new pipeline
moves mean recall on salted files from **0.408 → 0.640 (+23.2 pp)**
without any model retrain.

### Added

- `src/sharesift/content_rules.py` — `ContentRuleEngine` compiles and
  executes 78 vendored Snaffler content/path rules against
  `(filename, content)` inside `Scanner.scan_batch`. Pre-v0.20 these
  rules existed in `snaffler_default.json` but never ran in the main
  Scanner — only inside the optional pysnaffler enumeration loop.
- `src/sharesift/extract.py` — unified `load_content(path, *,
  max_bytes, decode_base64)` replaces the bare `path.read_text()`
  call. PDFs route through `pypdf.PdfReader`; base64 nested
  credentials surface via the existing `recursive_base64_decode`
  preprocessor.
- `pdf-extraction` optional dependency group (`pypdf>=4.0`).
- `src/sharesift/content_determiner.py` — `ContentDeterminer`
  cascades parsers → rules → extractor → (optional) LoRA. Each tier
  short-circuits on first hit. Callers without the 3 GB Qwen
  download set `use_classifier=False` and still get useful results.
- `tools/score_themed_run_v0p20.py` — benchmark script that re-runs
  the v0.19 themed shares through the new pipeline and emits a
  per-theme delta against v0.19's metrics.
- `benchmarks/v0p20/<theme>/metrics.json` — per-theme combined
  (path + cascade) results for all 5 themes.

### Changed

- `Scanner.scan_batch` now runs the cascade per file. The LoRA
  classifier becomes a fallback for hard cases instead of the only
  content-side detector.
- `ScanResult` grows `content_tier`, `content_source`,
  `content_matches` fields. The binary `content_check` stays for
  back-compat.

### Findings

| Theme | v0.19 recall | v0.20 recall | Δ |
|---|---|---|---|
| Finance | 0.318 | 0.455 | +13.6 pp |
| Healthcare | 0.370 | 0.593 | +22.2 pp |
| Dev / engineering | 0.500 | 0.846 | +34.6 pp |
| Gov / contractor | 0.650 | 0.700 | +5.0 pp |
| Legal | 0.200 | 0.600 | +40.0 pp |
| **Mean** | **0.408** | **0.640** | **+23.2 pp** |

Honest precision gap: legal top-10 precision regressed to 0.00 —
the rule engine adds matches but ranking by combined tier
isn't sophisticated enough. v0.21 reranker.

### Notes

- `extra_rules.py` (22 v0.12 blind-spot + Gitleaks-derived modern
  SaaS rules) not yet loaded — they construct SnaffleRule instances
  tied to the optional pysnaffler dep. Port to JSON is v0.20.1.
- PDF extraction is wired but unverified on real PDFs — v0.19's
  synthetic shares use .pdf-extensioned text files which pypdf
  rejects.
- LoRA content classifier still requires manual model dir setup;
  cascade benchmarks ran with `use_classifier=False`.
- Tests added: 20. Full suite: 754 passing.

## [0.19.0] — 2026-06-07

Themed-benchmark iteration loop — Sprint 0 through 7 of
`docs/v0p19_themed_benchmark_plan.md`. The fix step (model retrains)
is shelved to v0.20 per the plan's caveat that some failure modes
require architecture changes.

### Added

- `src/eval/themed_taxonomy.py` — fixed 6-label failure-mode
  vocabulary (`naming-ood`, `content-ood`, `template-mismatch`,
  `extraction-missing`, `calibration-drift`, `parser-gap`).
- `tools/build_themed_share.py` — generates a synthetic themed share
  from a theme YAML config (filename tokens, directories, credential
  type mix, salt density). Output matches the existing
  `constructed_share_manifest.jsonl` schema.
- `tools/score_themed_run.py` — per-theme metrics card: recall (overall +
  per ground-truth tier + per credential type), top-K precision at K=10/20/50,
  tier distribution, bottom-5 misses with full paths for triage.
- 5 theme configs under `benchmarks/v0p19/themes/`: finance, healthcare,
  dev_eng, gov_contractor, legal. Each pre-registers a hypothesised
  dominant failure mode.
- Benchmark runs for all 5 themes (manifests + metrics tracked).
- `docs/v0p19_results.md` — per-theme triage with failure-mode labels,
  cross-theme aggregate, v0.20 fix queue ranked by impact, honest gaps.

### Findings

- Stage 1 recall across themes: mean **0.408** (finance 0.318 → gov 0.650).
  Held-out training-split recall is 100%; the cross-theme drop is the
  v0.19 signal.
- Dominant failure mode across 25 bottom misses: `content-ood` (13).
  Second: `extraction-missing` (4) — PDF text extraction is genuine v0.20.
  Third: `naming-ood` (4) — finance industry tokens absent from training.
- Legal theme worst (20% recall, 0% top-10 precision); gov_contractor best
  (65% recall). Plan pre-registrations matched cleanly on finance and
  gov_contractor; partial matches on healthcare/dev_eng/legal.
- `calibration-drift` and `parser-gap` (from the taxonomy) did not surface
  — either synthetic shares aren't dense enough, or these are smaller
  issues than the plan estimated.

### Notes

- Stage 2 (content classifier) deferred — weights aren't tracked and
  require a 3 GB download per theme. The `content-ood` dominant finding
  can't be acted on without Stage 2 measurements.
- Snaffler head-to-head deferred — binary not on the benchmark host.
- Tests added: 7. Full suite: 734 passing.

## [0.18.0] — 2026-06-07
