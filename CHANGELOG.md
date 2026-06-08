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

v0.19 — themed-benchmark iteration plan in
`docs/v0p19_themed_benchmark_plan.md`. Builds 5 themed synthetic
shares (finance, healthcare, dev/eng, gov/contractor, legal) one at a
time, using each to drive a specific code change in the next release.
