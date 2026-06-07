# Changelog

All notable changes to ShareSift are listed here. Format loosely follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow
[Semantic Versioning](https://semver.org/).

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

The full v0.18 ergonomics work (Phases B–F): top-level `--quiet`/`--verbose`,
progress bars, `--json` summaries, the one-shot `sharesift scan` subcommand,
and updated docs.
