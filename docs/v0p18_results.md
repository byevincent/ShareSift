# v0.18 results — CLI ergonomics

Released 2026-06-07.

v0.17.1 shipped Phase A (`--version` + warning suppression) on the
same day the rename to ShareSift landed. v0.18.0 closes the rest of
the plan in `~/.claude/plans/keen-stargazing-hollerith.md` — top-level
verbosity controls, progress bars, structured `--json` summaries, and
the one-shot `sharesift scan` subcommand that makes the whole pipeline
a single command.

## What changed, by phase

### Phase A — already in v0.17.1

- `sharesift --version` reports the package version.
- 3rd-party warning filters for `transformers`, `peft`, `urllib3`,
  `bitsandbytes`.

### Phase B — verbosity controls

- New `src/sharesift/_output.py` — 60-line `Verbosity` enum +
  `Output` class with a module-level singleton. The CLI configures the
  singleton once after parsing top-level `-q`/`-v`; every emitter
  (cli.py, verify/runner.py, pipeline.py) respects the same level.
- `-q` / `--quiet` silences info and progress; warnings (incl. the
  verify safety banner) and errors still print.
- `-v` / `--verbose` adds debug lines (model dirs, batch sizes, rate
  limits, device, target file) and bypasses the 3rd-party warning
  filter so debugging operators see the underlying chatter.
- The two are mutually-exclusive — argparse rejects `-q -v`.
- Phase A's warning filter also picked up `UserWarning` and `sklearn`
  (the LGBMClassifier feature-name nag was leaking under `--quiet`).

### Phase C — progress bars

- `Output.progress(iterable, desc, total)` wraps with `tqdm` and
  gates by verbosity. QUIET returns the iterable as-is (no tqdm
  import); NORMAL uses tqdm's TTY auto-detect; VERBOSE always renders,
  even non-TTY.
- Applied to `Scanner.scan_batch` (the model-heavy stage-2 inference
  loop) and `verify_records`. The hand-rolled every-25-records
  checkpoint in `verify/runner.py` is gone.
- `tqdm>=4.66` is now a direct dep (it was transitively available via
  transformers, but verify-only installs missed it).

### Phase D — `--json` end-of-run summary

- Top-level `--json` flag, independent of `-q`/`-v`.
- `Output.summary(payload)` emits a single JSON object on stderr at
  end-of-run when the flag is on.
- Common envelope: `command`, `version`, `elapsed_s`,
  `input_count`/`output_count`, `exit_code`.
- Per-subcommand fields:
  - `score-paths`: `tier_flagged`, `output_path`
  - `scan-files`: `content_{yes,no,skipped}`, `model.{content_model_dir,device}`, `output_path`
  - `verify`: `by_status`, `dry_run`, `output_path`
  - `render-report`: `output_path`, `output_size_kb`, `title`
  - `scan` (one-shot): `share`, `output_dir`, `stages_run`, `intermediates.{files,paths,hits,verified,report}`
- `--quiet --json` emits ONLY the summary block (no info / progress
  lines) — useful for CI.

### Phase E — one-shot `sharesift scan`

- New `sharesift scan --share <dir> --output-dir <dir>` subcommand.
- Wraps enumerate → score-paths → scan-files → verify → render-report
  into a single call. Each stage prints `[N/5] ...` banner.
- `--skip-verify` and `--skip-report` drop the late stages.
- The sub-handlers each have their own `--json` summary; the scan
  command silences those during sub-calls and emits one combined
  summary at the end.
- Demo bundle and tests' Quick Start now lead with `sharesift scan`;
  the manual stage chain is positioned as the "finer control"
  alternative.

### Phase F — ship

- Version bumped 0.17.1 → 0.18.0.
- README's Quick Start leads with `sharesift scan` + `--output-dir`
  semantics.
- This file (`docs/v0p18_results.md`).
- `dist/sharesift-v0p18.zip` source-only release bundle.
- Tag `v0.18.0`, GitHub release.

## Before / after

Pre-v0.18, the demo bundle ran ~35 lines of bash:

```bash
find share -type f > file_list.txt
uv run sharesift scan-files --input file_list.txt --output hits.jsonl
uv run sharesift verify --input hits.jsonl --output verified.jsonl \
    --target-file targets.yaml --no-banner
uv run sharesift render-report --input verified.jsonl --output report.html
# ... + ~25 lines of error handling, output dir management, etc.
```

Post-v0.18:

```bash
uv run sharesift scan --share ./share --output-dir ./out
```

## Honest gaps

- The two `--quiet`/`--verbose` CLI integration tests
  (`test_cli_quiet_silences_stderr`, `test_cli_verbose_emits_debug`)
  skip without `models/path_classifier_v0/calibrated.joblib`, which
  isn't in the public repo. The functionality is covered by the
  Output-class unit tests; the CLI integration tests run when the
  artifact is present.
- The `_ns(**kwargs)` helper that `cmd_scan` uses to construct
  argparse.Namespace objects for sub-handlers is brittle if any
  cmd_* grows new required fields. Acceptable for v0.18 scope; future
  Sprint should refactor into the `_run_*` helpers in the original plan.
- No CI test of the one-shot `scan` end-to-end with real models —
  CI's test workflow gates on the same `models/path_classifier_v0/`
  artifact. The orchestration test with fakes confirms the stage
  sequence and intermediate file shape.

## What's next

v0.19 — themed-benchmark iteration loop in
`docs/v0p19_themed_benchmark_plan.md`. v0.18 ergonomics (the `--json`
summary + one-shot `scan`) are what makes per-theme runs cheap to
execute.

## Test counts

| Phase | Tests added | Tests passing |
|---|---|---|
| A (v0.17.1) | 2 | 710 |
| B | 9 (7 in test_output, 3 in test_runtime, -1 dropped) | 718 |
| C | 3 | 721 |
| D | 3 | 724 |
| E | 3 | 727 |
| **Total** | **20** | **727 passing, 8 skipped** |
