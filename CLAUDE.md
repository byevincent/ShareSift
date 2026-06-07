# ShareSift

## Project goal

ShareSift is an ML-augmented successor to Snaffler: a tool for hunting interesting
files on SMB shares during authorized red-team and internal security engagements.
The aim is to move beyond Snaffler's hand-curated regex rules toward a learned
classifier that ranks paths and file contents by likelihood of containing
credentials, secrets, or otherwise sensitive material — trained on synthetic data
generated with Qwen3 and validated against a held-out evaluation set drawn from
real engagement notes. Expected build horizon is 6–10 weeks.

## Hard rules

These are non-negotiable. Read them before every response.

1. **Do not write source code until I approve a plan.** When I describe a feature
   or task, respond with a plan (approach, files to touch, open questions) and
   wait for explicit approval before editing or creating source files. Scaffolding,
   configs, and docs that I explicitly ask for are exempt.
2. **Do not generate more than one source file per response without checking in.**
   After creating or substantively editing one file, stop and confirm before
   moving on. This keeps review tractable.
3. **Ask before installing dependencies.** No `uv add`, `pip install`, or
   modifications to `pyproject.toml` dependency lists without my approval. Name
   the package, justify it, and wait.

## Tech stack

- **Language**: Python 3.11
- **Env / packaging**: `uv`
- **Lint / format**: `ruff`
- **Tests**: `pytest`

## Conventions

This project follows the same working conventions as my `qwen_cyber` project —
defer to those patterns for anything not specified here.

## Layout

- `references/` — cloned reference repos (Snaffler, etc.), gitignored
- `data/eval/` — held-out evaluation set, version controlled
- `data/synthetic/` — generated training data, gitignored
- `data/engagement/` — hand-labeled paths from my own notes, version controlled
- `src/generator/` — synthetic data generation with Qwen3
- `src/classifier/` — model training and inference
- `src/eval/` — evaluation harness
- `docs/` — decision logs, taxonomy, journal
- `notebooks/` — exploration, gitignored
