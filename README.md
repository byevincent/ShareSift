# ShareSift

[![tests](https://github.com/byevincent/ShareSift/actions/workflows/test.yml/badge.svg)](https://github.com/byevincent/ShareSift/actions/workflows/test.yml)
[![python](https://img.shields.io/badge/python-3.10--3.12-blue)](pyproject.toml)
[![license](https://img.shields.io/badge/license-Apache--2.0-green)](LICENSE)

ML augmented SMB share hunter. Snaffler successor with a two stage classifier pipeline.

ShareSift ranks files on SMB shares by likelihood of containing credentials or secrets. Stage 1 runs a LightGBM path classifier on every path. Stage 2 runs a Qwen3 1.7B LoRA content classifier on the flagged files to confirm. Run Stage 1 alone or both stages together.

## Why it exists

Snaffler catches the obvious patterns like `id_rsa`, `NTDS.dit`, and `.kdbx`. It misses the long tail. Custom scripts on shares, secrets in unusual filenames, and password directories with unconventional names all slip through.

ShareSift adds an ML layer on top. The path classifier beats Snaffler on recall by 29.3 percentage points on the Snaffler blind benchmark. The content classifier closes most of the gap to Biringa and Kul 2025 at one quarter the parameter count.

## Performance

Classifier-level on held-out splits:

| Metric | ShareSift | Baseline |
|---|---|---|
| Windows path classifier PR AUC, Snaffler blind benchmark | 0.985 | Snaffler has no ML |
| Linux path classifier PR AUC, Linux rule blind benchmark | 0.99 | Rule pack F1 0.45 |
| Linux F1 vs hand curated rule pack | +52 pp | Rule pack F1 0.45 |
| Content classifier F1 on docx benchmark (v0p6) | 0.776 | v0p5 0.385 |
| Content classifier precision on docx benchmark | 0.974 | 2.6% false positive rate |
| End to end F1 on constructed share benchmark | 0.387 | v0p5 0.166 |

Head-to-head against Snaffler on benchmark shares (re-run on v0.42, 2026-06-09):

| Share | Metric | ShareSift v0.42 | Snaffler |
|---|---|---|---|
| Metasploitable 3 (Windows AD, 40 credentials) | Recall | **100% (40/40)** | 97.5% (39/40) |
| Metasploitable 2 (Linux server, 34 credentials) | Recall | **97.1% (33/34)** | 44.1% (15/34) |
| DiskForge (Windows forensic, 13 plants) | Recall | 92.3% (12/13) | 92.3% (12/13) |
| GOAD (Linux AD, 18 credentials) — v0.15 numbers | Recall | 100% (18/18) | 55.6% (10/18) |

ShareSift catches everything Snaffler catches plus 19 additional credentials across the three re-tested benchmarks. Snaffler catches nothing ShareSift misses. **Linux recall lead: +53 percentage points** (0.971 vs 0.441 on MSF2).

See [docs/snaffler_benchmark_2026-06.md](docs/snaffler_benchmark_2026-06.md) for the full v0.42 head-to-head with per-rule attribution, methodology, speed benchmarks, and honest caveats about what the comparison doesn't measure (top-K ranking, content classifier value, live verification value).

## Install

**Quick install** — drop a binary on Kali (no `git clone`, no `uv` setup, no Python required):

```bash
# Truly single-file binary — Stage 1 path classifier + rules + tier engine
# + Snaffler-TSV + engagement DB + sort + query + export. ~77 MB, zero
# Python prereq. Available from v0.46 onward.
wget https://github.com/byevincent/ShareSift/releases/latest/download/sharesift
chmod +x sharesift
./sharesift --version
```

Or via pipx (needs Python 3.10+):

```bash
pipx install 'sharesift[smb]'      # SMB-direct workflow
pipx install sharesift             # Stage 1 only
```

**Full install from source** — if you want to develop, train, or run the content classifier:

```bash
# Latest milestone release (recommended)
git clone --branch v0.48.0 https://github.com/byevincent/ShareSift.git
# Or track main for unreleased work
git clone https://github.com/byevincent/ShareSift.git

cd ShareSift

# Stage 1 only (path classifier, ~100MB)
uv sync

# Both stages (adds ~3GB of torch and transformers)
uv sync --group content-inference

# SMB-direct support (no mount required) — adds smbprotocol + pyspnego
uv sync --extra smb
```

Add `--group content-training` for LoRA fine-tuning. That pulls another 5GB.

Milestone releases: [v0.48.0](https://github.com/byevincent/ShareSift/releases/tag/v0.48.0) (current — held-out v1 36→91%, v2 70%), [v0.47.0](https://github.com/byevincent/ShareSift/releases/tag/v0.47.0) (Snaffler-issues benchmark + MSF2 recall 1.000), [v0.46.0](https://github.com/byevincent/ShareSift/releases/tag/v0.46.0) (77MB single-file binary + DB exporters), [v0.45.0](https://github.com/byevincent/ShareSift/releases/tag/v0.45.0) (top-K precision 0.20 → 0.70), [v0.43.0](https://github.com/byevincent/ShareSift/releases/tag/v0.43.0) (Linux rule gap closure), [v0.41.0](https://github.com/byevincent/ShareSift/releases/tag/v0.41.0) (engagement datastore). Intermediate tags are shown as pre-releases on the [releases page](https://github.com/byevincent/ShareSift/releases).

## Quick start

### Remote SMB share (no mount required, v0.35+)

Point ShareSift at a UNC + credentials and it walks the share over SMB2/3 directly. Auth flags match netexec conventions (`-u/-p/-H/-k/-d`).

```bash
# Password auth
uv run sharesift //10.10.10.5/Finance$ -u user -p pass

# Pass-the-hash (NT hash or LM:NT)
uv run sharesift //10.10.10.5/Finance$ -u CORP/user -H 'aad3b435b51404eeaad3b435b51404ee:27c4...'

# Kerberos (reads ticket from KRB5CCNAME)
uv run sharesift //dc01.corp.local/SYSVOL$ -u alice -k --use-kcache

# Anonymous / null session
uv run sharesift //10.10.10.5/Public --no-pass

# Pre-flight: confirm creds work before committing to a long walk
uv run sharesift //10.10.10.5/Finance$ -u user -p pass --check
```

Output lands in `./sharesift-<host>-<share>/` by default (override with `--output-dir`). The full one-shot pipeline runs (enumerate → triage → content scan → verify → HTML report) using the live SMB session for content reads — no local mount required.

### Local / mounted share

```bash
uv run sharesift /mnt/downloaded_share

# Or to skip live verification + the report and just get triaged hits:
uv run sharesift /mnt/downloaded_share \
    --skip-verify --skip-report

# Explicit subcommand form (legacy v0.18 flag set, still supported):
uv run sharesift scan --share /mnt/downloaded_share --output-dir ./scan-out
```

Intermediates land in `--output-dir`:

```
scan-out/
├── files.txt       # enumerated paths
├── paths.jsonl     # stage 1 scores
├── hits.jsonl      # stage 1+2 results
├── verified.jsonl  # live credential checks
└── report.html     # interactive HTML report
```

Add `--json` for a structured end-of-run summary on stderr (useful for CI). Add `-q` / `--quiet` to silence progress or `-v` / `--verbose` for debug detail.

The individual subcommands below let you run each stage on its own when you need finer control.

### Score paths from share enumeration

Pipe output from your enumeration tool directly into ShareSift.

```bash
manspider --target \\fileserver -d corp.local | \
    uv run sharesift score-paths --stdin

# Or from a file
uv run sharesift score-paths \
    --input enumerated_paths.txt \
    --output scored.jsonl
```

Output is JSONL with path, probability, and tier (Black, Red, Yellow, or null).

```json
{"path": "\\\\fileserver\\Finance\\backups\\creds.kdbx", "probability": 0.987, "tier": "Black"}
{"path": "\\\\fileserver\\Dev\\notes.txt", "probability": 0.523, "tier": "Yellow"}
{"path": "\\\\fileserver\\Marketing\\Q4.pdf", "probability": 0.012, "tier": null}
```

Work through Black first, then Red, then Yellow. Use `jq` to sort and filter.

### Scan files with both stages

```bash
find ./downloaded_share -type f | \
    uv run sharesift scan-files --stdin \
        --output deep_scan.jsonl
```

Stage 2 adds `content_check` and `content_excerpt` to each record.

```json
{"path": "./downloaded_share/Dev/notes.txt", "path_probability": 0.52, "path_tier": "Yellow", "content_check": "yes", "content_excerpt": "API_KEY = 'sk_live_...'"}
```

Stage 2 runs only on tier flagged paths. Override with `--force-content`. On CPU this takes 5 to 8 seconds per file. On CUDA it runs in about 150ms.

## Architecture

Two stage pipeline. Each stage runs independently.

```
                ┌─────────────────────────────────────────┐
                │ Stage 1 router (by path shape)          │
                │                                         │
                │   UNC path  → Windows model             │
   path list  → │   Unix path → Linux model               │ → (probability, tier)
                │                                         │
                │   LightGBM + char n-grams +             │
                │   8 hand features, calibrated           │
                │   probability, per-model tier band      │
                └─────────────────────────────────────────┘
                              │
                  (tier flagged subset)
                              ↓
                ┌──────────────────────────┐
                │ Stage 2: Qwen3-1.7B LoRA │ → (yes / no on secret presence)
                │ via transformers + PEFT  │
                │ 4-bit base on CUDA       │
                │ bf16 on CPU              │
                └──────────────────────────┘
```

Stage 1 trains on 11,190 Windows and 1,685 Linux records. It scores each path in under one millisecond. Stage 2 is 1.5 to 3.4GB depending on your hardware.

Full design in [docs/architecture.md](docs/architecture.md) and [docs/build_plan.md](docs/build_plan.md).

## pysnaffler integration

`ShareSiftPathRule` is a `SnaffleRule` subclass that plugs the path classifier into pysnaffler's SMB enumeration loop.

```bash
uv sync --group pysnaffler-integration
```

```python
from sharesift.pysnaffler_run import build_ruleset
from pysnaffler.snaffler import pySnaffler

# ML only: ShareSift replaces Snaffler's rule pack
ruleset = build_ruleset()

# Hybrid: Snaffler defaults plus ShareSift
ruleset = build_ruleset(include_defaults=True)

snaffler = pySnaffler(ruleset=ruleset, dry_run=True)
```

## Limitations

No validation against real engagement findings. ShareSift labels come from a Claude rule and Codex audit pipeline on public corpus data. That is useful signal, but it is a different class from internal engagement grade ground truth.

Calibration holds in distribution. The tier band precision contracts are reliable on data from the same source as training. On out of distribution data the Windows model ECE rises from 0.007 to 0.30. Treat tier assignments as triage ordering, not probability contracts, when scanning real SMB shares.

Cross source generalization is weaker than the headline numbers suggest. Windows PR AUC drops from 0.97 to 0.76 when you train on Stack Exchange and test on GitHub Code Search. Real SMB shares are a third distribution that neither training nor evaluation covers.

The content classifier sits 13 F1 points below Biringa and Kul 2025. The gap comes from model size. Mistral 7B is four times larger than Qwen3 1.7B, and ShareSift targets an RTX 4070 deployment.

Rare credential categories are undertrained. Private keys, SSH credentials, cloud credentials, and IAC each have three or fewer training records. Recall on those classes is weak.

CPUs without AVX 512 are slow. Benchmarked at 5 to 8 seconds per file on a Ryzen 5 3600.

See [docs/audit_2026-05-31.md](docs/audit_2026-05-31.md) and [docs/audit_2026-05-30.md](docs/audit_2026-05-30.md) for the full audit history.

## Project layout

```
src/sharesift/         runtime package
    path.py            PathClassifier router (Windows and Linux models)
    content.py         content classifier wrapper
    tier.py            probability to tier band
    features.py        char n-gram and hand features
    prompt.py          content classifier chat template formatter
    pysnaffler_rule.py SnaffleRule plugin
    pysnaffler_run.py  build_ruleset() helper
    cli.py             score-paths and scan-files entry point
src/eval/              training and evaluation scripts
tools/                 training, dataset builders, audit tools
docs/                  engineering log and architecture docs
models/                trained model weights
```

## License

Apache 2.0. See [NOTICE](NOTICE) for GPLv3 components (vendored Snaffler ruleset and pysnaffler).

## Contributing

This is an active solo build. Track major design decisions in [docs/build_plan.md](docs/build_plan.md) and [docs/journal.md](docs/journal.md). Open an issue before sending a PR.
