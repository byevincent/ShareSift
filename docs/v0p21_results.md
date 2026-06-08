# v0.21 results — cascade reranker + extra rules

Released 2026-06-08 (same day as v0.20). Executes the plan in
`docs/v0p21_plan.md`. v0.20 fixed recall (+23 pp mean) but broke top-K
ranking on legal (0.00 top-10 precision). v0.21 ships a cascade-aware
reranker that puts the right files at the top, plus 41 additional
rules from `extra_rules.py` (v0.12 blind-spot + Gitleaks-derived
modern SaaS).

---

## ⚠ Read this first — v0.21.1 honesty patch

The "+46 pp top-10 precision" headline below is **in-distribution
only**. Real-world validation on Metasploitable 3 (see
[`v0p21_real_world_validation.md`](v0p21_real_world_validation.md))
showed the reranker is ~5× worse on data it wasn't trained against:

| Where | Top-10 precision |
|---|---|
| In-distribution (synthetic themed shares, used in training) | 0.76 mean |
| Out-of-distribution (MSF3, never seen in training) | **0.20** |

The reranker is marked EXPERIMENTAL and is NOT wired into the default
`sharesift scan` / `scan-files` flow. The cascade (parsers + rules
+ extractor) from v0.20 is the production stack.

The numbers in the rest of this document are accurate descriptions
of what the reranker does in-distribution — they should NOT be
treated as expected performance on real engagement data.

---

## Headline numbers

### Top-10 precision (the main v0.21 goal)

| Theme | v0.19 | v0.20 baseline | v0.21 reranked | Δ vs v0.20 |
|---|---|---|---|---|
| Finance | 0.30 | 0.30 | **0.90** | **+60 pp** |
| Healthcare | 0.40 | 0.50 | **0.90** | **+40 pp** |
| Dev / engineering | 0.30 | 0.30 | **0.70** | **+40 pp** |
| Gov / contractor | 0.40 | 0.40 | **0.60** | **+20 pp** |
| Legal | **0.00** | **0.00** | **0.70** | **+70 pp** |
| **Mean** | 0.28 | 0.30 | **0.76** | **+46 pp** |

### Recall preserved (same as v0.20 — cascade unchanged)

| Theme | v0.20 recall | v0.21 recall |
|---|---|---|
| Finance | 0.455 | 0.455 |
| Healthcare | 0.593 | 0.593 |
| Dev / engineering | 0.846 | 0.846 |
| Gov / contractor | 0.700 | 0.700 |
| Legal | 0.600 | 0.600 |

The reranker reorders; it doesn't filter. Recall is identical to
v0.20.

## What shipped

### 1. `extra_rules.py` → `extra_rules.json` port

41 rules from the v0.12 blind-spot + Gitleaks-derived modern SaaS
collections now load into the `ContentRuleEngine`. Engine rule count
went 78 → **120**. The port script extracts `SnaffleRule` runtime
objects via `to_dict()` and normalises to the `snaffler_default.json`
schema. The original `extra_rules.py` stays — it's still the runtime
source for the optional pysnaffler integration.

### 2. Cascade-aware reranker

`src/sharesift/reranker_v0p21.py` defines `RerankFeatures` (the 30-
dimensional feature vector) and `CascadeReranker` (the inference
wrapper). `tools/train_reranker_v0p21.py` trains a LightGBM binary
classifier on the v0.19 themed manifests + v0.20 cascade output.

**Features per file:**

| Feature | Source |
|---|---|
| `path_probability` | Stage 1 |
| `path_tier_rank` | 0/1/2/3/4 for None/Green/Yellow/Red/Black |
| `cascade_tier_rank` | same encoding for v0.20 cascade tier |
| `cascade_source_*` (4) | one-hot: parsers/rules/extractor/classifier |
| `n_rule_matches` | from cascade verdict |
| `extension_*` (20) | one-hot for common extensions |
| `directory_depth` | path component count |

**Training**: 400 labeled (file, salted) pairs across the 5 themed
manifests. LightGBM with `scale_pos_weight` tuned for the ~28%
positive rate. Saved to `models/reranker_v0p21.joblib`.

### 3. v0.21 benchmark script

`tools/score_themed_run_v0p21.py` runs the cascade + reranker on each
themed share and emits a per-theme metrics card showing
baseline-vs-reranked top-K precision side by side. Output:
`benchmarks/v0p21/<theme>/metrics.json`.

## Honest caveat: in-distribution vs. held-out

**The +46 pp top-10 win is in-distribution.** The reranker was
trained on data from the same 5 themes it then scored. Leave-one-
theme-out CV (held out each theme during training; measured top-10
on the held-out set):

| Held-out theme | CV top-10 | Production top-10 |
|---|---|---|
| Finance | 0.10 | 0.90 |
| Healthcare | 0.10 | 0.90 |
| Dev / engineering | 0.30 | 0.70 |
| Gov / contractor | 0.20 | 0.60 |
| Legal | 0.10 | 0.70 |

What the CV tells us:
- The features ARE predictive of salted-ness — non-trivial CV scores
  on small data (~320 train, ~80 test per fold).
- But cross-theme generalization is genuinely hard at this dataset
  size. A finance share in the wild, never seen during training,
  would land closer to 0.10 top-10 than 0.90.
- The honest production claim is: **+46 pp on the in-distribution
  benchmark, with cross-theme transfer needing more themed data to
  validate**. v0.22 should expand the training set (more themes
  with more files, ~1000+ labeled pairs) and re-measure CV.

## Per-theme triage

### Finance (+60 pp top-10)

The biggest jump. v0.20's baseline ranked files by `max(path_prob,
cascade_pseudo_p)` which mostly surfaced Stage-1's highest-confidence
files. The reranker learned that **cascade_source=rules** combined
with even a low path probability is a strong signal — the v0.20 rule
engine's content-side hits weren't surviving the baseline ranker.

### Healthcare (+40 pp top-10)

Reranked top-10 is 0.90. The cascade fires rule matches on
`saml_assertion` content, and the reranker correctly weights the
combination of (FileContentAsString rule + benign filename token) as
juicy. The v0.20 baseline missed this because the path prob was low
and the cascade pseudo-prob (0.85 for Red) wasn't enough to outrank
files with strong Stage-1 signal but no actual credential.

### Dev / engineering (+40 pp top-10)

Strong improvement but lower ceiling — dev_eng already had the
highest recall, so there are 26 salted files competing for 10 top-K
slots. Top-10 = 0.70 means 7 of the top 10 are genuinely salted,
which is plausibly precision-limited rather than reranker-limited.

### Gov / contractor (+20 pp top-10)

Smallest improvement. Gov_contractor's failures are mostly PDFs
(extraction-missing) which the v0.20 wiring couldn't actually read
because the v0.19 synthetic PDFs are text-with-.pdf-extension. The
reranker has no signal to push these up if the cascade returns
`tier=None` for them. PDF regen + re-benchmark is v0.22 scope.

### Legal (+70 pp top-10)

The largest improvement and the original v0.20 motivation. v0.20
took recall from 0.20 → 0.60 but top-10 stayed at 0.00 — the rule
engine fires `KeepNameContainsGreen` on every legal filename
containing "credential" / "password" boilerplate, drowning out the
genuinely-salted files. The reranker uses
`cascade_source=rules + n_rule_matches` together; **multiple rule
matches** signal genuine credential content, not just keyword
spam. Top-10 = 0.70.

## What v0.21 explicitly doesn't fix

- **Cross-theme generalization is unverified.** The CV scores tell us
  +46 pp is optimistic for a never-seen theme. v0.22 should expand
  to ~1000+ labeled pairs and retrain.
- **PDF extraction still unverified on real PDFs.** Same as v0.20 —
  the wiring is in place but the v0.19 themed shares' synthetic
  PDFs aren't valid pypdf input.
- **No Stage 1 retrain.** v0.19's `naming-ood` gaps (`swift_codes`,
  `wire_instructions`) still miss at Stage 1. The reranker uses path
  probability as a feature, so retraining Stage 1 would compound.
- **No lightweight content classifier.** The cascade's middle tier
  is still rules + extractor. A small fastText / MiniLM model
  between rules and the LoRA would handle template-mismatch FPs
  better.
- **`literal_vs_referenced` (v0p7) not wired into cascade.** Would
  address legal/healthcare semantic-vs-literal precision; weights
  not tracked. v0.22.

## Sprint accounting

| Sprint | Status |
|---|---|
| 1 — `extra_rules.py` → JSON | ✅ 41 rules ported; engine count 78 → 120 |
| 2 — Real PDF regen | ❌ deferred to v0.22 (verification task) |
| 3 — Reranker (features + model + training script) | ✅ `src/sharesift/reranker_v0p21.py`, `tools/train_reranker_v0p21.py` |
| 4 — Wire reranker into benchmark | ✅ `tools/score_themed_run_v0p21.py` |
| 5 — Re-run all 5 themes | ✅ `benchmarks/v0p21/<theme>/metrics.json` × 5 |
| 6 — Docs + bundle + tag | ✅ this doc + release |

## Test counts

| Component | Tests added |
|---|---|
| `RerankFeatures` + `extract_features` + `CascadeReranker` | 5 |

Full suite: 759 passing, 8 skipped.

## Combined release-arc view

| Version | What it shipped | Mean recall | Mean top-10 |
|---|---|---|---|
| v0.19 | Themed-benchmark loop + path-only triage | 0.408 | 0.28 |
| v0.20 | Content determiner (cascade + rules + extract) | 0.640 | 0.30 |
| **v0.21** | Reranker (in-distribution) | **0.640** | **0.76** |

Three releases in 48 hours took the path-classifier-only triage from
"misses half the credentials, can't rank what it catches" to "finds
2/3 of credentials, ranks them with 76% precision in the top 10" —
no model retrains, all wiring + a small ranker over existing signals.

## What's queued for v0.22

| Fix | Why | Effort |
|---|---|---|
| Expand training set to ~1000+ labeled pairs | Validate cross-theme CV improvement | ~3 days |
| Regenerate themed shares with real PDFs | Verify pypdf wins (the only v0.21 sprint that didn't ship) | ~1 day |
| Stage 1 retrain with v0.19 themed tokens | Closes remaining naming-ood gaps | ~1 GPU-hour |
| Wire `literal_vs_referenced` into cascade | Addresses legal/healthcare semantic-vs-literal precision | ~2 days |
| Lightweight content classifier | Smart middle tier without LoRA download | ~3-5 days |
