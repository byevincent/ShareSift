# v0.21 — reranker + extra rules + real-PDF validation

Drafted 2026-06-08 from v0.20's results in `docs/v0p20_results.md`.
v0.20 wired the dormant content infrastructure and lifted mean recall
+23 pp across the 5 themed shares, but left three concrete gaps:

1. **Legal top-10 precision regressed to 0.00.** The rule engine
   adds matches but the cascade's `max(path_prob, cascade_pseudo_p)`
   ranking isn't sophisticated enough to put the right files in the
   top 10. This is the v0.21 reranker's job.
2. **22 `extra_rules.py` rules** (v0.12 blind-spot + Gitleaks-derived
   modern SaaS) still don't load — they're tied to the optional
   pysnaffler dep, not the JSON format the rule engine consumes.
3. **PDF extraction unverified.** v0.19 themed shares use `.pdf`-
   extensioned text files; pypdf rejects them. Real PDFs would
   extract — but we don't have a metric.

## Phases

| Sprint | Scope | Deliverable |
|---|---|---|
| 1 | Port `extra_rules.py` to JSON | `src/sharesift/rules/extra_rules.json` + extend `ContentRuleEngine` loader |
| 2 | Regenerate v0.19 themed shares with real PDFs | `benchmarks/v0p19/<theme>/share/` updated; pypdf wins measurable |
| 3 | Build reranker + cascade-aware features | `src/sharesift/reranker_v0p21.py`, `tools/train_reranker_v0p21.py` |
| 4 | Wire reranker into v0.20 benchmark script | `tools/score_themed_run_v0p21.py` |
| 5 | Re-run all 5 themes; measure top-K precision delta | `benchmarks/v0p21/<theme>/metrics.json` × 5 |
| 6 | Docs + bundle + tag | `docs/v0p21_results.md` + `dist/sharesift-v0p21.zip` + `v0.21.0` |

## Reranker design

**Features per file** (cheap to compute from existing scan output):

| Feature | Source |
|---|---|
| `path_probability` | Stage 1 |
| `path_tier_rank` | 0/1/2/3 for None/Yellow/Red/Black |
| `cascade_tier_rank` | same encoding |
| `cascade_source` | categorical: parsers/rules/extractor/classifier/none |
| `n_rule_matches` | count from cascade verdict |
| `extension` | categorical, top 20 most common |
| `directory_depth` | path component count |

**Model**: LightGBM ranker (LambdaRank objective). Same family as the
existing path classifier, so the dep is already in `pyproject.toml`.

**Training data**: the v0.19 + v0.20 themed manifests. Each manifest
is `(local_path, salted)` ground truth. We have ~400 labeled
(path, salted) pairs across 5 themes. Leave-one-theme-out
cross-validation prevents overfitting to any single theme's
filename pool.

**Where it runs**: after the v0.20 cascade, the reranker produces a
`rerank_score` per file. The CLI / benchmark scripts sort by
`rerank_score` for top-K precision computation. The reranker doesn't
filter; it just orders.

## Out of scope for v0.21 (carryover)

- **Stage 1 path-classifier retrain** with v0.19 themed tokens. ~1
  GPU-hour; deferred because the wiring wins haven't been fully
  measured yet (v0.21 reranker tells us whether the precision gap
  is rankable or whether we still need recall on naming-ood).
- **Lightweight content classifier** for the cascade's smart middle
  tier. Real ML work; needs a labeled training corpus. v0.22.
- **`literal_vs_referenced` (v0p7) wiring** into the cascade. The
  class exists but its weights aren't tracked. Without weights the
  wiring would be no-op. v0.22.

## Risks

1. **Small-N training.** ~400 labeled files across 5 themes is enough
   for a LightGBM ranker but won't generalize to themes outside the
   training distribution. Mitigation: leave-one-theme-out CV so we
   measure cross-theme generalization, not just in-theme fit.
2. **Reranker can mask recall problems.** If the reranker pushes a
   true positive out of top-10 by mistake, it looks like a precision
   win but hides recall regression. Measure both before/after.
3. **`extra_rules.py` patterns may FP heavily.** GPP cpassword is
   safe; modern SaaS regexes (GitHub PAT, AWS keys) are well-tuned;
   but the v0.12 blind-spot rules were ported from blog posts, not
   audited at scale. Watch for legal/healthcare boilerplate FPs.

## Verification

```bash
# After Sprint 1:
uv run python -c "
from sharesift.content_rules import get_default_engine
e = get_default_engine()
print(f'rules loaded: {len(e)}')
"  # Expect: ~100 (78 base + 22 extra)

# After Sprint 5:
for theme in finance healthcare dev_eng gov_contractor legal; do
  uv run python tools/score_themed_run_v0p21.py --theme $theme
done
# Expect: top-10 precision >= v0.20 across the board; legal up
# from 0.00; recall maintained.
```

## Sprint 5 expected outcome

Per-theme delta vs. v0.20:

| Theme | v0.20 top-10 | v0.21 target |
|---|---|---|
| Finance | 0.30 | ≥ 0.40 |
| Healthcare | 0.50 | ≥ 0.50 (already high) |
| Dev / engineering | 0.30 | ≥ 0.50 |
| Gov / contractor | 0.40 | ≥ 0.40 |
| Legal | 0.00 | ≥ 0.30 (biggest improvement opportunity) |

If legal stays at 0.00 with the reranker, it tells us the ranking gap
isn't features-derivable from the cascade output — meaning v0.22
needs a content-classifier-level distinguisher, not a reranker.
