# v0.22 — versatility-first

Drafted 2026-06-08 after the v0.21 MSF3 validation showed the
synthetic-trained reranker doesn't transfer to real data
(`docs/v0p21_real_world_validation.md`).

## Why this plan exists

The v0.19 → v0.21 arc has a methodology problem. Every benchmark
informed the implementation, and every model saw test-distribution-
like data:

- v0.19 themed shares were built by me with my assumptions about
  what industry shares look like
- v0.20 cascade tuned against those themed shares
- v0.21 reranker trained on those same themed shares' labels
- v0.21 headline (top-10 +46 pp) was in-distribution
- v0.21 MSF3 reality (top-10 0.20) is what happens at first contact
  with data outside that distribution

The "fix" I proposed in the validation doc — retrain on MSF3 + GOAD
+ themed combined — **doesn't actually solve overfitting**. It just
shifts the target. Whatever's in training becomes in-distribution;
everything else becomes the next surprise.

This plan is the rethink: stop chasing benchmark numbers, invest in
components that don't admit overfitting, and adopt evaluation
discipline that makes future overfit claims impossible.

## Principles

In priority order — ranked by robustness to distribution shift:

1. **Rules and parsers over ML.** Snaffler-style rules and format-
   aware parsers don't overfit because they aren't learned. They
   have ceilings instead. v0.20's cascade was right; the rule
   engine should be the workhorse, not a feature for a downstream
   model to tune around.

2. **Strong inductive biases > learned features.** Credential
   format regexes (`ghp_` + 36 chars = GitHub PAT) are versatile by
   construction. ML features like `cascade_source=rules` are not —
   their predictive power depends on the training distribution.

3. **ML only where rules can't reach, with rigorous held-out eval.**
   Path classifier is reasonable because it trains on broad public
   corpora. The Stage 2 LoRA classifier needs honest cross-
   distribution evaluation — its training data is docx-corpus +
   Kingfisher salts, a specific distribution.

4. **Never train and test on the same data ever again.** This is the
   bright line v0.21 crossed. From now on: every reported number
   comes from a held-out set the model has not seen at training
   time, full stop.

5. **Multiple independent test sets; report the worst.** If MSF3 =
   0.20 and GOAD = 0.50 and CredData = 0.40, the honest claim is
   "ShareSift maintains ≥ 0.20" — not the mean.

6. **Calibrated confidence with abstention.** A tool that says
   "I don't know" when uncertain is more versatile than one that
   confidently mis-classifies. The cascade has `source` + `tier`
   already; surface that to the operator instead of collapsing to
   one score.

## Phases

### Phase A — Stop the bleeding (v0.21.1, this release)

| Move | Done? |
|---|---|
| Add EXPERIMENTAL warning to top of `reranker_v0p21.py` | ✅ |
| Cross-distribution caveat at top of `v0p21_results.md` | ✅ |
| `docs/v0p22_versatility_plan.md` (this doc) | ✅ |
| v0.21.1 tag + GitHub release with honesty notes | (in this commit) |

### Phase B — Evaluation discipline (v0.22.0)

| Component | New file |
|---|---|
| **Frozen held-out test sets**: MSF3 (1054 paths, has labels), GOAD (when accessible), CredData (1500 records, content-side) — never trained against, measured once per release | `benchmarks/v0p22_eval/` |
| **`tools/eval_harness.py`** — runs the full detection pipeline against all 3 held-out sets, emits per-set metrics + the MIN as the headline | `tools/eval_harness.py` |
| **CI gate** — fails the build if MIN precision or MIN recall drops below the previous release's MIN | `.github/workflows/eval_gate.yml` |
| **Reranker excluded from default** | Already not wired into production; explicit doc + flag stays |

### Phase C — Fix the rule engine over-fire (v0.22)

The MSF3 root cause is `KeepNameContainsGreen` firing on ~95% of
PowerShell + .NET files (every comment mentioning passw/secret/
credential). Fixes:

| Fix | Mechanism |
|---|---|
| Require multi-match for Green-tier name rules | A single occurrence of "passw" in a 10KB script is noise; 3+ occurrences is signal |
| Length / context window check | Match must occur outside a 2KB comment block to count |
| Audit the other broad-firing rules | Run the eval harness, identify which rules fire on >50% of MSF3, gate or down-tier each |
| Tier-down Green to "informational" | Green is not a credential signal; it shouldn't contribute to the Black/Red/Yellow ranking |

### Phase D — Versatile component investments (v0.22)

| Component | Why |
|---|---|
| **More parsers**: PDF body extraction (real PDFs), OOXML traversal (docx/xlsx as ZIP+XML), registry hive parsing, PuTTY .ppk files | Parsers are architecturally versatile — no training step, no overfitting risk |
| **More credential-format extractors**: Stripe keys, Plaid client IDs, GCP service-account JSON, Azure connection strings | Strong inductive biases; works the same on every engagement |
| **Expose cascade `source` + `tier` + `n_matches` in the operator UI** | Calibrated confidence beats false confidence; operator can triage by source |

### Phase E — Stage 2 cross-distribution honesty (v0.22 or v0.23)

The v0p6 content classifier (docx_salted) hasn't been evaluated
cross-distribution rigorously. v0.22 should:

| Step | Output |
|---|---|
| Evaluate v0p6 on CredData (source-code distribution) | Honest F1 number with the distribution mismatch declared upfront |
| Evaluate v0p6 on MSF3 content (when scraped) | Honest number |
| Decide: is v0p6 worth keeping as Stage 2, or does a regex-and-extractors-only Stage 2 work better? | If LoRA doesn't beat regex by enough on held-out data, simplify. |

## What's out of scope for v0.22

- **More themed synthetic shares.** Building more of the same kind
  of benchmark doesn't address overfitting. Don't add to
  `benchmarks/v0p19/themes/` — instead, accept those as a tuning
  set and never report on them.
- **Reranker retrain on real data.** Same methodology problem. The
  reranker stays experimental until evaluation discipline is in
  place and we can train on one set and report on a frozen held-
  out set.
- **Stage 1 path classifier retrain with industry tokens.** Same
  reason — adding finance tokens to training overfits to the
  finance theme. The honest path is more diverse training data
  AND a frozen eval set.

## Verification

After Phase B-D land:

```bash
# Eval harness runs all held-out sets and emits per-set + MIN metrics.
uv run python tools/eval_harness.py
# Expect: per-set recall + top-10 precision for MSF3, GOAD,
# CredData. The MIN top-10 across sets is the headline number.
```

The MIN being honest is the v0.22 success criterion — not "we got
0.76 on a synthetic benchmark."

## Sprint accounting

| Sprint | Scope | Estimate |
|---|---|---|
| A | v0.21.1 honesty patch (this commit) | done |
| B | Frozen held-out test sets + `eval_harness.py` + CI gate | ~2 days |
| C | Rule engine over-fire fix (`KeepNameContainsGreen` + audit) | ~2 days |
| D | New parsers (real PDFs, OOXML, registry) + new extractors | ~3-5 days |
| E | Stage 2 cross-distribution eval + simplification decision | ~2 days |

Total v0.22: ~2 weeks if no slippage.

## Honest meta

This plan is itself something to be careful with. "Versatility-first"
is the right framing today, but if v0.22 ships and the MIN held-out
top-10 is still 0.20, we'll be tempted to fix it. The discipline is:
**fix the failure mode, not the number**. If MSF3 top-10 is 0.20 and
the failure mode is rule over-fire, fix the over-fire. Don't tune
the reranker against MSF3 to push the number up.

That's the hard line. It's hard to draw, and easy to cross. The
eval harness is the guardrail that makes crossing it visible.
