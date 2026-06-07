# v0.9 — Writeup-realistic share benchmark (path-side)

Follows [v0.8 docx-corpus content benchmark](v0p8_realistic_share_benchmark.md).
v0.8 found that v0p5's F1=0.853 on CredData *didn't* transfer to a
business-document distribution — recall collapsed from 0.820 to 0.254.
The implicit symmetric question for v0.9: does the path classifier's
+29.3 pp Snaffler-beat (calibrated on GitHub-mined paths) transfer to
realistic SMB-share path topology?

v0.9 builds a writeup-derived benchmark to answer that. Result: **the
path classifier's PR-AUC drops from 0.99 in-distribution to 0.27 on
writeup paths**, and the tier-band precision contract is essentially
broken on the new distribution.

## Why this benchmark exists

The existing v0.5 Snaffler-blind benchmark (the source of the +29.3 pp
claim) was built from GitHub Code Search + Stack Exchange path-mining.
It exercises *ShareSift's* training distribution. The honest question
that distribution can't answer is whether the classifier generalizes
to:

* Realistic AD share topology (SYSVOL/Policies subtrees, redirected
  user homes, share-mapping prompts)
* Pentester-judgment labels (multi-author implicit consensus from
  write-ups, not Vincent-singular + Claude/Codex audit)
* Path patterns that *ShareSift's training mining* never surfaced
  (NOPASSWD sudo targets, DPAPI subdirs, scheduled cleanup scripts in
  user dirs)

Public corpora for share *topology* don't exist (per the
[asymmetry memory](../../.claude/projects/-home-george-5090-sharesift/memory/feedback_sharesift_data_asymmetry.md)) —
that's the structural NDA wall. The available proxy is mining the
security community's published write-ups. Not engagement data, but
multi-author independently-derived data from a population that does
adversarial enumeration as a routine activity.

## Build

`tools/scrape_writeups.py`:

* Fetched HTML from 0xdf.gitlab.io (the entire visible archive of HTB
  write-ups, 2022-09 → 2026-05, 231 box write-ups). Polite 1-req/sec
  rate limit, descriptive User-Agent.
* Parsed `<pre>` / `<code>` blocks (where shell sessions, smbmap
  output, and directory listings appear in writeup convention).
* Ran three regex families (UNC `\\host\share\…`, Windows-drive
  `C:\…`, Linux absolute `/…`) plus filters that reject URL paths,
  shell-prompt residue, escape-sequence noise, IP-prefixed URLs, and
  TLD-suffixed pseudo-paths.
* HTML discarded after parsing; only path strings + source URL +
  scrape date persist per record (fair-use research extraction route
  decided in v0.8 closeout — paths are facts, not redistributable
  text).

Output: 7,073 path records across 230 boxes; 4,556 unique paths
(32% cross-box overlap from common system paths).

* `linux_abs`: 6,284 — ~12× the existing 500-record Linux benchmark
* `win_drive`: 744
* `unc`: 45 — sparse because writeups typically show post-foothold
  filesystem context, not initial SMB enumeration

`tools/build_writeup_labeling_kit.py` + paste workflow:

* Stratified-sampled to 1,500 paths (all 45 UNC + all 500 Win-drive +
  955 of 4,011 random Linux).
* Generated `labeling_kit_v0p9/` with 15 chunks of 100 paths each, a
  system prompt encoding Vincent's 15 calibration positions from
  `memory:feedback_labeling_calibration`, and a manifest mapping
  (chunk_id, idx) → original record metadata.
* Vincent paste-labeled all 15 chunks against Sonnet (~30 min). One
  record truncated mid-line; 1499 of 1500 valid.

`tools/llm_label_writeup_ingest.py`: parsed the responses, joined to
manifest, emitted `data/eval/writeups/labeled_paths.jsonl`.

* **Final labeled corpus: 1,499 records (282 juicy / 1,217 not_juicy)**

## Eval — Snaffler-blind subset

`tools/eval_path_classifier_on_writeups.py`:

* Applied Snaffler's TOML rule pack (reused
  `tools/build_snaffler_blind_benchmark.py` machinery).
* Snaffler verdict breakdown over the 1,499 labeled records:
  - Snaffle/Relay (Snaffler engages): ~30% of records — the
    obvious-juicy paths that don't need a model
  - Discard (Snaffler skips): ~17% of records
  - **Silent (Snaffler-blind): 995 records** — the long-tail where
    ShareSift's claim lives
* Routed Snaffler-blind paths through the deployed `PathClassifier`.

### Results — Snaffler-blind subset, by shape

**Windows UNC (43 records, 10 juicy):**

| Metric | Value |
|---|---|
| Precision @ 0.5 | 1.000 |
| Recall @ 0.5 | 0.200 |
| F1 @ 0.5 | 0.333 |
| PR-AUC | 0.524 |
| ECE | 0.187 |

Black tier: 2 records, 2 juicy (100% precision). All other records
fall in tier None where the classifier has correctly identified 2 of
10 juicy paths and missed 8. **Sample too small for confident
generalization, but directionally: Windows precision holds at the
top tier, recall collapses.**

**Linux absolute (952 records, 168 juicy):**

| Metric | Value | v0.5 in-distribution reference |
|---|---|---|
| Precision @ 0.5 | 0.208 | 0.96 |
| Recall @ 0.5 | 0.440 | 0.98 |
| F1 @ 0.5 | 0.283 | 0.96 |
| **PR-AUC** | **0.273** | **0.99** |
| ECE | 0.316 | 0.04 |

**The PR-AUC dropped 72 points from 0.99 (linux-rule-blind benchmark)
to 0.27 on writeup paths.** This is the path-side analog of v0.8's
content-stage finding. The training distribution (GitHub-mined paths)
doesn't transfer to the realistic share distribution that writeups
sample.

### Per-tier-band precision — the contract is broken

The v0.5 audit guaranteed tier-band precision contracts only on the
in-distribution test split (footnote in README). v0.9 is the first
external validation:

| Tier | n | juicy | precision | (v0.5 in-distribution contract) |
|---|---|---|---|---|
| Black (≥0.95) | 44 | 18 | **0.41** | (~0.95) |
| Red (0.80–0.95) | 175 | 40 | **0.23** | (~0.80) |
| Yellow (0.50–0.80) | 176 | 22 | **0.13** | (~0.50) |
| None (<0.50) | 557 | 88 | 0.16 | (~base rate) |

Black tier precision drops from ~0.95 to 0.41 (−54 pp). Red drops
from ~0.80 to 0.23 (−57 pp). Yellow from ~0.50 to 0.13 (−37 pp). And
**None-tier precision (0.16) ≈ writeup base rate (0.177)**, meaning
the classifier's "not juicy" decisions carry essentially no signal
on this distribution beyond what you'd guess from the base rate.

## Eval — End-to-end constructed share

`tools/build_constructed_share.py` + `eval_constructed_share.py`:

* Constructed a synthetic share at
  `data/external/constructed_share/` mirroring 1,117 writeup-mined
  paths (UNC and Windows-drive paths map to `_unc/server/share/…`
  and `_winC/Users/…` under the share root; Linux paths map to
  `_linux/…`).
* Populated each file with random docx-corpus content (the v0.8 cache);
  salted 154 juicy files with real-shape credentials from
  Kingfisher's CredData findings.
* Invoked `sharesift scan-files --input` against the full path list
  (uses runtime-default v0p5 content classifier).

### End-to-end results (1117 files, 154 salted)

| Stage | Precision | Recall | F1 | TP | FP | FN |
|---|---|---|---|---|---|---|
| Stage 1 (path classifier) | 0.328 | 0.304 | 0.315 | 58 | 119 | 133 |
| Stage 2 (content classifier, on flagged) | 0.933 | 0.091 | 0.166 | 14 | 1 | 140 |
| End-to-end (both stages must agree) | 0.933 | 0.091 | 0.166 | 14 | 1 | 140 |

**End-to-end recall: 9.1%.** The deployed pipeline caught 14 of 154
salted credentials in a writeup-shaped, docx-content-bearing share.

Mechanism:
- **Stage 1 fails** at the path-routing step: F1=0.32 vs ~0.96 on the
  in-distribution Linux benchmark. Most juicy paths don't get flagged.
- **Stage 2 fails** on the *content* side exactly as v0.8 predicted:
  the content classifier trained on CredData source-code snippets
  doesn't recognize credentials embedded in business documents. R=0.09
  (vs the v0p5 CredData R=0.82) confirms the v0.8 generalization gap.
- **The two-stage architecture compounds** these failures: stage 2
  only sees what stage 1 already flagged, so stage 2's miss rate
  multiplies with stage 1's.

End-to-end precision (0.93) is high because the docx-corpus negative
class is largely benign business prose and the content classifier
doesn't false-positive heavily on it. But precision at 9% recall is
not operationally useful — you're missing 91% of the credentials.

## What v0.9 means for the project

This is the single most consequential finding since v0.5. The
+29.3 pp Snaffler-beat headline was *real for the v0.5 Snaffler-blind
benchmark*, but that benchmark is from the same labeling distribution
as the training data, and Vincent's labels (+ Codex audit) are one
operator's calibration. On writeup-mined paths labeled against the
same calibration positions by Sonnet (15 numbered rules from
`feedback_labeling_calibration`):

* Linux PR-AUC drops 72 points
* Linux Black-tier precision drops 54 points
* The "not juicy" decision is essentially uninformative
* Windows sample is too small to call but the trend points the same way

The honest reframe of the README headline:

> ShareSift's path classifier beats Snaffler by +29.3 pp on the v0.5
> Snaffler-blind benchmark. That benchmark exercises ShareSift's
> training distribution (GitHub Code Search + Stack Exchange path
> mining); generalization to writeup-realistic share topology is
> meaningfully weaker (Linux PR-AUC 0.27, tier-band contracts hold
> only loosely). The v0.5 in-distribution result is real but does not
> ceiling ShareSift's deploy-realistic performance.

## What this enables for v0.10+

The natural retrain path:

* **v0.10**: Retrain Win+Linux path classifiers on a corpus that
  includes the writeup-mined labels (with careful by-box partitioning
  to prevent leakage between training and eval). Aim is to recover
  Black-tier precision ≥0.80 on the writeup benchmark while
  preserving the in-distribution numbers.
* **v0.11**: Re-validate against a held-out portion of writeup paths
  + the existing Snaffler-blind benchmark. Same calibration positions,
  larger corpus, broader operator-implicit consensus.

The fundamental ceiling — real engagement data — still doesn't move.
But the writeup corpus closes some of the gap between "trained on
public web mining" and "validated on adversarially-realistic share
topology."

## What ships in v0.9

* `tools/scrape_writeups.py` — fetcher + path extractor
* `tools/build_writeup_labeling_kit.py` + `llm_label_writeup_ingest.py`
  — paste-workflow tooling
* `tools/eval_path_classifier_on_writeups.py` — Snaffler-filter + eval
* `tools/build_constructed_share.py` + `eval_constructed_share.py` —
  end-to-end orchestration test
* `data/eval/writeups/raw_paths.jsonl` — 7,073 mined paths
* `data/eval/writeups/labeled_paths.jsonl` — 1,499 labeled records
* `labeling_kit_v0p9/` — frozen paste workflow + responses
* `reports/writeup_benchmark_eval.json` — v0.9.3 path-classifier eval
* `reports/constructed_share_eval.json` — v0.9.5 end-to-end eval
* This document

## References

* `docs/v0p8_realistic_share_benchmark.md` — v0.8 docx-corpus content
  benchmark (mirror-image finding on the content side)
* `docs/v0p6_content_rebuild.md` — v0.6+v0.7 content rebuild
* `docs/audit_2026-05-31.md` — v0.5 audit (origin of the +29.3 pp
  Snaffler-beat claim that v0.9 contextualizes)
* `memory:feedback_sharesift_data_asymmetry.md` — the calibration
  correction that drove v0.8 + v0.9 together
* 0xdf write-up corpus: https://0xdf.gitlab.io/
