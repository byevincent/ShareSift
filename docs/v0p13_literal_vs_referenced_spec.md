# v0.13 spec — literal-vs-referenced credential discriminator

First content-classifier component of the v0.12 post-mortem roadmap.
The structural distinction (literal credential value vs variable
reference / parameter / template) is one Snaffler's regex rules
**cannot** make — its patterns match the structural shape
``password=<anything>`` without inspecting the RHS. That makes this
classifier a genuine ML wedge: not redundant with Snaffler's rules,
not theater. Spec was redirected after auditing Snaffler's 1,279
Metasploitable 3 hits (supersedes the earlier template-vs-real spec).

**Strategic context (2026-06-03):** This is v0.13 in a roadmap aimed
at *beating* Snaffler on pedagogical-realistic + well-deployed-OSS
shares (Metasploitable, HTB, VulnLab, GOAD). v0.14 adds the
filename-allowlist + binary-filter + ranker components; v0.15 adds
path-classifier retrain with engagement+synthetic data. v0.13 is one
piece — the content-precision wedge — not the whole answer.

A content classifier that distinguishes:

- **Literal credential** (positive): file content contains a literal
  string assignment to a credential field — `password='Ok6/FqR5='`,
  `<AdministratorPassword>actualpass</AdministratorPassword>`,
  `DB_PASSWORD=hunter2`
- **Referenced credential** (negative): file content references
  credential-related tokens as variables, parameters, regex patterns,
  or example documentation — `-Password $password`, `password=%SSLPassword%`,
  `[-Password <SecureString>]`, `.EXAMPLE PS C:\> Set-SecureAutoLogon -Password (Read-Host -AsSecureString)`

The output becomes the strongest single feature in v0.14's
Snaffler-noise ranker.

## Goal

> *Given a Snaffler content-rule match snippet (or short file content
> window), predict P(this match contains a literal credential value |
> snippet) vs P(this is a variable reference / parameter / example /
> regex pattern).*

This is **not** the same as v0p6's "is this content juicy" question.
v0p6 answers "does this file type plausibly contain credentials".
v0.13 answers, given a Snaffler hit on a plausibly-juicy file, "is
the matched text a literal cred value or just a credential-shaped
reference?"

In scope:
- Public github scrape of PowerShell + CMD/BAT corpora (and incidental
  XML/INI/YAML where Snaffler's content rules also fire)
- Binary literal-vs-referenced classification head
- Trained on Snaffler-match-style short snippets (≤500 chars), not
  full file content
- Calibration good enough to use as a ranking feature in v0.14
- Reality check on 1,279 Metasploitable 3 Snaffler hits (1,054
  ground-truth records once the patched ingester runs)

Out of scope:
- Live credential validation (no DB connection attempts)
- Multi-line key block detection (Snaffler already covers; not
  the FP class we're trying to filter)
- v0.14 ranker integration (next ticket)
- Template/example file detection (the original v0.13 target —
  Metasploitable has zero template files; revisit only if a later
  corpus surfaces template FPs as a meaningful class)
- Hard filtering (the classifier is a ranking feature, not a cutoff)

## Why this target, not template-vs-real

Audit of Snaffler's 1,279 Metasploitable 3 hits (2026-06-03):

| Rule | Count | % | What it fires on |
|---|---|---|---|
| KeepPassOrKeyInCode | 686 | 54% | regex over content, password-token patterns |
| KeepCmdCredentials | 241 | 19% | regex over CMD/BAT credential patterns |
| KeepPsCredentials | 238 | 19% | regex over PowerShell credential patterns |
| KeepDatabaseByExtension | 64 | 5% | .bak files (Windows boot backups) |
| filename-only rules (Ruby/SSH/Nix/etc.) | ~50 | 4% | bypass content scoring entirely |

- **91% of hits fire on three content-pattern rules**, all firing on
  PowerShell or CMD/BAT code
- **88% of hits are `.ps1` files** — dominantly Boxstarter installer
  tutorial/parameter/example code
- Template/example files (`-sample`, `.example`, `.tpl`) are
  **effectively absent** — Metasploitable is a pre-built deployment,
  not a github repo
- Filename-rule TPs (`database.yml`, `authorized_keys`, `passwd`,
  `secrets.yml`) bypass content scoring entirely — they don't need
  filtering and the v0.13 classifier doesn't touch them

**Verified literal/referenced separation against actual content
snippets:**

| Class | Sample | Content shape |
|---|---|---|
| TP literal | `resetPWD.xml` | `AaaPassword.PASSWORD='Ok6/FqR5WtJY5UCLrnvjQQ=='` |
| TP literal | `unattend.xml` | `<AdministratorPassword>...</AdministratorPassword>` |
| Partial TP (reference) | `ssl_servicedesk.bat` | `-storepass %SSLPassword% -storetype jks` |
| FP reference | `Set-SecureAutoLogon.ps1` | `.EXAMPLE PS C:\> Set-SecureAutoLogon -Password (Read-Host -AsSecureString)` |
| FP reference | `Chocolatey.ps1` | `$script:BoxstarterPassword='$($script:BoxstarterPassword)'` |
| FP reference | `Enable-RemotePsRemoting.ps1` | `schtasks /CREATE ... /RP "$password" /XML "$taskFile"` |

The literal-vs-referenced distinction maps cleanly onto the
TP/FP split for content-rule hits, with **one structural casualty:**
"partial TP" config files (`ssl_servicedesk.bat`,
`setDBEnv.bat`, `initPgsql.bat`) reference credential variables
without storing literals. The classifier would score them as
references (low P(literal)). v0.14 mitigates by using the score
as a ranking feature alongside other signals (filename rule,
Snaffler tier) — partial TPs get ranked low but stay in the queue
rather than getting filtered.

## Phase 0 — Snaffler suppression audit ✓ COMPLETE (2026-06-03)

Confirmed by direct inspection of Snaffler's rule TOML files
(`SnaffRules/DefaultRules/FileRules/Keep/Code/`):

- `KeepPassOrKeyInCode`, `KeepCmdCredentials`, `KeepPsCredentials`
  have **zero in-rule allowlist/exclusion fields**
- Global suppression (`PostMatchRules/Discard*`, `PathRules/Discard*`)
  is narrow: psexec, Git internals, MSSQL templates, `\usr\share\doc`.
  No Boxstarter, `.EXAMPLE`, comment-block, or literal-vs-referenced
  awareness anywhere
- Snaffler's regex patterns are structurally incapable of
  distinguishing `password="literalvalue"` from `password="$varRef"` —
  the regex doesn't inspect the RHS

**Verdict:** v0.13 is not redundant with any existing Snaffler feature.
Proceed to Phase 1.

## Phase 1 — corpus selection

Two corpora, mined separately:

### A. PowerShell corpus (~80% of expected positive class)

Source: public github `.ps1` files containing password-related tokens.
Github code search query: `password extension:ps1 OR Password extension:ps1`.

Per-file labeling:
- **Literal positive (rare):** content contains literal string
  assignment to a credential field. Detection: regex for
  `Password\s*=\s*['""][^'""$]{6,}['""]` (must have non-empty,
  non-variable-prefixed string of length ≥6). Manual audit a sample
  to verify these are real credentials, not honeytokens.
- **Referenced negative (common):** content contains password tokens
  in parameter declarations, variable references, SecureString
  prompts, `.EXAMPLE` blocks, or comment-style documentation.
  Detection: presence of `param(`, `$password`, `-AsSecureString`,
  `Read-Host`, `.EXAMPLE`, `<#` (PowerShell comment block).

Estimated yield: ~5k literal positives + ~50k referenced negatives.
Class imbalance is **expected** — referenced-shape is the dominant
on-disk pattern. Handle with class weights or focal loss.

### B. CMD/BAT corpus

Source: public github `.bat` + `.cmd` files containing password-related
tokens. Github code search: `password extension:bat`.

Per-file labeling:
- **Literal positive:** `set\s+password=[^%$"\s]{6,}` (literal
  password assignment not pointing to a variable)
- **Referenced negative:** `%PASSWORD%`, `-pass %VAR%`,
  `:: comment about password`

Estimated yield: ~2k literal + ~20k referenced.

### C. Incidental positives from Metasploitable's resetPWD.xml shape

Source: public github XML files with `<Password>literal</Password>`
or SQL-style `PASSWORD='literal'` patterns. Smaller, ~1k examples.

Total target corpus: ~80k examples, 90% referenced / 10% literal.

## Phase 2 — github scrape pipeline

`tools/scrape_powershell_credentials.py` (new) — same scaffolding
as the prior path-scraper but content-targeted.

Approach:
- Github code search API (rate-limited; budget 1 day for full scrape)
  OR `bigquery-public-data.github_repos` SQL for cheaper bulk extract
- Pull files; apply regex labelers; emit `(snippet, label, source_repo, file_path)`
- Snippet extraction: 500-char window centered on the matched
  password token (matches Snaffler's snippet shape)
- Spot-audit ~200 examples per class manually before training

Filters:
- Repo activity: ≥10 stars OR ≥3 commits in last 2 years
- File size: 100 chars min, 200kB max
- Exclude repos already in v0p6 docx corpus, CredData training set,
  ShareSift writeup corpus

## Phase 3 — Leakage controls

- **No repo overlap** with v0p6 docx corpus, CredData, ShareSift
  writeup corpus
- **By-repo train/test split** (80/10/10), not by-file
- **De-duplicate identical snippets** across repos (Boxstarter is
  forked thousands of times — keep one copy)
- **Hold out Metasploitable Snaffler hits entirely** — they are the
  reality-check eval, not training data

## Phase 4 — Training

Inherit v0p6's stack:
- Qwen3-1.7B base, Unsloth LoRA (r=16, alpha=32)
- Snippet input, max 512 tokens (vs v0p6's 4000-char snippets)
- Batch size 1, grad accum 16
- Class-weighted loss (10:1 reference:literal ratio in corpus →
  weight literal class up to balance)

Output: `models/content_classifier_v0p7_literal_vs_referenced/`.

Kept as a **dedicated head** separate from v0p6. v0.14's ranker
consumes both heads' probabilities as independent features.

## Phase 5 — Evaluation

### Held-out test set (10% of github scrape, by-repo)

Metrics:
- Precision/recall on literal class at default 0.5 threshold
- Per-corpus breakdown (PowerShell / CMD-BAT / XML)
- Calibration: Brier score + reliability diagram
- Robustness to snippet variation: cut to 200/300/500 chars, see
  if predictions stay stable

### Reality check (the eval that matters)

Run v0p7 on the 1,279 Snaffler Metasploitable 3 match snippets
(now ingested via the patched `build_msf3_ground_truth.py`).

Questions to answer:
- Of the ~7 known-TP Snaffler hits with literal content, what
  fraction does v0p7 score P(literal) > 0.5?
  *(Expected: 6/7. The casualty is `ssl_servicedesk.bat` as a
  reference-shape partial TP.)*
- Of the ~1,150 known-FP Snaffler hits on Boxstarter/tutorial code,
  what fraction does v0p7 score P(literal) > 0.5?
  *(Expected: <10%. If this number is >25%, the classifier didn't
  learn the structural distinction — back to data.)*
- ROC AUC for ranking-feature use case: how well does P(literal)
  separate the TP from FP distributions overall?
  *(Bar to clear: AUC ≥ 0.85. Below 0.80 → reassess.)*

## Phase 6 — Write-up + decision

`docs/v0p13_literal_vs_referenced_results.md`:
- Test set + reality-check metrics
- Confusion matrix on Metasploitable Snaffler hits
- Calibration plots
- Decision: green-light v0.14, or re-spec the head, or close

## Estimated effort

- **Week 1:** Phase 1 scrape (~80k snippets) + Phase 2 leakage
  filters + spot-audit
- **Week 2:** Phase 3 training + first v0p7 run
- **Week 3:** Phase 4 eval + reality check + Phase 5 write-up

Total: ~3 weeks.

## Risks

1. **Class collapse on imbalanced data.** Referenced negatives
   dominate ~10:1. Without class weighting, the model defaults to
   "always predict reference" and looks good on accuracy while being
   useless on the rare positive class. Mitigation: focal loss or
   inverse-frequency weights; monitor per-class precision/recall
   during training.

2. **Snippet boundary effects.** Snaffler's match snippets clip the
   surrounding context; the classifier may need full-line or
   full-statement context to make the literal/referenced call.
   Mitigation: Phase 4 robustness check (cut to 200/300/500); if
   short snippets hurt accuracy meaningfully, train at 1000+ char
   windows.

3. **Honeytoken / scrubbed-literal poisoning.** `unattend.xml` on
   Metasploitable contains `<AdministratorPassword>*SENSITIVE*DATA*DELETED*</AdministratorPassword>`
   — literal *shape* but scrubbed value. Github scraping will pull
   in lots of these (autogenerated configs, CI test fixtures, doc
   examples with `'CHANGE_ME'` literals). Mitigation: positive class
   labeler requires value length ≥6 AND not in a placeholder denylist
   (`CHANGE_ME`, `YOUR_PASSWORD`, `xxxxx`, `*DATA*DELETED*`, etc.).
   The denylist also has training-data value: these are exactly the
   "literal-shaped placeholder" patterns we want the model to handle.

4. **Snaffler already filters tutorial code in some way we
   don't see.** Audit confirms it doesn't (1,165 Boxstarter FPs on
   Metasploitable). But Snaffler may have config flags or
   `--allowlist` patterns that experienced operators use to suppress
   this class. If our v0.13 wedge is "the thing Snaffler operators
   already do via config", the marginal value is zero. Mitigation:
   read Snaffler's rule files in Phase 0 to confirm no built-in
   suppression for Boxstarter-shape FPs; this takes ~30 min and
   should happen before Phase 1.

## What success looks like

v0p7 reaches **AUC ≥ 0.85** at separating Metasploitable Snaffler
TP hits from Boxstarter-style FP hits, with **≥80% precision at
80% recall** on the held-out github test set. That's the green light
for v0.14.

What failure looks like: AUC < 0.80 on Metasploitable Snaffler hits,
OR the model collapses to "always reference" despite class
weighting, OR Snaffler's existing config already handles the
Boxstarter FP class. Either case → reassess. The non-ML alternative
would be a rule-based "exclude PowerShell files whose only match is
in a `.EXAMPLE` block or comment region" — much smaller scope.
