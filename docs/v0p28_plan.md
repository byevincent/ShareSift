# v0.28 — extension-frequency penalty experiment

Drafted 2026-06-08 from v0.27's finding that the 0.20 MIN top-10
floor is MSF3-specific (Windows + PowerShell saturation),
demonstrated by MSF2 hitting 0.80 with the same pipeline on a
different real distribution.

## The hypothesis

The v0.22 filename-frequency penalty (`score /
sqrt(filename_frequency)`) declared a universal principle:
**files repeated many times on the same share are likely package-
manager noise.** MSF3's `Install-BoxstarterPackage.ps1` was the
proof-of-concept; +20 pp to MSF3 top-10 vs v0.21.

The same principle generalises one level up: **shares dominated by
a single file extension are likely build-artifact / source-tree /
log-file heavy, and individual files of that extension carry less
unique credential signal.** Credentials cluster in minority-extension
files because:

* A 5000-file PowerShell share is unlikely to have 4000 actual
  credential files. The `.ps1`'s are scripts.
* The 17 wp-config.php files on a WordPress share are more
  credential-suggestive than the 4000 .html template files around
  them.
* A `.pem` file in a sea of `.py` files is the operationally
  interesting one.

Declarative fix candidate: extend the harness scoring to also
divide by `sqrt(extension_frequency)`. Same architectural shape as
the filename penalty. No training, no MSF3-specific tuning.

## The discipline test

A change that helps MSF3 but degrades MSF2 or CredData is
**overfitting**, by v0.22's definition. The CI eval gate already
fails the build if MIN regresses; the same constraint applies to
declarative changes:

| Test | Pass |
|---|---|
| Does MSF3 top-10 improve? | TBD |
| Does MSF2 top-10 hold? | **MUST hold** (else back out) |
| Does CredData top-10 hold? | **MUST hold** (path-only — should be unaffected since content-cascade test ignores path features) |

## Phases

| Phase | Scope | Deliverable |
|---|---|---|
| 1 | Add `_score_with_full_dedup_penalty` to the harness — adds extension-frequency divisor on top of filename-frequency | edit `tools/eval_harness.py` |
| 2 | Re-run harness on all 3 primary sets | check each top-10 individually |
| 3 | Decide: ship if MIN improves AND no per-set regression; back out otherwise | document either way |
| 4 | If shipping: add the same scoring logic to the production cascade (`Scanner.scan_batch` ranking) | edit `src/sharesift/pipeline.py` |
| 5 | Azure storage account verifier (v0.26 carryover) | small declarative add |
| 6 | Re-run harness + ship | `docs/v0p28_results.md` + release |

## Honest pre-registration

Before running anything I'm registering my prediction:

* **MSF3 top-10**: should improve from 0.20. The Boxstarter `.ps1`'s
  saturate the extension; their score divisor doubles.
* **MSF2 top-10**: should hold or slightly improve. MSF2's extension
  distribution is flatter, and known positives include
  configuration files (`.conf`, `.cnf`) that ARE minority extensions.
* **CredData top-10**: completely unaffected. Content cascade
  doesn't use path-frequency features.

If reality diverges from this — particularly if MSF2 top-10 drops —
that's evidence the penalty is wrong-shaped, not that v0.28 needs
tuning. Backing out is the right answer; the discipline doesn't
let us iterate on the penalty against MSF2 + MSF3 to find one that
helps both.

## What v0.28 explicitly doesn't do

- **No training.** Same principle as v0.22-v0.27.
- **No MSF3-specific rules.** Any per-share tuning fails the
  versatility test.
- **No reranker.** Stays experimental.
- **No Stage 2 LoRA eval.** Weights still untracked.
