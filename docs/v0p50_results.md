# v0.50 results — close v0.49 held-out v3, lock v4 from open PRs

Released 2026-06-10 as a follow-up to v0.49. Fourth generation of
the discipline-honest research cycle. v0.50 (a) locks held-out v4
from previously-unread OPEN Snaffler PRs (sources upstream
Snaffler does NOT yet bundle), (b) adds 1 rule sourced from v0.49's
single OLD held-out v3 failure, and (c) shows the
`ShareSiftKeepSccmContentLibShare` rule (sourced from v3-locked
PR #112) generalizing to a v4 probe sourced from PR #186 — a real
structural signal.

## Headline

| Set | v0.49 | v0.50 |
|---|---|---|
| Corpus (training) | 18/19 (95%) | 18/19 (95%) |
| Held-out v1 | 11/11 (100%) | 11/11 (100%) |
| Held-out v2 | 10/10 (100%) | 10/10 (100%) |
| Held-out v3 | 9/10 (90%) | **10/10 (100%)** |
| Held-out v4 (new locked) | n/a | **7/10 (70% — incl. +1 generalization)** |
| MSF3 / MSF2 / DiskForge recall | 1.000 / 1.000 / 0.923 | 1.000 / 1.000 / 1.000¹ |
| v0.50 rule FP contribution | n/a | 0 across all three |

¹ Direct PathClassifier ∨ ContentRuleEngine cascade. v0.49's 0.923
DiskForge number was the head-to-head with a specific pysnaffler
ruleset configuration; the cascade-as-shipped catches all 13 GT
positives.

## The generalization signal

v0.48's structural win was the browser-creds meta-rule (Firefox →
Chrome + Edge). v0.50's analogous win: the SCCMContentLib$ FilePath
rule was authored from PR #112 (v3-locked share-name rule) and
catches `heldout-v4-186-sccm-reg-export` — a probe locked from
PR #186 that I never wrote a rule for.

The rule's premise: any file under `\\<host>\SCCMContentLib$\` is
worth a Yellow tier because the share itself is a CMLoot target
(per PR #112). The premise turns out to be true for PR #186's
SCCM ContentLib coverage too — the `.reg` file under
`SCCMContentLib$\PkgLib\PKG00100\settings.reg` matches the
share-name regex and lifts Green → Yellow.

That's the discipline working: an operator-complaint-general rule
catching parallel patterns the original source never named.

## The discipline experiment, generation 4

1. **Lock held-out v4 first.** 10 probes from previously-unread
   OPEN PRs: #192 (unencrypted PPK content detection via
   `Encryption: none` marker) and #186 (SCCM Indexing + Filelib
   Hash Resolution — broad coverage of DataLib/FileLib/PkgLib/
   SMSPKG scripts, configs, certificates, unattend files,
   installers). Critical property: **these PRs are still open
   upstream**, so pysnaffler does NOT bundle their rules. Tighter
   generalization test than v3 (where pysnaffler bundled the
   already-merged #140 and #112 file rules).
2. **Baseline v4 BEFORE rules: 6/10 (60%).** Surprise upside:
   ShareSift's pre-existing `ShareSiftKeepPuttyPpkUnencrypted`
   already catches PR #192's unencrypted PPK signature — that
   rule was written before #192 even opened, so it generalized
   from earlier sources. Free signal.
3. **Author rules from OLD held-out v3 failures only.** ONE rule
   (`ShareSiftKeepSccmContentLibShare`) sourced from PR #112
   (v3-locked).
4. **Validate against v4 + existing benchmarks.** v4 lifted to
   7/10 (the share-name rule generalized to PR #186's reg-export
   probe). MSF3/MSF2/DiskForge cascade recall held at 1.000 with
   zero v0.50 rule FPs.

## One new rule

| Rule | Tier | Match | Closes |
|---|---|---|---|
| ShareSiftKeepSccmContentLibShare | Yellow | FilePath | #112 SCCMContentLib$ share |

Regex: `\\SCCMContentLib\$\\` (FilePath match). PR #112's original
upstream rule is `ShareEnumeration` scope on the share name itself;
ShareSift's content engine doesn't enumerate ShareName scope, so
the FilePath approximation catches any file under the share. Yellow
matches PR #112's tier.

## What about the held-out v4 fails (3 of 10)

The 3 v4 probes still failing all come from sources I MINED for
held-out v4 (#192, #186). Per discipline, v0.50 writes NO rules
for them. They become the v0.51 starting point:

- `ppk-encrypted-fp` — Encrypted PPK gets Yellow from upstream
  `KeepSSHKeysByFileExtension` Black-tier-for-all-.ppk default.
  PR #192 demotes the catch-all to Green and only re-elevates
  unencrypted via content-rule. ShareSift would need an explicit
  `ShareSiftKeepPpkEncryptedFloor` to override the upstream rule.
- `sccm-autounattend-txt` — `(autounattend|unattend|sysprep|answer)
  .txt` extension shape not currently caught by RelayUnattendXml.
  PR #186 explicitly extends to `.txt`.
- `sccm-msi-installer-fp` — MSI under SCCM ContentLib gets Yellow
  from path classifier + my share-name rule. PR #186 explicitly
  floors installers at Green (`KeepSCCMInstallers Triage = Green`)
  because they're bulk content. ShareSift would need a tier-cap
  rule.

## Existing benchmark impact

| Benchmark | v0.49 R | v0.50 R | v0.50 rule FP |
|---|---|---|---|
| MSF3 | 1.000 | 1.000 | 0 |
| MSF2 | 1.000 | 1.000 | 0 |
| DiskForge | ≥0.923 | 1.000 | 0 |

Zero v0.50 rules fired on MSF3 / MSF2 / DiskForge (neither TP nor
FP). The SCCMContentLib$ pattern doesn't appear in any of these
substrates (MSF is Linux-shaped, DiskForge is a Win10 forensic
image without SCCM stood up).

## v0.51 candidate list

1. **`ShareSiftKeepPpkEncryptedFloor`** — Floor encrypted PPK at
   Green to override `KeepSSHKeysByFileExtension`. Sourced from
   v4-locked PR #192.
2. **Broaden RelayUnattendXml-equivalent to .txt** — Catch
   autounattend.txt / sysprep.txt / answer.txt. v4-locked PR #186.
3. **MSI installer tier cap rule** — Override path classifier
   elevation of .msi under SCCMContentLib$ paths. v4-locked PR #186.
4. **Lock held-out v5** from yet-deeper sources: open PR comment
   threads I haven't mined, closed-but-unmerged operator forks, or
   engagement-derived synthetic probes (NDA-clean redaction).
5. **`snaffler-107-eml-content` corpus fail** — Still unaddressed.
   Worth a calibrated decision: .eml MIME-body credential
   extraction is a new content-rule scope.

After v0.51 closes those + locks v5, we'll have 5 generations of
held-out signal — getting close to "calibrated corporate-share
benchmark progress" territory.
