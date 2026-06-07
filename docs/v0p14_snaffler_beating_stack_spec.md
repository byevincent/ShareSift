# v0.14 spec — Snaffler-beating triage stack

The first version of ShareSift that aims to beat Snaffler in a measured
head-to-head, not just augment it. Combines a port of Snaffler's
filename + content rules into ShareSift's pipeline with new rules for
v0.12's shared blind spots, a binary-extension preprocessor that
eliminates ShareSift's worst FP class, v0.13's literal-vs-referenced
content classifier as a ranking feature, and a ranker that fuses all
signals into a single ordered output.

## Goal

> *On Metasploitable 3 and at least one additional held-out share
> (GOAD), ShareSift matches or exceeds Snaffler on recall (catches
> everything Snaffler does, plus the shared blind spots Snaffler
> misses) and beats it on precision (FP rate at least 30% lower).*

Specific bars:

- **Recall:** catch every credential-bearing file Snaffler catches, plus
  at minimum `wp-config.php` and `config.inc.php` (the v0.12 shared blind
  spot) on Metasploitable
- **Precision:** ≥30% lower FP rate than Snaffler on the same corpus,
  driven by binary preprocessor (eliminates ~80% of v0.11's FPs) +
  v0.13 P(literal) ranking
- **Generalization sanity:** the same stack run on GOAD must not collapse
  (recall ≥80% of Snaffler's, precision still better) — confirms we
  didn't just overfit to Metasploitable's specific files

If we hit recall but fall short on precision, v0.14 still ships as
Snaffler-parity-with-better-triage. If we miss recall too, we haven't
beaten Snaffler and need to debug before claiming the win.

## Architecture decision: independent pipeline, not augmenter

v0.13's earlier "augmenter" framing positioned ShareSift as a
*post-processor* of Snaffler's output. v0.14 reverses this. ShareSift is
a **standalone replacement** that ports the parts of Snaffler that
work (rules) and adds the parts Snaffler can't do (learned path
generalization, content P(literal) ranking).

Implications:
- ShareSift at runtime does NOT call Snaffler. The "vs Snaffler" eval
  runs both tools independently and compares.
- Snaffler's TOML rules are read once at build time, parsed, and
  embedded into ShareSift's `src/sharesift/rules/` module. The rule
  format is borrowed; the runtime is ShareSift's.
- License compatibility: Snaffler is GPLv3. Porting the *rule
  definitions* (pattern strings) is fair use of public security
  intelligence; we're not redistributing Snaffler's code. The
  pattern strings carry no copyright (they're literal regexes).
  Attribution lives in `src/sharesift/rules/SOURCES.md`.

## Components

### 1. Snaffler rule port (`src/sharesift/rules/`) — EXHAUSTIVE

Port **all 86** `.toml` rule files (yielding **88 ClassifierRules** —
three files carry 2 rules each) from `Snaffler/SnaffRules/DefaultRules/`
in [SnaffCon/Snaffler](https://github.com/SnaffCon/Snaffler).

Captured from upstream at commit `50ed78372b2cdf6df5a61cfdf6fd49c0d575331f`
(2026-06-03). The original audit estimated 84 files / 84 rules; the
clone-based port_snaffler_rules.py confirmed the true counts (86 files,
88 rules) and updated this section accordingly.

The taxonomy is organized by *domain* (Code, Infrastructure, UserFiles,
BusinessDocs) with `MatchLocation` (FileName / FilePath / FileExtension /
FileContentAsString / ShareName — **NOT** FileContentAsBytes; the earlier
audit reported that type but upstream doesn't actually use it) and
`MatchAction` (Snaffle / Relay / Discard / CheckForKeys) as fields
*inside* each TOML — NOT top-level dirs.

**Multi-rule files (3) — preserve all rules during port:**
- `FileRules/Keep/Code/CSharpAndASP/KeepCSharpDbConnStrings.toml` (2 rules)
- `FileRules/Keep/Infrastructure/DeploymentAutomation/KeepUnattendXmlRelay.toml` (2 rules)
- `FileRules/Keep/UserFiles/BrowserCreds/KeepFfLoginsJsonRelay.toml` (2 rules) Don't restructure during the port; preserve the
upstream layout under `src/sharesift/rules/snaffler_default/` so future
upstream changes are easy to merge.

**Complete file checklist (84 files; tick each during port):**

#### FileRules/Discard (2)
- [ ] `DiscardByFileExtension.toml` — Green, drop boring extensions
- [ ] `DiscardByFileName.toml` — Green, drop boring filenames

#### FileRules/Keep/BusinessDocs (1)
- [ ] `ByPartialName/KeepFilenameContainsPamOrPwdVault.toml` — Green/Snaffle

#### FileRules/Keep/Code — top-level cross-language (7)
- [ ] `KeepAwsKeysInCode.toml` — Red, Content/Snaffle
- [ ] `KeepDbConnStringPw.toml` — Yellow, Content/Snaffle
- [ ] `KeepInlinePrivateKey.toml` — Red, Content/Snaffle
- [ ] `KeepPassOrKeyInCode.toml` — Red, Content/Snaffle  *(686/1279 of MSF3 hits)*
- [ ] `KeepS3UriPrefixInCode.toml` — Yellow, Content/Snaffle
- [ ] `KeepSlackTokensInCode.toml` — Red, Content/Snaffle
- [ ] `KeepSqlAccountCreation.toml` — Red, Content/Snaffle

#### FileRules/Keep/Code — per-language (24)
- [ ] `Cmd/KeepCmdCredentials.toml` — Red, Content/Snaffle  *(241/1279 of MSF3 hits)*
- [ ] `Cmd/RelayCmdByExtension.toml` — Green/Relay
- [ ] `CSharpAndASP/KeepCSharpDbConnStrings.toml` — Yellow, Content/Snaffle
- [ ] `CSharpAndASP/KeepCSharpViewstateKeys.toml` — Red, Content/Snaffle
- [ ] `CSharpAndASP/RelayCSharpByExtension.toml` — Green/Relay
- [ ] `GenericConfig/KeepConfigByName.toml` — Red, FileName/Snaffle
- [ ] `GenericConfig/RelayConfigByExtension.toml` — Green/Relay
- [ ] `Java/KeepJavaDbConnStrings.toml` — Red, Content/Snaffle
- [ ] `Java/RelayJavaByExtension.toml` — Green/Relay
- [ ] `JavaScript/RelayJsByExtension.toml` — Green/Relay
- [ ] `Perl/KeepPerlDbConnStrings.toml` — Red, Content/Snaffle
- [ ] `Perl/RelayPerlByExtension.toml` — Green/Relay
- [ ] `PHP/KeepPhpByName.toml` — Red, FileName/Snaffle
- [ ] `PHP/KeepPhpDbConnStrings.toml` — Red, Content/Snaffle
- [ ] `PHP/RelayPhpByExtension.toml` — Green/Relay
- [ ] `PowerShell/KeepPsByName.toml` — Green, FileName/Relay
- [ ] `PowerShell/KeepPsCredentials.toml` — Red, Content/Snaffle  *(238/1279 of MSF3 hits)*
- [ ] `PowerShell/RelayPsByExtension.toml` — Green/Relay
- [ ] `Python/KeepPyDbConnStrings.toml` — Red, Content/Snaffle
- [ ] `Python/RelayPythonByExtension.toml` — Green/Relay
- [ ] `Ruby/KeepRubyByName.toml` — Red, FileName/Snaffle  *(caught database.yml on MSF3)*
- [ ] `Ruby/KeepRubyDbConnStrings.toml` — Red, Content/Snaffle
- [ ] `Ruby/RelayRubyByExtension.toml` — Green/Relay
- [ ] `ShellScript/KeepShellScriptCredentials.toml` — **empty upstream**, fill in ourselves
- [ ] `ShellScript/RelayShellScriptByExtension.toml` — Green/Relay
- [ ] `VBScript/RelayVBScriptByExtension.toml` — Green/Relay

#### FileRules/Keep/Infrastructure (24)
- [ ] `Certificates/RelayCertByExtension.toml` — Red, FileExtension/CheckForKeys
- [ ] `CiCdStuff/KeepJenkinsByName.toml` — Red, FileName/Snaffle
- [ ] `Databases/KeepDatabaseByExtension.toml` — Yellow, FileExtension/Snaffle  *(64/1279 of MSF3 hits, mostly .bak)*
- [ ] `DeploymentAutomation/KeepDefenderConfigByName.toml` — Yellow, FileName/Snaffle
- [ ] `DeploymentAutomation/KeepDeployImageByExtension.toml` — Yellow, FileExtension/Snaffle
- [ ] `DeploymentAutomation/KeepDomainJoinCredsByName.toml` — Yellow, FileName/Snaffle
- [ ] `DeploymentAutomation/KeepDomainJoinCredsByPath.toml` — Red, FilePath/Snaffle
- [ ] `DeploymentAutomation/KeepSCCMBootVarCredsByPath.toml` — Red, FilePath/Snaffle
- [ ] `DeploymentAutomation/KeepUnattendXmlRelay.toml` — Green, FileName/Relay  *(this is the unattend.xml relay; our new KeepWindowsUnattend rule supersedes/upgrades it)*
- [ ] `FTPServers/KeepFtpServerConfigByName.toml` — Red, FileName/Snaffle
- [ ] `InfraAsCode/KeepInfraAsCodeConfigByExtension.toml` — Red, FileExtension/Snaffle
- [ ] `MemDumps/KeepMemDumpByExtension.toml` — Red, FileExtension/Snaffle
- [ ] `MemDumps/KeepMemDumpByName.toml` — Black, FileName/Snaffle
- [ ] `NetworkDevice/KeepNetConfigCreds.toml` — Red, Content/Snaffle
- [ ] `NetworkDevice/KeepNetConfigFileByName.toml` — Black, FileName/Snaffle
- [ ] `NetworkDevice/RelayNetConfigByName.toml` — Green, FileName/Relay
- [ ] `NixKerberos/KeepKerberosCredentialsByExtension.toml` — Yellow, FileExtension/Snaffle
- [ ] `NixKerberos/KeepKerberosCredentialsByName.toml` — Yellow, FileName/Snaffle
- [ ] `NixLocalHashes/KeepNixLocalHashesByName.toml` — Black, FileName/Snaffle  *(caught passwd on MSF3)*
- [ ] `PacketCapture/KeepPcapByExtension.toml` — Yellow, FileExtension/Snaffle
- [ ] `PAMAndPwVault/KeepCyberArkConfigsByName.toml` — Black, FileName/Snaffle
- [ ] `PAMAndPwVault/RelayCyberArkByExtension.toml` — Red, FileExtension/Snaffle
- [ ] `Infrastructure/RelayInfraConfigByExtension.toml` — Green, FileExtension/Relay
- [ ] `VirtualMachines/KeepVMDisksByExtension.toml` — Red, FileExtension/Snaffle
- [ ] `WinHashes/KeepWinHashesByName.toml` — Black, FileName/Snaffle

#### FileRules/Keep/UserFiles (18)
- [ ] `APIKeys/KeepCloudApiKeysByName.toml` — Black, FileName/Snaffle
- [ ] `APIKeys/KeepCloudApiKeysByPath.toml` — Black, FilePath/Snaffle
- [ ] `BrowserCreds/KeepFfLoginsJsonRelay.toml` — Green, FileName/Relay
- [ ] `DBMgmt/KeepDbMgtConfigByName.toml` — Red, FileName/Snaffle
- [ ] `DotFiles/KeepGitCredsByName.toml` — Red, FileName/Snaffle
- [ ] `DotFiles/KeepShellHistoryByName.toml` — Green, FileName/Snaffle  *(our calibration: bump to Red per `feedback_labeling_calibration.md` — shell history regularly contains fat-fingered creds)*
- [ ] `DotFiles/KeepShellRcFilesByName.toml` — Green, FileName/Snaffle
- [ ] `PassMgrs/KeepPassMgrsByExtension.toml` — Black, FileExtension/Snaffle
- [ ] `PassMgrs/KeepPasswordFilesByName.toml` — Red, FileName/Snaffle
- [ ] `RemoteAccess/KeepFtpClientByName.toml` — Red, FileName/Snaffle
- [ ] `RemoteAccess/KeepRdpPasswords.toml` — Red, Content/Snaffle
- [ ] `RemoteAccess/KeepRemoteAccessConfByExtension.toml` — Yellow, FileExtension/Snaffle
- [ ] `RemoteAccess/KeepRemoteAccessConfByName.toml` — Black, FileName/Snaffle
- [ ] `RemoteAccess/RelayRdpByExtension.toml` — Green, FileExtension/Relay
- [ ] `SSH/KeepSSHFilesByFileName.toml` — Black, FileName/Snaffle  *(caught authorized_keys on MSF3 via the path variant)*
- [ ] `SSH/KeepSSHFilesByPath.toml` — Black, FilePath/Snaffle
- [ ] `SSH/KeepSSHKeysByFileExtension.toml` — Black, FileExtension/Snaffle
- [ ] `SSH/RelayPrivKeyByEnding.toml` — Green, FileName/Relay

#### PathRules/Discard (2)
- [ ] `DiscardLargeFalsePosDirs.toml` — Green, FilePath/Discard
- [ ] `DiscardWinSystemDirs.toml` — Green, FilePath/Discard

#### PostMatchRules (2)
- [ ] `DiscardPostMatchByName.toml` — Green, FileName/Discard
- [ ] `DiscardPostMatchByPath.toml` — Green, FilePath/Discard

#### ShareRules (3)
- [ ] `Discard/DiscardNonFileShares.toml` — Green, ShareName/Discard
- [ ] `Keep/KeepDollarShares.toml` — Black, ShareName/Snaffle
- [ ] `Keep/KeepSCCMShares.toml` — Yellow, ShareName/Snaffle

**Port audit asserts** (`port_snaffler_rules.py` exits non-zero on mismatch):

- Total `.toml` files: 86 (85 rule-bearing + 1 empty placeholder)
- Total `ClassifierRules` parsed: 88 (3 files contribute 2 rules each)
- Tier distribution: Black=13, Red=34, Yellow=12, Green=29
- Action distribution: Snaffle=61, Relay=19, Discard=7, CheckForKeys=1
- 5 `MatchLocation` types represented: FileName, FilePath, FileExtension, FileContentAsString, ShareName

**Gotcha — the Relay mechanic.** 18 of the 84 rules are `Relay` not
`Snaffle`. Relay does *not* flag the file; it says "this file is in
scope for further inspection by other Keep rules" — typically pairs a
filename rule with a content-pattern rule. E.g.
`PowerShell/RelayPsByExtension.toml` (Green/Relay) says "any .ps1 is
relevant to look at"; `PowerShell/KeepPsCredentials.toml` (Red/Snaffle)
then runs against the content of those .ps1 files. **Don't conflate
Green/Relay with a triage hit.** The rule engine must implement
Relay+Snaffle composition correctly or we lose recall.

**License posture.** Snaffler is GPLv3. We are porting the *rule
definitions* (regex pattern strings and filename literals from public
TOML files), not the C# runtime code. Pattern strings are not
copyrightable in any jurisdiction we operate in. Upstream attribution
lives in `src/sharesift/rules/SOURCES.md`: full URL, commit hash at
port time, license note, list of files. If Snaffler ships new rules
later, re-port and update the SHA pinning — don't drift silently.

Implementation: `tools/port_snaffler_rules.py` clones the Snaffler
repo (or fetches the TOML files via raw.githubusercontent.com), parses
each, validates against the port-audit asserts above, and emits a
single `src/sharesift/rules/snaffler_default.json`. A minimal rule
engine in `src/sharesift/rules/engine.py` evaluates rules in the
correct order: ShareRules.Discard > PathRules.Discard >
FileRules.Discard > Relay-expansion > Keep rules > tier resolution
(highest wins) > PostMatchRules.Discard.

### 2. New rules for v0.12 blind spots

Add these to ShareSift's rule set (NOT in Snaffler's default):

- `KeepWordpressConfig`: `wp-config.php` (any path)
- `KeepPhpMyAdminConfig`: `config.inc.php` (any path)
- `KeepWindowsUnattend`: `unattend.xml` regardless of enumeration path
- `KeepLaravelEnv`: `.env` not in `node_modules\`
- `KeepDockerCompose`: `docker-compose.yml` (often has secrets at top level)
- ~5-10 more from your HTB/VulnLab observation set

These are free wins — Snaffler missed them on Metasploitable, we won't.

### 3. Binary-extension preprocessor (`src/sharesift/preprocess.py`)

Before Stage 1 path scoring, drop files matching:
```
.jar .exe .dll .pdb .wim .bak .cab .zip .tar .gz .iso .vhd .vmdk
.mui .png .jpg .gif .ico .ttf .woff .woff2 .pyc .class .o .so .a
.dat .bin (when size > 1MB and no detected text encoding)
```

Rationale: these can't contain plaintext credentials but accounted
for ~80% of ShareSift's FP load on Metasploitable (GlassFish JARs,
Boxstarter EXEs, etc.). Filtering them upstream is mechanical and
free precision.

Note: `.bak` is tricky — SQL backup files DO sometimes contain text
credential dumps. Keep `.bak` UNLESS size > 5MB AND `file(1)` says
"data". Vincent's labeling memory has the bumped-Yellow call on
SQL backup directories; respect it.

### 4. Cross-check labeling pipeline (`tools/label_snaffler_hits.py`)

Adapter for the v0.14 labeling bottleneck. Reuses your existing
`claude_label.py` + `codex_audit.py` + `calibration_audit.py`
infrastructure, adapted for the `has_credential: bool` schema (vs
the existing `juicy: bool / tier: enum` schema).

Pipeline:
1. Read `data/external/<share>/ground_truth.jsonl` (Snaffler-flagged
   records from `build_msf3_ground_truth.py`)
2. For each record, present (path, Snaffler tier, Snaffler rule,
   Snaffler match snippet) to both Sonnet and Codex
3. Each model returns `{has_credential: bool, credential_type: str,
   confidence: float, reasoning: str}`
4. Disagreements (different has_credential between models) → manual
   review queue
5. Agreements with low confidence (both < 0.7) → manual spot-check
   queue
6. Agreements with high confidence → auto-accept

Expected agreement rate: 85-90% (higher than path-only labeling
because content snippet gives both models more signal). Manual
review burden: ~100-150 records per share, ~1.5 hours each.

Inherits Vincent's signed-off calibration calls from
`feedback_labeling_calibration.md` — script-on-share juicy,
known_hosts Red, sudoers Red, etc. These don't directly map to
has_credential (a script with literal credential commands IS
has_credential=true; without is false), but the underlying judgment
patterns transfer.

### 5. Ranker (`src/sharesift/ranker.py`)

Combines features into a single ordered score per file.

Feature vector per hit:
- `path_tier` (Black=3, Red=2, Yellow=1, None=0)
- `filename_rule_matched` (boolean)
- `filename_rule_tier` (same encoding)
- `content_rule_matched` (boolean)
- `content_rule_tier`
- `content_p_literal` (from v0.13 v0p7, when content was scanned)
- `path_classifier_prob` (from v0p2)
- `file_extension` (one-hot for ps1/bat/xml/yml/php/conf/ini/...)
- `path_depth` (int)
- `enclosing_dir_token_count` (hash of last 3 path components)

Model: gradient-boosted ranker (lightgbm `LGBMRanker` with NDCG@10
objective). Training data: cross-check-labeled Snaffler-hit
ground-truth from Metasploitable, with manual labels from Vincent's
disagreement review.

Output: per-file score in [0, 1]. Threshold for "flag" decision at
the operating point that matches Snaffler's recall on the labeled
training set.

### 6. Eval (`tools/eval_v0p14_vs_snaffler.py`)

Runs ShareSift v0.14 and Snaffler independently on the same share's
file list. For each tool, computes:

- Total hits flagged
- Per-file precision (TP / (TP + FP))
- Per-file recall (TP / (TP + FN))
- F1
- Per-tier breakdown
- FP distribution by file type

Then for the head-to-head:

- Files ShareSift caught that Snaffler missed
- Files Snaffler caught that ShareSift missed
- Files both caught (precision agreement)
- Files both missed (shared blind spot — these get logged for
  future spec attention)

Decision: emit "BEAT" / "TIE" / "LOST" based on the success criteria
above.

## Sequencing within v0.14

Component dependencies:

```
Snaffler rule port ──┐
New rules (blind spots) ┤
Binary preprocessor ─────┤
                         ├─→ Ranker training data ──→ Ranker ──→ Eval
Cross-check labeling ────┘                                       (v0.14 done)
v0.13 v0p7 (parallel) ───────────────────────────────────────────┘
```

Recommended week-by-week:

- **Week 1:** Port Snaffler rules. Add v0.12 blind-spot rules. Write
  binary preprocessor. Test rule engine on Metasploitable file list.
- **Week 2:** Adapt cross-check labeling pipeline. Run on Metasploitable
  Snaffler hits (already ingested via the patched `build_msf3_ground_truth.py`).
  Vincent reviews disagreements.
- **Week 3:** Ranker training + initial eval on Metasploitable. Iterate
  on feature engineering if AUC is low.
- **Week 4:** Set up GOAD eval share (or equivalent). Run full pipeline.
  Compare head-to-head.
- **Weeks 5-6:** Failure analysis + targeted fixes (likely: add more
  blind-spot rules, tune ranker threshold, address GOAD-specific FPs).

Total: 4-6 weeks. v0.13 v0p7 model arrives around week 1-2 (training
finishes ~10 hours after the scrape, which finishes ~4 hours from now).

## Success criteria (specific, measurable)

Metasploitable 3 head-to-head:
- ✓ ShareSift v0.14 recall ≥ Snaffler recall
- ✓ ShareSift v0.14 catches at least `wp-config.php` and `config.inc.php`
  (which Snaffler misses)
- ✓ ShareSift v0.14 precision ≥ Snaffler precision + 0.30 (absolute)
- ✓ ShareSift v0.14 F1 > Snaffler F1

GOAD head-to-head:
- ✓ ShareSift v0.14 recall ≥ 0.80 × Snaffler recall (no collapse)
- ✓ ShareSift v0.14 precision > Snaffler precision

If all 5 hit: v0.14 is shipped, document the win, move to v0.15 path
retrain for further generalization.

If recall hits but precision doesn't: ship as Snaffler-parity with
known precision tie, address in v0.14.1 patch.

If recall misses: debug. Likely cause is a rule port bug or an
unlabeled-training-data issue. Don't proceed to v0.15.

## Risks

1. **Rule porting introduces bugs.** Snaffler's rule semantics are
   subtle (case sensitivity, regex anchors, MatchAction precedence).
   A miss in the porting layer means we silently lose recall.
   Mitigation: side-by-side test on Metasploitable file list —
   Snaffler standalone vs ShareSift's rule engine — and assert
   per-file decisions match before adding any new rules.

2. **GOAD eval surfaces FPs we didn't anticipate.** AD-heavy shares
   have different file distributions (GPOs, SYSVOL, NETLOGON, scripts
   directories). Our binary preprocessor may not cover the right
   extensions. Mitigation: leave 1-2 weeks in the sequence for
   GOAD-specific iteration.

3. **Ranker overfit to Metasploitable.** Training the ranker only on
   Metasploitable-derived data risks learning quirks specific to that
   VM. Mitigation: include GOAD records in the ranker training set
   too (cross-check labeled), and reserve a third share for final
   eval. The third share could be a different HTB box from the v0.9
   writeup corpus that hasn't been used for any prior work.

4. **Snaffler updates its rules and we drift.** Snaffler's ruleset
   evolves. If we port at v1.4.0 and they ship v1.5.0 with new rules,
   our claim of "beats Snaffler" becomes ambiguous. Mitigation:
   pin to a specific Snaffler version (likely the head at port time)
   and document the comparison anchor.

## What v0.14 does NOT do

- Solve the corporate-share generalization problem (that's v0.15's
  path retrain with engagement+synthetic)
- Address the wp-config.php empty-password edge case (Metasploitable's
  wp-config has placeholder values — Snaffler doesn't flag, we will
  catch via filename rule, but neither catches "this is a real prod
  wp-config" without content evaluation)
- Beat Snaffler on bespoke internal corporate naming conventions
  (out of reach without engagement data)

The v0.14 win is bounded: "beats Snaffler on pedagogical-realistic +
well-deployed-open-source shares." That's a defensible win. It's not
the whole problem.
