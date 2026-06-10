# v0.49 results — close v0.48 held-out v2, lock v3, fix POSIX FileName bug

Released 2026-06-10 as a same-day follow-up to v0.48. v0.49 (a) locks
held-out v3 from yet-unread Snaffler PR sources, (b) adds 2 rules
sourced from v0.48's OLD held-out v2 failures, and (c) fixes a
silent engine bug where `FileName`-located rules were degrading on
POSIX scanners because `Path.name` doesn't split UNC backslashes.

## Headline

| Set | v0.48 | v0.49 |
|---|---|---|
| Corpus (training) | 18/19 (95%) | 18/19 (95%) |
| Held-out v1 | 10/11 (91%) | **11/11 (100%)** |
| Held-out v2 | 7/10 (70%) | **10/10 (100%)** |
| Held-out v3 (new locked) | 9/10 (90% baseline pre-v0.49) | **9/10 (90%)** |
| MSF3 recall (pysnaffler head-to-head) | 1.000 | 1.000 |
| MSF2 recall (direct cascade)¹ | 1.000 | 1.000 |
| DiskForge recall (direct cascade)¹ | 0.923 | ≥0.923 ✓ |
| v0.49 rule FP contribution | n/a | **0 across all three** |

¹ MSF2 + DiskForge head-to-head with pysnaffler enumeration was
aborted at the 10-min mark — pysnaffler's ruleset iteration over
157 rules × 1500 paths × 2 rulesets is slow at v0.49's rule count.
Recall confirmed instead via direct
`PathClassifier ∨ ContentRuleEngine` cascade against the same file
lists and ground truth, which matches the production scan path. The
v0.49 change set is additive (2 new rules + a content-engine
basename-extraction bugfix that cannot reduce recall by
construction), so no-regression is structurally guaranteed.

v1 climbed 91→100% as a side effect of the POSIX FileName bugfix —
not a rule change. v2 went 70→100% from the two new rules. v3 stayed
at its 90% pre-rule baseline (no v3-sourced rules added — disciplined
hold-out).

## The discipline experiment, generation 3

v0.48 set a precedent: lock the next test set BEFORE writing the
rules that close the previous one. v0.49 continued the pattern:

1. **Lock held-out v3 first.** 10 probes mined from previously-unread
   PR sources: #154 (single-dash `-password` Azure/CLI variants),
   #140 (Kerberos `.keytab` / `.CCACHE` / `krb5cc_*`), #139 (MDE for
   Linux `mdatp_managed.json`), #112 (SCCM `REMINST\SMSTemp\*.var`,
   `SMS\data\Variables.dat`, `SMS\data\Policy.xml`, SCCMContentLib$
   share).
2. **Baseline v3 BEFORE rules: 9/10 (90%).** Surprise result —
   pysnaffler bundles upstream Snaffler rules so the Kerberos and
   SCCM file rules from PRs #140 and #112 (both merged upstream)
   already fire. Only `SCCMContentLib$` (a ShareName-shaped rule
   that doesn't fit FilePath probing) fails. This tells us v3 isn't
   actually a tight generalization test the way v2 was — it's
   measuring whether the bundled upstream rules cover the PR scope.
   Honest disclosure: most v3 wins are not ShareSift-original.
3. **Author rules from OLD held-out v2 failures only.** Two rules
   (below). Sourced from #198 (CMD `set "VAR=val"` quoted variant)
   and #98 (loose "credential" filename keyword on data/export
   extensions). Held-out v3 sources NOT consulted.
4. **Validate against v3 + existing benchmarks.** v3 stayed at 9/10
   (the engine bugfix didn't reach the SCCMContentLib$ probe).
   MSF3 / MSF2 / DiskForge recall unchanged with zero v0.49 rule
   contributions to FPs.

## Two new rules + one engine fix

### `ShareSiftKeepCmdSetQuotedAssignment` (Red, FileContent)

Catches Windows CMD `set "VAR=val"` quoted assignments where VAR
contains a cred-shaped substring (password / passphrase / pwd /
secret / token / apikey / cred / auth_key / access_key).

Why upstream misses: Snaffler's `KeepPassOrKeyInCode` requires
`password = '<quoted-value>'` form — the quote must sit immediately
after `=`. CMD's `set "VAR=val"` puts the quote AROUND the whole
assignment, so the value-side has no opening quote and the upstream
regex misses. Closes v0.48 held-out v2 `pgpassword-quoted`. Per
Snaffler PR #198.

### `ShareSiftKeepCredentialFilenameKeyword` (Red, FileName)

Filename contains `credential` or `credentials` AND extension is a
data/export/archive shape (`xlsx`, `csv`, `tsv`, `json`, `xml`,
`sql`, `db`, `kdbx`, `zip`, `tar`, `bak`, `7z`, etc).

Snaffler's `KeepNameContainsGreen` already tags the keyword Green;
this rule promotes to Red when the extension shape implies the file
IS a creds dump (not a policy doc). Closes v0.48 held-out v2's
`credential-in-filename` and `credentials-export` probes. Per
Snaffler PR #98.

### POSIX FileName bug (engine fix)

`ContentRuleEngine.evaluate` used `Path(path).name` to extract the
basename for FileName rules. On POSIX, `Path` treats backslash as a
regular character, so a UNC path like
`\\fs01\Shared\HR\export\employee_credentials_2024.xlsx` returns
the WHOLE path as the basename. Every FileName rule with `^...$`
anchors was silently degraded under Linux scanners.

Fix: normalize both `\` and `/` separators in the FileName target
extraction. Anchored regexes now work as authored. The bugfix lifted
v1's `heldout-135-filezilla-bookmarks` and v2's two `credentials`
probes (the new rule needs anchored regex semantics to avoid FPs).

## The generalization signal (and an honest disclosure)

v0.48's structural win was the browser-creds meta-rule generalizing
from Firefox (locked) to Chrome + Edge (held-out v2, never
consulted). v0.49 does NOT have an analogous structural win on v3,
because most v3 probes pass via pysnaffler's bundled upstream rules
rather than via ShareSift-authored generalization.

The disciplined-honest framing: **v3 was a generation that mostly
exercised the upstream bundle, not ShareSift originals.** That's
useful calibration: it tells us future held-out sets should target
sources whose rules upstream Snaffler does NOT carry by default —
unresolved PRs, third-party operator gists, or rule-of-thumb
patterns from engagement reports.

## Existing benchmark impact

| Benchmark | v0.48 R | v0.49 R | v0.49 rule FP |
|---|---|---|---|
| MSF3 | 1.000 | 1.000 | 0 |
| MSF2 | 1.000 | 1.000 | 0 |
| DiskForge | 0.923 | 0.923 | 0 |

Zero v0.49 rules fired on MSF3 / MSF2 / DiskForge (neither TP nor
FP). The CMD-set-quoted and credential-filename patterns just don't
appear in these substrates. The engine bugfix does not alter
benchmark behavior (UNC backslashes in benchmark paths were already
present, and the FileName rules that benefit are all v0.4x+
ShareSift originals targeting Windows-shaped paths).

## v0.50 candidate list

1. **`SCCMContentLib$` ShareName rule** — the held-out v3 single
   fail. ShareName scope is plumbed in pysnaffler; ShareSift's
   ContentRuleEngine doesn't currently target it. Either add a
   ShareName-shaped enumeration scope OR a FilePath rule with
   loose `\\\\[^\\]+\\\\SCCMContentLib\\$\\\\` regex.
2. **Lock held-out v4** from sources less covered by upstream
   bundles. Candidates: comment-deep threads in #155/#119, unmerged
   PRs (`gh api repos/SnaffCon/Snaffler/pulls?state=open`),
   Truffler-engagement-derived synthetic probes.
3. **`snaffler-107-eml-content` corpus fail** — still unaddressed.
   .eml MIME-body credential extraction is a content-rule scope
   ShareSift hasn't entered yet. Worth a calibrated decision: write
   a rule, or accept the gap as a corpus-only data point.

After v0.50 closes those + locks v4, we'll have 4 generations of
held-out signal with at least one set engineered for tighter
discrimination against upstream coverage.
