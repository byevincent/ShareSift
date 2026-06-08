# v0.28 results — falsified hypothesis (the discipline working)

Released 2026-06-08. **The interesting thing about this release is
what didn't ship.** A declarative fix that looked obvious by analogy
to v0.22's filename-frequency penalty turned out to be wrong-shaped
when measured against the v0.27 three-set harness. The discipline
caught it; we backed out instead of iterating against the data.

## Headline (held)

| Metric | v0.27 | v0.28 |
|---|---|---|
| MIN top-10 precision (primary) | 0.20 | 0.20 |
| MIN recall any-tier (primary) | 0.90 | 0.90 |

```
v0.22.0     ▇▇░░░░░░░░ 0.20     ▇▇▇▇▇▇▇▇▇░ 0.90
v0.23.0     ▇▇░░░░░░░░ 0.20     ▇▇▇▇▇▇▇▇▇░ 0.90
v0.24.0     ▇▇░░░░░░░░ 0.20     ▇▇▇▇▇▇▇▇▇░ 0.90
v0.25.0     ▇▇░░░░░░░░ 0.20     ▇▇▇▇▇▇▇▇▇░ 0.90
v0.26.0     ▇▇░░░░░░░░ 0.20     ▇▇▇▇▇▇▇▇▇░ 0.90
v0.27.0     ▇▇░░░░░░░░ 0.20     ▇▇▇▇▇▇▇▇▇░ 0.90  ← 3 primary sets
v0.28.0     ▇▇░░░░░░░░ 0.20     ▇▇▇▇▇▇▇▇▇░ 0.90
```

## The hypothesis (pre-registered)

v0.27 surfaced that MSF3's 0.20 top-10 floor is share-specific
(Windows + PowerShell saturation), not pipeline-shaped — MSF2 hits
0.80 on the same pipeline.

v0.28's hypothesis: **shares dominated by a single file extension
carry less per-file unique signal at that extension**. By analogy
to the v0.22 filename-frequency penalty
(`score / sqrt(filename_freq)`), add an extension-frequency divisor
(`score / sqrt(extension_freq)`) to push down high-extension-count
files (84% of MSF3 is `.ps1`) without affecting minority-extension
positives.

Pre-registered prediction (written before the harness ran):

| Set | Expected |
|---|---|
| MSF3 | Top-10 improves from 0.20 |
| MSF2 | Holds or slightly improves |
| CredData | Unchanged (content cascade, no path features) |

## What actually happened

| Set | Top-10 before | Top-10 after | Δ vs prediction |
|---|---|---|---|
| MSF3 | 0.20 | **0.10** | **wrong direction** — drop, not gain |
| MSF2 | 0.80 | **0.40** | **wrong direction** — major drop |
| CredData | 0.70 | 0.70 | matched |
| **MIN** | **0.20** | **0.10** | overall regression |

## Why the hypothesis failed

The implicit assumption was "credential files cluster in minority
extensions." That's true on Windows + dev shares (the v0.19 themed
shares had credentials in `.env`, `.pem`, `.kdbx` — all minority).
It is **not** true on Linux server shares:

| Linux credential file type | Typical extension |
|---|---|
| MySQL configs | `.cnf` (common — every install has one) |
| ProFTPD / vsftpd / Asterisk / Samba / OpenLDAP configs | `.conf` (very common) |
| DVWA / TikiWiki / phpMyAdmin configs | `.inc.php` or `.php` (common in web apps) |
| Apache htpasswd | `.htpasswd` (less common) |
| SSH host keys | no extension |
| /etc/shadow, /etc/passwd, /etc/gshadow | no extension |

The penalty pushed `.conf` / `.cnf` / `.php` credential files DOWN
because they live in the busy parts of the Linux filesystem. The
no-extension ones (`/etc/shadow`) were unaffected. Net result:
real credentials lost their top ranking; precision tanked.

The principle "minority-extension = credential" was empirically a
Windows + dev assumption, not universal. v0.22 dodged this because
it only had the MSF3 + CredData benchmarks at that point and the
filename-frequency penalty's mechanism (specific file names
repeated dozens of times) was a genuinely-universal pattern.

## The discipline working

What the discipline gave us:

1. **A trustworthy "no"**. MIN regressed; the eval gate would have
   flagged this in CI. We didn't argue with the data.
2. **No iteration against the harness.** A tempting move would be to
   tune the penalty (use cube-root instead of sqrt, cap at 4×,
   exempt certain extensions) until MIN climbed. That's exactly the
   overfitting v0.22 prohibited. We backed out instead.
3. **A new measured fact about real shares**. We now know that
   "extension distribution heaviness" is a Windows-vs-Linux signal,
   not a credential signal. That's useful for v0.29+ thinking even
   though it doesn't ship anything today.

What the discipline cost:

1. The MSF3 floor stays where it is. 0.20 is still the honest top-10.
2. We don't get the satisfaction of moving the trajectory chart
   upward this release. v0.28 ships a flat-line.

That's the tradeoff every honest release will have. Flat
trajectories aren't failures; they're the prior we operate under
when we're not allowed to manufacture an improvement.

## What did ship

The backout itself (`tools/eval_harness.py` reverted to the v0.22
filename-frequency-only scoring) plus this writeup. Code change is
net-zero from v0.27.

The comment on `_score_with_dedup_penalty` now documents the
failed hypothesis so a future contributor reading "what about
adding extension penalty too?" sees the answer before re-running
the experiment.

## What stays open for v0.29+

The MSF3 floor is still 0.20. Honest paths forward:

| Option | Versatile? | Risk |
|---|---|---|
| **A.** Accept 0.20 as the Windows-share floor; report cross-set MIN as 0.20 forever. | ✅ | Loses information value — "this number means MSF3 is hard" stops surfacing |
| **B.** Find a different declarative pattern (path-depth penalty? directory-name penalty? something MSF3-specific that's also universal?). | Maybe — needs same pre-registration + harness test discipline. | Most candidate ideas die the same way the extension penalty did. |
| **C.** Acquire more held-out Windows shares (DC-1 is Linux; Mr-Robot is Linux; we'd need Windows-shaped lab data). MSF2-style discipline. | ✅ — same labeling approach | Time. |
| **D.** Stage 1 path classifier retrain — but ONLY on data that's NOT MSF3 and with a held-out test on MSF3. v0.22 disallowed retrains for overfitting reasons; the carve-out would be "retrain on diverse non-test data, never on the held-out set itself." | Conditional | Most rigorous available option but takes engineering time + GPU. |

I'd rank C > D > B > A. **C is the most informative** — until we
know whether v0.27's "MSF3 is share-specific" finding holds across
multiple Windows shares, the floor's interpretation is partly
guesswork. Acquiring another Windows-shaped held-out set would
turn "MSF3 is hard" into either "MSF3 is uniquely hard" or
"Windows shares with PowerShell heavy distributions are hard."
The first is fine; the second deserves D.

## Sprint accounting

| Sprint | Status |
|---|---|
| 1 — implement extension-frequency penalty | ✅ implemented |
| 2 — re-run harness on 3 primary sets | ✅ ran; pre-registration violated |
| 3 — decision: ship or back out | ✅ backed out (-10 pp MIN regression) |
| 4 — production cascade adoption | ❌ no — change failed discipline |
| 5 — Azure storage verifier (carryover) | ❌ deferred to v0.29 — falsified-hypothesis writeup is the v0.28 story; Azure would dilute the message |
| 6 — ship + document | ✅ this doc |

## Tests

Full suite unchanged: 821 passing, 8 skipped. The backout reverted
to the v0.22 scoring; no test changes needed.

## What's queued for v0.29

| Item |
|---|
| **C.** Acquire another Windows-shaped held-out share (look for VulnHub Windows VMs; SecMicro / Hackable III / etc. — or pull one from a non-Metasploitable lab) |
| Azure storage account verifier (the v0.26 carryover that got bumped here) |
| GCP service-account verifier |
| Registry hive parser when samples accessible |
| Stage 2 LoRA cross-distribution eval when weights tracked |

## Meta

v0.28 is the first release where the discipline produced a clear
"we tried something and it didn't work." That's structurally
important. A track record of "every release moved the number up"
would tell you the eval gate isn't catching anything. A track
record of "5 releases flat, 1 release where we tested an
idea and rolled it back" tells you the gate IS catching things —
and that we're willing to ship the no-op when honesty demands it.

The v0.28 trajectory entry says: **at 7 releases of honest
measurement, MIN is still 0.20 / 0.90, and we have a documented
list of declarative fixes that the data rejected.** That's
information that compounds.
