# Snaffler issue-tracker benchmark

Synthetic-but-grounded benchmark mined from 198 issues + PRs in
[SnaffCon/Snaffler](https://github.com/SnaffCon/Snaffler). The
premise: real corporate SMB shares are NDA-walled, but five years
of Snaffler bug reports are the closest free proxy. Each
"Snaffler missed X" issue is a real-world false negative an
operator filed against the tool; each "Snaffler false-positived Y"
is a real-world FP.

## Pipeline

1. `tools/mine_snaffler_issues.py` — fetches all issues + comments
   via `gh api`. Output: `raw/issues.json`, `raw/comments/*.json`.
2. `tools/bucket_snaffler_issues.py` — heuristic-classify by
   signal type (miss/fp/feat/bug/q/unk). Stdout: triage TSV.
3. Hand-curated `corpus.jsonl` — one probe per line. Format:

   ```json
   {
     "id": "snaffler-46-firefox-logins",
     "source_issue": "https://github.com/SnaffCon/Snaffler/issues/46",
     "signal_type": "miss",
     "probe_type": "path",
     "path": "...",
     "expected_tier": "Black",
     "expected_rule_hint": "firefox-saved-passwords",
     "notes": "..."
   }
   ```
4. `tools/eval_snaffler_issues.py` — scores ShareSift cascade vs
   each probe. Path probes go through `PathClassifier`; content
   probes go through `ContentRuleEngine`.

## Current state (v0.46.0 baseline)

19 probes — 18 miss + 1 fp. **8 pass, 11 fail.**

The 11 failures are the v0.47 rule-addition target list. Grouped
by engagement impact:

| Priority | Probe | Why fails today |
|---|---|---|
| **Critical (AD)** | GPP Groups.xml | Path classifier scores 0.029 on sysvol Preferences path; no content rule for `cpassword` |
| **Critical (browser)** | Firefox `logins.json` (Win + Linux) | Path classifier scores 0.21-0.33; no rule for browser saved-password file |
| **High (Euro corp)** | German keywords (Passwoerter, Anmeldedaten, Kennwoerter) | English-trained model returns ~0.0; no German keyword rules |
| **Medium (modern VPN)** | WireGuard `PrivateKey`, AnyConnect XML | No content rule for WG; no path rule for AnyConnect profile |
| **Medium (mail)** | .eml content scan | No .eml extension extractor, content engine never sees the body |
| **Low (regex)** | OpenVPN `auth-user-pass`, `--passphrase=` flag | Existing rules catch the file but not the credential reference inside |

Each failure cites a real Snaffler issue number. The benchmark is
self-documenting: every probe's `notes` field explains why an
operator cared about this specific case.

## Why this matters

This is the first corporate-SMB benchmark we have grounded in real
operator complaints. MSF3 / DiskForge / Govdocs1 / Enron are all
synthetic substrates; this corpus is synthetic content built from
real authority claims ("operator filed bug saying Snaffler missed
X on a real engagement").

Score progression over time becomes a credible
"are-we-closing-the-gap-with-Snaffler-on-corporate-shares?" metric.
v0.46 baseline: 8/19 (42%). v0.47 target: 19/19.
