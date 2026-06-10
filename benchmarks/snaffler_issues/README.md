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

## Probe sets — training + 3 generations of held-out

- `corpus.jsonl` (19 probes) — visible while authoring v0.47 rules.
  Use to surface gaps and validate rule semantics.
- `heldout.jsonl` (11 probes, "v1") — locked at v0.47 rule-authoring
  time. Sources: #78 (Cisco config), #135 (filezilla.xml /
  credentials.xml), #67 (SQL connection strings).
- `heldout_v2.jsonl` (10 probes) — locked at v0.48 rule-authoring
  time. Sources: #198 (CMD `set`), #155 (Azure CLI), #124 (XML
  password tag), #98 (credential filename keyword), and Chrome /
  Edge variants of #46 (browser saved creds).
- `heldout_v3.jsonl` (10 probes) — locked at v0.49 rule-authoring
  time. Sources: #154 (single-dash `-password`), #140 (Kerberos
  keytab / CCACHE / krb5cc), #139 (MDE Linux mdatp_managed.json),
  #112 (SCCM REMINST/SMSTemp/.var, Variables.dat, Policy.xml,
  SCCMContentLib$ share).

The discipline: each version locks the NEXT held-out set BEFORE
writing the rules that close the PREVIOUS one's failures. Rules
shipped in v0.N can only reference sources that were locked at or
before v0.(N-1).

If training passes 19/19 but held-out passes <50%, the rules
overfit. v0.28's falsified extension-frequency hypothesis (MSF2
top-10 0.80 → 0.40) is the precedent.

## v0.46.0 baselines

| Set | Result |
|---|---|
| corpus | 8 / 19 (42%) |
| heldout | 1 / 11 (9%) |

Held-out 9% is the honest pre-rule generalization signal —
existing cascade catches only Cisco SNMP RW (via existing
`KeepNetConfigCreds`).

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
