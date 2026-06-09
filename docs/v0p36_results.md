# v0.36 results — Snaffler displacement begins

Released 2026-06-09. v0.35 made ShareSift remote-share-addressable —
operators can point it at a UNC without mounting CIFS. v0.36 makes
the case that ShareSift is unambiguously better than Snaffler at
the finding job: more rules covering modern credential surfaces,
smarter triage on PPK files, correct R/W reporting on shares, and
drop-in compatibility with the Snaffler downstream-tool ecosystem
(SnafflerParser / Efflanrs / Parsler / snafflepy).

## Headline

| Dimension | Snaffler | v0.35 | v0.36 |
|---|---|---|---|
| Default rule count | 89 | 137 | **144** |
| Modern cloud-credential rules (2023-2026 surface) | minimal | partial | full |
| `.ppk` encryption-aware triage | ✗ #191 open | ✗ | ✅ |
| Correct share R/W reporting | ✗ #184 open | n/a | ✅ |
| Snaffler-output ecosystem (SnafflerParser/Efflanrs/Parsler) | native | ✗ | ✅ drop-in |
| 20 live credential verifiers | ✗ | ✅ | ✅ |
| SMB-direct (no mount required) | n/a (.NET-on-Windows native) | ✅ | ✅ |
| Tests passing (no flag) | n/a | 993 | **1069** |

## Audit finding — the rule-coverage gap was inverted

The biggest surprise of the release was the rule audit. The earlier
framing assumed ShareSift was missing rules vs Snaffler. The actual
state:

- Snaffler upstream: **89 rules** (only 1 added since our June 2026 pin
  — and that one is an empty placeholder file)
- ShareSift ported: **88 of Snaffler's rules**
- ShareSift extras: **49 modern-credential rules** that Snaffler doesn't
  ship at all (AWS CLI, GCP gcloud, GitHub CLI, K8s, .env variants,
  Docker compose, Rails, Laravel, WordPress, phpMyAdmin, AI service
  keys: Anthropic, OpenAI, Hugging Face, AWS Bedrock, Databricks,
  GitLab PAT, ClickHouse Cloud, Render, Perplexity, Datadog, Dropbox,
  Fastly, Netlify, and more)
- v0.36 additions: **+7** for the remaining 2023-2026 surface
- Total ShareSift rules: **144 vs Snaffler's 89** — 1.6× coverage

The marketing claim changes from "we match Snaffler's rules" to
"we exceed Snaffler's coverage by 1.6×, including 56 modern
credential surfaces Snaffler doesn't catch at all."

## What shipped

### Step 1 — modern credential rule backfill (+7 rules)

| Rule | Tier | Surface |
|---|---|---|
| `ShareSiftKeepTerraformState` | Red | `.tfstate` / `.tfstate.backup` — GitGuardian-flagged 2025 |
| `ShareSiftKeepVaultToken` | Black | `~/.vault-token` HashiCorp Vault bearer |
| `ShareSiftKeepPulumiCredentials` | Black | `~/.pulumi/credentials.json` |
| `ShareSiftKeepTerraformCloudCredentials` | Black | `~/.terraform.d/credentials.tfrc.json` |
| `ShareSiftKeepAzureModernCliCache` | Black | post-2023 `az login` MSAL cache + service principals + legacy `accessTokens.json` |
| `ShareSiftKeepAwsSsoCache` | Red | `~/.aws/sso/cache/*.json` — RedCanary 2024 attack pattern |
| `ShareSiftKeepAnsibleVaultHeader` | Yellow | files starting with `$ANSIBLE_VAULT;X.Y;AES256` |

Each rule carries positive + negative cross-distribution tests
following the v0.30 pattern. 29 new tests; all pass first run.
False-positive guards cover `.terraform.lock.hcl`, `.vault/config`,
bare `credentials.json` outside `.pulumi/`, `.azureml/`,
`.aws/credentials` (the existing AWS CLI rule), and YAML files
that mention but don't start with the Ansible Vault header.

### Step 2 — PPK encryption-aware tiers (Snaffler #191)

Snaffler issue #191 documented the volume problem: every `.ppk`
file ends up in the high-priority queue, but most are passphrase-
protected and not actionable without the passphrase. ShareSift now
distinguishes the two:

- Any `.ppk` extension → Yellow (visible but lower priority)
- `.ppk` with `Encryption: none` in content → Black (immediate grab)

The Snaffler-ported `KeepSSHKeysByFileExtension` (the only rule
covering `.ppk`) was demoted from Black to Yellow as the floor;
the new `ShareSiftKeepPuttyPpkUnencrypted` content rule promotes
when the encryption status is confirmed plaintext via the file's
header + `Encryption: none` field within 500 chars.

11 tests, all pass. False-positive guards: non-PPK file with
`Encryption: none` somewhere in content, distance >500 chars
between header and encryption field, `.ppk` extension on a file
that isn't actually a PPK.

### Step 3 — share-level R/W access probe (Snaffler #184)

Snaffler reports writable shares as `R` (read-only) due to a bug
in its effective-access calculation. The bug is open as #184 with
no shipping fix. ShareSift probes both rights explicitly via two
cheap SMB2 CREATE round-trips on the share root:

- Read probe: open share root with `FILE_LIST_DIRECTORY`
- Write probe: open share root with `FILE_ADD_FILE`

The server returns `STATUS_ACCESS_DENIED` when a request would
have been refused. Non-destructive (no file is created or
modified) and indistinguishable from normal SMB access pattern on
the wire.

Surface:

- `ShareAccess(can_read, can_write)` dataclass with `.display`
  property → `"R"` / `"RW"` / `"W"` / `"-"`
- `SmbShare.probe_share_access()` — idempotent, cached
- `cmd_scan` auto-probes after auth, logs result during enumeration
- `--check` mode: `auth ok; tree-connected to \\host\share [RW]`
- Scan summary JSON gets a `share_access` field

12 tests + live smoke against `dperson/samba` confirmed.

### Step 4 — Snaffler-compatible TSV output

New subcommand `sharesift to-snaffler-tsv` emits the 11-column
line format Snaffler emits with `-y`, matching exactly the format
that SnafflerParser, Efflanrs, Parsler, and snafflepy already
parse. Operators don't have to choose between ShareSift's finding
capability and Snaffler's downstream-tool ecosystem.

Workflow:

```bash
sharesift //10.10.10.5/Finance$ -u user -p pass
sharesift to-snaffler-tsv < ./sharesift-10.10.10.5-Finance$/hits.jsonl \
    > scan.snaf.tsv
# scan.snaf.tsv ingested by Efflanrs / SnafflerParser unchanged
```

The format is what `SnaffleRunner.cs::FileResultLogFromMessage`
emits:

```
<ts>[File]<sep><triage><sep><rule><sep><R><sep><W><sep><M><sep><matched><sep><size><sep><modified><sep><path><sep><altname><sep><context>
```

Field mapping from ShareSift records:

- triage: highest tier from `content_matches` → `content_tier` → `path_tier`
- rule: first content match's rule name, or `Parser:<name>` for
  parser-extracted creds, or `PathClassifier` for path-only
- R: always set (we read the file to score it)
- W/M: empty (TSV per-file plumbing is a follow-on commit)
- size + modified: `os.stat()` lookup for local paths; empty for
  UNC paths (SMB session is closed post-scan)
- matched + context: from `content_matches[0]`; truncated, newlines
  escaped to `\n`, control chars stripped, embedded tabs replaced
  with space

24 tests, all pass.

## What didn't ship

**Step 5 — TOML rule format.** Converting JSON rule files to TOML
+ updating the engine loader to accept either format. ~1-2 days
of work because of the test surface. Bundles into v0.37 alongside
the multi-threaded SMB walk + network-wide share discovery work
— thin release on its own.

**Per-file R/W in Snaffler-TSV.** The share-level verdict is
already known (v0.36 step 3); plumbing it into per-record output
so the TSV W/M columns get filled is a small follow-on commit. The
TSV docstring documents the limitation.

## Sprint accounting

| Step | Status | Tests added |
|---|---|---|
| 1 — modern credential rule backfill | ✅ | +29 |
| 2 — `.ppk` encryption-aware tiers | ✅ | +11 |
| 3 — share-level R/W probe | ✅ | +12 |
| 4 — Snaffler-compatible TSV output | ✅ | +24 |
| 5 — TOML rule format | deferred to v0.37 | — |

**1069 passing total**, 29 skipped (21 SMB-gated + 8 pre-existing),
0 regressions. All four landed steps include positive +
negative test coverage following the project pattern.

## What's queued

| Release | Theme |
|---|---|
| v0.37 | Speed + distribution: concurrent SMB reads (multi-threaded walk), network-wide share discovery, TOML rule format, `pipx install`, PyInstaller single-file binary |
| v0.38 | Engagement-shape: SQLite engagement datastore (smbcrawler-style), resume after crash, content-hash dedup, GhostWriter / SysReptor exporters |
| v0.39+ | OpSec polish: noise exclusions, `--max-file-size` + chunked reads, `--stealth` preset, status heartbeat, Markdown report bundle |

Full backlog: `docs/pentester_backlog.md`.

## Meta

v0.35 made the operator-side install friction-free. v0.36 makes
the actual finding job demonstrably better than Snaffler — more
rules, smarter triage, correct R/W, ecosystem-compatible output.

The headline shift is from "ShareSift is a research tool with
methodology rigor" (v0.22-v0.34) to "ShareSift catches modern
credentials Snaffler doesn't, triages smarter on credential types
Snaffler triages noisily, gets share permissions right where
Snaffler gets them wrong, and slots into existing operator
tooling without code changes."

The MIN top-10 = 0.20 / MIN recall = 0.90 chart stays flat. The
operator-facing capability matrix changed substantively.
