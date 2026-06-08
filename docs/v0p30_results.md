# v0.30 results — parser-without-rule gap closed

Released 2026-06-08. Closes the gap surfaced by v0.29's DiskForge
benchmark (the `.pypirc` plant the cascade missed because we had
a parser for it but no rule). The benchmark loop working as designed:
**v0.29 surfaced a problem → v0.30 fixed it.**

## Headline (DiskForge moves up, primary MIN unchanged)

| Metric | v0.29 | v0.30 | Δ |
|---|---|---|---|
| MIN top-10 (primary) | 0.20 | 0.20 | 0 |
| MIN recall (primary) | 0.90 | 0.90 | 0 |
| DiskForge recall (supp) | 0.917 | **1.000** | **+8.3 pp** |
| DiskForge top-10 (supp) | 0.50 | 0.60 | +10 pp |
| MSF3 / CredData / MSF2 | unchanged | unchanged | 0 — new rules don't FP cross-distribution |
| Engine rule count | 120 | **128** | +8 |

## What got added

8 declarative rules in `src/sharesift/rules/extra_rules.json`, one
per v0.24-v0.26 parser family that lacked a paired filename rule:

| Rule | Match shape | Tier | Targets |
|---|---|---|---|
| `ShareSiftKeepPypirc` | FileName Exact `\.pypirc`, `pypirc` | Red | v0.25 pypirc parser |
| `ShareSiftKeepNetrc` | FileName Exact `\.netrc`, `_netrc` | Red | v0.24 netrc parser |
| `ShareSiftKeepGcloudCredentials` | FileName Exact `application_default_credentials.json`, `adc.json`, `credentials.db.json` | Black | v0.25 gcloud_credentials parser |
| `ShareSiftKeepKeyringFile` | FileName Exact `keyring_pass.cfg`, `keyring_cryptfile_pass.cfg`, `keyringrc.cfg` | Red | v0.25 keyring_credentials parser |
| `ShareSiftKeepAwsCliCredentialsByPath` | FilePath Contains `.aws/credentials`, `.aws/config` | Black | v0.24 aws_cli_credentials parser |
| `ShareSiftKeepMavenSettingsByPath` | FilePath Contains `.m2/settings.xml`, `apache-maven/conf/settings.xml` | Yellow | v0.24 maven_settings_xml parser |
| `ShareSiftKeepGhCliConfigByPath` | FilePath Contains `.config/gh/hosts.yml(.yaml)` | Red | v0.25 gh_cli_config parser |
| `ShareSiftKeepPuttyPpkByExtension` | FileExtension Exact `\.ppk` | Red | v0.26 putty_ppk parser |

## Discipline notes on the rule choices

1. **Filename-distinctive vs path-context.** `.pypirc` / `.netrc` /
   `application_default_credentials.json` / `keyring*.cfg` / `.ppk`
   are distinctive enough as bare filenames — no path context
   needed. They aren't going to false-positive on a Linux server
   share or a source-code corpus.
2. **Generic filenames require path context.** `credentials` /
   `settings.xml` / `hosts.yml` are too ambiguous as bare
   filenames (`credentials` could be anything; `settings.xml` is
   used by VS Code, many .NET projects, IIS; `hosts.yml` is the
   Ansible inventory default). The rules require their
   identifying directory context (`.aws/`, `.m2/`,
   `.config/gh/`) so they fire on the credential-bearing
   locations specifically and skip the look-alikes.
3. **The harness confirms.** MSF3 + MSF2 + CredData unchanged
   means the new rules don't false-positive on Linux server
   filesystems or source-code corpora. If they HAD started
   tripping on bare `credentials` files in `/etc/squirrelmail/`
   or `settings.xml` in `/etc/`, the precision regression would
   have shown up on those primary sets.

Tests assert both behaviors:
- `test_aws_cli_credentials_path_rule_fires` — rule fires on the right path
- `test_aws_cli_credentials_does_not_fire_on_bare_credentials_filename` — rule does NOT fire on `/home/alice/Documents/credentials`
- `test_maven_settings_xml_does_not_fire_on_vscode` — rule does NOT fire on `.vscode/settings.json`
- `test_gh_cli_hosts_yml_does_not_fire_on_ansible_inventory` — rule does NOT fire on `/etc/ansible/hosts.yml`

## What this means structurally

Before v0.30, the cascade had **18 structured parsers** that could
extract content from credential-bearing files — but **only 8 of
them had paired filename rules** in the engine. The other 10
parsers contributed nothing to path-only enumeration. v0.30 closes
8 of those gaps. The remaining 2 parsers (`web_config`,
`docker_config_json`) are already covered by Snaffler default
rules.

In retrospective terms: the parsers and rules were two parallel
detection mechanisms that grew without explicit coordination.
v0.29's DiskForge benchmark surfaced the lack of coordination as
a concrete recall miss; v0.30 added the bridge.

## Tests

| Component | Tests added |
|---|---|
| 8 new rules — each tested for firing on its intended path AND not firing on look-alike paths | 12 |

Full suite: **833 passing**, 8 skipped (was 821 — +12 new, 0 regressions).

## Sprint accounting

| Sprint | Status |
|---|---|
| 1 — Identify the v0.29 gap | ✅ (.pypirc miss on DiskForge) |
| 2 — Design 8 rules with path-context where filename alone is too ambiguous | ✅ |
| 3 — Add tests for both firing AND not-FP-on-look-alikes | ✅ 12 tests |
| 4 — Re-run harness; confirm MSF3/MSF2/CredData unchanged | ✅ no cross-distribution regression |
| 5 — Ship | ✅ this doc |

## What's queued for v0.31

| Item | Status |
|---|---|
| Generate a larger DiskForge image (more negatives → realistic density) so it can be promoted to primary | Bigger lift |
| Azure storage account verifier (4-release carryover) | Small declarative |
| GCP service-account verifier (4-release carryover) | Small declarative |
| Registry hive parser when samples accessible | Needs samples |

## Meta

v0.30 is what a release should look like:
- A benchmark identified a problem
- The fix was declarative (no training, no benchmark tuning)
- The fix was tested for both intended behavior AND for not introducing
  cross-distribution regressions
- The harness confirmed both
- The release shipped

The trajectory chart still says 0.20 / 0.90 on primary. DiskForge
recall hit 1.00 — but that's supplementary, and DiskForge being
perfect on a 28%-positive-density planted benchmark isn't a
headline. The honest headline stays the cross-distribution MIN.

What we DID gain: the parser-rule architecture is now coherent.
Every v0.24-v0.26 parser has a paired rule. Future parser additions
will follow the pattern: parser + rule together, or document why the
filename is too ambiguous and the rule should be content-based.
