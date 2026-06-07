# Pattern Taxonomy

**Status:** v1, approved 2026-05-17. Synthesized from Snaffler's `DefaultRules/` (86 TOML rules) and Kingfisher's `crates/kingfisher-rules/data/rules/` (583 YAML rules).

## How to read this

Two orthogonal axes:

- **Family** describes *what kind of finding* it is (a private key, a database dump, a token).
- **Tier** describes *how we detect it* — regex, ML, or hybrid.

These are independent. A family is about finding type; a tier is about detection method.

### Detection tiers

- `regex` — a hand-written pattern catches it cleanly (extension, distinctive token prefix, exact filename). ML adds little.
- `ML` — pattern matching is brittle here. Correct triage needs surrounding context (filename, file type, neighboring lines, whether it's a test fixture, doc, or real config). These are where ShareSift should beat Snaffler.
- `hybrid` — regex catches the artifact; ML extends coverage (catching patterns regex can't see) *and/or* denoises (suppressing matches that regex can't tell apart from real findings). Each hybrid family lists which role the ML layer plays.

### Severity tiers (for the eval set `tier` field)

Snaffler-style 4-tier severity, used in eval labels:

- **Black** — credential material with immediate authentication value (raw private keys, NTDS.DIT, cleartext passwords in IaC state).
- **Red** — high-value indirect access (cloud IAM tokens, SaaS API keys, vault files where the key is recoverable).
- **Yellow** — interesting context that often leads somewhere (config files with weak protection, IaC files, network device configs, sealed vaults).
- **Green** — low-value but worth surfacing (filename signals, possibly-sensitive business docs, dotfiles).

### v0 scope

**Windows-only.** Patterns that primarily surface on Linux/macOS shares (`~/.ssh/` directories, `/etc/` configs) are still in the taxonomy but deprioritized in eval. Re-scope at week 4.

### Provenance markers

- ★ **modern gap** — Kingfisher covers this and Snaffler does not. These are the strongest argument for replacing Snaffler's ruleset.

Tiering is a hypothesis to test against the eval set, not a final assignment.

## Families

### 1. Private keys & raw X.509 material

- **Slug:** `private_keys_x509`
- **Tier:** regex
- **Severity bias:** Black
- **Examples:**
  - Unencrypted PEM/DER: `.pem`, `.der`, `.key`
  - Java keystores: `.jks`, `.keystore`
  - Content header: `-----BEGIN (RSA|EC|DSA|OPENSSH|PGP) PRIVATE KEY-----`
  - GPG keyrings: `secring.gpg`
- **Scope note:** Encrypted PKCS#12 (`.pfx`, `.p12`) is in `credential_containers` — different operator workflow (crack-then-use vs. import-and-use).
- **Source:** Snaffler `FileRules/Keep/Infrastructure/Certificates`; Kingfisher `pem.yml`, `privkey.yml`

### 2. SSH credentials & host trust

- **Slug:** `ssh_credentials`
- **Tier:** regex
- **Severity bias:** Black (private keys) / Yellow (trust files)
- **Examples:**
  - Private keys by name: `id_rsa`, `id_ed25519`, `id_dsa`, `id_ecdsa`
  - PuTTY: `.ppk`
  - Trust files: `authorized_keys`, `known_hosts`, `.ssh/config`
  - sshpass invocations: `sshpass -p <pw>` content pattern
- **Source:** Snaffler `FileRules/Keep/UserFiles/SSH`; Kingfisher `sshpass.yml`

### 3. Credential containers (sealed)

- **Slug:** `credential_containers`
- **Tier:** regex
- **Severity bias:** Red
- **Examples:**
  - Password manager vaults: `.kdbx`, `.kdb`, `.psafe3`, `.agilekeychain`, `.opvault`, `.keychain`, `.kwallet`, `.cred`
  - Encrypted PKCS#12: `.pfx`, `.p12`, `.pkcs12`, `.pk12`
  - Password-protected archives: `.zip`/`.7z`/`.rar` with encryption flag set (detected from container header, not extension alone)
  - Rights-managed Office docs (when detectable from header)
- **Classification rule:** **File existence is the finding; crackability is exploitation-time, not classification-time.** A sealed `.kdbx` is a juicy positive even if we never crack it.
- **Source:** Snaffler `FileRules/Keep/UserFiles/PassMgrs` (vaults) + `Infrastructure/Certificates` (PKCS#12)

### 4. Browser-stored credentials

- **Slug:** `browser_credentials`
- **Tier:** hybrid
- **Severity bias:** Red
- **Hybrid breakdown:** *regex layer detects* the well-known filenames (`logins.json`, `Login Data`, `Cookies`) and the `"encryptedPassword":"..."` content pattern; *ML layer denoises* stale/empty profiles and ranks by recency and likely user importance (a `Login Data` on a shared admin's roaming profile beats an abandoned VM image's).
- **Examples:**
  - Firefox: `logins.json`, content `"encryptedPassword":"[A-Za-z0-9+/=]+"`
  - Chrome / Edge: `Login Data` (SQLite), `Cookies`
- **Source:** Snaffler `FileRules/Keep/UserFiles/BrowserCreds`

### 5. Cloud provider credential files

- **Slug:** `cloud_credentials`
- **Tier:** hybrid (partial ★)
- **Severity bias:** Red
- **Hybrid breakdown:** *regex layer detects* token prefixes (`AKIA*`, `AIza*`, Azure SAS structure, etc.); *ML layer denoises* the well-known example/sample tokens that flood tutorial files (e.g. `AKIAIOSFODNN7EXAMPLE` is the canonical AWS docs key) and triages by surrounding context (real config file vs. README code block).
- **Examples:**
  - AWS: `(AKIA|ASIA|AROA|AGPA|AIDA)[A-Z2-7]{12,16}`; `aws_secret_access_key\s*=`
  - GCP: `AIza[A-Za-z0-9_\-]{35}`; service-account JSON `"private_key_id":"..."`
  - Azure: SAS tokens, Storage account keys, ~26 service-specific variants (APIM, Cosmos, Logic Apps, ...)
  - Long tail: DigitalOcean, Linode, Vultr, Hetzner, OVH, Scaleway, Equinix, UpCloud
- **Source:** Snaffler `KeepAwsKeysInCode.toml` (AWS only); Kingfisher ~35 files. Partial ★ — Snaffler is missing ~30 providers.

### 6. Modern SaaS API tokens ★

- **Slug:** `modern_saas_tokens`
- **Tier:** hybrid
- **Severity bias:** Red
- **Sub-types (enum):**
  - `ai_llm` — OpenAI (`sk-...`, `sk-proj-...`), Anthropic (`sk-ant-api03-...`, `sk-ant-admin01-...`), Cohere, HuggingFace (`hf_...`), Mistral, Groq, DeepSeek, Perplexity, Together, Replicate
  - `paas` — Vercel, Netlify, Fly.io, Railway, Render, Heroku
  - `baas` — Supabase, Firebase, Convex, PlanetScale, Neon, CockroachDB, Snowflake, BigQuery
  - `identity` — Clerk, Auth0, Stytch, Okta, OneLogin, Ping, Workos, Authress
  - `package_registry` — npm `_authToken`, PyPI `pypi-...`, Maven/Gradle, Crates.io, Hex, NuGet, Artifactory, Nexus, Clojars
  - `payments` — Stripe (`sk_live_...`, `sk_test_...`), PayPal, Square, Coinbase, Razorpay, Paddle, Braintree, Adyen
  - `observability` — Datadog, Sentry DSN, New Relic, Splunk HEC, Posthog, Segment, Axiom, Rollbar
- **Hybrid breakdown:** *regex layer detects* each provider's distinctive prefix or structure; *ML layer denoises* documentation/example tokens and tutorial copy-paste, *and extends coverage* to providers whose tokens are generic-looking (32-char hex with no prefix) where context alone is the signal.
- **Source:** Kingfisher, ~100+ files across these clusters. Snaffler: **zero coverage** for all seven sub-types.

### 7. Source-control & CI/CD platform tokens

- **Slug:** `scm_cicd_tokens`
- **Tier:** hybrid
- **Severity bias:** Red
- **Hybrid breakdown:** *regex layer detects* token formats (`ghp_*`, `gho_*`, `ghs_*`, `github_pat_*`, `glpat-*`) and known workflow filenames (`.github/workflows/*.yml`, `.gitlab-ci.yml`, `.circleci/config.yml`, `Jenkinsfile`); *ML layer extends* by distinguishing real embedded tokens from harmless `${{ secrets.X }}` *references*, and catching tokens inside inline bash heredocs / shell scripts where the prefix sits inside unusual quoting.
- **Examples:**
  - GitHub PATs and fine-grained tokens
  - GitLab project/runner tokens
  - Bitbucket, Jenkins, CircleCI, Travis, Buildkite, Harness, Drone, TeamCity
- **Note:** Stays separate from `modern_saas_tokens` because the operator workflow is different — developer credential vs. deployed-app credential.
- **Source:** Snaffler `Infrastructure/CiCdStuff` (filename only); Kingfisher ~14 files

### 8. Communication & messaging platform tokens

- **Slug:** `comms_tokens`
- **Tier:** hybrid (partial ★)
- **Severity bias:** Yellow
- **Hybrid breakdown:** *regex layer detects* token formats and webhook URL structures; *ML layer denoises* webhook URLs shared in screenshots/docs/issue trackers (a high-volume FP source on engagement shares) and extends to internal/custom webhook patterns.
- **Examples:**
  - Slack: `xox[pboaer]-[0-9]{10,12}-...`; Slack incoming webhooks
  - Discord bot tokens, Telegram bot tokens
  - Twilio `SK...` + auth tokens, SendGrid `SG.`, Mailgun, Mailchimp, Brevo, Zoom, Mattermost
- **Source:** Snaffler covers Slack; Kingfisher covers ~19. Partial ★.

### 9. Database files, dumps & backups

- **Slug:** `db_files`
- **Tier:** hybrid
- **Severity bias:** Red (live dumps) / Green (test fixtures)
- **Hybrid breakdown:** *regex layer detects* extensions; *ML layer triages* by file size, modification time, and content sample to separate live/recent production dumps from empty fixtures or developer test data. Snaffler treats a 2KB test `.bak` and a 50GB prod backup identically — ShareSift shouldn't.
- **Examples:**
  - SQL Server: `.mdf`, `.ldf`, `.bak`
  - SQL CE: `.sdf`
  - Generic: `.sqldump`, `.sqlite`, `.sqlite3`, `.fdb`, `.dbf`
- **Source:** Snaffler `Infrastructure/Databases`

### 10. Secrets embedded in code or config — **ML tier**

- **Slug:** `embedded_secrets`
- **Tier:** ML
- **Severity bias:** Red (real) / Green (FP)
- **Examples (the brittle Snaffler rules — high FP):**
  - Generic: `passw?o?r?d\s*=\s*['"][^'"]+['"]` (Snaffler `KeepPassOrKeyInCode`)
  - JDBC: `\.getConnection\("jdbc:` + `passwo?r?d\s*=`
  - SQL acct creation: `CREATE (USER|LOGIN) .{0,200} (IDENTIFIED BY|WITH PASSWORD)`
  - `connectionstring.{1,200}passw` — catches the word "password" within 200 chars
- **Why pure ML:** Snaffler matches the literal word `password` in any quoted context — fixtures, comments, docs, mock data, error messages. The signal is high-entropy values in real config contexts, not lexical co-occurrence. Regex prefiltering helps recall but cannot help precision; ML is the whole game.
- **Source:** Snaffler `FileRules/Keep/Code/**`; Kingfisher `generic.yml`, `credentials.yml`

### 11. Infrastructure-as-code & IaC vaults

- **Slug:** `iac`
- **Tier:** hybrid
- **Severity bias:** Black (state files with cleartext) / Yellow (templates)
- **Hybrid breakdown:** *regex layer detects* file extensions/names; *ML layer extends* by decoding base64 secret blobs in Helm/k8s manifests, distinguishing real embedded secrets from placeholder/example values, and triaging whether a `.tfstate` belongs to a sandbox or prod environment.
- **Examples:**
  - Terraform: `.tf`, `.tfvars`, `.tfstate` (state files often contain plaintext secrets)
  - Ansible: `ansible-vault` files, `group_vars/`, `host_vars/`
  - Kubernetes: `Secret` manifests with base64 `data:` blocks; Helm `values.yaml`
  - Cloud-init: `user-data` blobs (folded in for v0; candidate for promotion if week-4 analysis shows distinct ML characteristics)
- **Source:** Snaffler `Infrastructure/InfraAsCode`

### 12. Network device configs & secrets

- **Slug:** `network_device`
- **Tier:** regex
- **Severity bias:** Black (Type-7 / cleartext) / Red (Type-5)
- **Examples:**
  - Cisco: `enable secret 5 $1$...`, `enable password 7 ...` (Type-7 reversible), `snmp-server community ...`
  - Filenames: `running-config`, `startup-config`, `*.cfg` from network backups
  - Juniper, F5, Palo Alto config formats
- **Source:** Snaffler `Infrastructure/NetworkDevice`

### 13. Windows credential artifacts

- **Slug:** `windows_credential_artifacts`
- **Tier:** regex
- **Severity bias:** Black
- **Examples:**
  - Registry hives: `NTDS.DIT`, `SYSTEM`, `SAM`, `SECURITY`
  - Memory dumps: `.dmp`, `lsass.dmp`, `procdump` output
  - Packet captures: `.pcap`, `.pcapng`
  - VM disks: `.vmdk`, `.vdi`, `.vhd`, `.vhdx`
  - **Group Policy Preferences with reversible passwords:** `Groups.xml` / `Services.xml` / `ScheduledTasks.xml` containing the `cpassword` attribute (placed here because the discovery vector is share-walk into `SYSVOL`, not code review)
- **Source:** Snaffler `Infrastructure/{WinHashes, MemDumps, PacketCapture, VirtualMachines}`

### 14. Decoy documents — **ML tier**

- **Slug:** `decoy_docs`
- **Tier:** ML
- **Severity bias:** Yellow (real) / Green (FP)
- **Examples:**
  - Filenames containing: `password`, `passwords`, `secret`, `credential`, `creds`, `thycotic`, `cyberark`, `vault`
  - Dotfiles: `.netrc`, `.pgpass`, `.bash_history`, `.zsh_history`, `.aws/credentials`, `.kube/config`
  - Business docs: `DBA-passwords-prod.xlsx`, `PasswordResetProcedure.docx` (one is gold, one is noise)
- **Why pure ML:** Snaffler's `KeepNameContainsGreen` keys off any filename containing "password" — equally flags a real wallet and an HR doc explaining how to reset one. The discriminator is filename + extension + path + size/owner — classic ML territory.
- **Source:** Snaffler `FileRules/Keep/BusinessDocs/ByPartialName`, `UserFiles/DotFiles`

## Tier distribution

- **regex (5):** `private_keys_x509`, `ssh_credentials`, `credential_containers`, `network_device`, `windows_credential_artifacts`
- **hybrid (7):** `browser_credentials`, `cloud_credentials`, `modern_saas_tokens`, `scm_cicd_tokens`, `comms_tokens`, `db_files`, `iac`
- **ML (2):** `embedded_secrets`, `decoy_docs`

The bulk of ShareSift's lift over Snaffler comes from the seven hybrid families (where ML denoises, extends, or both) plus the two pure-ML families. The five regex families are tablestakes that Snaffler already does well.

## Modern-gap summary

The ★ modern gap concentrates in **family 6 (`modern_saas_tokens`)**, which covers seven sub-types (ai_llm, paas, baas, identity, package_registry, payments, observability) where Snaffler has zero coverage. Partial ★ in families 5 (cloud_credentials, ~30 providers missing) and 8 (comms_tokens, Snaffler only covers Slack).

## Open questions deferred to v1.x

- Whether `credential_containers` should also include S/MIME and PGP encrypted blobs.
- Whether `iac` should split out a `secrets_in_state` sub-family for `.tfstate` specifically (cleartext-in-state is a distinct severity story).
- Whether `db_files` triage needs to peek inside the binary (size + filename may suffice; sampling adds I/O cost).
