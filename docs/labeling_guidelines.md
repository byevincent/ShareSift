# Labeling Guidelines

This document codifies labeling decisions for the ShareSift eval set. Updates committed alongside the eval records they explain.

## Tier Criteria

Tier attaches only to `juicy` records. Three severity levels — Black, Red,
Yellow — describe the operational impact of the finding. For `not_juicy`
records, tier is null: that IS the not-a-finding state. (An earlier "Green
tier" ambiguously conflated juicy-but-irrelevant with not-a-finding; the
removal of Green resolved the contradiction by making `not_juicy` the
single representation of negative results.)

Tiers describe operational severity, not detection confidence. An uncertain
positive is still tier-rated by likely impact, with the labeler's lower
confidence surfaced via the uncertainty flag (see Uncertainty Policy
below).

**Black — immediate compromise.** Finding the file gives the operator effective
access to credentials, secrets, or compromise paths without further exploitation
needed at engagement time. Examples: cleartext domain admin credentials, GPP
groups.xml with cpassword in SYSVOL, unprotected .kdbx files in shared
locations, private keys (RSA/SSH/PFX) with no passphrase, .ntds.dit extracts,
SAM/SYSTEM registry hive dumps.

**Red — high-value sensitive content, exploitation likely.** The file contains
material that an attacker would use as part of compromise but isn't itself
turnkey access. Examples: protected credential vaults (.kdbx with unknown
passphrase, .pfx with unknown password), database connection strings with
inline credentials, cloud service account JSON keys, mass PII or financial
exports, internal documentation revealing infrastructure layout, source code
with embedded API keys.

**Yellow — context-useful but not immediately exploitable.** Useful for
intelligence gathering, reconnaissance, or building exploitation chains, but
not directly compromising on its own. Examples: configuration files referencing
external secret managers, scripts revealing scheduled task accounts, network
diagrams, password policy documents, sanitized credential rotation procedures,
SaaS tokens for low-impact integrations.

Tier is assigned based on the **likely operational impact** of the file's
existence and contents, conditioned on the labeler's best inference from path
features alone (this is path-tier evaluation; content inspection is downstream).

## Uncertainty Policy

When path features alone are insufficient to confidently determine
juiciness, label by base-rate prior for the path pattern across enterprise
shares and flag the record with `validator_warnings: ["uncertainty_prior"]`
plus a notes-field explanation of which way the prior leans and why.

The eval set is subset by uncertainty class downstream for separate analysis:
high-confidence labels are the primary benchmark; uncertainty-flagged labels
are a calibration set for measuring model behavior on ambiguous inputs.

Do not skip uncertain paths. Labeling forces decisions, and the model needs
to learn behavior on ambiguous inputs too. The flag is the escape valve, not
the skip button.

Base-rate priors are explicit judgments based on operational experience.
Document the prior in notes: "Settings files named *_prod.* contain inline
credentials in roughly 60% of enterprise shares observed; labeling juicy on
prior." Future-self in week four needs to see the reasoning, not just the
label.

Do not consult external tools (Claude, Snaffler, Kingfisher) during labeling
to resolve uncertainty. Independent ground truth requires independent
judgment. If you cannot make a call from your own knowledge, label by
explicit base-rate prior with the flag.

## Source-Specific Notes

**Engagement-derived paths** (source: engagement) carry priority and should
constitute the majority of the eval set. Sanitize identifying information
(replace company names with placeholder tokens like `<COMPANY>`,
`<HOSTNAME>`, `<USERNAME>`) but preserve all structural patterns: share
names, directory hierarchy, filename conventions, extension distribution.
Path structure is the signal; specific organizational identifiers are
noise that risks deanonymization without aiding model training.

**GitHub Code Search paths** (source: github_search) are real paths that
appeared in someone's real environment because they were hardcoded into a
script or config that got committed. High value, but skewed toward paths
present in tooling rather than naturally browsed paths. Mark as such; do
not over-represent.

**Public corpus paths** (source: public) come from leaked or published
datasets where path structure is preserved. Use ethically and document
provenance in notes. These paths reflect actual organizational structure
but may be over-represented for specific industries.

**Seed paths** (source: seed) are hand-constructed by the labeler from
operational memory without a specific source document. Acceptable for
calibration set construction but should not exceed 15% of the full eval
set. Seed paths reflect labeler intuition more than ground truth and can
bias the eval toward the labeler's existing model rather than real
distribution.

**Synthetic paths** (source: synthetic) are generated by LLM and should
not appear in the eval set at all in v0. Synthetic generation is reserved
for training data. The eval set's purpose is independent ground truth;
synthetic eval is circular evaluation.

## Category-Specific Guidelines

**Convention for this section (load-bearing — read by the labeling GUI):**
each `` ### `<slug>` `` block's FIRST paragraph is the canonical one-line
definition and boundary statement. The labeling GUI parses these paragraphs
from this doc at startup and renders them inline under the category
dropdown so the in-GUI help can't drift from the canonical guidelines —
same shared-source discipline as everywhere else in the eval pipeline.
Additional paragraphs in a section (examples, distinguishing tests, tier
guidance) are doc-only — they're for offline reading, not surfaced inline.
The parser fast-fails at startup if any `CATEGORY_SLUGS` entry is missing
its `` ### `<slug>` `` heading, or if any first-paragraph is empty/
whitespace-only.

### `private_keys_x509`

Standalone X.509 private-key files by extension: `.pem`, `.crt`, `.cer`,
`.der`, `.key`. **Boundary:** sealed in `.pfx`/`.p12`/`.jks` →
`credential_containers`; SSH key (`id_rsa`, `id_ed25519`, `.ppk`) →
`ssh_credentials`.

### `ssh_credentials`

SSH client/server key and auth files: `id_rsa`/`id_dsa`/`id_ecdsa`/
`id_ed25519`, `authorized_keys`, `known_hosts`, `.ppk`, anything under
`\.ssh\`. **Boundary:** a `.pem` at a non-SSH location is
`private_keys_x509`; a sealed key vault (`.pfx`/`.kdbx`) is
`credential_containers`.

### `credential_containers`

Sealed credential vaults by extension: `.kdbx`/`.kdb` (KeePass), `.pfx`/
`.p12` (PKCS#12), `.jks`/`.keystore` (Java). **Boundary:** the sealed-ness
is what defines this — if a container is opened/exported to a `.pem` or
text dump, that derivative is `private_keys_x509` or `embedded_secrets`.

### `browser_credentials`

Browser stores by canonical basename: Chromium `Login Data` / `Web Data` /
`Cookies`, Firefox `key4.db` / `signons.sqlite` / `logins.json`.
**Boundary:** a `.db`/`.sqlite` that isn't one of these canonical browser
basenames → `db_files`.

### `cloud_credentials`

Credential FILES used by cloud SDKs/CLIs for API auth: `.aws/credentials`,
`application_default_credentials.json`, `service-account*.json`, anything
under `\.azure\` or `\.gcp\`. **Boundary:** NOT IAM policy documents — a
JSON that describes IAM resources without auth material is
`embedded_secrets` if it contains secrets, otherwise judge by content.

### `modern_saas_tokens`

API keys/tokens for modern hosted services; filenames mention `openai` /
`anthropic` / `stripe` / `auth0` / `okta` / `vercel` / `supabase` /
`datadog` / etc. **Sub-type required** (`ai_llm` / `paas` / `baas` /
`identity` / `package_registry` / `payments` / `observability`).
**Boundary:** a generic `.env` mentioning these tokens →
`embedded_secrets` (filename generic); a service-specific filename like
`openai_keys.txt` → `modern_saas_tokens`.

### `scm_cicd_tokens`

Source-control + CI/CD credential files: `.npmrc`, `.pypirc`,
`.git-credentials`, `bitbucket-pipelines*`, `\.docker\config.json`,
`\.github\workflows\`. **Boundary:** a `secrets.yml` inside a workflow
directory is `embedded_secrets` (filename generic); a workflow file that
NAMES secret variables without containing them is `scm_cicd_tokens`.

### `comms_tokens`

Tokens/webhooks for communications platforms; filenames mention `slack` /
`discord` / `teams` / `webhook`. **Boundary:** a `.env` with a
`SLACK_TOKEN` → `embedded_secrets` (filename generic);
`slack_webhook.txt` → `comms_tokens` (filename specific).

### `db_files`

ACTUAL database files by extension: `.bak`, `.mdf`, `.ldf`, `.sqlite`,
`.sqlitedb`, `.db`, `.mdb`. **Boundary calls that overlap with other
categories:** (a) NOT a `.config` that MENTIONS a database — that's
`embedded_secrets` if it has a connection string, `decoy_docs` if the
filename signals but content is benign; (b) NOT `NTDS.dit` — that's
`windows_credential_artifacts` (AD-specificity wins over generic db-file);
(c) NOT `key4.db` / `signons.sqlite` — those are `browser_credentials`
(canonical browser store wins).

### `embedded_secrets`

A real secret living inside an ORDINARY file: `passwords.txt`, `.env` /
`.env.*`, `app.config` / `web.config` / `appsettings.json`, `secrets.yml`,
generic txt/json/yaml with real credentials. **Boundary calls:** (a) the
file must be ORDINARY — if it's an AD/Windows credential-extraction file
type (`NTDS.dit`, registry hives, GPP XML, Kerberos ticket),
`windows_credential_artifacts` wins; (b) if it's an ACTUAL database file
(`.bak` / `.mdf` / `.sqlite` / etc.), `db_files` wins (the file IS the
secret container, not a config mentioning a secret); (c) distinct from
`decoy_docs` — embedded_secrets = content IS a real secret regardless of
filename; decoy_docs = content is benign despite a juicy-looking
filename.

### `iac`

Infrastructure-as-Code artifacts: `.tfstate` (juicy: rendered secrets),
`.tf` / `.tfvars`, `ansible-vault.yml`, `cloud-init.yaml`. **Boundary:**
a plain `.yml` outside an IaC tooling context is `embedded_secrets` if it
has secrets, otherwise judge by content.

### `network_device`

Network-device configurations: `cisco-running-config`, files with
`routerconfig`-prefix or `running-config` substring. **Boundary:** a
network-related `.yaml` is `iac` (Ansible); a network device's secrets
dumped to a `.txt` is `embedded_secrets`.

### `windows_credential_artifacts`

AD/Windows credential-extraction artifacts: SYSVOL GPP cpassword XML
(e.g. `Groups.xml` under `\SYSVOL\…\Policies\`), `NTDS.dit`, registry
hive copies (`SAM` / `SYSTEM` / `SECURITY` without extension), Kerberos
ticket files (`.kirbi` / `.ccache`). **Boundary calls:** (a) NTDS.dit IS
a database file, but `windows_credential_artifacts` wins because
AD-extraction is the point; (b) SAM hives ARE files containing secrets,
but `windows_credential_artifacts` wins because pentester-recognized
AD/Windows-extraction context is the point; (c) a `passwords.txt` on a
user's desktop is NOT this — it's `embedded_secrets` (ordinary file with
a real secret); this category is reserved for the canonical AD/Windows
credential-extraction file types.

### `decoy_docs`

Documents whose filename baits a keyword scanner (`password` / `secret` /
`credential` in the name) but whose content is benign — the **false-positive
class** for filename-based detection. **Boundary:** distinct from
`benign_noise` (decoy: filename signals juiciness deceptively; noise:
filename doesn't pretend) and from `embedded_secrets` (decoy: benign content
despite signaling filename; embedded_secrets: real-secret content
regardless of filename).

Examples:
- `\\hr\policies\password_policy.docx` — the HR password policy (text about
  passwords, not an actual password)
- `\\corp\security\credentials_mockup.psd` — a Photoshop mockup of a
  credentials UI
- `\\internal\training\secret_handshake_intro.pdf` — internal training doc

Distinguishing test: would a naive keyword scanner flag this filename as
juicy? If yes AND a careful reader concludes the content is benign, the
record is `decoy_docs`. If the same filename's content IS a real secret,
it's `embedded_secrets` instead.

Tier guidance: `decoy_docs` is a `not_juicy` label with tier null.
(Tier attaches only to `juicy` records.)

### `benign_noise`

Path is genuinely irrelevant — no sensitivity signal in the filename, no
credential-bearing potential in the file type. These are the **clean-negative
class** that reflects the 90%+ of a real file share that's just operational
junk: marketing assets, media files, fonts, generic binaries.

Examples:
- `\\corp\marketing\spring_banner.jpg`
- `\\fileserv\recordings\all-hands-2026-q1.mp4`
- `\\corp\design\logos\primary_v3.png`
- `\\corp\fonts\corporate-display.ttf`
- `C:\Program Files\Vendor\product.exe`

Distinguishing test: would a naive keyword scanner flag this filename as
juicy? If NO and the file's type is essentially incapable of being a
credential container (media, generic binary, font), the record is
`benign_noise`.

Boundary with `decoy_docs`: if the filename contains a sensitivity
keyword (`password`, `secret`, `credential`, etc.), the record is
`decoy_docs`, NOT `benign_noise` — even if you conclude the file
is benign on inspection. The category distinction is about WHY the path
deserves to be in the negative class, and the why is different for each.

Boundary with credential containers / archives / docs: `.zip`, `.rar`,
`.7z` are NOT `benign_noise` candidates — protected archives can be sealed
credential containers, so a boring-looking ZIP in a backup share is
typically `credential_containers` (with the appropriate tier), or `iac` /
`db_files` / etc. depending on what it backs up. Same for `.pdf` / `.docx`
/ `.txt`: those doc types can carry juicy content and fall into
`decoy_docs` if the filename signals it, otherwise they should be
judged on actual content semantics rather than reflexively labeled
`benign_noise`.

The pre-categorizer fires `benign_noise` on a narrow extension set
(images, audio/video, generic binaries, fonts) — these are the high-
confidence "essentially never a credential" file types. As a label
category in the GUI, use `benign_noise` whenever a path is genuinely
irrelevant regardless of extension. The pre-categorizer's coverage and
your label coverage do NOT have to match; the pre-categorizer is a
stratification hint, and erring narrow there preserves the unmatched
bucket as a "look at this carefully" signal.

Tier guidance: `benign_noise` is a `not_juicy` label with tier null.
(Tier attaches only to `juicy` records.)

### `high_value_software`

Software whose presence on a share is itself the finding. The category
is about **which file is present**, not about secrets in it or
permissions on the location. Common members span four conceptual
sub-types (named here as scope guidance — not enforced as a schema
field, for v0): RMM and remote-management agents (LabTech /
ConnectWise Automate, ConnectWise Control / ScreenConnect,
TacticalRMM, AnyDesk, Splashtop, Atera, Datto, Kaseya, NinjaOne /
NinjaRMM, MeshCentral); native and third-party lateral-movement
tooling (PsExec, SCCM client `CcmExec.exe`); deployment agents;
PAM / privileged-access software (CyberArk, Delinea / Thycotic
SecretServer, BeyondTrust). The finding is "this organization deploys
X management surface" — recon intelligence revealing capability,
chokepoint, or exploitation path.

**Boundary with `embedded_secrets`:** different question.
`embedded_secrets` is about a secret living inside an ordinary file
(a `.config` with a connection string is `embedded_secrets`
regardless of which software the config belongs to).
`high_value_software` is about the binary's presence (the
`LabTechAgent.exe` itself, not the config alongside it). Same
install, different files, different categories.

**Boundary with `benign_noise`:** `.exe`/`.msi` is in benign_noise's
extension set ("generic vendor binaries"). The pre-categorizer fires
`high_value_software` first for filenames matching the known
RMM/PAM/remote-admin software substrings, so `LabTechAgent.exe`
lands here, while `\\fs01\software\Adobe\Reader.exe` correctly lands
in `benign_noise`. The boundary is the specific software name, not
the extension.

**Boundary with "execution surface" as a concept:** there is NO
`execution_surface` category. `high_value_software` is about WHICH
SOFTWARE is on the share; ACL / write-permissions live in the tier
field. A writable share carrying `high_value_software` is higher
tier than a read-only one with the same software; the category
doesn't change.

Tier guidance: on path features alone, typically **Yellow**
(recon-useful — reveals a management chokepoint, lateral-movement
vector, or privileged-access vault). Promote to **Red** when the
software has known unpatched exploits OR when the deployment context
strongly implies elevated impact — for example, domain-wide
deployment via NETLOGON or SYSVOL reaches every workstation; even
read-only, the path reveals an attractive target a pentester would
prioritize. **Black** is the ceiling, reserved for **confirmed write
access** on the share (operator can substitute the binary). This is
consistent with the "ACL drives tier" principle above: writability
is not a path feature; path-tier labels can promote to Red on
deployment context, but Black requires evidence the labeler doesn't
have from the path alone. The canonical category example is the
dogfood case `\\domain-name.local\Netlogon\LabTechAgent.exe` — an
RMM agent deployed domain-wide via NETLOGON, which lands in
`high_value_software` regardless of share permissions; its tier
depends on what the labeler can confirm about write access, not on
the path string alone.

## Common Edge Cases

_Populated as encountered during labeling. Each entry: example path,
decision, reasoning, and whether it represents a general rule worth
extracting to a category-specific guideline._
