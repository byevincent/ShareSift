# DiskForge Windows-share benchmark — build plan

Goal: replace the "Snaffler-blind Windows 500 paths" honesty caveat
in the v0.50.1 scorecard with a real-share-content corpus
generated via Stauffer's DiskForge tool.

The existing `data/external/diskforge_win10/` corpus (520 paths) is
OS-shape: C:\Windows, C:\Program Files, /Boot/ with 13 carefully
planted creds in standard Windows locations. Good for measuring
"can we find a known cred in a sea of OS files" — not good for
measuring "can we triage a corporate file share."

This plan builds `diskforge_winshare_v1` — Windows-share-shape,
~2500 paths, ~80 positives across ~16 credential categories.

## Target corpus characteristics

| Property | Value |
|---|---|
| Total files | 2000–3000 |
| Positives (creds) | 60–100 |
| Categories | ~16 (see below) |
| Share types | 4 (department FS, DC SYSVOL/NETLOGON, public templates, IT tooling) |
| Noise quality | Realistic corporate (docs, archives, install media, logs) |
| Reproducibility | One docker run from the committed manifest |

## Cred categories to cover (target 3–8 positives each)

| Category | Example path | Existing v0.50 rule |
|---|---|---|
| GPP cpassword | `\SYSVOL\corp\Policies\{GUID}\Machine\...\Groups.xml` | KeepGppPolicyXml |
| Unattend.xml / autounattend | `\Public\IT-Templates\install-server.xml` | RelayUnattendXml |
| AWS / GCP / Azure CLI creds | `\Users\<svc>\.aws\credentials` / `gcp_service_account.json` | KeepAwsCredentialsFile / DotNetAppSettingsConnString |
| SSH keys (RSA / ED25519 / unencrypted PPK) | `\Users\<svc>\.ssh\id_rsa` | KeepSSHKeysByFileExtension + PuttyPpkUnencrypted |
| KeePass DB | `\Departments\IT\password-vault\passwords.kdbx` | KeepKeepass |
| PowerShell history | `\Users\<admin>\AppData\Roaming\...\ConsoleHost_history.txt` | KeepPSHistoryByPath |
| Browser saved creds (Chrome / Edge / Firefox) | `\Users\<svc>\AppData\Local\Chrome\User Data\<profile>\Login Data` | KeepBrowserSavedCreds + FirefoxSavedCreds |
| Web.config / appsettings.json (db conn) | `\Departments\IT\webapps\internal\web.config` | KeepDbConnStringPw + DotNetAppSettingsConnString |
| wp-config.php | `\Public\dev-templates\blog\wp-config.php` | KeepWpConfigDbPassword |
| Cisco IOS config | `\Departments\IT\network\backups\corp-rtr01.config` | KeepCiscoEnableSecret + KeepCiscoSnmpCommunity |
| SCCM (REMINST/SMSTemp + SCCMContentLib$) | `\REMINST\SMSTemp\PKG00001.var` | KeepSCCMBootVarCredsByPath + KeepSccmContentLibShare |
| Kerberos keytab / krb5cc | `\Departments\IT\linux-backups\admin.keytab` | (upstream KeepKerberosCredentials*) |
| FileZilla saved sites | `\Users\<svc>\AppData\Roaming\FileZilla\sitemanager.xml` | KeepFileZillaSavedSites |
| German cred filenames | `\Abteilungen\IT\Passwoerter\zugaenge_2024.xlsx` | KeepGermanCredFilenames |
| Credential-keyword filename | `\Departments\HR\export\employee_credentials_2024.xlsx` | KeepCredentialFilenameKeyword |
| CMD batch with `set "VAR=val"` | `\Public\IT-Templates\setup\restore_db.bat` | KeepCmdSetQuotedAssignment |

This roster deliberately covers every rule generation v0.46→v0.50
added, so the benchmark doubles as a "do my rules actually fire on
shape-correct paths" sanity check, not just a recall measurement.

## Negative-noise classes (target ~95% of files)

Realistic share content the rules should NOT fire on:

- HR policy documents (`\Departments\HR\policies\handbook_v3.docx`)
- Finance reports (`\Departments\Finance\quarterly\Q3_2025.xlsx`)
- Marketing assets (`\Departments\Marketing\rebrand_2025\*.psd`)
- Software install media (`\Public\Software\Office_2021\*.msi`)
- Log archives (`\Departments\IT\logs\app_2024-*.log.gz`)
- Vendor PDFs (`\Public\Vendor-Docs\Dell_R740_install.pdf`)
- Project files (`\Departments\Eng\proj-x\src\*.cs`)
- Public read-only refs (`\Public\Templates\meeting_agenda.docx`)

The noise should LOOK ambiguous — file names with words like
"credentials", "secrets", "passwords" in policy/educational
contexts (e.g. `password_policy.docx`, `credential_request_form.docx`)
to stress-test the credential-keyword rules' precision.

## Build steps (one PR per step — plan-gated)

### Step 1: DiskForge prerequisites
- Clone `jknyght9/diskforge` into `/tmp/diskforge`
- `docker build -t diskforge .`
- Verify base manifest example produces an .img

**Deliverable:** confirmation comment with image size + build time.

### Step 2: Authoring the manifest
- Create `tools/diskforge_winshare/manifest.json` (the disk layout)
- Create `tools/diskforge_winshare/files/` with:
  - Real cred-shaped content for each of the 16 positive categories
    (synthetic but format-valid — e.g. real PPK structure with
    fake key material, real Cisco config syntax with fake passwords)
  - Realistic noise files in each negative-noise class
- Create `tools/diskforge_winshare/build_corpus.sh` — runs docker,
  mounts image, walks paths, emits `file_list.txt` + `ground_truth.jsonl`

**Deliverable:** committed manifest + files dir; one docker run
produces `data/external/diskforge_winshare_v1/`.

### Step 3: Ground-truth labeling
- Manifest-driven: every file added via the manifest has known
  provenance, so ground truth is mechanical (positive = file came
  from `/files/positives/{category}/...`, negative = everything
  else)
- LLM-assist (`tools/claude_label.py`) only for edge cases where
  the manifest-derived label seems wrong — should be rare

**Deliverable:** `ground_truth.jsonl` with `has_credential`,
`credential_type`, and `verified` fields populated. Hand-spot
20 random samples to verify accuracy.

### Step 4: Wire into the benchmark sweep
- Add the new corpus to `tools/run_full_sweep.py`
- Add `data/external/diskforge_winshare_v1/` to the data layout
- Run the sweep — report cascade F1 + per-category precision

**Deliverable:** new row in the scorecard, writeup at
`docs/diskforge_winshare_v1_results.md`.

### Step 5: Publish as v0.51 or v1.0
- Decide naming: this is genuinely a milestone (first
  real-share-content benchmark, replaces the LLM-labeled
  Snaffler-blind caveat). Probably v1.0.
- Update README headline + methodology doc with the new number

**Deliverable:** v0.51 or v1.0 tag, GitHub release with the new
scorecard row featured.

## Time estimate

| Step | Sessions | Notes |
|---|---|---|
| 1: DiskForge prereqs | 1 (½ day) | Docker setup risk |
| 2: Manifest + files | 2 (1–2 days) | The thinking work |
| 3: Ground truth | ½ (3 hr) | Mostly mechanical |
| 4: Sweep wiring | ½ (3 hr) | Trivial |
| 5: Ship | ½ (3 hr) | Standard |

**Total: 4–5 sessions.** Slightly more than the original 3–4
estimate because of the precision-by-category goal (16 categories
× synthetic-but-format-valid cred content takes longer than
"plant 13 known files").

## Open questions for review before Step 1 starts

1. **Naming:** `diskforge_winshare_v1` vs `diskforge_winshare_2026_06`?
   Convention used elsewhere in `data/external/` is descriptive
   (`metasploitable3`, `diskforge_win10`) so `diskforge_winshare_v1`
   fits.
2. **Negative class count:** ~95% noise = ~2400 negatives. Is that
   the right ratio? Real corp shares are ~99% noise but going to
   99% inflates the corpus to ~6000 files.
3. **Cred category coverage:** is the 16-category roster the right
   set, or should it match the 4-generation Snaffler-issues
   trajectory exactly?
4. **Public release of the manifest:** Stauffer's tool is MIT
   licensed; the manifest + synthetic cred content should be
   committable to the public ShareSift repo with no NDA risk.
   Confirm?
5. **Should the synthetic-cred files be functional (e.g. real PPK
   structure parseable by PuTTY) or just format-shaped?** Functional
   is harder but the closer to real, the more credible the
   benchmark.
