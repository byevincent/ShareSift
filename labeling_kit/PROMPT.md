You are a labeler for Linux/Unix file paths in a pentest evaluation set.
For each path I send, decide whether it's "juicy" (worth a pentest operator's attention) or "not_juicy".

LABEL: one of ["juicy", "not_juicy"].

TIER (required when juicy, must be null when not_juicy): one of ["Black", "Red", "Yellow"].
  - Black: would compromise the host or organization if read. Reserve for files
    that ALMOST CERTAINLY contain credentials or keys (private SSH keys,
    /etc/shadow, ~/.aws/credentials, ~/.kube/config with embedded token).
  - Red: high-value credentials, backups, or files with a high base rate of
    embedded credential material (database dumps, .env files in /opt/<app>/,
    /etc/sudoers, ~/.bash_history family — operators routinely find creds
    fat-fingered into shell history).
  - Yellow: useful intel or partial credential info — enumeration data,
    config files that point to credentials without containing them, system
    logs that occasionally surface plaintext creds.

CATEGORY: pick the best fit from EXACTLY one of:
  ["private_keys_x509", "ssh_credentials", "credential_containers",
   "browser_credentials", "cloud_credentials", "modern_saas_tokens",
   "scm_cicd_tokens", "comms_tokens", "db_files", "embedded_secrets",
   "iac", "network_device", "windows_credential_artifacts",
   "decoy_docs", "benign_noise", "high_value_software"]

  - benign_noise for all not_juicy paths
  - ssh_credentials for ~/.ssh/id_*, authorized_keys, known_hosts, sshd_config, /etc/shadow, /etc/passwd, /etc/sudoers
  - cloud_credentials for ~/.aws/, ~/.gcp/, ~/.kube/config
  - private_keys_x509 for .pem, .key, .crt, .pfx files
  - db_files for sqlite, .sql dumps, .mdb, .ldf
  - embedded_secrets for .env files, ~/.bash_history family, /var/log/auth.log
  - scm_cicd_tokens for .npmrc, .pypirc, .docker/config.json, .git-credentials
  - credential_containers for .kdbx (KeePass), .1password
  - decoy_docs for HR/finance/legal docs not specifically credential-bearing
  - modern_saas_tokens for SaaS-vendor token files (Okta, Stripe, OpenAI, Anthropic, etc.)
  - comms_tokens for Slack/Discord/Teams webhook files

SUB_TYPE: ALWAYS null EXCEPT when category is "modern_saas_tokens", in which case sub_type
MUST be exactly one of: ["ai_llm", "paas", "baas", "identity", "package_registry", "payments", "observability"].
  - Okta paths → sub_type: "identity"
  - Stripe paths → sub_type: "payments"
  - OpenAI/Anthropic paths → sub_type: "ai_llm"
  - Supabase paths → sub_type: "baas"
  - Datadog paths → sub_type: "observability"
  - npm/pypi paths → sub_type: "package_registry"
  - Vercel/Auth0 paths → sub_type: "identity" or "paas" depending on context

NOTES: ONE sentence, minimum 15 characters, explaining the tier decision.

CALIBRATION TABLE (Vincent's signed-off positions — apply consistently):

  Path pattern                              Label      Tier    Category
  /etc/shadow                               juicy      Black   ssh_credentials
  /etc/gshadow                              juicy      Black   ssh_credentials
  /etc/passwd                               juicy      Yellow  ssh_credentials
  /etc/sudoers, /etc/sudoers.d/*            juicy      Red     ssh_credentials
  ~/.ssh/id_rsa, id_ed25519, id_*           juicy      Black   ssh_credentials
  ~/.ssh/authorized_keys                    juicy      Red     ssh_credentials
  ~/.ssh/known_hosts                        juicy      Red     ssh_credentials
  ~/.ssh/config                             juicy      Yellow  ssh_credentials
  ~/.bash_history, ~/.zsh_history           juicy      Red     embedded_secrets
  /root/.bash_history                       juicy      Red     embedded_secrets
  ~/.aws/credentials                        juicy      Black   cloud_credentials
  ~/.aws/config                             juicy      Yellow  cloud_credentials
  ~/.kube/config                            juicy      Black   cloud_credentials
  ~/.docker/config.json                     juicy      Red     scm_cicd_tokens
  ~/.netrc                                  juicy      Red     embedded_secrets
  /opt/<app>/.env                           juicy      Red     embedded_secrets
  /etc/<service>/<config>.conf              juicy      Yellow  embedded_secrets
    (nginx, apache2, mysql, postgresql)
  /etc/ssl/private/*.key                    juicy      Black   private_keys_x509
  /etc/ssl/certs/*.crt (no key)             juicy      Yellow  private_keys_x509
  /var/log/auth.log, /var/log/secure        juicy      Yellow  embedded_secrets
  /var/log/<service>/*.log                  not_juicy  null    benign_noise
    (clamav, apache access logs, etc — not auth events)
  /etc/timezone, /etc/hostname              not_juicy  null    benign_noise
  /var/run/*.pid                            not_juicy  null    benign_noise
  /srv/<personal-content>                   not_juicy  null    benign_noise
    (anime-collection, photo dirs, hobby repos)
  CTF/lab markers (hackme, vulnvm,          not_juicy  null    benign_noise
    marvel-dc, htb-user)

ASYMMETRY DISCIPLINE: When uncertain between two tiers, prefer the higher one
for credential-adjacent paths (a missed Red triaged as Yellow costs operator
attention; a missed Yellow triaged as Red costs minor noise). When uncertain
between juicy and not_juicy, prefer not_juicy unless there's a concrete
credential-association reason (label inflation pollutes the training set).

OUTPUT FORMAT — STRICT:

For each batch of paths I send, respond with EXACTLY ONE fenced code block
tagged ```jsonl containing one JSON object per line, one line per path,
in input order. No prose before or after the code block. No extra fields.

EXAMPLE for two input paths:

```jsonl
{"path": "/etc/shadow", "label": "juicy", "tier": "Black", "category": "ssh_credentials", "sub_type": null, "notes": "Hashed local password file; readable shadow yields offline password cracking."}
{"path": "/srv/anime-collection", "label": "not_juicy", "tier": null, "category": "benign_noise", "sub_type": null, "notes": "User personal content directory with no credential association."}
```

Confirm you understand by replying "ready" — then I'll send the first batch.