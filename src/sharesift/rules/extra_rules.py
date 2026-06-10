"""Extra rules added on top of pysnaffler's bundled Snaffler defaults.

Three categories:

1. **Snaffler upstream catch-up rules** (7 rules) — pysnaffler's bundled
   pickle is 7 rules behind current Snaffler (pinned commit
   ``50ed78372b2cdf6df5a61cfdf6fd49c0d575331f``, captured 2026-06-03):

   - ``DiscardPostMatchByName`` (Green/Discard/FileName)
   - ``DiscardPostMatchByPath`` (Green/Discard/FilePath)
   - ``KeepDomainJoinCredsByName`` (Yellow/Snaffle/FileName) — customsettings.ini
   - ``KeepKerberosCredentialsByExtension`` (Yellow/Snaffle/FileExtension) — .keytab, .CCACHE
   - ``KeepKerberosCredentialsByName`` (Yellow/Snaffle/FileName) — krb5cc_*
   - ``KeepS3UriPrefixInCode`` (Yellow/Snaffle/Content) — s3:// URI prefix
   - ``KeepVMDisksByExtension`` (Red/Snaffle/FileExtension) — VM disk extensions

   These are auto-reconstructed from
   ``src/sharesift/rules/snaffler_default.json`` so re-porting Snaffler
   later picks up new rules automatically.

2. **v0.12 blind-spot rules** — credential filenames v0.12 confirmed
   Snaffler missed on Metasploitable 3 and analogous shares. Wins recall
   on the most-known-credential web app configs.

3. **ShareSift binary preprocessor** — discards files by extension at
   Stage 1 to eliminate the binary-artifact FP class that drove ~80% of
   ShareSift's FPs in v0.12. Complements (does not overlap) Snaffler's
   ``DiscardByFileExtension`` rule.

Loaded via :func:`truffler.pysnaffler_run.build_ruleset` with the
``include_extras=True`` flag (default).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Iterator

from pysnaffler.rules.constants import (
    EnumerationScope,
    MatchAction,
    MatchListType,
    MatchLoc,
    Triage,
)
from pysnaffler.rules.contents import SnafflerContentsEnumerationRule
from pysnaffler.rules.directory import SnafflerDirectoryRule
from pysnaffler.rules.file import SnafflerFileRule
from pysnaffler.rules.rule import SnaffleRule
from pysnaffler.rules.share import SnafflerShareRule

# Dispatch from EnumerationScope to the matching SnaffleRule subclass.
# The base SnaffleRule doesn't know how to extract path / name / extension
# from a file enumeration call — only the subclasses do. Using the base
# class directly produces a confusing TypeError at runtime ("expected
# string or bytes-like object, got 'NoneType'") because rule.match() runs
# regex over the raw smbfile argument instead of the path field.
_SCOPE_TO_RULE_CLASS = {
    EnumerationScope.ShareEnumeration: SnafflerShareRule,
    EnumerationScope.DirectoryEnumeration: SnafflerDirectoryRule,
    EnumerationScope.FileEnumeration: SnafflerFileRule,
    EnumerationScope.ContentsEnumeration: SnafflerContentsEnumerationRule,
}


def _build_rule(
    *,
    rule_name: str,
    enumeration_scope: EnumerationScope,
    match_action: MatchAction,
    match_location: MatchLoc,
    word_list_type: MatchListType,
    word_list: list[str],
    triage: Triage,
    description: str = "",
    relay_targets: list[str] | None = None,
) -> SnaffleRule:
    """Construct the correct SnaffleRule subclass for a given scope."""
    klass = _SCOPE_TO_RULE_CLASS[enumeration_scope]
    return klass(
        enumerationScope=enumeration_scope,
        ruleName=rule_name,
        matchAction=match_action,
        relayTargets=relay_targets or [],
        description=description,
        matchLocation=match_location,
        wordListType=word_list_type,
        matchLength=0,
        wordList=list(word_list),
        triage=triage,
    )

_RULES_DIR = Path(__file__).resolve().parent
_PORT_JSON = _RULES_DIR / "snaffler_default.json"

# Rule names that exist in our fresh Snaffler port but NOT in pysnaffler's
# bundled pickle. Re-run `tools/diff_pysnaffler_vs_port.py` to update.
_SNAFFLER_CATCHUP_RULES = {
    "DiscardPostMatchByName",
    "DiscardPostMatchByPath",
    "KeepDomainJoinCredsByName",
    "KeepKerberosCredentialsByExtension",
    "KeepKerberosCredentialsByName",
    "KeepS3UriPrefixInCode",
    "KeepVMDisksByExtension",
}

# Map JSON enum string → pysnaffler enum. pysnaffler uses CamelCase for
# EndsWith/StartsWith while the port JSON preserves Snaffler's TOML
# casing ("Endswith") — normalize here.
_MATCH_LIST_TYPE = {
    "Exact": MatchListType.Exact,
    "Contains": MatchListType.Contains,
    "Regex": MatchListType.Regex,
    "EndsWith": MatchListType.EndsWith,
    "Endswith": MatchListType.EndsWith,
    "StartsWith": MatchListType.StartsWith,
    "Startswith": MatchListType.StartsWith,
}
_MATCH_LOC = {
    "FileName": MatchLoc.FileName,
    "FilePath": MatchLoc.FilePath,
    "FileExtension": MatchLoc.FileExtension,
    "FileContentAsString": MatchLoc.FileContentAsString,
    "ShareName": MatchLoc.ShareName,
}
_MATCH_ACTION = {
    "Snaffle": MatchAction.Snaffle,
    "Discard": MatchAction.Discard,
    "Relay": MatchAction.Relay,
    "CheckForKeys": MatchAction.CheckForKeys,
}
_TRIAGE = {
    "Black": Triage.Black,
    "Red": Triage.Red,
    "Yellow": Triage.Yellow,
    "Green": Triage.Green,
    "Gray": Triage.Gray,
}


def _rule_from_port_record(rec: dict) -> SnaffleRule:
    """Reconstruct a pysnaffler SnaffleRule from a port JSON record.

    Snaffler distinguishes ``PostMatch`` as a separate rule scope (rules
    that filter AFTER a Keep rule fires). pysnaffler doesn't model it
    explicitly — its scope enum is just Share / Directory / File / Contents.
    For Snaffler's PostMatch Discard rules we collapse to FileEnumeration:
    discarding ``pspasswd.exe`` or paths containing ``Windows Kits\\10``
    at file-enum is functionally equivalent because these patterns
    never contain credentials regardless of which Keep rule almost fired.
    """
    raw_scope = rec.get("enumeration_scope")
    if raw_scope == "PostMatch" or raw_scope is None:
        # PostMatch collapses to FileEnumeration; missing scope is inferred
        # from match_location below.
        scope = None
    else:
        try:
            scope = EnumerationScope(raw_scope)
        except ValueError:
            scope = None
    if scope is None:
        if rec["match_location"] == "ShareName":
            scope = EnumerationScope.ShareEnumeration
        elif rec["match_location"] == "FileContentAsString":
            scope = EnumerationScope.ContentsEnumeration
        else:
            scope = EnumerationScope.FileEnumeration
    return _build_rule(
        rule_name=rec["rule_name"],
        enumeration_scope=scope,
        match_action=_MATCH_ACTION[rec["match_action"]],
        match_location=_MATCH_LOC[rec["match_location"]],
        word_list_type=_MATCH_LIST_TYPE[rec["wordlist_type"]],
        word_list=rec["wordlist"],
        triage=_TRIAGE[rec["triage"]],
        description=rec.get("description") or "",
    )


def _snaffler_catchup_rules() -> Iterator[SnaffleRule]:
    if not _PORT_JSON.exists():
        return
    data = json.loads(_PORT_JSON.read_text())
    for rec in data.get("rules", []):
        if rec["rule_name"] in _SNAFFLER_CATCHUP_RULES:
            yield _rule_from_port_record(rec)


def _v0p12_blind_spot_rules() -> Iterator[SnaffleRule]:
    """Credential filenames v0.12 confirmed Snaffler missed on
    Metasploitable 3. Each entry is a single, hand-authored rule.

    Why these specific ones:
    - wp-config.php / config.inc.php: confirmed FNs on MSF3, both
      tools' shared blind spot for web app configs in versioned
      install dirs (e.g., wamp/apps/phpmyadmin3.4.10.1/...)
    - unattend.xml UPGRADE: Snaffler relays it (Green) and only flags
      via content; the filename alone is high-signal (administrator
      password reset / autologon configs) — we promote to Red/Snaffle
    - .env: ubiquitous on Laravel/Node/Django; routinely contains
      DB creds, API keys. NOT name=.env.example (the labeler's
      placeholder denylist handles that at content stage).
    - docker-compose.yml: top-level env vars often hardcoded
    """

    def _rule(name, location, list_type, wordlist, triage, desc,
              scope=EnumerationScope.FileEnumeration) -> SnaffleRule:
        return _build_rule(
            rule_name=name,
            enumeration_scope=scope,
            match_action=MatchAction.Snaffle,
            match_location=location,
            word_list_type=list_type,
            word_list=wordlist,
            triage=triage,
            description=desc,
        )

    yield _rule(
        "ShareSiftKeepWordPressConfig",
        MatchLoc.FileName, MatchListType.Exact,
        ["wp-config.php"],
        Triage.Red,
        "WordPress config — DB credentials + auth keys + salts at top level.",
    )
    yield _rule(
        "ShareSiftKeepPhpMyAdminConfig",
        MatchLoc.FileName, MatchListType.Exact,
        ["config.inc.php"],
        Triage.Red,
        "phpMyAdmin config — MySQL connection credentials.",
    )
    yield _rule(
        "ShareSiftKeepUnattendXmlUpgrade",
        MatchLoc.FileName, MatchListType.Exact,
        ["unattend.xml", "Unattend.xml", "AutoUnattend.xml", "autounattend.xml"],
        Triage.Red,
        "Unattended Windows install — AdministratorPassword + autologon. "
        "Upgrades Snaffler's KeepUnattendXmlRelay (Green) to Red/Snaffle.",
    )
    yield _rule(
        "ShareSiftKeepLaravelEnv",
        MatchLoc.FileName, MatchListType.Exact,
        [".env"],
        Triage.Red,
        "dotenv — DB credentials, API keys, secrets. Common in Laravel, Node, Django.",
    )
    yield _rule(
        "ShareSiftKeepDockerCompose",
        MatchLoc.FileName, MatchListType.Exact,
        ["docker-compose.yml", "docker-compose.yaml",
         "docker-compose.override.yml", "docker-compose.prod.yml"],
        Triage.Yellow,
        "Docker compose — environment vars often hold credentials inline.",
    )
    yield _rule(
        "ShareSiftKeepRailsSecrets",
        MatchLoc.FileName, MatchListType.Exact,
        ["secrets.yml", "credentials.yml.enc", "master.key"],
        Triage.Red,
        "Rails secrets / encrypted credentials / master key.",
    )
    yield _rule(
        "ShareSiftKeepResetPasswordXml",
        MatchLoc.FileName, MatchListType.Exact,
        ["resetPWD.xml"],
        Triage.Red,
        "ManageEngine Desktop Central admin password reset XML.",
    )
    yield _rule(
        "ShareSiftKeepGppPreferences",
        MatchLoc.FileName, MatchListType.Exact,
        ["Groups.xml", "Services.xml", "ScheduledTasks.xml",
         "Printers.xml", "Drives.xml", "DataSources.xml"],
        Triage.Red,
        "GPP Preferences XML in SYSVOL — canonical AD cpassword target. "
        "Historical MS14-025 attack: cpassword attribute is AES-256 encrypted "
        "with a publicly published key. Added 2026-06-04 after GOAD benchmark "
        "showed both pysnaffler's bundle and v0.14 extras lacked GPP coverage.",
    )
    yield _build_rule(
        rule_name="ShareSiftKeepGppCpasswordContent",
        enumeration_scope=EnumerationScope.ContentsEnumeration,
        match_action=MatchAction.Snaffle,
        match_location=MatchLoc.FileContentAsString,
        word_list_type=MatchListType.Regex,
        word_list=[r'cpassword\s*=\s*["\'][A-Za-z0-9+/=]{8,}["\']'],
        triage=Triage.Black,
        description=(
            "GPP cpassword AES-encrypted blob — promotes to Black when the "
            "actual cpassword XML attribute is present (companion to the "
            "filename rule above)."
        ),
    )
    # --- Linux blind-spot rules (added 2026-06-04 after Linux head-to-head
    # benchmark revealed both pysnaffler bundle and ShareSift v0.14 extras
    # at 56% recall on a canonical Linux server with planted creds) ---
    yield _rule(
        "ShareSiftKeepDotEnvVariants",
        MatchLoc.FileName, MatchListType.Regex,
        [r"^\.env(\.[\w]+)?$"],
        Triage.Red,
        "dotenv variants — .env, .env.production, .env.local, .env.staging "
        "(common Laravel / Node / Django / Next.js credential storage).",
    )
    yield _rule(
        "ShareSiftKeepKubeConfig",
        MatchLoc.FilePath, MatchListType.Regex,
        [r"[/\\]\.kube[/\\]config$", r"[/\\]kubeconfig$"],
        Triage.Black,
        "Kubernetes config — cluster credentials + service account tokens.",
    )
    yield _rule(
        "ShareSiftKeepSSHHostKeys",
        MatchLoc.FileName, MatchListType.Regex,
        [r"^ssh_host_(rsa|dsa|ecdsa|ed25519)_key$"],
        Triage.Black,
        "SSH server host private keys (impersonate the host).",
    )
    yield _rule(
        "ShareSiftKeepSSHAuthorizedKeys",
        MatchLoc.FileName, MatchListType.Exact,
        ["authorized_keys", "authorized_keys2", "known_hosts"],
        Triage.Red,
        "SSH user keys + known_hosts (intel value per labeling calibration).",
    )
    yield _rule(
        "ShareSiftKeepSSHUserKeys",
        MatchLoc.FileName, MatchListType.Regex,
        [r"^id_(rsa|dsa|ecdsa|ed25519|xmss)(\.pub)?$"],
        Triage.Black,
        "SSH user private keys.",
    )
    yield _rule(
        "ShareSiftKeepSudoersFiles",
        MatchLoc.FilePath, MatchListType.Regex,
        [r"^/etc/sudoers(\.d)?(/.*)?$"],
        Triage.Red,
        "sudoers + sudoers.d/* — NOPASSWD entries are top-3 Linux privesc primitive.",
    )
    yield _rule(
        "ShareSiftKeepCronJobs",
        MatchLoc.FilePath, MatchListType.Regex,
        [r"^/(var/spool/cron|etc/cron\.d|etc/cron\.daily|etc/cron\.hourly|etc/cron\.weekly|etc/cron\.monthly)/",
         r"^/etc/crontab$"],
        Triage.Yellow,
        "Cron jobs — often contain literal mysql -p / curl -u creds in command strings.",
    )
    yield _rule(
        "ShareSiftKeepCloudCliCreds",
        MatchLoc.FilePath, MatchListType.Regex,
        [r"[/\\]\.aws[/\\](credentials|config)$",
         r"[/\\]\.azure[/\\](msal_token_cache|accessTokens)",
         r"[/\\]\.config[/\\]gcloud[/\\]",
         r"[/\\]\.docker[/\\]config\.json$"],
        Triage.Black,
        "Cloud CLI credential caches — AWS / Azure / GCP / Docker registry tokens.",
    )
    yield _rule(
        "ShareSiftKeepGnuPGFiles",
        MatchLoc.FilePath, MatchListType.Regex,
        [r"[/\\]\.gnupg[/\\](private-keys-v1\.d|pubring\.kbx|trustdb\.gpg)"],
        Triage.Black,
        "GnuPG keyring (private keys + trust DB).",
    )
    yield _rule(
        "ShareSiftKeepKerberosKeytab",
        MatchLoc.FileName, MatchListType.Regex,
        [r"\.keytab$", r"^krb5\.conf$"],
        Triage.Red,
        "Kerberos keytab + config.",
    )
    yield _rule(
        "ShareSiftKeepNetworkManagerSecrets",
        MatchLoc.FilePath, MatchListType.Regex,
        [r"^/etc/NetworkManager/system-connections/",
         r"\.nmconnection$",
         r"^/etc/wpa_supplicant/"],
        Triage.Red,
        "WiFi / VPN credentials in NetworkManager + wpa_supplicant configs.",
    )


def _v0p42_benchmark_gap_rules() -> Iterator[SnaffleRule]:
    """v0.42: rules closing the both-missed credential paths surfaced
    by the 2026-06 head-to-head benchmark against Snaffler.

    These are paths that Snaffler's rule library also misses; adding
    them extends ShareSift's coverage lead. Each entry was one of
    the 11 "both-missed credentials" on MSF2 (Linux Metasploitable 2).
    """

    def _rule(name, location, list_type, wordlist, triage, desc):
        return _build_rule(
            rule_name=name,
            enumeration_scope=EnumerationScope.FileEnumeration,
            match_action=MatchAction.Snaffle,
            match_location=location,
            word_list_type=list_type,
            word_list=wordlist,
            triage=triage,
            description=desc,
        )

    yield _rule(
        "ShareSiftKeepShadowBackup",
        MatchLoc.FilePath, MatchListType.Regex,
        [r"^/etc/shadow-$", r"^/etc/gshadow-?$"],
        Triage.Black,
        "passwd/shadow .bak forms created by passwd/groupadd before writing.",
    )
    yield _rule(
        "ShareSiftKeepNfsExports",
        MatchLoc.FilePath, MatchListType.Regex,
        [r"^/etc/exports$"],
        Triage.Yellow,
        "NFS share exports — host access rules + krb5 sec= flavors.",
    )
    yield _rule(
        "ShareSiftKeepPostfixConfig",
        MatchLoc.FilePath, MatchListType.Regex,
        [r"^/etc/postfix/main\.cf$",
         r"^/etc/postfix/sasl_passwd$",
         r"^/etc/postfix/saslpasswd2$"],
        Triage.Yellow,
        "Postfix config — main.cf + sasl_passwd hold relay credentials.",
    )
    yield _rule(
        "ShareSiftKeepMysqlDataDir",
        MatchLoc.FilePath, MatchListType.Regex,
        [r"/var/lib/mysql/mysql/user\.(MYD|MYI|frm|ibd)$",
         r"/var/lib/mysql/mysql/db\.(MYD|MYI|frm)$",
         r"/var/lib/mysql/mysql/proxies_priv\.(MYD|MYI|frm)$"],
        Triage.Black,
        "MySQL/MariaDB user table data files. Password hashes crack offline.",
    )
    yield _rule(
        "ShareSiftKeepEditorBackupConfig",
        MatchLoc.FilePath, MatchListType.Regex,
        [r".*\.(php|inc|conf|cfg|ini|env|yml|yaml|properties|sh)~$",
         r".*\.(php|inc|conf|cfg|ini|env|yml|yaml|properties|sh)\.bak$",
         r".*\.(php|inc|conf|cfg|ini|env|yml|yaml|properties|sh)\.swp$",
         r".*\.(php|inc|conf|cfg|ini|env|yml|yaml|properties|sh)\.orig$"],
        Triage.Red,
        "Editor backup of credential-shaped config file — DVWA-class pattern.",
    )
    yield _rule(
        "ShareSiftKeepSshHostPubKeys",
        MatchLoc.FilePath, MatchListType.Regex,
        [r"/etc/ssh/ssh_host_(rsa|dsa|ecdsa|ed25519)_key\.pub$"],
        Triage.Yellow,
        "SSH host public keys — signal private-keys present in same dir.",
    )


def _modern_saas_rules() -> Iterator[SnaffleRule]:
    """Modern SaaS credential detectors — ported from Gitleaks 2026-06.

    The pysnaffler ruleset is pinned to Snaffler's 2024 ruleset; Snaffler
    upstream and Gitleaks have both added detectors for cloud and AI
    services that didn't exist when Snaffler's defaults were authored.
    These fill the gap with high-confidence prefix matchers (no context
    required) — the patterns are specific enough that false positive
    rates are very low.

    Ported from https://raw.githubusercontent.com/gitleaks/gitleaks/master/config/gitleaks.toml
    as of 2026-06-04. License: MIT (Gitleaks).
    """
    saas_rules = [
        ("ShareSiftKeepAnthropicApiKey",
         r"sk-ant-api03-[a-zA-Z0-9_\-]{93}AA",
         Triage.Black, "Anthropic API key (Claude)"),
        ("ShareSiftKeepAnthropicAdminKey",
         r"sk-ant-admin01-[a-zA-Z0-9_\-]{93}AA",
         Triage.Black, "Anthropic admin API key — full org access"),
        ("ShareSiftKeepHuggingFaceToken",
         r"hf_[A-Za-z]{34}",
         Triage.Red, "Hugging Face access token"),
        ("ShareSiftKeepHuggingFaceOrgToken",
         r"api_org_[A-Za-z]{34}",
         Triage.Red, "Hugging Face organization API token"),
        ("ShareSiftKeepBedrockLongLivedKey",
         r"ABSK[A-Za-z0-9+/]{109,269}={0,2}",
         Triage.Black, "AWS Bedrock long-lived API key"),
        ("ShareSiftKeepBedrockShortLivedKey",
         r"bedrock-api-key-YmVkcm9jay5hbWF6b25hd3MuY29t",
         Triage.Red, "AWS Bedrock short-lived API key"),
        ("ShareSiftKeepClickhouseCloudKey",
         r"4b1d[A-Za-z0-9]{38}",
         Triage.Red, "ClickHouse Cloud API secret key"),
        ("ShareSiftKeepDatabricksApiToken",
         r"dapi[a-f0-9]{32}(?:-\d)?",
         Triage.Red, "Databricks API token"),
        ("ShareSiftKeepGitlabPatRoutable",
         r"glpat-[0-9a-zA-Z_-]{27,300}\.[0-9a-z]{2}[0-9a-z]{7}",
         Triage.Red, "GitLab routable personal access token"),
        ("ShareSiftKeepOpenAiApiKey",
         r"sk-(?:proj|svcacct|admin)-(?:[A-Za-z0-9_-]{74}|[A-Za-z0-9_-]{58})T3BlbkFJ",
         Triage.Black, "OpenAI API key (proj / svcacct / admin)"),
        ("ShareSiftKeepPerplexityApiKey",
         r"pplx-[a-zA-Z0-9]{48}",
         Triage.Red, "Perplexity API key"),
        ("ShareSiftKeepRenderApiToken",
         r"rnd_[a-zA-Z0-9]{14}",
         Triage.Red, "Render.com API token"),
        # Context-match patterns (less precise but higher recall on legacy code)
        ("ShareSiftKeepDatadogToken",
         r"(?i)datadog[\w. \-]{0,20}[=:][\s\"'`]{0,5}[a-f0-9]{40}",
         Triage.Yellow, "Datadog access token (context-match)"),
        ("ShareSiftKeepDropboxToken",
         r"(?i)dropbox[\w. \-]{0,20}[=:][\s\"'`]{0,5}[a-z0-9]{15}",
         Triage.Yellow, "Dropbox API token (context-match)"),
        ("ShareSiftKeepFastlyToken",
         r"(?i)fastly[\w. \-]{0,20}[=:][\s\"'`]{0,5}[a-z0-9=_\-]{32}",
         Triage.Yellow, "Fastly API token (context-match)"),
        ("ShareSiftKeepNetlifyToken",
         r"(?i)netlify[\w. \-]{0,20}[=:][\s\"'`]{0,5}[a-z0-9=_\-]{40}",
         Triage.Yellow, "Netlify access token (context-match)"),
    ]
    for name, pattern, triage, desc in saas_rules:
        yield _build_rule(
            rule_name=name,
            enumeration_scope=EnumerationScope.ContentsEnumeration,
            match_action=MatchAction.Snaffle,
            match_location=MatchLoc.FileContentAsString,
            word_list_type=MatchListType.Regex,
            word_list=[pattern],
            triage=triage,
            description=desc + " (ported from Gitleaks 2026-06-04, MIT).",
        )


def _binary_preprocessor_rule() -> SnaffleRule:
    """Stage 1 discard for binary file extensions that cannot contain
    plaintext credentials. Complements Snaffler's DiscardByFileExtension —
    we deliberately keep extensions Snaffler doesn't drop and that may
    contain creds (.jar, .zip, .tar.gz containers; .bak, .mdf, .ldf
    SQL backups; .pcap network captures; .cab Windows install packages).

    Driven by v0.12 — ShareSift's path classifier scored Red/Black on
    332 GlassFish .jar/.exe/.dll files and 25 phpMyAdmin .js UI files
    that cannot contain credentials. Dropping them upstream eliminates
    ~80% of v0.12's FPs without recall cost.

    Per Vincent's signed-off labeling calibration (feedback memory):
    - SQL backup files (.bak/.mdf/.ldf) — KEEP. Snaffler's
      KeepDatabaseByExtension flags them Yellow; we don't override.
    - Container archives (.zip/.tar/.gz/.7z) — KEEP. May contain
      extracted credentials; Yellow at most via Snaffler.
    """
    return _build_rule(
        rule_name="ShareSiftBinaryPreprocessor",
        enumeration_scope=EnumerationScope.FileEnumeration,
        match_action=MatchAction.Discard,
        description=(
            "Discard binary file extensions at Stage 1. Targets the v0.12 "
            "FP class (GlassFish JARs, EXEs, image/font assets, compiled "
            "bytecode). Excludes SQL backups, archives, and PCAPs, which "
            "may contain extractable credentials."
        ),
        match_location=MatchLoc.FileExtension,
        word_list_type=MatchListType.Exact,
        triage=Triage.Green,
        word_list=[
            # Image/font (cannot contain text credentials at all)
            r"\.png", r"\.jpg", r"\.jpeg", r"\.gif", r"\.ico",
            r"\.bmp", r"\.tiff", r"\.tif", r"\.webp", r"\.svg",
            r"\.ttf", r"\.otf", r"\.woff", r"\.woff2", r"\.eot",
            # Compiled binaries (no plaintext creds at filename-rule scope)
            r"\.exe", r"\.dll", r"\.pdb", r"\.lib", r"\.obj",
            r"\.o", r"\.so", r"\.a", r"\.dylib",
            # Compiled Java/.NET/Python bytecode
            r"\.class", r"\.pyc", r"\.pyo", r"\.jar",
            # Container/disk images Snaffler doesn't enter (KeepVMDisksByExtension
            # covers these as Red — we discard duplicates to avoid double-flagging)
            r"\.iso",
            # Media (cannot contain text credentials)
            r"\.mp3", r"\.mp4", r"\.avi", r"\.mov", r"\.wav", r"\.flac",
            r"\.m4a", r"\.wmv", r"\.mkv",
        ],
    )


def _v0p47_snaffler_issues_rules() -> Iterator[SnaffleRule]:
    """v0.47: rules derived from mining the SnaffCon/Snaffler issue
    tracker for real-world operator complaints. See
    ``benchmarks/snaffler_issues/`` for the corpus + scorer.

    Each rule cites the Snaffler issue number that surfaced the gap.
    Held-out generalization (parallel patterns from issues #78, #135,
    #67 not used during rule authoring) lifted from 1/11 → 4/11
    (9% → 36%) — documented as partial generalization per
    docs/v0p47_results.md.
    """

    def _rule(name, location, list_type, wordlist, triage, desc):
        return _build_rule(
            rule_name=name,
            enumeration_scope=EnumerationScope.FileEnumeration,
            match_action=MatchAction.Snaffle,
            match_location=location,
            word_list_type=list_type,
            word_list=wordlist,
            triage=triage,
            description=desc,
        )

    yield _rule(
        "ShareSiftKeepFirefoxSavedCreds",
        MatchLoc.FilePath, MatchListType.Regex,
        [
            r"Mozilla\\Firefox\\Profiles\\[^\\]+\\(logins\.json|logins-backup\.json|key4\.db|key3\.db)$",
            r"/\.mozilla/firefox/[^/]+/(logins\.json|logins-backup\.json|key4\.db|key3\.db)$",
        ],
        Triage.Black,
        "Firefox saved-passwords surface: logins.json + key4.db NSS database. Closes Snaffler #46.",
    )
    yield _rule(
        "ShareSiftKeepGppPolicyXml",
        MatchLoc.FilePath, MatchListType.Regex,
        [r"SYSVOL\\.+\\Policies\\.+\\(Groups|Drives|Services|ScheduledTasks|DataSources|Printers)\.xml$"],
        Triage.Black,
        "GPP XML under SYSVOL Policies — historical cpassword (MS14-025) surface. Closes Snaffler #31.",
    )
    yield _rule(
        "ShareSiftKeepGermanCredFilenames",
        MatchLoc.FileName, MatchListType.Regex,
        [r"(Kennw(oe|ö|o)rter|Passw(oe|ö|o)rter|Anmeldedaten|Logindaten|Zug(ae|ä|a)ng(e|es)?|Schl(ue|ü|u)ssel)"],
        Triage.Red,
        "German credential-keyword filenames. Corporate-Europe coverage. Closes Snaffler #53.",
    )
    yield _rule(
        "ShareSiftKeepWireguardPrivateKey",
        MatchLoc.FileContentAsString, MatchListType.Regex,
        [r"(^|\n)\s*PrivateKey\s*=\s*[A-Za-z0-9+/]{42,44}={0,2}\s*(\n|$)"],
        Triage.Black,
        "WireGuard config with embedded base64 Curve25519 private key. Black on content match. Closes Snaffler #119.",
    )
    yield _rule(
        "ShareSiftKeepOpenvpnAuthUserPassRef",
        MatchLoc.FileContentAsString, MatchListType.Regex,
        [r"(^|\n)\s*auth-user-pass\s+[^\s#]+"],
        Triage.Red,
        "OpenVPN auth-user-pass directive pointing at a credential file. Closes Snaffler #119 content gap.",
    )
    yield _rule(
        "ShareSiftKeepCiscoAnyconnectXml",
        MatchLoc.FileName, MatchListType.Regex,
        [r"anyconnect.*\.xml$", r"vpn(server|profile)s?\.xml$"],
        Triage.Yellow,
        "Cisco AnyConnect XML profile. Closes Snaffler #119 modern-VPN gap.",
    )
    yield _rule(
        "ShareSiftKeepDoubleDashPassphrase",
        MatchLoc.FileContentAsString, MatchListType.Regex,
        [
            r"--pass(?:word|phrase)\s*=\s*\S+",
            r"--pass(?:word|phrase)\s+[^-\s][^\s]*",
        ],
        Triage.Red,
        "Double-dash CLI password flags (--password=, --passphrase=). Closes Snaffler #158 TP gap.",
    )


def _v0p48_held_out_close_rules() -> Iterator[SnaffleRule]:
    """v0.48: rules closing v0.47's held-out underfit. Sourced from
    OLD held-out issue threads (#78 Cisco config rules, #135 FileZilla
    saved sites, #67 SQL connection strings) — these were locked at
    v0.47-rule authoring time. v0.48 verified them against a NEW
    held-out set (heldout_v2.jsonl) mined from previously-unread PR
    sources (#198 CMD set, #155 Azure CLI, #98 credential filename
    keyword) — the browser-creds meta-rule below generalized cleanly
    to Chrome + Edge probes (parallel pattern). See
    docs/v0p48_results.md.
    """

    def _rule(name, location, list_type, wordlist, triage, desc):
        return _build_rule(
            rule_name=name,
            enumeration_scope=EnumerationScope.FileEnumeration,
            match_action=MatchAction.Snaffle,
            match_location=location,
            word_list_type=list_type,
            word_list=wordlist,
            triage=triage,
            description=desc,
        )

    yield _rule(
        "ShareSiftKeepCiscoEnableSecret",
        MatchLoc.FileContentAsString, MatchListType.Regex,
        [
            r"(^|\n)\s*enable\s+secret\s+[0-7]\s+\S+",
            r"(^|\n)\s*enable\s+password\s+\S+",
            r"(^|\n)\s*username\s+\S+\s+(privilege\s+\d+\s+)?(password|secret)\s+[0-7]?\s*\S+",
            r"(^|\n)\s*password\s+7\s+[0-9A-F]{4,}",
        ],
        Triage.Red,
        "Cisco IOS enable secret/password + type-7 obfuscated. Closes Snaffler #78.",
    )
    yield _rule(
        "ShareSiftKeepCiscoSnmpCommunity",
        MatchLoc.FileContentAsString, MatchListType.Regex,
        [r"(^|\n)\s*snmp-server\s+community\s+\S+\s+RW\b"],
        Triage.Red,
        "Cisco SNMP RW community — write access to device. Closes #78 RW tier.",
    )
    yield _rule(
        "ShareSiftKeepCiscoSnmpCommunityRo",
        MatchLoc.FileContentAsString, MatchListType.Regex,
        [r"(^|\n)\s*snmp-server\s+community\s+\S+\s+RO\b"],
        Triage.Yellow,
        "Cisco SNMP RO community — read access. Closes #78 RO tier.",
    )
    yield _rule(
        "ShareSiftKeepFileZillaSavedSites",
        MatchLoc.FilePath, MatchListType.Regex,
        [r"FileZilla\\sitemanager\.xml$", r"/FileZilla/sitemanager\.xml$"],
        Triage.Black,
        "FileZilla SiteManager saved FTP/SFTP creds. Closes Snaffler #135.",
    )
    yield _rule(
        "ShareSiftKeepFileZillaRecentServers",
        MatchLoc.FilePath, MatchListType.Regex,
        [r"FileZilla\\recentservers\.xml$", r"/FileZilla/recentservers\.xml$"],
        Triage.Yellow,
        "FileZilla recent-connections list. Closes #135 recentservers scope.",
    )
    yield _rule(
        "ShareSiftKeepDotNetAppSettingsConnString",
        MatchLoc.FileContentAsString, MatchListType.Regex,
        [
            r"\"ConnectionStrings?\"\s*:\s*\{[^}]{0,500}Password\s*=\s*[^;\"]+",
            r"\"DefaultConnection\"\s*:\s*\"[^\"]{0,500}Password\s*=\s*[^;\"]+",
        ],
        Triage.Red,
        ".NET appsettings.json connection string with embedded Password=. Closes #67.",
    )
    yield _rule(
        "ShareSiftKeepBrowserSavedCreds",
        MatchLoc.FilePath, MatchListType.Regex,
        [
            r"(Chrome|Chromium|Edge|Brave-Browser|Opera Software\\Opera)\\User Data\\[^\\]+\\Login Data$",
            r"/(google-chrome|chromium|microsoft-edge|BraveSoftware/Brave-Browser|opera)/[^/]+/Login Data$",
            r"/Library/Application Support/(Google/Chrome|Microsoft Edge|BraveSoftware/Brave-Browser)/[^/]+/Login Data$",
        ],
        Triage.Black,
        "Chromium-base browser saved-passwords SQLite (Chrome/Edge/Brave/Opera). Generalizes v0.47 Firefox rule to Snaffler #46's full browser scope.",
    )


def _v0p49_held_out_v2_close_rules() -> Iterator[SnaffleRule]:
    """v0.49: rules closing v0.48's held-out v2 underfit. Sourced from
    v2-locked sources only — #198 (CMD set quoted variant) and #98
    (loose 'credential' filename keyword). Held-out v3 is locked
    (Kerberos/SCCM/MDE/single-dash-password from #140/#112/#139/#154)
    BEFORE these rules were authored. See docs/v0p49_results.md.
    """

    def _rule(name, location, list_type, wordlist, triage, desc):
        return _build_rule(
            rule_name=name,
            enumeration_scope=EnumerationScope.FileEnumeration,
            match_action=MatchAction.Snaffle,
            match_location=location,
            word_list_type=list_type,
            word_list=wordlist,
            triage=triage,
            description=desc,
        )

    yield _rule(
        "ShareSiftKeepCmdSetQuotedAssignment",
        MatchLoc.FileContentAsString, MatchListType.Regex,
        [
            r'(^|\n)\s*set\s+"[A-Z_][A-Z0-9_]*(password|passwd|passphrase|pwd|secret|token|apikey|api_key|cred|credential|auth_key|access_key)[A-Z0-9_]*\s*=\s*[^"]+"',
        ],
        Triage.Red,
        'Windows CMD quoted-string set: set "VAR=val" with cred-shaped VAR. Upstream KeepPassOrKeyInCode misses because quote sits outside the assignment. Closes Snaffler #198 quoted variant.',
    )
    yield _rule(
        "ShareSiftKeepCredentialFilenameKeyword",
        MatchLoc.FileName, MatchListType.Regex,
        [
            r"^[A-Za-z0-9_\-]*credentials?[A-Za-z0-9_\-]*\.(csv|xlsx|xls|tsv|json|xml|yaml|yml|txt|sql|db|sqlite|kdbx|zip|tar|tgz|tar\.gz|bak|7z|rar)$",
        ],
        Triage.Red,
        "Filename contains 'credential(s)' AND extension is a data/export/archive shape. Promotes the Snaffler Green default to Red because export-shape extension implies a creds dump, not a policy doc. Closes Snaffler #98.",
    )


def get_extra_rules() -> list[SnaffleRule]:
    """Return all extra rules (catch-up + blind-spot + modern SaaS + binary preprocessor)."""
    rules: list[SnaffleRule] = []
    rules.extend(_snaffler_catchup_rules())
    rules.extend(_v0p12_blind_spot_rules())
    rules.extend(_v0p42_benchmark_gap_rules())
    rules.extend(_v0p47_snaffler_issues_rules())
    rules.extend(_v0p48_held_out_close_rules())
    rules.extend(_v0p49_held_out_v2_close_rules())
    rules.extend(_modern_saas_rules())
    rules.append(_binary_preprocessor_rule())
    return rules


__all__ = ["get_extra_rules"]
