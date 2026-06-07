"""Claude-judgment labeling layer for the eval set.

Reads ``data/eval/queue.jsonl``, skips paths already in
``data/eval/eval_set.jsonl``, applies path-feature heuristics encoded
as deterministic rules, and emits ``data/eval/eval_set_claude.jsonl``.
``added_by`` is ``"claude"`` so the file is distinguishable from
``eval_set.jsonl`` (Vincent's directly-labeled records).

Idempotent: re-running overwrites the output with current rules. The
rules are reviewable here as numbered ``Rule N`` blocks in ``decide()``,
and the per-rule justification text in each record's ``notes`` field
lets the operator sample-audit any rule's effect across all records it
touched.

Epistemological note (post-2026-05-28 recalibration): these labels are
NOT engagement-grade pentester ground truth. They're a deterministic
rule-based judgment layer calibrated against Vincent's lab-shape
preferences. Useful signal, but the eval set's ceiling is bounded by
the rules encoded here — the model trained on this can't be measured
against real-engagement priors until engagement-derived ground truth
exists. See ``docs/journal.md`` (2026-05-28 recalibration entry) for
the full framing.

Negative-validator integration: every emitted record echoes any
``negative_validator.check_path`` heuristics that fire on its path
into ``validator_warnings``, so the ``validate.py`` integrity-check
phase doesn't flag drift between the labeler and the heuristic
registry.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import date
from pathlib import Path, PureWindowsPath

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from src.eval.build_queue import pre_categorize
from src.eval.negative_validator import check_path as negative_check
from src.eval.schema import EvalRecord

QUEUE_PATH = REPO_ROOT / "data" / "eval" / "queue.jsonl"
EVAL_SET_PATH = REPO_ROOT / "data" / "eval" / "eval_set.jsonl"
OUTPUT_PATH = REPO_ROOT / "data" / "eval" / "eval_set_claude.jsonl"

TODAY = date(2026, 5, 29)

# ---------------------------------------------------------------------------
# Path-feature detectors
# ---------------------------------------------------------------------------

_SYSVOL_NETLOGON_RE = re.compile(r"\\(sysvol|netlogon)\\", re.IGNORECASE)
_NETLOGON_RE = re.compile(r"\\netlogon(\\|$)", re.IGNORECASE)
_SYSVOL_RE = re.compile(r"\\sysvol(\\|$)", re.IGNORECASE)
_POLICIES_RE = re.compile(r"\\policies(\\|$)", re.IGNORECASE)

# Logon-script extensions: writable → RCE on every login.
_SCRIPT_EXTS = frozenset(
    {".bat", ".cmd", ".vbs", ".ps1", ".vbe", ".js", ".wsf", ".exe", ".msi", ".mof"}
)

# Backup-directory signals (SQL, system, file backups).
_BACKUP_DIR_TOKENS = (
    "sqlbackup",
    "sql_backup",
    "sql-backup",
    "dbbackup",
    "db_backup",
    "db-backup",
    "databasebackup",
    "database_backup",
    "backup",
    "backups",
    "bak",
)

# Departmental shares with elevated base-rate prior for sensitive content.
_HIGH_VALUE_DEPT_TOKENS = (
    "finance",
    "financial",
    "accounting",
    "accounts",
    "payroll",
    "hr",
    "humanresources",
    "human_resources",
    "human-resources",
    "legal",
    "compliance",
    "executive",
    "exec",
    "ceo",
    "cfo",
    "director",
    "board",
    "treasury",
    "audit",
    "controller",
)

# IT / admin / ops shares: scripts, credentials, tooling commonly stored.
_IT_ADMIN_TOKENS = (
    "it-tools",
    "ittools",
    "it_tools",
    "sysadmin",
    "sys_admin",
    "admin-tools",
    "admintools",
    "admin_tools",
    "devops",
    "scripts",
    "automation",
    "deployment",
    "deploy",
    "provisioning",
    "build-tools",
    "buildtools",
    "build_tools",
)

# Hostname tokens hinting "domain controller" — SYSVOL/NETLOGON only live on DCs.
_DC_HOSTNAME_TOKENS = (
    "-dc",
    "dc-",
    "dc01",
    "dc02",
    "dc1",
    "dc2",
    "domaincontroller",
    "domain-controller",
    "domain_controller",
    "-ad",
    "ad-",
    "-pdc",
    "pdc-",
)

# Placeholder / lab / demo / test hostnames — synthetic, not real environments.
_PLACEHOLDER_TOKENS = (
    "example",
    "myhost",
    "myserver",
    "yourhost",
    "yourserver",
    "hostname",
    "<host",
    "<server",
    "ip_address",
    "ipaddress",
    "sharedfolder",
    "sharename",
    "servername",
    "computername",
    "machine",
    "demohost",
    "testhost",
    "test-host",
    "fake",
    "placeholder",
    "foo",
    "bar",
    "baz",
    "lorem",
    "asdf",
    "mydomain",
    "mydomain.local",
    "mydomain.com",
    "yourdomain",
    "yourdomain.local",
    "yourdomain.com",
    "uncpath",
    "newname",
    "newserver",
    "oldserver",
    "computerorip",
    "computerip",
    "ipaddress",
    "ip_address",
    "printserver",
    "domaindfsroot",
    "domain_name",
    "domainname",
    "xxxxx",
    "xxxx",
    "xxx",
    "ip.address",  # catches `your.ip.address.number` and similar dotted placeholders
    "your.ip",
    "address.number",
    "your.domain",
    "your.share",
    "thesmbserver",  # SE-style placeholder
    "thenetworkshare",
    "fileserveraddress",
    "smbserver",
    "smbshare",
    "sharename",
    "networkshare",
    "pc-name",  # `\\PC-Name-Where-Share-Is\...` SE-style placeholder
    "pc_name",
    "pcname",
    "where-share-is",
    "user_name",
    "username_here",
    "usernamehere",  # `\\Gamer-pc\c\Users\UsernameHere\...`
    "computer_name",  # `\\COMPUTER_NAME\Users\USER_NAME\...`
    "company_name",
    "company-name",
    "linked_dir",
    "linked-dir",
)

# Special-case software substrings that should land in high_value_software
# rather than the generic credential-keyword bucket. Identity-sync /
# directory-sync tools — finding them on a share is recon intelligence
# revealing a chunk of the AD-to-cloud identity bridge.
_HIGH_VALUE_SOFTWARE_NAME_EXTRAS = (
    "googleappspasswordsync",
    "azureadconnect",
    "adconnect",
    "adsync",
    "directorysync",
    "passwordsync",
)

# CTF/lab leakage that escaped the security filter.
_CTF_TOKENS = (
    "flag-tier",
    "flag_tier",
    "flag.txt",
    "flag-kerberoast",
    "flag-ad",
    "flag-",  # generic flag-* pattern caught by CTF challenges
    "ctf",
    "thm-",
    "hackthebox",
    "hack-the-box",
    "tryhackme",
    "vulnhub",
    "hackme",
    "kerberoast.txt",  # canonical CTF challenge artifact name
)

# Credential-keyword tokens for path-substring detection (anywhere in path,
# not just filename). Used as a fallback for paths where a strong
# credential signal appears as a directory or share name but didn't match
# a more specific rule. Conservative list to avoid FP creep (e.g. "auth"
# matches authentication contexts too broadly; "key" matches keynote).
_PATH_CREDENTIAL_KEYWORDS = (
    "vault",  # passwords, secrets, KeePass directory
    "password",  # singular — catches `passworddictionaries`, `password-archive`
    "passwords",
    "passwd",
    "credentials",  # plural — "credentials" dir hits this
    "keystore",
    "wallets",
    "wallet",
)

# Windows answer files (unattend.xml / autounattend.xml) — canonical
# credential primitive. Used during OS deployment to provide the
# Administrator password (typically plaintext or trivially-encoded);
# finding one on a share is direct compromise material.
_UNATTEND_NAME_SUBSTRINGS = ("unattend",)

# .rdp connection files — frequently embed server hostname, username,
# and (depending on options) password or password hash. Even without
# credentials, the file reveals which RDP targets the user routinely
# connects to (recon).
_RDP_EXT = ".rdp"

# Logon-script directory at SYSVOL/NETLOGON: config-ish files that
# reveal automation logic and GPO content even when not directly
# executable. Pentester always inspects these. Excluded: image/asset
# extensions (wallpapers, logos) which are legitimately not_juicy.
_NETLOGON_CONFIG_EXTS = frozenset(
    {".xml", ".ini", ".reg", ".pol", ".bgi", ".rdp", ".inf", ".admx", ".adml"}
)

# Azure file-share host pattern.
_AZURE_FILESHARE_RE = re.compile(r"\.file\.core\.windows\.net", re.IGNORECASE)

# Apps/software/installer share tokens — installers often carry embedded secrets.
_SOFTWARE_REPO_TOKENS = (
    "installers",
    "installer",
    "msi-share",
    "software",
    "apps",
    "applications",
    "deployments",
    "packages",
    "patches",
    "updates",
)

# User-home and personal-share signals.
_USER_HOME_TOKENS = (
    "userdata",
    "user_data",
    "userhome",
    "user_home",
    "userhomes",
    "user_homes",
    "homes",
    "users",
    "folderredirection",
    "folder_redirection",
    "folder-redirection",
    "profiles",
    "userprofile",
    "redirected",
)

# Generic-share names that are too thin to call juicy without more context.
_THIN_SHARE_NAMES = frozenset(
    {
        "share",
        "shares",
        "shared",
        "public",
        "common",
        "partage",  # FR "sharing"
        "compartilhamento",  # PT "share"
        "compartido",  # ES "shared"
        "gemeinsam",  # DE "shared"
    }
)

# Vendor/publicly-available binary-name tokens — if any appear in the
# .exe/.msi filename, the binary is treated as not_juicy/benign_noise
# (standard vendor installer/utility, no embedded-secret prior).
_VENDOR_BINARY_TOKENS = (
    "adobe",
    "creativecloud",
    "creative-cloud",
    "microsoft",
    "defender",
    "mpam",  # MS Defender update
    "sysmon",
    "sysinternals",
    "bginfo",  # Sysinternals BGInfo — vendor utility
    "stinger",  # McAfee Stinger standalone scanner — vendor utility
    "psexec",  # covered by high_value_software earlier but defensive
    "handle.exe",
    "libreoffice",
    "openoffice",
    "mozilla",
    "firefox",
    "chrome",
    "googleupdate",
    "google",
    "edge",
    "java",
    "jre-",
    "jdk-",
    "oracle",
    "vmware",
    "citrix",
    "wireshark",
    "putty",
    "winscp",
    "securecrt",
    "filezilla",
    "7-zip",
    "7zip",
    "winrar",
    "notepad++",
    "notepadplusplus",
    "vlc",
    "skype",
    "zoom",
    "tightvnc",
    "realvnc",
    "ultravnc",
    "kix32",  # KIX script engine, publicly available
    "kix64",
    # NOTE: OctopusTentacle (deployment) and GLPI-agent (asset mgmt) are
    # deliberately NOT in this list — they are deployment/management
    # tooling whose presence is itself a recon-relevant finding for a
    # pentester. They flow through the custom-binary rule and land as
    # juicy/Yellow/embedded_secrets. Future fix: add to
    # build_queue.py:_HIGH_VALUE_SOFTWARE_NAME_SUBSTRINGS so they
    # pre-categorize correctly.
    "autopcc",  # Trend Micro client, vendor
)

# Public toolkit / vendor archive tokens — when these appear in a .zip/
# .rar/.7z filename, the archive is a known public artifact (toolkit,
# vendor distribution) and not a sealed credential container.
_PUBLIC_TOOLKIT_ARCHIVE_TOKENS = (
    "first-responder",
    "responder-kit",
    "first_responder",
    "responder_kit",
    "sysinternals",
    "sysinternalssuite",
    "brent-ozar",
    "brentozar",
    "powersploit",
    "powerview",
    "nirsoft",
    "pstools",
)


# Trailing-junk characters introduced by GitHub Code Search regex extraction:
# backtick (markdown code fence), CJK punctuation, comma/semicolon/colon,
# closing brackets/parens, double-quote, single-quote. The cleaned-suffix
# helper strips these before extension-based rules run, so paths like
# ``login.vbs```  still match the script-extension rules.
_TRAILING_JUNK_CHARS = "`'\"。、）):;,]}>"


def _clean_path(raw: str) -> str:
    """Strip trailing GitHub extraction artifacts from a path. Also strips
    a trailing backslash that some extractions leave behind."""
    s = raw.rstrip(_TRAILING_JUNK_CHARS).rstrip("\\")
    return s


def _norm(s: str) -> str:
    return s.lower()


def _path_lower(p: PureWindowsPath) -> str:
    return str(p).lower()


def _has_token(haystack: str, tokens: tuple[str, ...]) -> bool:
    return any(tok in haystack for tok in tokens)


def _share_segment(p: PureWindowsPath) -> str:
    """Return the share name (the path segment between ``\\\\host\\`` and
    the rest), lowercased. Returns ``""`` if path doesn't have the
    expected UNC shape.

    PureWindowsPath collapses the host+share into ``parts[0]`` (the
    UNC anchor like ``\\\\host\\share\\``); the share name is INSIDE
    that, not at ``parts[1]`` (which is the first subdirectory under
    the share). Earlier version of this function returned parts[1]
    by mistake — pinned by 2026-05-28 codex-audit calibration where
    the fully-synthetic-path rule failed to fire on ``\\\\machine\\
    share\\dir\\file.bak`` because share was reported as "dir".
    """
    parts = p.parts
    if not parts or not parts[0].startswith("\\\\"):
        return ""
    # Strip leading "\\", split on "\", take the second component
    # (first is host, second is share, anything after is empty trailing).
    components = parts[0].lstrip("\\").split("\\")
    return components[1].lower() if len(components) >= 2 else ""


def _host_segment(p: PureWindowsPath) -> str:
    """Return the host segment of a UNC path lowercased, or ``""``."""
    parts = p.parts
    if not parts:
        return ""
    first = parts[0]
    if first.startswith("\\\\"):
        # parts[0] is "\\\\host\\share" for typical UNC
        stripped = first.lstrip("\\")
        return stripped.split("\\")[0].lower()
    return ""


# ---------------------------------------------------------------------------
# Decision rules
# ---------------------------------------------------------------------------


def decide(path: str, pre_cat: str | None) -> dict:
    """Apply pentester heuristics. Returns a dict with label/tier/category/
    sub_type/notes/warnings. ``path`` is the raw record path; rules run
    against a cleaned form with GitHub extraction junk stripped."""
    cleaned = _clean_path(path)
    p = PureWindowsPath(cleaned)
    name_lower = p.name.lower()
    path_lower = _path_lower(p)
    suffix = p.suffix.lower()
    host = _host_segment(p)
    share = _share_segment(p)

    # Regex-escape-sequence artifact (e.g. "\\r\n\t\t)") — not a real path.
    if not host or any(esc in path.lower() for esc in ("\\r\\n", "\\t\\t", "\\n\\t")):
        return {
            "label": "not_juicy",
            "tier": None,
            "category": "benign_noise",
            "sub_type": None,
            "notes": "GitHub regex-extraction artifact (escape sequences, partial path fragment); not a real enterprise UNC path.",
            "warnings": [],
        }

    # Strong-prose placeholder host: descriptive multi-word hostnames
    # that literally spell out what they represent (e.g.,
    # ``PC-Name-Where-Share-Is``, ``computer_name``, ``user_name``,
    # ``where-share-is``). These are unambiguously synthetic prose
    # placeholders — no real hostname looks like this. Fires BEFORE
    # the pre-categorizer credential class so a synthetic example with
    # a real-looking file extension (e.g. ``\\PC-Name-Where-Share-Is\
    # TempDB\test001.mdf``) doesn't get a spurious db_files Red label.
    # Caught by 2026-05-28 codex-audit pass 4.
    _STRONG_PROSE_PLACEHOLDERS = (
        "where-share-is",
        "pc-name",
        "pc_name",
        "computer_name",
        "computername-",
        "user_name",
        "username_here",
        "usernamehere",
        "company_name",
        "company-name",
        "your-server",
        "your_server",
        "yourserver",
        "winpcdemo",
        "pcdemo",
        "demopc",
        "demohost",
    )
    if _has_token(host, _STRONG_PROSE_PLACEHOLDERS):
        return {
            "label": "not_juicy",
            "tier": None,
            "category": "benign_noise",
            "sub_type": None,
            "notes": "Strong-prose placeholder host (descriptive multi-word hostname like ``PC-Name-Where-Share-Is`` or ``computer_name``) — clearly a documentation/tutorial example, not a real share.",
            "warnings": [],
        }

    # IP-placeholder shape host: patterns like ``XXX.XX.XX.XX``,
    # ``x.x.x.x``, ``XX.XX.XX.XX`` — anonymization shapes used in
    # Stack Exchange answers to redact a real IP. Pure all-X-and-dots
    # form; real IP addresses won't match because they contain digits.
    # Caught by 2026-05-28 codex-audit calibration (the
    # ``\\XXX.XX.XX.XX\vol\\...\\.bak`` case where pre-cat .bak fired
    # before my exact-match placeholder check).
    if re.match(r"^[xX]+(\.[xX]+){2,}$", host):
        return {
            "label": "not_juicy",
            "tier": None,
            "category": "benign_noise",
            "sub_type": None,
            "notes": "IP-placeholder shape host (all-X-and-dots pattern like XXX.XX.XX.XX) — anonymized IP in Stack Exchange answer; synthetic example, not a real share.",
            "warnings": [],
        }

    # DOS device namespace (``\\.\PhysicalDrive0``, ``\\.\pipe\X``,
    # ``\\.\root\ccm\...``) — NT object manager paths, not network
    # shares. Won't yield credential value via SMB enumeration.
    if path.startswith("\\\\.\\") or host == ".":
        return {
            "label": "not_juicy",
            "tier": None,
            "category": "benign_noise",
            "sub_type": None,
            "notes": "DOS device namespace path (``\\\\.\\X`` — physical drives, named pipes, WMI/CIM, NT object manager) — not an SMB share; no credential value via network enumeration.",
            "warnings": [],
        }

    # Fully-synthetic path: host AND share are BOTH placeholders / thin
    # generic names. Catches tutorial examples like ``\\machine\share\
    # dir\file.bak`` where every path component is generic, even when
    # the basename looks like a real credential file. Runs BEFORE the
    # pre-categorizer credential class to prevent spurious credential
    # labels on synthetic example paths. Distinguished from the
    # placeholder-host-only case (e.g. ``\\mydomain.local\Netlogon\
    # real_script.bat`` keeps juicy because Netlogon + real script name
    # is the structural pattern we want to teach even with synthetic
    # hostname).
    host_is_placeholder = _has_token(host, _PLACEHOLDER_TOKENS)
    share_is_thin = share in _THIN_SHARE_NAMES or _has_token(share, _PLACEHOLDER_TOKENS)
    if host_is_placeholder and share_is_thin:
        return {
            "label": "not_juicy",
            "tier": None,
            "category": "benign_noise",
            "sub_type": None,
            "notes": "Fully-synthetic path — both host and share are placeholder/generic tokens; documentation or tutorial example rather than a real enterprise share.",
            "warnings": [],
        }

    # Rule 0: Documentation/tutorial-pattern placeholder. A path
    # containing ``\path\to\`` is overwhelmingly a Stack Exchange /
    # README example with a substituted placeholder. Even when the
    # basename names a real credential file (``\\fs\path\to\id_rsa``),
    # the tutorial context means it isn't a real enterprise share —
    # so this check runs BEFORE the pre-categorizer credential class
    # to prevent spurious credential-class labels on tutorial paths.
    if "\\path\\to\\" in path_lower or "\\path\\to" == path_lower[-8:]:
        return {
            "label": "not_juicy",
            "tier": None,
            "category": "benign_noise",
            "sub_type": None,
            "notes": "Documentation/tutorial placeholder pattern (``\\path\\to\\`` substring) — Stack Exchange or README example with substituted path; not a real enterprise share path.",
            "warnings": [],
        }

    # Rule 0b: Host == share with thin trailing components — placeholder
    # shape. ``\\vault2\vault2\dir1\dir2`` (host=share="vault2", numeric-
    # suffixed placeholder subdirs) is unambiguously synthetic.
    # Real enterprise shares occasionally do name their share after the
    # host, but only when paired with realistic content paths — the
    # subdirectory test (``\dir<N>\``, ``\folder<N>\``, ``\subfolder<N>\``)
    # distinguishes. Caught by 2026-05-29 codex-audit pass 3 where the
    # "vault" substring rule was firing credential_containers on a path
    # whose every component was a placeholder. Runs BEFORE Rule 3c so
    # the credential-keyword check doesn't override on synthetic paths.
    if host and host == share and re.search(
        r"\\(dir|folder|subfolder|path|subdir)\d", path_lower
    ):
        return {
            "label": "not_juicy",
            "tier": None,
            "category": "benign_noise",
            "sub_type": None,
            "notes": "Placeholder shape — host and share are identical AND subpath uses numeric-suffix placeholder dir names (``dir1``/``dir2``/``folder1``/etc.); synthetic documentation example, not a real share.",
            "warnings": [],
        }

    # ------------------------------------------------------------------
    # Rule 1: pre-categorizer credential-class hits — accept verbatim
    # for label/category, apply tier from category semantics.
    # ------------------------------------------------------------------
    if pre_cat == "high_value_software":
        on_netlogon_sysvol = bool(_SYSVOL_NETLOGON_RE.search(path_lower))
        # GPO-deployment context: share named ``gpo``, or path traversing
        # an ``\gpo\Install\`` / ``\gpo\Deploy\`` directory pattern, both
        # imply domain-wide rollout via Group Policy software install.
        # Same domain-wide blast radius as NETLOGON/SYSVOL → Red tier.
        # Caught by 2026-05-29 codex-audit pass 3 (AnyDesk on
        # ``\\dc1\gpo\Install\AnyDesk_Client_v2.msi`` was being labeled
        # Yellow; GPO rollout makes it Red).
        on_gpo_deploy = share == "gpo" or bool(
            re.search(r"\\gpo\\(install|deploy)\\", path_lower)
        )
        domain_deployment = on_netlogon_sysvol or on_gpo_deploy
        tier = "Red" if domain_deployment else "Yellow"
        if on_netlogon_sysvol:
            ctx = " on NETLOGON/SYSVOL (domain-wide reach)"
        elif on_gpo_deploy:
            ctx = " on GPO deployment share (domain-wide rollout)"
        else:
            ctx = ""
        return {
            "label": "juicy",
            "tier": tier,
            "category": "high_value_software",
            "sub_type": None,
            "notes": f"RMM/PAM/lateral-movement software binary{ctx}; reveals management plane / lateral-movement vector — pentester recon intel.",
            "warnings": [],
        }

    if pre_cat == "private_keys_x509":
        return {
            "label": "juicy",
            "tier": "Red",
            "category": "private_keys_x509",
            "sub_type": None,
            "notes": "X.509 key material on a share; if private key with no passphrase, direct compromise — at minimum, certificate-pivot recon material.",
            "warnings": [],
        }
    if pre_cat == "ssh_credentials":
        return {
            "label": "juicy",
            "tier": "Red",
            "category": "ssh_credentials",
            "sub_type": None,
            "notes": "SSH key/auth material on shared storage; private keys = direct compromise primitive, authorized_keys = persistence vector.",
            "warnings": [],
        }
    if pre_cat == "credential_containers":
        return {
            "label": "juicy",
            "tier": "Red",
            "category": "credential_containers",
            "sub_type": None,
            "notes": "Sealed credential vault on share; offline cracking primitive (KeePass) or PKCS#12 keystore — high pentester value.",
            "warnings": [],
        }
    if pre_cat == "browser_credentials":
        return {
            "label": "juicy",
            "tier": "Red",
            "category": "browser_credentials",
            "sub_type": None,
            "notes": "Browser credential store on shared storage; saved passwords decryptable with user DPAPI keys. Red tier per guideline — Black would require confirmed write access which isn't inferable from path alone.",
            "warnings": [],
        }
    if pre_cat == "cloud_credentials":
        return {
            "label": "juicy",
            "tier": "Red",
            "category": "cloud_credentials",
            "sub_type": None,
            "notes": "Cloud SDK credential file on share; typically yields API access to AWS/GCP/Azure. Red tier per guideline — Black would require confirmed write access.",
            "warnings": [],
        }
    if pre_cat == "modern_saas_tokens":
        return {
            "label": "juicy",
            "tier": "Red",
            "category": "modern_saas_tokens",
            "sub_type": "paas",
            "notes": "SaaS API token filename on share; impact depends on service (LLM = cost; identity = compromise; payments = financial fraud).",
            "warnings": [],
        }
    if pre_cat == "scm_cicd_tokens":
        return {
            "label": "juicy",
            "tier": "Red",
            "category": "scm_cicd_tokens",
            "sub_type": None,
            "notes": "SCM/CI credential file on share; npm/PyPI/GitHub registry tokens = supply-chain primitive, .git-credentials = repo access.",
            "warnings": [],
        }
    if pre_cat == "comms_tokens":
        # Vendor app binary / bare app directory exception: pre-cat
        # matches on "teams"/"slack"/"discord" substring, but the
        # vendor app itself (Teams.exe, AppData\Local\slack, etc.)
        # carries no extractable tokens. Tokens live elsewhere in
        # the user profile. Caught by 2026-05-28 codex-audit pass 4.
        _COMMS_APP_VENDOR_BASENAMES = (
            "teams.exe", "slack.exe", "discord.exe", "skype.exe",
            "skydrive.exe", "zoom.exe", "teams_setup.exe",
        )
        _COMMS_APP_VENDOR_DIRS = (
            "\\local\\slack", "\\local\\discord",
            "\\local\\microsoft\\teams", "\\local\\microsoft\\skype",
            "\\local\\microsoft\\skydrive", "\\roaming\\slack",
            "\\roaming\\discord", "\\roaming\\microsoft\\teams",
        )
        if name_lower in _COMMS_APP_VENDOR_BASENAMES or any(
            d in path_lower for d in _COMMS_APP_VENDOR_DIRS
        ):
            return {
                "label": "not_juicy",
                "tier": None,
                "category": "benign_noise",
                "sub_type": None,
                "notes": "Comms-app vendor binary or installed directory (Teams/Slack/Discord/Skype) — the app itself, not its token storage. Bare app directory carries no extractable credentials.",
                "warnings": [],
            }
        return {
            "label": "juicy",
            "tier": "Yellow",
            "category": "comms_tokens",
            "sub_type": None,
            "notes": "Comms platform webhook/token filename; lower-impact (post-as-bot, phishing primitive) but a live foothold into the org's chat surface.",
            "warnings": [],
        }
    if pre_cat == "db_files":
        return {
            "label": "juicy",
            "tier": "Red",
            "category": "db_files",
            "sub_type": None,
            "notes": "Database file on share; SQL backup/MDF/SQLite — offline access to schema, data, and any hashed credential tables stored within.",
            "warnings": [],
        }
    if pre_cat == "embedded_secrets":
        return {
            "label": "juicy",
            "tier": "Red",
            "category": "embedded_secrets",
            "sub_type": None,
            "notes": "Config/settings file on share with high base-rate prior for embedded credentials (.env, web.config, appsettings.json).",
            "warnings": [],
        }
    if pre_cat == "iac":
        return {
            "label": "juicy",
            "tier": "Red",
            "category": "iac",
            "sub_type": None,
            "notes": ".tfstate files render secrets in plaintext; .tf/.tfvars often carry inline credentials — IaC artifacts are high-value secret carriers.",
            "warnings": [],
        }
    if pre_cat == "network_device":
        return {
            "label": "juicy",
            "tier": "Red",
            "category": "network_device",
            "sub_type": None,
            "notes": "Network device config on share; reveals topology, ACLs, and frequently contains hashed/cleartext credentials and SNMP community strings.",
            "warnings": [],
        }
    if pre_cat == "windows_credential_artifacts":
        return {
            "label": "juicy",
            "tier": "Black",
            "category": "windows_credential_artifacts",
            "sub_type": None,
            "notes": "AD/Windows credential-extraction artifact on share (SYSVOL GPP / NTDS.dit / SAM hive / Kerberos ticket) — canonical compromise primitive.",
            "warnings": [],
        }

    # ------------------------------------------------------------------
    # Rule 2: SYSVOL / NETLOGON script files — RCE primitive if writable,
    # major recon and lateral-movement value even read-only.
    # ------------------------------------------------------------------
    if _SYSVOL_NETLOGON_RE.search(path_lower) and suffix in _SCRIPT_EXTS:
        return {
            "label": "juicy",
            "tier": "Red",
            "category": "embedded_secrets",
            "sub_type": None,
            "notes": "Logon script in NETLOGON/SYSVOL — domain-wide execution on every authenticated login if writable; even read-only reveals automation logic, mapped drives, scheduled tasks.",
            "warnings": ["uncertainty_prior"],
        }

    # ------------------------------------------------------------------
    # Rule 2b: SYSVOL / NETLOGON config files — XML/INI/REG/POL/BGI/RDP
    # in domain-distributed locations. Not executable, but reveal GPO
    # content, scheduled-task definitions, deployment configurations,
    # security-tool config (sysmon-config.xml), VPN profiles
    # (ProfileXML.xml), etc. Pentester always inspects these. Excludes
    # image/asset extensions (wallpapers, logos) which legitimately are
    # not_juicy.
    # ------------------------------------------------------------------
    if _SYSVOL_NETLOGON_RE.search(path_lower) and suffix in _NETLOGON_CONFIG_EXTS:
        return {
            "label": "juicy",
            "tier": "Yellow",
            "category": "embedded_secrets",
            "sub_type": None,
            "notes": "Config artifact in NETLOGON/SYSVOL (XML/INI/REG/POL/RDP/BGI) — domain-distributed configuration revealing GPO content, security-tool config, VPN profiles, or deployment scripts; high recon value even when not directly executable.",
            "warnings": ["uncertainty_prior"],
        }

    # ------------------------------------------------------------------
    # Rule 3a: SYSVOL Policies subtree (bare directory) — the specific
    # location where GPP-cpassword XML files live. Higher prior than
    # bare SYSVOL root because the directory itself names the GPO content.
    # ------------------------------------------------------------------
    if _SYSVOL_RE.search(path_lower) and _POLICIES_RE.search(path_lower) and suffix == "":
        return {
            "label": "juicy",
            "tier": "Yellow",
            "category": "windows_credential_artifacts",
            "sub_type": None,
            "notes": "SYSVOL Policies subtree — direct path to legacy GPP cpassword XML (Groups.xml, Services.xml); canonical AD-domain enumeration target with high credential-artifact prior.",
            "warnings": ["uncertainty_prior"],
        }

    # ------------------------------------------------------------------
    # Rule 3b: Bare SYSVOL/NETLOGON share root or non-Policies subdir
    # without a script-file extension — recon signal (DC exposure) but
    # no specific credential artifact in the path. Per Vincent's pattern,
    # bare-dir recon ≠ juicy.
    # ------------------------------------------------------------------
    if (_SYSVOL_RE.search(path_lower) or _NETLOGON_RE.search(path_lower)) and suffix == "":
        return {
            "label": "not_juicy",
            "tier": None,
            "category": "benign_noise",
            "sub_type": None,
            "notes": "SYSVOL/NETLOGON directory (non-Policies) — confirms target is a domain controller, but no specific credential-bearing file or script artifact in the bare directory path.",
            "warnings": ["uncertainty_prior"],
        }

    # ------------------------------------------------------------------
    # Rule 3a2: Identity-sync / directory-sync software (Google Apps
    # Password Sync, Azure AD Connect, etc.) — the filename signals
    # high_value_software (it's the management plane that syncs AD
    # passwords to a cloud identity provider), not a credential
    # container. Without this, the generic "password" keyword in
    # ``googleappspasswordsync.msi`` would land in credential_containers
    # via Rule 3c. Caught by 2026-05-28 codex-audit pass 4.
    # ------------------------------------------------------------------
    if _has_token(path_lower, _HIGH_VALUE_SOFTWARE_NAME_EXTRAS):
        return {
            "label": "juicy",
            "tier": "Yellow",
            "category": "high_value_software",
            "sub_type": None,
            "notes": "Identity-sync / directory-sync software on share (Google Apps Password Sync, Azure AD Connect, similar) — reveals the AD-to-cloud identity bridge; writable here means intercepting every domain password as it syncs.",
            "warnings": ["uncertainty_prior"],
        }

    # ------------------------------------------------------------------
    # Rule 3a3: Vendor comms-app binaries / bare app directories
    # (Teams.exe, Slack/, Discord/, etc.) — the comms-tokens pre-cat
    # fires on "teams"/"slack"/"discord" substrings, but the bare app
    # binary or vendor-installed directory carries no actual tokens.
    # Tokens live in the user's roaming data (Teams: tokens.json,
    # Slack: storage/state.json, etc.) which would have a different
    # path shape. Caught by 2026-05-28 codex-audit pass 4.
    # ------------------------------------------------------------------
    _COMMS_APP_VENDOR_BASENAMES = (
        "teams.exe",
        "slack.exe",
        "discord.exe",
        "skype.exe",
        "skydrive.exe",
        "zoom.exe",
    )
    _COMMS_APP_VENDOR_DIRS = (
        "\\local\\slack",
        "\\local\\discord",
        "\\local\\microsoft\\teams",
        "\\local\\microsoft\\skype",
        "\\local\\microsoft\\skydrive",
        "\\roaming\\slack",
        "\\roaming\\discord",
        "\\roaming\\microsoft\\teams",
    )
    if name_lower in _COMMS_APP_VENDOR_BASENAMES or any(
        d in path_lower for d in _COMMS_APP_VENDOR_DIRS
    ):
        return {
            "label": "not_juicy",
            "tier": None,
            "category": "benign_noise",
            "sub_type": None,
            "notes": "Comms-app vendor binary or installed directory (Teams/Slack/Discord/Skype) — the app itself, not its token storage. Bare app directory carries no extractable credentials.",
            "warnings": [],
        }

    # ------------------------------------------------------------------
    # Rule 3b2: ``.publishsettings`` extension — Azure SDK / Visual
    # Studio cloud-auth format. Contains directly-usable cloud
    # management credentials. Fires BEFORE the credential-keyword
    # rule because the basename pattern (``-credentials.publishsettings``)
    # would otherwise hit the generic "credentials" keyword rule and
    # land under the wrong category. Path substring check (vs suffix
    # match) because PureWindowsPath sometimes collapses bare
    # ``\\host\file.publishsettings`` into the anchor (name=='' and
    # suffix=='') — same gotcha as Rule 14 hit. Caught by 2026-05-28
    # codex-audit.
    # ------------------------------------------------------------------
    if ".publishsettings" in path_lower:
        return {
            "label": "juicy",
            "tier": "Red",
            "category": "cloud_credentials",
            "sub_type": None,
            "notes": ".publishsettings extension — Azure SDK / Visual Studio cloud-auth file embedding a subscription management certificate; directly-usable cloud-management credentials.",
            "warnings": ["uncertainty_prior"],
        }

    # ------------------------------------------------------------------
    # Rule 3c: Credential-keyword in path component (vault/wallet/
    # keystore/passwords/etc.) — checked early so a path like
    # ``\\fs\Users\UsersVault`` wins over the generic user-home rule
    # later. Strong juicy signal because the directory or share name
    # itself advertises credential storage.
    #
    # Exclusions (per 2026-05-28 codex-audit calibration): "vault" co-
    # occurring with engineering-data-vault tokens ("pdm" — SolidWorks
    # Product Data Management) is a data vault, not a credential vault.
    # "password" co-occurring with wordlist tokens ("dictionar"/
    # "wordlist") is pentester input tooling, not credential storage.
    # ------------------------------------------------------------------
    _vault_data_exceptions = ("pdm", "pdmvault", "pdmworks")
    _password_wordlist_exceptions = ("dictionar", "wordlist", "wordlists")
    _embedded_secret_blob_exts = (".bin", ".dat", ".blob")
    if _has_token(path_lower, _PATH_CREDENTIAL_KEYWORDS):
        is_data_vault = "vault" in path_lower and _has_token(path_lower, _vault_data_exceptions)
        is_wordlist = "password" in path_lower and _has_token(path_lower, _password_wordlist_exceptions)
        if not (is_data_vault or is_wordlist):
            # Blob-shape carve-out: ``.bin``/``.dat``/``.blob`` with a
            # credential keyword in the basename is an embedded-secret
            # blob, not a sealed credential container. The
            # credential_containers category is reserved for sealed
            # formats (``.kdbx``, ``.pfx``, ``.p12``, ``.jks``); a
            # password.bin reads as a binary file with embedded secret
            # material, more accurately embedded_secrets. Caught by
            # 2026-05-29 codex-audit pass 3 (``password.bin`` under a
            # LogonScripts\Modules\BIOS\sp93030 dir).
            if suffix in _embedded_secret_blob_exts and _has_token(
                name_lower, _PATH_CREDENTIAL_KEYWORDS
            ):
                return {
                    "label": "juicy",
                    "tier": "Yellow",
                    "category": "embedded_secrets",
                    "sub_type": None,
                    "notes": "Credential-themed basename with binary-blob extension (``.bin``/``.dat``/``.blob``) — embedded secret material in a blob, not a sealed credential-container format.",
                    "warnings": ["uncertainty_prior"],
                }
            return {
                "label": "juicy",
                "tier": "Yellow",
                "category": "credential_containers",
                "sub_type": None,
                "notes": "Path component advertises credential storage (vault/wallet/keystore/passwords) — high pentester prior for sealed credential containers or password-manager exports in the directory.",
                "warnings": ["uncertainty_prior"],
            }
        if is_data_vault:
            return {
                "label": "not_juicy",
                "tier": None,
                "category": "benign_noise",
                "sub_type": None,
                "notes": "Engineering / product-data vault (PDM context) — data storage, not credential storage; vault here is a data-management term, not a secret-management one.",
                "warnings": [],
            }
        # is_wordlist branch
        return {
            "label": "not_juicy",
            "tier": None,
            "category": "benign_noise",
            "sub_type": None,
            "notes": "Password-dictionaries / wordlist directory — pentester input tooling rather than credential storage; share contains attack inputs, not extractable secrets.",
            "warnings": [],
        }

    # ------------------------------------------------------------------
    # Rule 3d: ``.pwd`` extension — legacy/proprietary password file
    # format. High prior for direct credential content.
    # ------------------------------------------------------------------
    if suffix == ".pwd":
        return {
            "label": "juicy",
            "tier": "Red",
            "category": "embedded_secrets",
            "sub_type": None,
            "notes": ".pwd extension — legacy/proprietary password file format; high prior for cleartext or weakly-protected credential storage.",
            "warnings": ["uncertainty_prior"],
        }

    # ------------------------------------------------------------------
    # Rule 3d3: ``.mof`` extension — PowerShell DSC compiled
    # configuration (Managed Object Format). DSC = Infrastructure-as-
    # Code for Windows; the .mof IS the compiled IaC output.
    # Frequently carries embedded credentials (encrypted with a key
    # the operator can recover from the same share or LCM config).
    # Caught by 2026-05-28 codex-audit calibration as a real category
    # gap. NETLOGON/SYSVOL .mof is already handled by Rule 2b above.
    # ------------------------------------------------------------------
    if suffix == ".mof":
        return {
            "label": "juicy",
            "tier": "Yellow",
            "category": "iac",
            "sub_type": None,
            "notes": "PowerShell DSC compiled configuration (.mof) — Infrastructure-as-Code output for Windows; reveals desired-state config and frequently carries embedded credentials (encrypted with LCM-recoverable key).",
            "warnings": ["uncertainty_prior"],
        }

    # ------------------------------------------------------------------
    # Rule 3e: Unattend / autounattend files — Windows answer files used
    # during OS deployment that embed the local Administrator password
    # in plaintext or trivially-decodable form. Canonical credential
    # primitive — finding one on a share is direct compromise material.
    # ------------------------------------------------------------------
    if any(s in name_lower for s in _UNATTEND_NAME_SUBSTRINGS) or any(
        s in path_lower for s in _UNATTEND_NAME_SUBSTRINGS
    ):
        return {
            "label": "juicy",
            "tier": "Red",
            "category": "embedded_secrets",
            "sub_type": None,
            "notes": "Windows unattend / autounattend artifact — answer files used during OS deployment; canonical pattern is plaintext or trivially-encoded Administrator password embedded in the XML. Direct compromise material if accessible.",
            "warnings": ["uncertainty_prior"],
        }

    # ------------------------------------------------------------------
    # Rule 3f: ``.rdp`` connection files — frequently embed server
    # hostname + username + sometimes credential blob. Even without
    # credentials, reveals which RDP targets the user routinely
    # connects to (recon for lateral-movement targeting).
    # ------------------------------------------------------------------
    if suffix == _RDP_EXT:
        return {
            "label": "juicy",
            "tier": "Yellow",
            "category": "embedded_secrets",
            "sub_type": None,
            "notes": ".rdp connection file — embeds target server hostname/username and may include DPAPI-protected password blob; recon-valuable for lateral-movement targeting at minimum, direct credential carrier at maximum.",
            "warnings": ["uncertainty_prior"],
        }

    # ------------------------------------------------------------------
    # Rule 4: CTF / lab / training corpus leakage through the security filter.
    # ------------------------------------------------------------------
    if _has_token(path_lower, _CTF_TOKENS):
        return {
            "label": "not_juicy",
            "tier": None,
            "category": "benign_noise",
            "sub_type": None,
            "notes": "CTF/lab artifact (flag file, training-corpus path); leaked past the security filter — not a real enterprise finding.",
            "warnings": [],
        }

    # ------------------------------------------------------------------
    # Rule 5: Placeholder / synthetic hosts — README examples, not real shares.
    # ------------------------------------------------------------------
    if _has_token(host, _PLACEHOLDER_TOKENS) or _has_token(share, _PLACEHOLDER_TOKENS):
        return {
            "label": "not_juicy",
            "tier": None,
            "category": "benign_noise",
            "sub_type": None,
            "notes": "Synthetic / placeholder UNC path (example documentation, README skeleton, lab fixture) — not a real organizational share.",
            "warnings": [],
        }

    # ------------------------------------------------------------------
    # Rule 6: SQL/DB/system backup directories — pentester target, but
    # the directory itself (vs an actual .bak file on the share) is
    # lower confidence; Vincent's calibration call (post codex-audit
    # 2026-05-28) tier-downs from Red to Yellow. Reasoning: "SQLBackups"
    # share name signals .bak content inside, but the directory itself
    # isn't the file artifact — worth looking into, not direct
    # extraction primitive on path features alone.
    #
    # Splits the path by `\`, `_`, `-`, `.` separators and matches DB
    # context tokens against those word-units. Prevents false positives
    # where "db" appears as coincidental letters inside a longer word
    # (e.g. "sharedbackup" → "shareDBackup" letters d+b adjacent).
    # ------------------------------------------------------------------
    _PATH_WORD_SPLIT = re.compile(r"[\\/_\-.]")
    path_words = [w for w in _PATH_WORD_SPLIT.split(path_lower) if w]
    _DB_CONTEXT_PREFIXES = ("sql", "db", "database", "mssql", "mysql")
    _has_db_word = any(
        w == prefix or w.startswith(prefix) and (len(w) == len(prefix) or w[len(prefix)].isdigit())
        for w in path_words
        for prefix in _DB_CONTEXT_PREFIXES
    ) or any(w in {"db", "database", "databases"} for w in path_words)
    if _has_token(path_lower, ("sqlbackup", "sql_backup", "sql-backup")) or (
        "backup" in path_lower and _has_db_word
    ):
        # If the file is a script in the backup dir (e.g.
        # ``Backups\Database\X.ps1``), that's a backup-script artifact,
        # not a db file — embedded_secrets fits (the script likely
        # carries inline credentials). If the file IS a db artifact
        # (.bak/.mdf/.ldf), keep db_files with Red tier. If it's a
        # bare directory or other extension, fall through to Yellow/
        # db_files as a directory-prior label.
        if suffix in {".ps1", ".bat", ".cmd", ".vbs", ".vbe", ".wsf", ".js"}:
            return {
                "label": "juicy",
                "tier": "Yellow",
                "category": "embedded_secrets",
                "sub_type": None,
                "notes": "Backup script in a database-backup directory — the file IS a script, not a db file; high prior for inline service-account credentials, connection strings, or sa-account passwords used by the backup automation.",
                "warnings": ["uncertainty_prior"],
            }
        is_db_file_artifact = suffix in {".bak", ".mdf", ".ldf", ".mdb"}
        tier = "Red" if is_db_file_artifact else "Yellow"
        return {
            "label": "juicy",
            "tier": tier,
            "category": "db_files",
            "sub_type": None,
            "notes": "Database backup directory — typical contents are .bak files restorable to extract schema, data, and credential tables. Tier Red when the path is the actual file artifact; Yellow for the bare directory (worth looking into, not direct extraction primitive on path features alone).",
            "warnings": ["uncertainty_prior"],
        }

    # ------------------------------------------------------------------
    # Rule 7: Generic backup directories — recon-worthy but data exposure
    # alone is not the eval set's juicy criterion. Vincent's pattern:
    # bare dirs with sensitivity-suggestive names → not_juicy/benign_noise.
    # ------------------------------------------------------------------
    if suffix == "" and _has_token(path_lower, _BACKUP_DIR_TOKENS):
        return {
            "label": "not_juicy",
            "tier": None,
            "category": "benign_noise",
            "sub_type": None,
            "notes": "Backup directory — recon-worthy (snapshots of configs/VHDs/exports may carry credentials at content level) but path alone carries no credential-bearing file artifact.",
            "warnings": ["uncertainty_prior"],
        }

    # ------------------------------------------------------------------
    # Rule 8: IT / admin / scripts / devops directories — recon-interesting
    # but the path alone is just a directory; juicy attaches to specific
    # script files, not the parent directory's name.
    # ------------------------------------------------------------------
    if _has_token(path_lower, _IT_ADMIN_TOKENS) and suffix == "":
        return {
            "label": "not_juicy",
            "tier": None,
            "category": "benign_noise",
            "sub_type": None,
            "notes": "IT/admin/scripts directory — recon target (scripts here often have inline credentials at content level), but no specific credential-bearing file in the path itself.",
            "warnings": ["uncertainty_prior"],
        }

    # ------------------------------------------------------------------
    # Rule 9: Finance / HR / Legal / Executive shares — sensitive data
    # exposure, not credential value. Per Vincent's pattern (SalesDocs
    # on DC labeled not_juicy/benign_noise), data exposure isn't the
    # eval set's juicy criterion.
    # ------------------------------------------------------------------
    if _has_token(path_lower, _HIGH_VALUE_DEPT_TOKENS):
        return {
            "label": "not_juicy",
            "tier": None,
            "category": "benign_noise",
            "sub_type": None,
            "notes": "High-value departmental share (finance/HR/legal/exec) — contains PII/payroll/contracts on prior, but data sensitivity ≠ credential value for this eval set; recon-interesting, not credential-juicy on path alone.",
            "warnings": [],
        }

    # ------------------------------------------------------------------
    # Rule 10: Software / installer / package repositories — generic
    # software share, no specific credential artifact in the path.
    # ------------------------------------------------------------------
    if _has_token(path_lower, _SOFTWARE_REPO_TOKENS) and suffix == "":
        return {
            "label": "not_juicy",
            "tier": None,
            "category": "benign_noise",
            "sub_type": None,
            "notes": "Software/installer repository share (bare directory) — installer payloads may carry credentials at content level, but no specific credential-bearing artifact in path itself.",
            "warnings": [],
        }

    # ------------------------------------------------------------------
    # Rule 11: User home / profile / folder-redirection — bare directory.
    # Per Vincent's pattern, juicy attaches to specific files within
    # (e.g. custom application binaries, .ssh keys, browser stores), not
    # to the parent users/homes directory itself.
    # ------------------------------------------------------------------
    if _has_token(path_lower, _USER_HOME_TOKENS) and suffix == "":
        return {
            "label": "not_juicy",
            "tier": None,
            "category": "benign_noise",
            "sub_type": None,
            "notes": "User home / folder-redirection directory — high recon value (profiles accumulate credentials over time), but no specific credential file in the bare directory path.",
            "warnings": ["uncertainty_prior"],
        }

    # ------------------------------------------------------------------
    # Rule 12: Azure file-share hosts — cloud-hosted SMB; recon value but
    # contents are workload-dependent. Default to not_juicy with prior.
    # ------------------------------------------------------------------
    if _AZURE_FILESHARE_RE.search(path_lower):
        return {
            "label": "not_juicy",
            "tier": None,
            "category": "benign_noise",
            "sub_type": None,
            "notes": "Azure Files (cloud-hosted SMB) — host pattern reveals tenant/storage account; contents workload-dependent and not inferable from path alone.",
            "warnings": ["uncertainty_prior"],
        }

    # ------------------------------------------------------------------
    # Rule 13: pre_category benign_noise — split by extension.
    # For .exe/.msi binaries: vendor names → not_juicy/benign_noise;
    # custom-looking names → juicy/Yellow/embedded_secrets on prior
    # (custom-built application binaries often carry embedded credentials,
    # connection strings, hardcoded URLs — per Vincent's labeling of
    # French_Press_POS.exe).
    # For media/font/other: not_juicy/benign_noise.
    # ------------------------------------------------------------------
    if pre_cat == "benign_noise":
        if suffix in {".exe", ".msi"}:
            if _has_token(name_lower, _VENDOR_BINARY_TOKENS):
                return {
                    "label": "not_juicy",
                    "tier": None,
                    "category": "benign_noise",
                    "sub_type": None,
                    "notes": "Vendor / publicly-available binary (recognized vendor name in filename); standard installer or utility, no embedded-secret prior.",
                    "warnings": [],
                }
            return {
                "label": "juicy",
                "tier": "Yellow",
                "category": "embedded_secrets",
                "sub_type": None,
                "notes": "Custom-looking binary on share (no recognized vendor name); base-rate prior is that custom-built application binaries carry embedded credentials, connection strings, or hardcoded service endpoints worth decompilation.",
                "warnings": ["uncertainty_prior"],
            }
        return {
            "label": "not_juicy",
            "tier": None,
            "category": "benign_noise",
            "sub_type": None,
            "notes": "Generic media / font / library binary; extension class essentially never credential-bearing on path features alone.",
            "warnings": [],
        }

    # ------------------------------------------------------------------
    # Rule 14: Decoy-doc filename signal (password/secret/credential in name)
    # that didn't pre-categorize because of unusual extension.
    # ------------------------------------------------------------------
    if any(kw in name_lower for kw in ("password", "secret", "credential")):
        return {
            "label": "juicy",
            "tier": "Yellow",
            "category": "decoy_docs",
            "sub_type": None,
            "notes": "Filename baits a keyword scanner (password/secret/credential) — could be a real secret carrier or a decoy doc; content inspection required, prior leans decoy.",
            "warnings": ["uncertainty_prior"],
        }

    # ------------------------------------------------------------------
    # Rule 15: Thin share names (just `\\host\share`, `\\host\public`,
    # generic single-word shares with no extension and no other tokens).
    # ------------------------------------------------------------------
    if suffix == "" and share in _THIN_SHARE_NAMES:
        return {
            "label": "not_juicy",
            "tier": None,
            "category": "benign_noise",
            "sub_type": None,
            "notes": "Generic share name (`share`/`public`/`shared`) with no further path context — uninformative on path features alone; would not draw pentester attention.",
            "warnings": [],
        }

    # ------------------------------------------------------------------
    # Rule 16: .ps1 / .bat / .vbs / .cmd scripts NOT in SYSVOL/NETLOGON —
    # moderate prior; scripts often carry inline service-account
    # credentials. Exception (per 2026-05-28 codex-audit calibration):
    # scripts named for well-known public package-management tooling
    # (Chocolatey installer scripts in particular) are vendor-public
    # boilerplate, not credential carriers.
    # ------------------------------------------------------------------
    _PUBLIC_TOOLING_SCRIPT_TOKENS = (
        "chocoinstall",
        "chocolatey",
        "choco-install",
        "ohmyzsh",
        "oh-my-zsh",
        "winget",
        "scoop",
    )
    if suffix in {".ps1", ".bat", ".cmd", ".vbs", ".vbe", ".wsf", ".js"}:
        if _has_token(name_lower, _PUBLIC_TOOLING_SCRIPT_TOKENS):
            return {
                "label": "not_juicy",
                "tier": None,
                "category": "benign_noise",
                "sub_type": None,
                "notes": "Script for a public package-management tool (Chocolatey, scoop, winget, oh-my-zsh) — vendor-public boilerplate, no embedded credentials.",
                "warnings": [],
            }
        return {
            "label": "juicy",
            "tier": "Yellow",
            "category": "embedded_secrets",
            "sub_type": None,
            "notes": "Script file on share (.ps1/.bat/.vbs/etc.) — base-rate prior is moderate-to-high for inline service-account credentials, hardcoded passwords, and connection strings.",
            "warnings": ["uncertainty_prior"],
        }

    # ------------------------------------------------------------------
    # Rule 17: XML / CSV / TXT / LOG files on shares — could be anything;
    # default to not_juicy unless filename signals.
    # ------------------------------------------------------------------
    if suffix in {".xml", ".csv", ".txt", ".log", ".mof", ".cache", ".date", ".local", ".resources"}:
        return {
            "label": "not_juicy",
            "tier": None,
            "category": "benign_noise",
            "sub_type": None,
            "notes": "Generic data file (xml/csv/txt/log) without sensitivity keywords in filename; prior leans non-credential — would require content inspection to upgrade.",
            "warnings": ["uncertainty_prior"],
        }

    # ------------------------------------------------------------------
    # Rule 18: .zip / .pdb / .py / .java files — workload-dependent.
    # ------------------------------------------------------------------
    if suffix in {".zip", ".rar", ".7z"}:
        if _has_token(name_lower, _PUBLIC_TOOLKIT_ARCHIVE_TOKENS):
            return {
                "label": "not_juicy",
                "tier": None,
                "category": "benign_noise",
                "sub_type": None,
                "notes": "Archive named for a publicly-available toolkit/utility (Sysinternals, First Responder Kit, etc.); not a sealed credential container.",
                "warnings": [],
            }
        return {
            "label": "juicy",
            "tier": "Yellow",
            "category": "credential_containers",
            "sub_type": None,
            "notes": "Archive on share — could be sealed credential container (protected ZIP/RAR/7z) or benign backup; prior leans benign but pentester would always check.",
            "warnings": ["uncertainty_prior"],
        }
    if suffix in {".pdb", ".py", ".java", ".cs", ".c", ".cpp", ".h"}:
        return {
            "label": "not_juicy",
            "tier": None,
            "category": "benign_noise",
            "sub_type": None,
            "notes": "Source-code or debug-symbol file on share; not a credential carrier on path features alone, though source review may surface embedded secrets at content level.",
            "warnings": ["uncertainty_prior"],
        }

    # ------------------------------------------------------------------
    # Rule 18b: Tokens-by-host (or similar token-storage) path tokens not
    # captured by the earlier credential-keyword check.
    # ------------------------------------------------------------------
    if "tokensbyhost" in path_lower or "tokens-by-host" in path_lower:
        return {
            "label": "juicy",
            "tier": "Yellow",
            "category": "credential_containers",
            "sub_type": None,
            "notes": "Path component explicitly names token storage — high pentester prior for OAuth/API token caches recoverable from the directory.",
            "warnings": ["uncertainty_prior"],
        }

    # ------------------------------------------------------------------
    # Rule 19: Bare UNC directory paths with no extension and no other
    # informative tokens — default to not_juicy with uncertainty prior.
    # ------------------------------------------------------------------
    if suffix == "":
        return {
            "label": "not_juicy",
            "tier": None,
            "category": "benign_noise",
            "sub_type": None,
            "notes": "Bare UNC directory path with no extension and no informative tokens; prior leans operational-junk for the majority of enterprise shares not matched by other rules.",
            "warnings": ["uncertainty_prior"],
        }

    # ------------------------------------------------------------------
    # Rule 20: catch-all — unknown extension, no signals.
    # ------------------------------------------------------------------
    return {
        "label": "not_juicy",
        "tier": None,
        "category": "benign_noise",
        "sub_type": None,
        "notes": f"Uncategorized path with extension {suffix!r}; no path features match known credential patterns; prior leans non-credential.",
        "warnings": ["uncertainty_prior"],
    }


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Apply the deterministic Claude-judgment labeling rules to a "
            "queue.jsonl-format input and emit eval_set-shape records. "
            "Defaults preserve the original behavior; v0.5 added flags "
            "so the Linux corpus expansion can write to a separate output."
        ),
    )
    parser.add_argument(
        "--queue",
        type=Path,
        default=QUEUE_PATH,
        help=f"Queue JSONL input (default: {QUEUE_PATH.relative_to(REPO_ROOT)})",
    )
    parser.add_argument(
        "--eval-set",
        type=Path,
        default=EVAL_SET_PATH,
        help=(
            f"Vincent's ground-truth eval set; paths already in it are "
            f"skipped (default: {EVAL_SET_PATH.relative_to(REPO_ROOT)})"
        ),
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=OUTPUT_PATH,
        help=f"Output JSONL path (default: {OUTPUT_PATH.relative_to(REPO_ROOT)})",
    )
    args = parser.parse_args()

    queue_path = args.queue
    eval_set_path = args.eval_set
    output_path = args.output

    # Load already-labeled paths so we don't relabel Vincent's ground truth.
    labeled_paths: set[str] = set()
    if eval_set_path.exists():
        for line in eval_set_path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            labeled_paths.add(json.loads(line)["path"])

    # Load queue.
    queue_records = []
    for line in queue_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        queue_records.append(json.loads(line))

    # Process each unlabeled record; validate every emitted EvalRecord.
    written = 0
    skipped_labeled = 0
    out_lines: list[str] = []
    distribution = {"juicy": 0, "not_juicy": 0}
    tier_dist = {"Black": 0, "Red": 0, "Yellow": 0, None: 0}
    cat_dist: dict[str, int] = {}

    for q in queue_records:
        if q["path"] in labeled_paths:
            skipped_labeled += 1
            continue
        # Re-run pre_categorize so any high_value_software hits added after
        # the queue was built are surfaced now.
        pre_cat = pre_categorize(q["path"])
        decision = decide(q["path"], pre_cat)
        # Echo any negative_validator heuristics that fire on this path
        # into validator_warnings — the validator's discipline expects
        # the labeler to acknowledge each fired heuristic explicitly
        # (otherwise it raises a validator_drift integrity warning).
        warnings = list(decision["warnings"])
        for h in negative_check(q["path"]):
            if h not in warnings:
                warnings.append(h)
        rec = EvalRecord(
            path=q["path"],
            label=decision["label"],
            tier=decision["tier"],
            category=decision["category"],
            sub_type=decision["sub_type"],
            source=q["source"],
            notes=decision["notes"],
            added_date=TODAY,
            added_by="claude",
            pre_category=pre_cat,
            validator_warnings=warnings,
        )
        out_lines.append(rec.model_dump_json())
        written += 1
        distribution[decision["label"]] += 1
        tier_dist[decision["tier"]] += 1
        cat_dist[decision["category"]] = cat_dist.get(decision["category"], 0) + 1

    output_path.write_text("\n".join(out_lines) + "\n", encoding="utf-8")

    def _rel(p: Path) -> str:
        """Display path relative to repo root, or absolute if outside."""
        try:
            return str(p.relative_to(REPO_ROOT))
        except ValueError:
            return str(p)

    print(f"Skipped {skipped_labeled} paths already in {_rel(eval_set_path)}")
    print(f"Wrote {written} records to {_rel(output_path)}")
    print()
    print("Label distribution:")
    for k, v in distribution.items():
        print(f"  {k}: {v} ({100*v/written:.1f}%)")
    print()
    print("Tier distribution (juicy only — None means not_juicy):")
    for k, v in tier_dist.items():
        pct = f" ({100*v/written:.1f}%)" if written else ""
        print(f"  {k}: {v}{pct}")
    print()
    print("Category distribution:")
    for k, v in sorted(cat_dist.items(), key=lambda x: -x[1]):
        print(f"  {k}: {v} ({100*v/written:.1f}%)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
