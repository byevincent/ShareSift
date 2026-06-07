"""Stratified labeling-queue builder for the eval set.

Reads raw path inputs (CSV or JSONL) and produces a single JSONL queue
file that the labeling GUI consumes. Two responsibilities, kept separate
from one another and from the labeling decision itself:

1. **Pre-categorize** each path with a best-effort regex hint. The result
   populates ``QueueRecord.pre_category`` (and downstream
   ``EvalRecord.pre_category``). It is a stratification hint, NOT a
   labeling claim — the labeler overrides during labeling, and the
   pre-categorizer being wrong is fine. This is deliberately the opposite
   precision posture from ``negative_validator``: broader patterns,
   looser precision, over-inclusion is free here because wrong guesses
   cost nothing (the labeler corrects during labeling).

2. **Stratify** the emission order so labeling sessions encounter a
   balanced mix across categories. Per-bucket deterministic shuffle plus
   a seeded shuffle of the cross-bucket round-robin order. The
   cross-bucket shuffle (rather than alphabetical) avoids positional
   attention bias toward whichever category sorts first.

Queue records are NOT labeled — no label/tier/notes. The GUI fills those
in. Filtering: paths that already appear in ``data/eval/eval_set.jsonl``
are skipped (cross-file dedup). Duplicates within the input are reduced
to their first occurrence (within-file dedup). Both comparisons are
case-insensitive on the ``PureWindowsPath``-normalized form.
"""

from __future__ import annotations

import argparse
import csv
import json
import random
import re
import secrets
import sys
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path, PureWindowsPath

from pydantic import BaseModel, ValidationError, field_validator

from src.eval._io import atomic_write_jsonl
from src.eval._paths import normalize_for_dedup
from src.eval.categories import CATEGORY_SLUGS, SOURCES

# ============================================================================
# Queue record schema
# ============================================================================


class QueueRecord(BaseModel):
    path: str
    source: str
    pre_category: str | None = None
    queue_index: int
    build_id: str

    @field_validator("path")
    @classmethod
    def _path_clean(cls, v: str) -> str:
        if not v:
            raise ValueError("path must be non-empty")
        if v.strip() != v:
            raise ValueError("path must not have leading/trailing whitespace")
        if any(ord(c) < 32 for c in v):
            raise ValueError("path must not contain control characters")
        _ = PureWindowsPath(v)
        return v

    @field_validator("source")
    @classmethod
    def _source_valid(cls, v: str) -> str:
        if v not in SOURCES:
            raise ValueError(f"source must be one of {SOURCES}")
        return v

    @field_validator("pre_category")
    @classmethod
    def _pre_category_valid(cls, v: str | None) -> str | None:
        if v is not None and v not in CATEGORY_SLUGS:
            raise ValueError(f"pre_category must be one of {CATEGORY_SLUGS} or None")
        return v


# ============================================================================
# Pre-categorizer rule registry
#
# Per-category basename and extension data, with one classifier function
# per category. Order in ``_PRECATEGORIZERS`` encodes precedence
# (first-match-wins). The tests pin the ordering-sensitive cases
# (e.g. ``key4.db`` → browser_credentials before db_files).
# ============================================================================

# --- windows_credential_artifacts ---
_GPP_CREDENTIAL_BASENAMES = frozenset(
    {
        "groups.xml",
        "services.xml",
        "scheduledtasks.xml",
        "datasources.xml",
        "printers.xml",
        "drives.xml",
    }
)
_KERBEROS_TICKET_EXTS = frozenset({".kirbi", ".ccache"})
# Case-sensitive: matches the validator's reasoning. Lowercase ``sam`` /
# ``system`` / ``security`` are common English words and would create
# significant stratifier noise; the precision tightening is worth it here
# even though over-inclusion is otherwise free in this engine.
_REGISTRY_HIVE_BASENAMES = frozenset({"SAM", "SYSTEM", "SECURITY"})

# --- credential_containers ---
_KEEPASS_EXTS = frozenset({".kdbx", ".kdb"})
_PKCS12_EXTS = frozenset({".pfx", ".p12"})
_JAVA_KEYSTORE_EXTS = frozenset({".jks", ".keystore"})

# --- ssh_credentials ---
_SSH_PRIVATE_KEY_BASENAMES = frozenset({"id_rsa", "id_dsa", "id_ecdsa", "id_ed25519"})
_SSH_OTHER_BASENAMES = frozenset({"authorized_keys", "known_hosts"})
# PuTTY private key. Deliberately broader than negative_validator
# (which has no .ppk heuristic): the validator's precision bar requires
# near-zero FP for the override pathway to stay credible, whereas the
# categorizer's stratification value justifies including .ppk as a hint
# even at some FP cost. Categorizer-vs-validator distinction.
_PUTTY_KEY_EXTS = frozenset({".ppk"})

# --- private_keys_x509 ---
_X509_EXTS = frozenset({".pem", ".crt", ".cer", ".der", ".key"})

# --- browser_credentials ---
_BROWSER_CREDENTIAL_BASENAMES = frozenset(
    {
        "login data",
        "web data",
        "cookies",
        "logins.json",
        "key3.db",
        "key4.db",
        "signons.sqlite",
        "cookies.sqlite",
    }
)

# --- cloud_credentials ---
_GCP_ADC_BASENAME = "application_default_credentials.json"
_SERVICE_ACCOUNT_RE = re.compile(r"^service-account.*\.json$", re.IGNORECASE)

# --- scm_cicd_tokens ---
_SCM_EXACT_BASENAMES = frozenset({".npmrc", ".pypirc", ".git-credentials"})

# --- modern_saas_tokens ---
_SAAS_NAME_SUBSTRINGS = (
    "openai",
    "anthropic",
    "stripe",
    "auth0",
    "okta",
    "vercel",
    "supabase",
    "datadog",
)

# --- comms_tokens ---
_COMMS_SERVICE_SUBSTRINGS = ("slack", "discord", "teams")

# --- iac ---
# ``.tfstate`` is the juicy Terraform artifact (state files contain
# rendered secrets), checked first within the iac classifier so it gets
# the high-priority hit. ``.tf`` source files usually aren't juicy on
# their own but still belong in this bucket for stratification.
_TFSTATE_EXT = ".tfstate"
_OTHER_IAC_EXTS = frozenset({".tfvars", ".tf"})
_IAC_BASENAMES = frozenset({"ansible-vault.yml", "cloud-init.yaml"})

# --- embedded_secrets ---
_EMBEDDED_BASENAMES_EXACT = frozenset(
    {
        "app.config",
        "web.config",
        "appsettings.json",
        "secrets.yml",
        "secrets.yaml",
    }
)
_EMBEDDED_APPSETTINGS_RE = re.compile(r"^appsettings\..+\.json$", re.IGNORECASE)
_EMBEDDED_DOTENV_RE = re.compile(r"^\.env(\..+)?$", re.IGNORECASE)

# --- network_device ---
# Kept in v0 even without engagement evidence: over-inclusion is free in
# the stratifier (the "drop if no evidence" rule applies to validator
# heuristics and trained-model categories, not stratification hints).
_NETWORK_DEVICE_BASENAMES_EXACT = frozenset({"cisco-running-config"})
_ROUTERCONFIG_PREFIX = "routerconfig"
_RUNNING_CONFIG_RE = re.compile(r"running-config", re.IGNORECASE)

# --- db_files ---
_DB_FILE_EXTS = frozenset({".bak", ".mdf", ".ldf", ".sqlite", ".sqlitedb", ".db", ".mdb"})

# --- decoy_docs ---
_DOC_EXTS = frozenset({".docx", ".pdf", ".txt", ".doc"})
_DOC_KEYWORDS = ("password", "secret", "credential")

# --- benign_noise ---
# Extensions that are essentially never credential-bearing as path signals
# alone. The set is deliberately narrow: media + generic binaries + fonts.
# Archives (.zip/.rar/.7z) are EXCLUDED because protected archives can be
# sealed credential containers; doc types (.pdf/.txt/.docx/.doc) are
# EXCLUDED because they're decoy_docs candidates. When in doubt,
# a path should NOT auto-categorize as benign_noise — better it lands
# unclassified (None) and gets a hand label. benign_noise as a pre-
# categorizer slot is "high-confidence-junk extensions only," not "anything
# that didn't match elsewhere." The fallthrough to None must be preserved
# so genuinely-unmatched paths surface "look at this carefully" rather than
# being silently swept up.
_BENIGN_NOISE_IMAGE_EXTS = frozenset(
    {".jpg", ".jpeg", ".png", ".gif", ".bmp", ".tif", ".tiff", ".svg", ".webp", ".ico"}
)
_BENIGN_NOISE_AUDIO_VIDEO_EXTS = frozenset(
    {".mp3", ".mp4", ".wav", ".avi", ".mov", ".mkv", ".wmv", ".flv", ".m4a", ".m4v", ".ogg"}
)
_BENIGN_NOISE_BINARY_AND_FONT_EXTS = frozenset(
    {
        ".exe",
        ".dll",
        ".so",
        ".dylib",
        ".iso",
        ".dmg",
        ".msi",
        ".bin",
        ".dat",
        ".ttf",
        ".otf",
        ".woff",
        ".woff2",
    }
)

# --- high_value_software ---
# Software whose presence on a share is itself the finding: RMM/remote-
# management agents, native + third-party lateral-movement tooling,
# PAM/privileged-access consoles. Substring match against filename
# (case-insensitive) AND extension restricted to .exe/.msi — tight,
# high-confidence, low FP. Same short-and-defensible discipline as the
# security/CTF filter list in source_github.py.
#
# Deliberate exclusions (per Vincent's review): .dll/.ps1/.config
# (extension creep / overlap with other categories), TeamViewer (too
# common for legitimate use), bare "vault" (matches too many unrelated
# things), VNC (borderline FP for v0). Add later if labeling surfaces
# them as real signal.
_HIGH_VALUE_SOFTWARE_NAME_SUBSTRINGS = (
    # RMM / remote-management agents
    "labtech",  # LabTech / ConnectWise Automate
    "ltsvc",  # LabTech service binary
    "cwagent",  # ConnectWise Automate (rebrand)
    "connectwisecontrol",  # ConnectWise Control (= ScreenConnect rebrand)
    "tacticalrmm",
    "meshagent",  # MeshCentral / TacticalRMM endpoint
    "anydesk",
    "screenconnect",
    "splashtop",
    "ateraagent",
    "dattoagent",
    "kaseyaagent",
    "ninjaagent",  # NinjaOne (NinjaRMM), common in MSP environments
    "ninjarmm",
    # Microsoft / native lateral-movement & deployment
    "psexec",
    "psexec64",
    "ccmexec",  # SCCM client agent
    "ccmsetup",
    # PAM / privileged-access
    "cyberark",
    "secretserver",  # Delinea / Thycotic
    "beyondtrust",
)
_HIGH_VALUE_SOFTWARE_EXTS = frozenset({".exe", ".msi"})


def _classifies_as_windows_credential_artifacts(p: PureWindowsPath) -> bool:
    name_lower = p.name.lower()
    if name_lower in _GPP_CREDENTIAL_BASENAMES:
        path_lower = str(p).lower()
        if "\\sysvol\\" in path_lower and "\\policies\\" in path_lower:
            return True
    if name_lower == "ntds.dit":
        return True
    if p.suffix.lower() in _KERBEROS_TICKET_EXTS:
        return True
    if p.name in _REGISTRY_HIVE_BASENAMES and p.suffix == "":
        return True
    return False


def _classifies_as_credential_containers(p: PureWindowsPath) -> bool:
    suffix = p.suffix.lower()
    return suffix in _KEEPASS_EXTS or suffix in _PKCS12_EXTS or suffix in _JAVA_KEYSTORE_EXTS


def _classifies_as_ssh_credentials(p: PureWindowsPath) -> bool:
    name_lower = p.name.lower()
    if name_lower in _SSH_PRIVATE_KEY_BASENAMES:
        return True
    if name_lower in _SSH_OTHER_BASENAMES:
        return True
    if p.suffix.lower() in _PUTTY_KEY_EXTS:
        return True
    if "\\.ssh\\" in str(p).lower():
        return True
    return False


def _classifies_as_private_keys_x509(p: PureWindowsPath) -> bool:
    return p.suffix.lower() in _X509_EXTS


def _classifies_as_browser_credentials(p: PureWindowsPath) -> bool:
    return p.name.lower() in _BROWSER_CREDENTIAL_BASENAMES


def _classifies_as_cloud_credentials(p: PureWindowsPath) -> bool:
    name_lower = p.name.lower()
    if name_lower == "credentials" and p.parent.name.lower() == ".aws":
        return True
    if name_lower == _GCP_ADC_BASENAME:
        return True
    if _SERVICE_ACCOUNT_RE.match(p.name):
        return True
    path_lower = str(p).lower()
    if "\\.azure\\" in path_lower or "\\.gcp\\" in path_lower:
        return True
    return False


def _classifies_as_scm_cicd_tokens(p: PureWindowsPath) -> bool:
    name_lower = p.name.lower()
    if name_lower in _SCM_EXACT_BASENAMES:
        return True
    if name_lower.startswith("bitbucket-pipelines"):
        return True
    path_lower = str(p).lower()
    if "\\.docker\\config.json" in path_lower:
        return True
    if "\\.github\\workflows\\" in path_lower:
        return True
    return False


def _classifies_as_modern_saas_tokens(p: PureWindowsPath) -> bool:
    name_lower = p.name.lower()
    return any(s in name_lower for s in _SAAS_NAME_SUBSTRINGS)


def _classifies_as_comms_tokens(p: PureWindowsPath) -> bool:
    name_lower = p.name.lower()
    if "webhook" in name_lower:
        return True
    return any(s in name_lower for s in _COMMS_SERVICE_SUBSTRINGS)


def _classifies_as_iac(p: PureWindowsPath) -> bool:
    suffix = p.suffix.lower()
    if suffix == _TFSTATE_EXT:
        return True
    if suffix in _OTHER_IAC_EXTS:
        return True
    if p.name.lower() in _IAC_BASENAMES:
        return True
    return False


def _classifies_as_embedded_secrets(p: PureWindowsPath) -> bool:
    name_lower = p.name.lower()
    if name_lower in _EMBEDDED_BASENAMES_EXACT:
        return True
    if _EMBEDDED_APPSETTINGS_RE.match(p.name):
        return True
    if _EMBEDDED_DOTENV_RE.match(p.name):
        return True
    return False


def _classifies_as_network_device(p: PureWindowsPath) -> bool:
    name_lower = p.name.lower()
    if name_lower in _NETWORK_DEVICE_BASENAMES_EXACT:
        return True
    if name_lower.startswith(_ROUTERCONFIG_PREFIX):
        return True
    if _RUNNING_CONFIG_RE.search(name_lower):
        return True
    return False


def _classifies_as_db_files(p: PureWindowsPath) -> bool:
    return p.suffix.lower() in _DB_FILE_EXTS


def _classifies_as_decoy_docs(p: PureWindowsPath) -> bool:
    if p.suffix.lower() not in _DOC_EXTS:
        return False
    name_lower = p.name.lower()
    return any(kw in name_lower for kw in _DOC_KEYWORDS)


def _classifies_as_benign_noise(p: PureWindowsPath) -> bool:
    """Fires only on the explicit extension set. Unmatched paths must
    continue to return None from ``pre_categorize`` — benign_noise is
    a positive classification (high-confidence-junk by extension), NOT
    the catch-all for everything that didn't match elsewhere."""
    suffix = p.suffix.lower()
    return (
        suffix in _BENIGN_NOISE_IMAGE_EXTS
        or suffix in _BENIGN_NOISE_AUDIO_VIDEO_EXTS
        or suffix in _BENIGN_NOISE_BINARY_AND_FONT_EXTS
    )


def _classifies_as_high_value_software(p: PureWindowsPath) -> bool:
    """Filename substring match against known RMM / PAM / lateral-
    movement / remote-admin software names, AND extension in
    ``_HIGH_VALUE_SOFTWARE_EXTS`` (.exe/.msi).

    Both axes required: a filename containing "labtech" with extension
    .txt or .docx does NOT match (extension restriction prevents
    documentation/install-script false positives). The narrow extension
    set keeps the classifier high-confidence; the labeler is the final
    filter for software the pre-categorizer misses.
    """
    if p.suffix.lower() not in _HIGH_VALUE_SOFTWARE_EXTS:
        return False
    name_lower = p.name.lower()
    return any(s in name_lower for s in _HIGH_VALUE_SOFTWARE_NAME_SUBSTRINGS)


# First-match-wins iteration order. More-specific categories first so
# overlaps resolve correctly: ``key4.db`` hits browser_credentials before
# db_files; ``NTDS.dit`` hits windows_credential_artifacts before any later category
# could claim it; ``\.aws\credentials`` hits cloud_credentials before
# embedded_secrets. ``high_value_software`` MUST be ordered before
# ``benign_noise`` because both can match .exe/.msi extensions:
# ``LabTechAgent.exe`` is a high-value RMM agent (lands in high_value_software),
# while ``Reader.exe`` is generic vendor binary noise (lands in benign_noise).
# The ordering is the load-bearing regression guard pinned by
# ``test_high_value_software_wins_over_benign_noise_for_rmm_binaries``.
# ``benign_noise`` is last because its members (broad media/binary
# extensions) must never shadow a more specific match — and there is NO
# catch-all entry after it; unmatched paths fall through to None.
# Ordering changes here will move overlap resolutions — pin any change
# with a test in the ordering section.
_PRECATEGORIZERS: tuple[tuple[str, Callable[[PureWindowsPath], bool]], ...] = (
    ("windows_credential_artifacts", _classifies_as_windows_credential_artifacts),
    ("credential_containers", _classifies_as_credential_containers),
    ("ssh_credentials", _classifies_as_ssh_credentials),
    ("private_keys_x509", _classifies_as_private_keys_x509),
    ("browser_credentials", _classifies_as_browser_credentials),
    ("cloud_credentials", _classifies_as_cloud_credentials),
    ("scm_cicd_tokens", _classifies_as_scm_cicd_tokens),
    ("modern_saas_tokens", _classifies_as_modern_saas_tokens),
    ("comms_tokens", _classifies_as_comms_tokens),
    ("iac", _classifies_as_iac),
    ("embedded_secrets", _classifies_as_embedded_secrets),
    ("network_device", _classifies_as_network_device),
    ("db_files", _classifies_as_db_files),
    ("high_value_software", _classifies_as_high_value_software),
    ("decoy_docs", _classifies_as_decoy_docs),
    ("benign_noise", _classifies_as_benign_noise),
)


def pre_categorize(path: str) -> str | None:
    """Return the best-effort category hint for ``path``, or None."""
    if not path or not path.strip():
        return None
    try:
        parsed = PureWindowsPath(path)
    except (ValueError, TypeError):
        return None
    for name, predicate in _PRECATEGORIZERS:
        if predicate(parsed):
            return name
    return None


# ============================================================================
# Dedup
# ============================================================================


def _load_labeled_paths(eval_set_path: Path) -> set[str]:
    """Return normalized paths already in eval_set.jsonl, or empty set."""
    if not eval_set_path.exists():
        return set()
    out: set[str] = set()
    with eval_set_path.open("r", encoding="utf-8") as f:
        for line_num, line in enumerate(f, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError as e:
                raise ValueError(f"{eval_set_path}:{line_num}: invalid JSON: {e}") from e
            p = obj.get("path", "")
            if p:
                out.add(normalize_for_dedup(p))
    return out


# ============================================================================
# Input readers
# ============================================================================


def _read_csv(path: Path, default_source: str | None) -> Iterator[dict]:
    with path.open("r", encoding="utf-8-sig", newline="") as f:
        reader = csv.DictReader(f)
        if reader.fieldnames is None or "path" not in reader.fieldnames:
            raise ValueError(
                f"{path}: CSV missing required 'path' column (got {reader.fieldnames!r})"
            )
        for row in reader:
            yield {
                "path": (row.get("path") or "").strip(),
                "source": (row.get("source") or default_source or "").strip(),
            }


def _read_jsonl(path: Path, default_source: str | None) -> Iterator[dict]:
    with path.open("r", encoding="utf-8") as f:
        for line_num, line in enumerate(f, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError as e:
                raise ValueError(f"{path}:{line_num}: invalid JSON: {e}") from e
            if not isinstance(obj, dict):
                raise ValueError(
                    f"{path}:{line_num}: expected JSON object, got {type(obj).__name__}"
                )
            yield {
                "path": (obj.get("path") or "").strip(),
                "source": (obj.get("source") or default_source or "").strip(),
            }


def _read_input(path: Path, default_source: str | None) -> Iterator[dict]:
    suffix = path.suffix.lower()
    if suffix == ".csv":
        return _read_csv(path, default_source)
    if suffix in {".jsonl", ".ndjson"}:
        return _read_jsonl(path, default_source)
    raise ValueError(
        f"{path}: unrecognized input extension {suffix!r} (expected .csv, .jsonl, or .ndjson)"
    )


# ============================================================================
# Stratification
# ============================================================================


def _stratify(records: list[QueueRecord], seed: int) -> list[QueueRecord]:
    """Bucket by pre_category, shuffle within and across buckets, round-robin.

    Deterministic given ``(records, seed)``. The cross-bucket shuffle
    (rather than alphabetical traversal) breaks positional attention
    bias toward whichever category sorts first.
    """
    buckets: dict[str | None, list[QueueRecord]] = {}
    for r in records:
        buckets.setdefault(r.pre_category, []).append(r)

    rng = random.Random(seed)
    for items in buckets.values():
        rng.shuffle(items)

    bucket_order = list(buckets.keys())
    rng.shuffle(bucket_order)

    out: list[QueueRecord] = []
    while True:
        progressed = False
        for key in bucket_order:
            if buckets[key]:
                out.append(buckets[key].pop(0))
                progressed = True
        if not progressed:
            break
    return out


# ============================================================================
# Build orchestrator
# ============================================================================


@dataclass
class BuildStats:
    read: int = 0
    invalid: int = 0
    within_file_dupes: int = 0
    cross_file_dupes: int = 0
    written: int = 0
    errors: list[str] = field(default_factory=list)


def _generate_build_id() -> str:
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S")
    return f"{ts}-{secrets.token_hex(2)}"


def build_queue(
    input_path: Path,
    output_path: Path,
    *,
    source_default: str | None = None,
    eval_set_path: Path | None = None,
    seed: int = 0,
    build_id: str | None = None,
) -> BuildStats:
    """Build the labeling queue. Returns stats; raises ``ValueError`` if
    any input row failed validation (errors are aggregated into a single
    message so the operator sees all problems at once)."""
    if build_id is None:
        build_id = _generate_build_id()

    labeled = _load_labeled_paths(eval_set_path) if eval_set_path else set()

    stats = BuildStats()
    seen_in_file: set[str] = set()
    candidates: list[QueueRecord] = []

    for row in _read_input(input_path, source_default):
        stats.read += 1
        raw_path = row["path"]
        if not raw_path:
            stats.invalid += 1
            stats.errors.append(f"row {stats.read}: missing path")
            continue
        try:
            normalized = normalize_for_dedup(raw_path)
        except (ValueError, TypeError):
            stats.invalid += 1
            stats.errors.append(f"row {stats.read}: invalid path {raw_path!r}")
            continue
        if normalized in seen_in_file:
            stats.within_file_dupes += 1
            continue
        if normalized in labeled:
            stats.cross_file_dupes += 1
            seen_in_file.add(normalized)
            continue
        seen_in_file.add(normalized)
        try:
            rec = QueueRecord(
                path=raw_path,
                source=row["source"],
                pre_category=pre_categorize(raw_path),
                queue_index=0,  # rewritten after stratify
                build_id=build_id,
            )
        except ValidationError as e:
            stats.invalid += 1
            first_err = e.errors()[0]
            loc = ".".join(str(x) for x in first_err["loc"])
            stats.errors.append(f"row {stats.read}: {loc}: {first_err['msg']}")
            continue
        candidates.append(rec)

    if stats.errors:
        raise ValueError(
            f"{len(stats.errors)} invalid row(s) in {input_path}:\n"
            + "\n".join(f"  - {e}" for e in stats.errors)
        )

    ordered = _stratify(candidates, seed=seed)
    final = [rec.model_copy(update={"queue_index": i}) for i, rec in enumerate(ordered)]
    atomic_write_jsonl(output_path, final)
    stats.written = len(final)
    return stats


# ============================================================================
# CLI
# ============================================================================


def _main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="build_queue",
        description="Build a stratified labeling queue from CSV or JSONL paths.",
    )
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--source-default", default=None)
    parser.add_argument(
        "--eval-set",
        type=Path,
        default=Path("data/eval/eval_set.jsonl"),
        help="Existing labeled file for cross-file dedup. Skipped if absent.",
    )
    parser.add_argument("--seed", type=int, default=0)
    parser.add_argument("--build-id", default=None)
    args = parser.parse_args(argv)

    try:
        stats = build_queue(
            input_path=args.input,
            output_path=args.output,
            source_default=args.source_default,
            eval_set_path=args.eval_set,
            seed=args.seed,
            build_id=args.build_id,
        )
    except (ValueError, FileNotFoundError, OSError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 1

    print(
        f"read {stats.read} rows, "
        f"wrote {stats.written}, "
        f"within-file dupes {stats.within_file_dupes}, "
        f"cross-file dupes {stats.cross_file_dupes}",
        file=sys.stderr,
    )
    if stats.written == 0:
        print(
            "warning: queue is empty (no rows after dedup/filtering)",
            file=sys.stderr,
        )
    return 0


if __name__ == "__main__":
    sys.exit(_main())
