"""Contamination tripwire for ``not_juicy`` labels in the eval set.

This validator is NOT a labeler. It does not decide whether a path is juicy;
the human labeler decides. Its only job is to check a path against a small
inventory of dead-obvious positive patterns and report which (if any) fired,
so the GUI can surface a "are you sure?" warning when a ``not_juicy`` label
sits on top of a near-certain positive.

Design contract (do not relax without revisiting the step 3 plan):

* High precision, low recall on warnings. A heuristic ships only if a
  ``not_juicy`` label against it is near-certainly a fatigue mistake.
* Heuristics draw only from regex-tier categories in the taxonomy. ml_tier
  and hybrid categories (``decoy_docs``, ``embedded_secrets``,
  ``iac``, ``network_device``, ``modern_saas_tokens``, ``scm_cicd_tokens``,
  ``comms_tokens``) are excluded — those are exactly where ``not_juicy``
  is frequently the correct call, and firing there would wreck precision.
* No cleverness. If a path matches a pattern, fire. The override pathway
  (fire → warning strip → second-click → log) is how legitimate
  ``not_juicy`` labels on matching paths are handled. Never add suppression
  logic for "looks like a training/example folder" — that drifts toward
  judging, which is the labeler's job.

High override rate on a heuristic is a signal to *remove* it from the
inventory (precision was overestimated), never to add a suppression rule.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from pathlib import PureWindowsPath

# --- ssh_credentials ---------------------------------------------------------

# Canonical OpenSSH private-key basenames. Matched case-insensitively: these
# terms are not common English words, so case-insensitive matching does not
# inflate the false-positive rate.
_SSH_PRIVATE_KEY_BASENAMES = frozenset(
    {
        "id_rsa",
        "id_dsa",
        "id_ecdsa",
        "id_ed25519",
    }
)


def _fires_ssh_private_key_filename(p: PureWindowsPath) -> bool:
    return p.name.lower() in _SSH_PRIVATE_KEY_BASENAMES


# Broader SSH private-key filename pattern: basenames like ``deploy_key``,
# ``production_key``, ``server-key`` etc. These are non-canonical naming
# but unambiguously SSH private-key material when they sit under an SSH
# directory. Requires BOTH the basename pattern AND SSH-directory context
# to avoid false positives on Windows software license files
# (``license_key`` under a Licenses/ share is not credential material).
# Added 2026-05-28 after the synthetic-generator exploration produced
# ``\\...\ssh\deploy_key`` as a hard-negative — exactly the contamination
# the regex-tier exclusion gate is supposed to catch.
_SSH_KEY_FILENAME_RE = re.compile(r"^[a-z0-9._-]+[_-]key$", re.IGNORECASE)


def _fires_ssh_key_filename_pattern(p: PureWindowsPath) -> bool:
    if p.suffix:
        # Files with an extension don't match the SSH-key naming convention;
        # `license_key.txt` shouldn't fire even if path has SSH context.
        return False
    if not _SSH_KEY_FILENAME_RE.match(p.name):
        return False
    # SSH-directory context is the disambiguator. ``\.ssh\`` (Unix dotfile
    # convention) is the canonical form; ``\ssh\`` (no dot) is also
    # accepted because the synthetic prompt produced that shape and it's
    # plausible on real shares.
    path_lower = str(p).lower()
    return "\\.ssh\\" in path_lower or "\\ssh\\" in path_lower


# --- credential_containers ---------------------------------------------------

_KEEPASS_V2_EXTS = frozenset({".kdbx"})
_KEEPASS_V1_EXTS = frozenset({".kdb"})
_PKCS12_EXTS = frozenset({".pfx", ".p12"})
_PEM_EXTS = frozenset({".pem"})


def _fires_kdbx_extension(p: PureWindowsPath) -> bool:
    return p.suffix.lower() in _KEEPASS_V2_EXTS


def _fires_kdb_extension(p: PureWindowsPath) -> bool:
    return p.suffix.lower() in _KEEPASS_V1_EXTS


def _fires_pfx_or_p12_extension(p: PureWindowsPath) -> bool:
    return p.suffix.lower() in _PKCS12_EXTS


def _fires_pem_extension(p: PureWindowsPath) -> bool:
    # ``.pem`` is in the regex-tier per the labeling taxonomy and the
    # synthetic-generator spec's Rule 5 explicitly lists it as a
    # never-generate-as-negative extension. Added 2026-05-28 after the
    # synthetic exploration produced ``server_key.pem`` ("corrupted
    # garbage") as a hard-negative — exactly the contamination the
    # exclusion gate is supposed to catch.
    return p.suffix.lower() in _PEM_EXTS


# --- browser_credentials -----------------------------------------------------

# Browser-store basenames. Matched case-insensitively: these are not common
# English basenames, and a manually-copied store with non-canonical casing
# is still credential material worth flagging.
_CHROMIUM_LOGIN_BASENAMES = frozenset({"login data", "web data"})
_FIREFOX_CREDENTIAL_BASENAMES = frozenset({"logins.json", "key3.db", "key4.db"})


def _fires_chromium_login_data_filename(p: PureWindowsPath) -> bool:
    return p.name.lower() in _CHROMIUM_LOGIN_BASENAMES


def _fires_firefox_credential_store_filename(p: PureWindowsPath) -> bool:
    return p.name.lower() in _FIREFOX_CREDENTIAL_BASENAMES


# --- cloud_credentials ---------------------------------------------------------------


def _fires_aws_credentials_file(p: PureWindowsPath) -> bool:
    # Tight scope: parent dir ``.aws`` AND basename ``credentials`` exactly.
    # AWS CLI creates this path; nothing else commonly does.
    return p.name.lower() == "credentials" and p.parent.name.lower() == ".aws"


def _fires_gcp_adc_file(p: PureWindowsPath) -> bool:
    # GCP Application Default Credentials. The basename is long and
    # specific enough that no broader path context is required.
    return p.name.lower() == "application_default_credentials.json"


# --- windows_credential_artifacts ---------------------------------------------------------

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

# Registry-hive basenames. Matched CASE-SENSITIVELY (unlike other heuristics):
# the lowercase forms ``sam``, ``system``, ``security`` are common English
# words and component names, and case-insensitive matching would inflate the
# false-positive rate. Windows-created hive dumps preserve uppercase.
_REGISTRY_HIVE_BASENAMES = frozenset({"SAM", "SYSTEM", "SECURITY"})

_KERBEROS_TICKET_EXTS = frozenset({".kirbi", ".ccache"})


def _fires_gpp_xml_in_sysvol(p: PureWindowsPath) -> bool:
    if p.name.lower() not in _GPP_CREDENTIAL_BASENAMES:
        return False
    # SYSVOL is typically the UNC share name (``\\dc\SYSVOL\...``), which
    # PureWindowsPath bundles into the anchor rather than emitting as its
    # own part. Substring-search the normalized path so both UNC and
    # drive-letter copies match.
    path_lower = str(p).lower()
    return "\\sysvol\\" in path_lower and "\\policies\\" in path_lower


def _fires_ntds_dit_filename(p: PureWindowsPath) -> bool:
    return p.name.lower() == "ntds.dit"


def _fires_registry_hive_extensionless(p: PureWindowsPath) -> bool:
    # Higher FP risk than siblings: bare-word ``SAM``/``SYSTEM``/``SECURITY``
    # could conceivably appear benignly (vendor names, environment labels,
    # acronyms). Watch override rate closely — this is the canary for the
    # override-rate analysis and the prime suspect if anything in the
    # inventory cries wolf. Case-sensitive match to keep precision tight.
    return p.name in _REGISTRY_HIVE_BASENAMES and p.suffix == ""


def _fires_kerberos_ticket_extension(p: PureWindowsPath) -> bool:
    return p.suffix.lower() in _KERBEROS_TICKET_EXTS


# --- linux_credential_files -------------------------------------------------

# Canonical Linux/Unix system credential databases. ``/etc/shadow`` holds
# hashed local-account passwords; ``/etc/gshadow`` holds group passwords.
# Basename-plus-parent check (not raw substring) keeps precision tight —
# ``\backups\shadow\`` as a folder name, or ``shadow.txt`` notes file,
# should not fire. PureWindowsPath normalizes ``/etc/shadow`` to
# ``\etc\shadow`` so the same heuristic works regardless of separator
# style on incoming paths.
_LINUX_SHADOW_BASENAMES = frozenset({"shadow", "gshadow"})


def _fires_etc_shadow(p: PureWindowsPath) -> bool:
    if p.name.lower() not in _LINUX_SHADOW_BASENAMES:
        return False
    return p.parent.name.lower() == "etc"


# --- registry ----------------------------------------------------------------

# Single source of truth. ``check_path`` iterates this; tests iterate the
# same tuple to assert per-heuristic coverage. Order here is alphabetical
# by name for readability; ``check_path`` sorts its result independently so
# the public return order is stable even if this tuple is reordered.
_HEURISTICS: tuple[tuple[str, Callable[[PureWindowsPath], bool]], ...] = (
    ("aws_credentials_file", _fires_aws_credentials_file),
    ("chromium_login_data_filename", _fires_chromium_login_data_filename),
    ("etc_shadow", _fires_etc_shadow),
    ("firefox_credential_store_filename", _fires_firefox_credential_store_filename),
    ("gcp_adc_file", _fires_gcp_adc_file),
    ("gpp_xml_in_sysvol", _fires_gpp_xml_in_sysvol),
    ("kdb_extension", _fires_kdb_extension),
    ("kdbx_extension", _fires_kdbx_extension),
    ("kerberos_ticket_extension", _fires_kerberos_ticket_extension),
    ("ntds_dit_filename", _fires_ntds_dit_filename),
    ("pem_extension", _fires_pem_extension),
    ("pfx_or_p12_extension", _fires_pfx_or_p12_extension),
    ("registry_hive_extensionless", _fires_registry_hive_extensionless),
    ("ssh_key_filename_pattern", _fires_ssh_key_filename_pattern),
    ("ssh_private_key_filename", _fires_ssh_private_key_filename),
)


def check_path(
    path: str,
    *,
    content_sample: bytes | None = None,
) -> list[str]:
    """Return the names of tripwire heuristics that fire for ``path``.

    Path-only in v0. ``content_sample`` is reserved for a future
    content-aware heuristic and is ignored here; any further metadata
    parameters added later must also be keyword-only so existing callers
    keep working.

    Returns an alphabetically sorted list of heuristic names, or ``[]``
    if nothing fires. Never raises — malformed paths return ``[]`` (the
    Pydantic schema is the gatekeeper for path well-formedness; this
    function's job is heuristic firing, not input validation).
    """
    del content_sample  # reserved for forward compatibility; ignored in v0.

    if not path or not path.strip():
        return []

    try:
        parsed = PureWindowsPath(path)
    except (ValueError, TypeError):
        return []

    fired = [name for name, predicate in _HEURISTICS if predicate(parsed)]
    return sorted(fired)
