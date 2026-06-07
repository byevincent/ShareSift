"""Tests for the contamination tripwire.

The tests below pin three things in addition to per-heuristic coverage:

1. Case-sensitivity: registry hives are case-SENSITIVE; SSH/browser/GPP
   basenames are case-INsensitive. This is the subtlest precision call
   in ``negative_validator.py`` and would be easy to "tidy" wrong.
2. GPP path-shape: both UNC and drive-letter layouts fire for a
   ``Groups.xml`` (or sibling) under a ``SYSVOL`` + ``Policies`` ancestry;
   paths outside that ancestry do not. Proves the normalized-substring
   workaround handles both shapes.
3. Forward-compat: passing ``content_sample`` does not change behavior.
   Reserves the v1 expansion surface against accidental coupling now.
"""

from __future__ import annotations

import pytest

from src.eval.negative_validator import _HEURISTICS, check_path

# -- Per-heuristic canonical positives ---------------------------------------

# One canonical positive path per heuristic in the v0 registry. Each is the
# kind of path Vincent would label ``juicy``; the tripwire's job is to flag
# it if he ever mislabels it ``not_juicy``.
_POSITIVE_CASES: tuple[tuple[str, str], ...] = (
    ("aws_credentials_file", r"C:\Users\bob\.aws\credentials"),
    (
        "chromium_login_data_filename",
        r"C:\Users\bob\AppData\Local\Google\Chrome\User Data\Default\Login Data",
    ),
    (
        "firefox_credential_store_filename",
        r"C:\Users\bob\AppData\Roaming\Mozilla\Firefox\Profiles\xyz.default\logins.json",
    ),
    (
        "gcp_adc_file",
        r"C:\Users\bob\AppData\Roaming\gcloud\application_default_credentials.json",
    ),
    (
        "gpp_xml_in_sysvol",
        r"\\dc01\SYSVOL\corp.local\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}"
        r"\Machine\Preferences\Groups\Groups.xml",
    ),
    ("kdb_extension", r"C:\Users\admin\Documents\old_passwords.kdb"),
    ("kdbx_extension", r"C:\Users\admin\Documents\secrets.kdbx"),
    ("kerberos_ticket_extension", r"C:\Users\admin\Downloads\ticket.kirbi"),
    ("ntds_dit_filename", r"C:\Users\admin\Backups\NTDS.dit"),
    ("etc_shadow", "/etc/shadow"),
    ("pem_extension", r"C:\Users\admin\Certs\server.pem"),
    ("pfx_or_p12_extension", r"C:\Users\admin\Certs\server.pfx"),
    ("registry_hive_extensionless", r"C:\Backups\hives\SAM"),
    ("ssh_key_filename_pattern", r"C:\Users\bob\.ssh\deploy_key"),
    ("ssh_private_key_filename", r"C:\Users\bob\.ssh\id_rsa"),
)


@pytest.mark.parametrize("name,path", _POSITIVE_CASES)
def test_each_heuristic_fires_cleanly_on_canonical_positive(name, path):
    # Strict equality (not membership) so accidental cross-heuristic
    # overlap on a canonical positive is caught as a precision regression.
    result = check_path(path)
    assert result == [name], (
        f"expected exactly [{name!r}] for {path!r}, got {result!r}. "
        f"If multiple names fired, the canonical positive is too broad "
        f"or two heuristics overlap unintentionally."
    )


def test_positive_cases_cover_every_registered_heuristic():
    """Drift guard: every entry in ``_HEURISTICS`` has a canonical positive."""
    registered = {name for name, _ in _HEURISTICS}
    covered = {name for name, _ in _POSITIVE_CASES}
    assert covered == registered, (
        f"_POSITIVE_CASES drifted from _HEURISTICS.\n"
        f"  missing positive case: {sorted(registered - covered)}\n"
        f"  extra positive case:   {sorted(covered - registered)}"
    )


# -- Per-heuristic near-miss negatives ---------------------------------------

# Each tuple: (heuristic_that_must_NOT_fire, deliberately-close-but-benign path).
# Designed to probe the precision boundary: same family, slight variation
# that should not trip the heuristic.
_NEAR_MISS_CASES: tuple[tuple[str, str], ...] = (
    ("ssh_private_key_filename", r"C:\Users\bob\notes\notes_id_rsa.txt"),
    ("ssh_private_key_filename", r"C:\Users\bob\.ssh\id_rsa.pub"),
    ("kdbx_extension", r"C:\Users\bob\Documents\notes.kdbxx"),
    ("kdb_extension", r"C:\Users\bob\Documents\photo.kdbphoto.png"),
    ("pfx_or_p12_extension", r"C:\Users\bob\Downloads\report.pdf"),
    ("chromium_login_data_filename", r"C:\Users\bob\Documents\login_data_export.csv"),
    ("firefox_credential_store_filename", r"C:\Users\bob\Documents\logins.json.bak"),
    ("aws_credentials_file", r"C:\projects\auth\credentials"),
    ("gcp_adc_file", r"C:\Users\bob\application_default_credentials.json.bak"),
    ("gpp_xml_in_sysvol", r"C:\Users\bob\Documents\Groups.xml"),
    ("ntds_dit_filename", r"C:\Users\bob\Documents\NTDS-export.csv"),
    ("registry_hive_extensionless", r"C:\Backups\hives\SAM.bak"),
    ("kerberos_ticket_extension", r"C:\Users\bob\notes\ticket_notes.txt"),
    # .pem precision boundary: similar-looking extensions don't fire
    ("pem_extension", r"C:\Users\bob\Documents\report.pem.txt"),
    ("pem_extension", r"C:\Users\bob\Documents\notes.pemfile.bak"),
    # ssh_key_filename_pattern precision boundary: basename pattern
    # without SSH context (Windows software license keys), files with
    # extensions, and basenames that don't end with _key/-key
    ("ssh_key_filename_pattern", r"C:\Software\Licenses\license_key"),
    ("ssh_key_filename_pattern", r"C:\projects\app\product_key.txt"),
    ("ssh_key_filename_pattern", r"C:\Users\bob\Downloads\keystore"),
    ("ssh_key_filename_pattern", r"C:\Users\bob\Downloads\keymanager"),
    # etc_shadow precision boundary: ``shadow`` basename outside an
    # ``etc/`` parent (a folder named shadow, a notes file, a screenshot
    # of the shadow DOM) must not fire.
    ("etc_shadow", r"C:\Users\bob\projects\shadow\notes.txt"),
    ("etc_shadow", "/var/log/shadow.bak"),
    ("etc_shadow", "/home/user/shadow.txt"),
    ("etc_shadow", "/etc/shadow.bak"),
)


@pytest.mark.parametrize("name,path", _NEAR_MISS_CASES)
def test_each_heuristic_silent_on_near_miss(name, path):
    result = check_path(path)
    assert name not in result, (
        f"heuristic {name!r} fired on near-miss path {path!r}; result was {result!r}"
    )


# -- ml_tier / hybrid scope-creep guard --------------------------------------

# Paths representing categories explicitly EXCLUDED from the tripwire
# (ml_tier and hybrid). If any future heuristic strays into these
# categories, this test fails. The fix is to REMOVE the offending
# heuristic, never to add a suppression rule.
_SCOPE_CREEP_GUARD_PATHS: tuple[str, ...] = (
    # decoy_docs (ml_tier) — exactly where ``not_juicy`` is often correct.
    r"\\fileserv\hr\policies\password_policy.docx",
    r"\\fileserv\public\security_handbook.pdf",
    r"C:\Users\bob\Documents\passwords_reminder.txt",
    # embedded_secrets (hybrid)
    r"C:\projects\webapp\app.config",
    r"C:\projects\webapp\appsettings.json",
    r"C:\projects\webapp\web.config",
    # iac (hybrid)
    r"C:\projects\infra\terraform.tfvars",
    r"C:\projects\infra\cloud-init.yaml",
    r"C:\projects\infra\ansible-vault.yml",
    # modern_saas_tokens (hybrid)
    r"C:\projects\app\.openai.env",
    r"C:\Users\bob\Documents\stripe_keys.txt",
    # scm_cicd_tokens (hybrid)
    r"C:\Users\bob\.npmrc",
    r"C:\projects\.github\workflows\deploy.yml",
    # comms_tokens (hybrid)
    r"C:\Users\bob\Documents\slack_webhook.txt",
    # network_device (hybrid)
    r"\\fileserv\netops\cisco-running-config.txt",
    # db_files (regex by family, but content-driven — out of v0 tripwire scope)
    r"C:\Backups\sales_q3.bak",
    r"C:\Backups\app.mdf",
)


@pytest.mark.parametrize("path", _SCOPE_CREEP_GUARD_PATHS)
def test_excluded_categories_never_fire(path):
    result = check_path(path)
    assert result == [], (
        f"scope-creep guard failed: {path!r} fired {result!r}. "
        f"This path represents an ml_tier or hybrid category that must NEVER "
        f"trigger the tripwire. If a heuristic now matches it, the heuristic "
        f"is out of scope — remove it from _HEURISTICS, do not add a "
        f"suppression rule."
    )


# -- Clean paths -------------------------------------------------------------

_CLEAN_PATHS: tuple[str, ...] = (
    r"C:\Windows\System32\notepad.exe",
    r"C:\Users\bob\Documents\report.pdf",
    r"\\fileserv\shared\meeting_notes.docx",
    r"D:\photos\vacation\IMG_001.jpg",
)


@pytest.mark.parametrize("path", _CLEAN_PATHS)
def test_clean_paths_return_empty(path):
    assert check_path(path) == []


# -- Multi-fire / collection-logic test --------------------------------------


# The v0 heuristics are deliberately well-scoped enough that no natural
# multi-fire case exists (basename-based heuristics check disjoint name
# sets; extension-based heuristics check disjoint suffix sets). To still
# pin the collection-and-sort logic against future regression, use a
# monkeypatched registry with three always-fire heuristics in non-
# alphabetical order and assert the result is all three, sorted.
def test_multi_fire_collects_all_matches_in_alphabetical_order(monkeypatch):
    fake_heuristics = (
        ("zeta_match", lambda p: True),
        ("alpha_match", lambda p: True),
        ("mid_match", lambda p: True),
        ("never_fires", lambda p: False),
    )
    monkeypatch.setattr(
        "src.eval.negative_validator._HEURISTICS",
        fake_heuristics,
    )
    assert check_path(r"C:\anywhere\anyfile.txt") == [
        "alpha_match",
        "mid_match",
        "zeta_match",
    ]


# -- Stable ordering ---------------------------------------------------------


def test_repeated_calls_return_identical_lists():
    path = (
        r"\\dc01\SYSVOL\corp.local\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}"
        r"\Machine\Preferences\Groups\Groups.xml"
    )
    assert check_path(path) == check_path(path)


# -- Empty / whitespace ------------------------------------------------------


@pytest.mark.parametrize("empty", ["", " ", "   ", "\t", "\n", "\r\n  "])
def test_empty_or_whitespace_returns_empty(empty):
    assert check_path(empty) == []


# -- Case-sensitivity pins ---------------------------------------------------


# Registry hives: CASE-SENSITIVE. Lowercase ``sam``/``system``/``security``
# are common English words and must NOT fire — that's the tight-precision
# call the canary comment in the source documents.
@pytest.mark.parametrize(
    "lowercase_hive_path",
    [
        r"C:\Backups\hives\sam",
        r"C:\Backups\hives\system",
        r"C:\Backups\hives\security",
        r"C:\Users\bob\Documents\sam",
        r"C:\projects\system",
    ],
)
def test_registry_hive_lowercase_does_not_fire(lowercase_hive_path):
    assert "registry_hive_extensionless" not in check_path(lowercase_hive_path)


@pytest.mark.parametrize(
    "uppercase_hive_path",
    [
        r"C:\Backups\hives\SAM",
        r"C:\Backups\hives\SYSTEM",
        r"C:\Backups\hives\SECURITY",
    ],
)
def test_registry_hive_uppercase_fires(uppercase_hive_path):
    assert "registry_hive_extensionless" in check_path(uppercase_hive_path)


# SSH private keys: CASE-INSENSITIVE. Manually-renamed copies with different
# casing are still credential material.
@pytest.mark.parametrize(
    "ssh_path",
    [
        r"C:\Users\bob\.ssh\id_rsa",
        r"C:\Users\bob\.ssh\ID_RSA",
        r"C:\Users\bob\.ssh\Id_Rsa",
        r"C:\Users\bob\.ssh\ID_ED25519",
        r"C:\Users\bob\.ssh\id_ECDSA",
    ],
)
def test_ssh_private_key_is_case_insensitive(ssh_path):
    assert "ssh_private_key_filename" in check_path(ssh_path)


# Browser stores: CASE-INSENSITIVE.
@pytest.mark.parametrize(
    "browser_path",
    [
        r"C:\Users\bob\AppData\Local\Chrome\Login Data",
        r"C:\Users\bob\AppData\Local\Chrome\LOGIN DATA",
        r"C:\Users\bob\AppData\Local\Chrome\login data",
        r"C:\Users\bob\AppData\Local\Edge\Web Data",
    ],
)
def test_chromium_login_is_case_insensitive(browser_path):
    assert "chromium_login_data_filename" in check_path(browser_path)


@pytest.mark.parametrize(
    "firefox_path",
    [
        r"C:\Users\bob\Mozilla\logins.json",
        r"C:\Users\bob\Mozilla\LOGINS.JSON",
        r"C:\Users\bob\Mozilla\Key4.DB",
    ],
)
def test_firefox_credential_store_is_case_insensitive(firefox_path):
    assert "firefox_credential_store_filename" in check_path(firefox_path)


# GPP basenames: CASE-INSENSITIVE (the SYSVOL/Policies path context is the
# precision constraint, not the basename casing).
@pytest.mark.parametrize(
    "gpp_path",
    [
        r"\\dc01\SYSVOL\corp\Policies\{GUID}\Groups.xml",
        r"\\dc01\SYSVOL\corp\Policies\{GUID}\GROUPS.XML",
        r"\\dc01\SYSVOL\corp\Policies\{GUID}\groups.xml",
        r"\\dc01\SYSVOL\corp\Policies\{GUID}\Services.xml",
        r"\\dc01\SYSVOL\corp\Policies\{GUID}\scheduledtasks.xml",
    ],
)
def test_gpp_basename_is_case_insensitive(gpp_path):
    assert "gpp_xml_in_sysvol" in check_path(gpp_path)


# -- GPP path-shape pins -----------------------------------------------------


@pytest.mark.parametrize(
    "gpp_path",
    [
        # UNC layout — SYSVOL is the share name; PureWindowsPath bundles it
        # into the anchor rather than emitting it as a discrete part.
        r"\\dc01\SYSVOL\corp.local\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}"
        r"\Machine\Preferences\Groups\Groups.xml",
        # Drive-letter layout — a local copy of SYSVOL on an analyst's box.
        # SYSVOL appears as a directory part, not the share.
        r"C:\backups\SYSVOL\corp.local\Policies\{GUID}\Machine\Preferences"
        r"\Groups\Groups.xml",
    ],
)
def test_gpp_xml_fires_for_both_unc_and_drive_letter_shapes(gpp_path):
    assert "gpp_xml_in_sysvol" in check_path(gpp_path)


@pytest.mark.parametrize(
    "non_gpp_path",
    [
        # Right basename, no SYSVOL anywhere in the path.
        r"C:\Users\bob\Documents\Groups.xml",
        r"\\fileserv\share\Groups.xml",
        # SYSVOL present but no Policies segment.
        r"\\dc01\SYSVOL\corp.local\scripts\Groups.xml",
        # Policies present but no SYSVOL — Group Policy Editor temp dirs etc.
        r"C:\Users\admin\AppData\Local\Policies\Groups.xml",
        # Substring trap: ``\sysvol_backup\`` must NOT match ``\sysvol\``.
        r"\\fileserv\sysvol_backup\corp\Policies\{GUID}\Groups.xml",
    ],
)
def test_gpp_xml_silent_outside_sysvol_policies(non_gpp_path):
    assert "gpp_xml_in_sysvol" not in check_path(non_gpp_path)


# -- Forward-compatibility pin -----------------------------------------------


# ``content_sample`` is the reserved v1 expansion surface. v0 must ignore it
# completely; if behavior ever differs based on it, callers built against the
# v0 contract would break silently when the v1 implementation lands.
@pytest.mark.parametrize(
    "path",
    [
        r"C:\Users\admin\Documents\secrets.kdbx",
        r"C:\Windows\System32\notepad.exe",
        r"C:\Users\bob\.ssh\id_rsa",
        r"\\dc01\SYSVOL\corp\Policies\{GUID}\Groups.xml",
    ],
)
def test_content_sample_kwarg_is_ignored(path):
    baseline = check_path(path)
    assert check_path(path, content_sample=None) == baseline
    assert check_path(path, content_sample=b"") == baseline
    assert check_path(path, content_sample=b"-----BEGIN RSA PRIVATE KEY-----") == baseline


# -- Contamination canary for the synthetic generator exclusion gate ---------

# Per ``docs/generator_spec.md`` Rule 5, the synthetic generator's
# hard-negative class is forbidden from using regex-tier extensions /
# filenames (``.pem``, ``id_rsa``, ``.kdbx``, etc.) — those are
# near-certain positives by design and using them as not_juicy training
# samples would teach the model to discount a high-confidence signal.
# The exclusion gate is ``check_path``; any candidate where it fires
# must be dropped before emission.
#
# These two paths are the EXACT contaminations the synthetic
# exploration produced on its first batch — the spec's
# "(server_key.pem corrupted garbage / ssh/deploy_key public half)"
# warning case made real. Pinning them here means a future relaxation
# of the heuristics that lets either through breaks loudly in the right
# place.
_SYNTHETIC_CONTAMINATION_CANARY_CASES: tuple[tuple[str, str], ...] = (
    (r"\\corp01\groups\security\certificates\server_key.pem", "pem_extension"),
    (r"\\corp01\groups\engineering\infra\ssh\deploy_key", "ssh_key_filename_pattern"),
    # Linux equivalents added 2026-05-28 alongside the pass-7 Linux-path
    # corpus extension. Same Rule 5 principle: a regex-tier Linux
    # credential file generated as a synthetic hard-negative would teach
    # the model to discount a high-confidence signal.
    ("/etc/shadow", "etc_shadow"),
    ("/home/jsmith/.ssh/id_rsa", "ssh_private_key_filename"),
    ("/home/jsmith/.aws/credentials", "aws_credentials_file"),
    ("/etc/ssl/private/server.pem", "pem_extension"),
)


@pytest.mark.parametrize("path,expected_heuristic", _SYNTHETIC_CONTAMINATION_CANARY_CASES)
def test_synthetic_contamination_canary_fires(path, expected_heuristic):
    """The synthetic generator's exclusion gate must catch the
    exact contaminations the spec warned about. If this fails,
    the synthetic prompt's hard-negative output can leak regex-tier
    samples into training data."""
    result = check_path(path)
    assert expected_heuristic in result, (
        f"Contamination canary {expected_heuristic!r} did not fire on "
        f"{path!r}. The synthetic generator's exclusion gate now lets a "
        f"regex-tier sample through as a hard negative — this is Rafael's "
        f"contamination lesson regression."
    )
