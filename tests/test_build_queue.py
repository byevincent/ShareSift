"""Tests for the stratified labeling-queue builder."""

from __future__ import annotations

import json

import pytest

from src.eval._paths import normalize_for_dedup
from src.eval.build_queue import (
    _PRECATEGORIZERS,
    QueueRecord,
    _stratify,
    build_queue,
    pre_categorize,
)
from src.eval.categories import CATEGORY_SLUGS
from src.eval.negative_validator import check_path

# ============================================================================
# Pre-categorizer: canonical positives
# ============================================================================

_CATEGORY_POSITIVE_PATHS: tuple[tuple[str, str], ...] = (
    ("windows_credential_artifacts", r"\\dc01\SYSVOL\corp\Policies\{GUID}\Groups.xml"),
    ("credential_containers", r"C:\Users\admin\Documents\secrets.kdbx"),
    ("ssh_credentials", r"C:\Users\bob\.ssh\id_rsa"),
    ("private_keys_x509", r"C:\Certs\server.pem"),
    ("browser_credentials", r"C:\Users\bob\AppData\Local\Chrome\Login Data"),
    ("cloud_credentials", r"C:\Users\bob\.aws\credentials"),
    ("scm_cicd_tokens", r"C:\Users\bob\.npmrc"),
    ("modern_saas_tokens", r"C:\projects\app\openai_keys.txt"),
    ("comms_tokens", r"C:\Users\bob\Documents\slack_webhook.txt"),
    ("iac", r"C:\projects\infra\terraform.tfstate"),
    ("embedded_secrets", r"C:\projects\webapp\appsettings.json"),
    ("network_device", r"\\fileserv\netops\cisco-running-config"),
    ("db_files", r"C:\Backups\sales.bak"),
    ("decoy_docs", r"\\fileserv\hr\password_policy.docx"),
    ("benign_noise", r"\\fileserv\marketing\spring_banner.jpg"),
    ("high_value_software", r"\\dc01\NETLOGON\LabTechAgent.exe"),
)


@pytest.mark.parametrize("category,path", _CATEGORY_POSITIVE_PATHS)
def test_precategorizer_canonical_positives(category, path):
    assert pre_categorize(path) == category


def test_positive_cases_cover_every_category_slug():
    covered = {c for c, _ in _CATEGORY_POSITIVE_PATHS}
    assert covered == set(CATEGORY_SLUGS), (
        f"_CATEGORY_POSITIVE_PATHS drift from CATEGORY_SLUGS.\n"
        f"  missing: {sorted(set(CATEGORY_SLUGS) - covered)}\n"
        f"  extra:   {sorted(covered - set(CATEGORY_SLUGS))}"
    )


def test_precategorizer_registry_covers_every_category_slug():
    registered = {c for c, _ in _PRECATEGORIZERS}
    assert registered == set(CATEGORY_SLUGS), (
        f"_PRECATEGORIZERS drift from CATEGORY_SLUGS.\n"
        f"  missing: {sorted(set(CATEGORY_SLUGS) - registered)}\n"
        f"  extra:   {sorted(registered - set(CATEGORY_SLUGS))}"
    )


# ============================================================================
# Pre-categorizer: ordering / first-match-wins (ordering-dependency pins)
# ============================================================================


@pytest.mark.parametrize(
    "path,expected",
    [
        # User-pinned: key4.db (Firefox credential store) hits
        # browser_credentials BEFORE db_files (.db extension).
        (r"C:\Users\bob\Mozilla\Profiles\xyz\key4.db", "browser_credentials"),
        # Companion: backup.db has no browser-store basename, falls
        # through to db_files via .db extension.
        (r"C:\Backups\backup.db", "db_files"),
        # NTDS.dit hits windows_credential_artifacts (basename) — must never be
        # mis-classified as db_files.
        (r"C:\Backups\NTDS.dit", "windows_credential_artifacts"),
        # .aws\credentials hits cloud_credentials (basename + parent), not
        # embedded_secrets despite "credentials" looking config-ish.
        (r"C:\Users\bob\.aws\credentials", "cloud_credentials"),
        # Cookies (Chromium, no extension) hits browser_credentials
        # before any later category.
        (r"C:\Users\bob\AppData\Local\Chrome\Cookies", "browser_credentials"),
        # signons.sqlite is a browser store; the .sqlite extension
        # would otherwise match db_files.
        (
            r"C:\Users\bob\AppData\Roaming\Mozilla\Firefox\Profiles\xyz\signons.sqlite",
            "browser_credentials",
        ),
        # User-pinned: .ppk → ssh_credentials (PuTTY key extension).
        (r"C:\Users\bob\Documents\server.ppk", "ssh_credentials"),
        # User-pinned: .tfstate → iac, high priority within iac classifier.
        (r"C:\projects\infra\production.tfstate", "iac"),
        # service-account*.json → cloud_credentials (regex match on basename).
        (r"C:\Users\bob\service-account-prod.json", "cloud_credentials"),
        # Anything under \.ssh\ → ssh_credentials even with an
        # otherwise-uncategorized filename.
        (r"C:\Users\bob\.ssh\config", "ssh_credentials"),
    ],
)
def test_precategorizer_first_match_wins_on_overlap(path, expected):
    assert pre_categorize(path) == expected


# ============================================================================
# Pre-categorizer: unmatched / empty
# ============================================================================


@pytest.mark.parametrize(
    "path",
    [
        # These have extensions NOT in benign_noise's set and don't
        # match any other classifier — they correctly return None
        # (pre-categorizer's fallthrough is "look at this carefully"
        # signal, not benign_noise).
        r"C:\Users\bob\Documents\report.xlsx",
        r"\\fileserv\shared\meeting_notes.txt",  # .txt without keywords
        r"C:\projects\src\main.py",
        r"C:\Users\bob\Downloads\unknown.xyz",
    ],
)
def test_precategorizer_returns_none_for_unmatched(path):
    assert pre_categorize(path) is None


@pytest.mark.parametrize("empty", ["", "   ", "\t"])
def test_precategorizer_returns_none_for_empty_or_whitespace(empty):
    assert pre_categorize(empty) is None


# ============================================================================
# benign_noise — extension positives + exclusions + fallthrough preservation
# ============================================================================


@pytest.mark.parametrize(
    "path",
    [
        # Image extensions.
        r"D:\photos\vacation\IMG_001.jpg",
        r"\\fileserv\marketing\logo.png",
        r"C:\design\assets\icon.svg",
        r"C:\favicons\site.ico",
        # Audio/video extensions.
        r"C:\videos\recording.mp4",
        r"C:\Users\bob\Music\song.mp3",
        r"\\fileserv\recordings\all-hands.mkv",
        # Generic binaries + fonts.
        r"C:\Windows\System32\notepad.exe",
        r"C:\Windows\System32\kernel32.dll",
        r"C:\Windows\Fonts\arial.ttf",
        r"C:\webapp\fonts\display.woff2",
        r"C:\installers\product.msi",
    ],
)
def test_benign_noise_extension_positives(path):
    assert pre_categorize(path) == "benign_noise"


@pytest.mark.parametrize(
    "path,expected",
    [
        # password_policy.docx → decoy_docs, NOT benign_noise:
        # .docx is excluded from benign_noise, and decoy_docs
        # sits earlier in the ordering anyway.
        (r"\\fileserv\hr\password_policy.docx", "decoy_docs"),
        # credentials_summary.pdf → decoy_docs, NOT benign_noise.
        (r"\\fileserv\docs\credentials_summary.pdf", "decoy_docs"),
        # Archives (.zip/.rar/.7z) are DELIBERATELY excluded from
        # benign_noise because protected archives can be sealed
        # credential containers. They fall through to None so the
        # labeler reads the path themselves and decides what they are.
        (r"\\fileserv\backup\archive.zip", None),
        (r"\\fileserv\share\bundle.7z", None),
        (r"\\fileserv\share\old.rar", None),
        # Doc extensions without a sensitivity keyword: NOT benign_noise
        # (the labeler should judge by content semantics), NOT
        # decoy_docs (no keyword), so None.
        (r"\\fileserv\docs\policy_overview.pdf", None),
        (r"\\fileserv\meeting_minutes.docx", None),
    ],
)
def test_benign_noise_exclusions_and_priority(path, expected):
    """Pins the benign_noise design constraint: archives and doc types
    are deliberately excluded from the extension set, so they fall to
    None / a more-specific category rather than being swept into
    benign_noise by extension alone."""
    assert pre_categorize(path) == expected


def test_pre_categorizer_unmatched_extensions_return_none_not_benign_noise():
    """Direct pin of the load-bearing design point: benign_noise fires
    only on its explicit extension set; genuinely-unmatched paths return
    None from the pre-categorizer. The fallthrough/unclassified bucket
    is preserved — adding benign_noise must NOT make it a catch-all.

    Without this pin, a future "broaden benign_noise to cover anything
    unmatched" change would silently destroy the unclassified bucket
    that surfaces 'the pre-categorizer had no idea, look at this one
    carefully' — which is signal the stratifier and the labeler both
    want.
    """
    # Extensions deliberately NOT in any of the benign_noise sets and
    # not matching any other classifier.
    for path in (
        r"C:\projects\report.xlsx",
        r"C:\projects\data.csv",
        r"C:\projects\src\main.py",
        r"C:\projects\spreadsheet.ods",
    ):
        assert pre_categorize(path) is None, (
            f"{path!r} returned non-None — benign_noise (or another classifier) "
            f"may have widened beyond its narrow extension set"
        )


# ============================================================================
# high_value_software — ordering pin + non-overreach pin + extension restriction
# ============================================================================


@pytest.mark.parametrize(
    "path",
    [
        # RMM agents
        r"\\dc01\NETLOGON\LabTechAgent.exe",
        r"\\dc01\NETLOGON\LabTechAgent.msi",
        r"\\fs01\software\ltsvc.exe",
        r"\\fs01\share\cwagent-installer.exe",
        r"\\fs01\share\ConnectWiseControl.ClientService.exe",
        r"\\fs01\deploy\tacticalrmm-agent.exe",
        r"\\fs01\deploy\meshagent.msi",
        r"\\fs01\share\AnyDesk.exe",
        r"\\fs01\install\ScreenConnect.WindowsClient.exe",
        r"\\fs01\install\splashtop-streamer.exe",
        r"\\fs01\install\AteraAgent.msi",
        r"\\fs01\install\DattoAgent.exe",
        r"\\fs01\install\KaseyaAgent.exe",
        r"\\fs01\install\NinjaAgent.exe",
        r"\\fs01\install\NinjaRMMAgent.msi",
        # Native lateral-movement / deployment
        r"\\dc01\NETLOGON\psexec.exe",
        r"\\dc01\NETLOGON\PsExec64.exe",
        r"\\sccm-srv\Sources\ccmexec.exe",
        r"\\sccm-srv\Sources\ccmsetup.msi",
        # PAM
        r"\\fs01\install\CyberArkInstall.msi",
        r"\\fs01\install\SecretServer.exe",
        r"\\fs01\install\BeyondTrustClient.exe",
    ],
)
def test_high_value_software_canonical_positives(path):
    """Every substring in _HIGH_VALUE_SOFTWARE_NAME_SUBSTRINGS produces
    a positive match for at least one canonical filename, AND the
    extension restriction (.exe/.msi) passes. Together these confirm
    the classifier's tight (name AND extension) shape works end-to-end."""
    assert pre_categorize(path) == "high_value_software"


def test_high_value_software_wins_over_benign_noise_for_rmm_binaries():
    """LOAD-BEARING ORDERING PIN. ``high_value_software`` MUST be
    ordered before ``benign_noise`` in ``_PRECATEGORIZERS`` because
    both can match ``.exe`` / ``.msi`` extensions. The motivating
    dogfood case (LabTechAgent in NETLOGON) is recon-valuable
    intelligence, not generic vendor binary noise — the wrong
    ordering would silently sweep it into benign_noise and the
    labeler would never see it as the high-value finding it is.

    A future reordering that puts benign_noise first breaks this
    test loudly.
    """
    assert pre_categorize(r"\\dc01\NETLOGON\LabTechAgent.exe") == "high_value_software"
    assert pre_categorize(r"\\fs01\share\ScreenConnect.exe") == "high_value_software"
    assert pre_categorize(r"\\sccm-srv\src\psexec.exe") == "high_value_software"


@pytest.mark.parametrize(
    "path",
    [
        # Real vendor binaries with no high-value-software substring match
        # → correctly classified as benign_noise (generic vendor binary).
        # The classifier's name-AND-extension shape prevents over-reach.
        r"\\fs01\software\Adobe\Reader.exe",
        r"\\fs01\software\7Zip\7z.exe",
        r"\\fs01\software\Microsoft\Office\winword.exe",
        r"\\fs01\drivers\printer-driver.msi",
    ],
)
def test_high_value_software_does_not_overreach_to_unrelated_binaries(path):
    """Non-overreach pin: a `.exe` / `.msi` whose filename DOESN'T
    contain a known RMM/PAM/lateral-movement software substring stays
    in ``benign_noise``. The category is about specific software, not
    about executable extensions generally."""
    assert pre_categorize(path) == "benign_noise"


@pytest.mark.parametrize(
    "path",
    [
        # Filenames containing high-value-software substrings but with
        # excluded extensions (.docx, .pdf, .txt, .ps1, .config, .dll)
        # must NOT classify as high_value_software. The classifier
        # requires BOTH name match AND extension in {.exe, .msi}.
        r"\\fs01\share\LabTech-install-notes.docx",
        r"\\fs01\share\ScreenConnect-deployment-guide.pdf",
        r"\\fs01\share\psexec-cheatsheet.txt",
        r"\\fs01\install\install-anydesk.ps1",
    ],
)
def test_high_value_software_requires_exe_or_msi_extension(path):
    """Extension-restriction pin: filename substring alone is not
    enough; the classifier requires .exe or .msi. Documentation,
    install scripts, configs, and DLLs are deliberately excluded
    (overlap risk with other categories OR weaker signal). Paths with
    a high-value-software name but excluded extension fall through to
    whatever later classifier matches them (most likely None or
    decoy_docs if filename contains a sensitivity keyword)."""
    assert pre_categorize(path) != "high_value_software"


# ============================================================================
# Categorizer vs. validator asymmetry pin
# ============================================================================


def test_ppk_in_categorizer_but_not_in_validator():
    """.ppk classifies as ssh_credentials for stratification, but the
    validator deliberately omits it — the validator's higher precision
    bar (override credibility) and the categorizer's stratification
    value lead to different inclusion thresholds. This asymmetry is the
    design working as intended; pin it so neither side drifts to match
    the other unintentionally."""
    path = r"C:\Users\bob\Documents\server.ppk"
    assert pre_categorize(path) == "ssh_credentials"
    assert check_path(path) == []


# ============================================================================
# Network device retention pin
# ============================================================================


@pytest.mark.parametrize(
    "path",
    [
        r"\\fileserv\netops\cisco-running-config",
        r"\\fileserv\netops\routerconfig-2024.txt",
        r"\\fileserv\netops\edge-router-running-config.cfg",
    ],
)
def test_network_device_classifier_kept_in_v0(path):
    """network_device stays in the categorizer despite no engagement
    evidence: over-inclusion is free in the stratifier. The 'drop if no
    evidence' rule applies to validator heuristics and trained-model
    categories, not stratification hints."""
    assert pre_categorize(path) == "network_device"


# ============================================================================
# Normalization
# ============================================================================


def test_normalize_for_dedup_is_case_insensitive():
    a = normalize_for_dedup(r"C:\Users\Bob\Document.TXT")
    b = normalize_for_dedup(r"c:\users\bob\document.txt")
    assert a == b


def test_normalize_for_dedup_collapses_separator_style():
    assert normalize_for_dedup("C:/Users/bob/file.txt") == normalize_for_dedup(
        r"C:\Users\bob\file.txt"
    )


# ============================================================================
# CSV reader
# ============================================================================


def test_csv_with_both_columns(tmp_path):
    src = tmp_path / "in.csv"
    src.write_text(
        "path,source\nC:\\file.txt,engagement\nC:\\v.kdbx,public\n",
        encoding="utf-8",
    )
    out = tmp_path / "queue.jsonl"
    stats = build_queue(src, out, source_default=None, eval_set_path=None)
    assert stats.read == 2
    assert stats.written == 2


def test_csv_with_source_default(tmp_path):
    src = tmp_path / "in.csv"
    src.write_text("path\nC:\\file.txt\nC:\\v.kdbx\n", encoding="utf-8")
    out = tmp_path / "queue.jsonl"
    stats = build_queue(src, out, source_default="engagement", eval_set_path=None)
    assert stats.written == 2
    records = [
        QueueRecord.model_validate_json(line)
        for line in out.read_text(encoding="utf-8").splitlines()
    ]
    assert all(r.source == "engagement" for r in records)


def test_csv_missing_path_column_raises(tmp_path):
    src = tmp_path / "in.csv"
    src.write_text("name,source\nfoo,engagement\n", encoding="utf-8")
    out = tmp_path / "queue.jsonl"
    with pytest.raises(ValueError, match="missing required 'path' column"):
        build_queue(src, out, source_default="engagement", eval_set_path=None)


def test_csv_missing_source_without_default_raises(tmp_path):
    src = tmp_path / "in.csv"
    src.write_text("path\nC:\\file.txt\n", encoding="utf-8")
    out = tmp_path / "queue.jsonl"
    with pytest.raises(ValueError) as exc:
        build_queue(src, out, source_default=None, eval_set_path=None)
    assert "source" in str(exc.value).lower()


def test_invalid_rows_aggregate_into_single_error(tmp_path):
    src = tmp_path / "in.csv"
    src.write_text(
        "path,source\n,engagement\nC:\\good.kdbx,bogus_source\nC:\\fine.txt,engagement\n",
        encoding="utf-8",
    )
    out = tmp_path / "queue.jsonl"
    with pytest.raises(ValueError) as exc:
        build_queue(src, out, source_default=None, eval_set_path=None)
    msg = str(exc.value)
    assert "missing path" in msg
    assert "source" in msg
    assert "2 invalid" in msg


# ============================================================================
# JSONL reader
# ============================================================================


def test_jsonl_happy_path(tmp_path):
    src = tmp_path / "in.jsonl"
    src.write_text(
        json.dumps({"path": r"C:\file.txt", "source": "engagement"})
        + "\n"
        + json.dumps({"path": r"C:\v.kdbx", "source": "public"})
        + "\n",
        encoding="utf-8",
    )
    out = tmp_path / "queue.jsonl"
    stats = build_queue(src, out, source_default=None, eval_set_path=None)
    assert stats.written == 2


def test_jsonl_malformed_line_raises(tmp_path):
    src = tmp_path / "in.jsonl"
    src.write_text(
        json.dumps({"path": r"C:\f.txt", "source": "engagement"}) + "\n" + "not json\n",
        encoding="utf-8",
    )
    out = tmp_path / "queue.jsonl"
    with pytest.raises(ValueError, match="invalid JSON"):
        build_queue(src, out, source_default=None, eval_set_path=None)


def test_jsonl_non_object_line_raises(tmp_path):
    src = tmp_path / "in.jsonl"
    src.write_text('["array", "not", "object"]\n', encoding="utf-8")
    out = tmp_path / "queue.jsonl"
    with pytest.raises(ValueError, match="expected JSON object"):
        build_queue(src, out, source_default=None, eval_set_path=None)


def test_unknown_input_extension_raises(tmp_path):
    src = tmp_path / "in.txt"
    src.write_text("anything", encoding="utf-8")
    out = tmp_path / "queue.jsonl"
    with pytest.raises(ValueError, match="unrecognized input extension"):
        build_queue(src, out, source_default="engagement", eval_set_path=None)


# ============================================================================
# Dedup
# ============================================================================


def test_within_file_dedup_keeps_first_case_insensitive(tmp_path):
    src = tmp_path / "in.csv"
    src.write_text(
        "path,source\nC:\\file.txt,engagement\nC:\\file.txt,engagement\nc:/file.txt,engagement\n",
        encoding="utf-8",
    )
    out = tmp_path / "queue.jsonl"
    stats = build_queue(src, out, source_default=None, eval_set_path=None)
    assert stats.read == 3
    assert stats.within_file_dupes == 2
    assert stats.written == 1


def test_cross_file_dedup_against_eval_set_case_insensitive(tmp_path):
    eval_set = tmp_path / "eval_set.jsonl"
    eval_set.write_text(
        json.dumps({"path": r"C:\already.kdbx"}) + "\n",
        encoding="utf-8",
    )
    src = tmp_path / "in.csv"
    src.write_text(
        "path,source\n"
        "C:\\already.kdbx,engagement\n"
        "c:/already.kdbx,engagement\n"
        "C:\\new.kdbx,engagement\n",
        encoding="utf-8",
    )
    out = tmp_path / "queue.jsonl"
    stats = build_queue(src, out, source_default=None, eval_set_path=eval_set)
    assert stats.cross_file_dupes == 1
    assert stats.within_file_dupes == 1
    assert stats.written == 1


def test_cross_file_dedup_skipped_when_eval_set_missing(tmp_path):
    src = tmp_path / "in.csv"
    src.write_text("path,source\nC:\\x.txt,engagement\n", encoding="utf-8")
    out = tmp_path / "queue.jsonl"
    nonexistent = tmp_path / "no_such_file.jsonl"
    stats = build_queue(src, out, source_default=None, eval_set_path=nonexistent)
    assert stats.cross_file_dupes == 0
    assert stats.written == 1


def test_cross_file_dedup_skipped_when_eval_set_path_is_none(tmp_path):
    src = tmp_path / "in.csv"
    src.write_text("path,source\nC:\\x.txt,engagement\n", encoding="utf-8")
    out = tmp_path / "queue.jsonl"
    stats = build_queue(src, out, source_default=None, eval_set_path=None)
    assert stats.cross_file_dupes == 0
    assert stats.written == 1


# ============================================================================
# Stratification
# ============================================================================


def _make_record(path: str, category: str | None) -> QueueRecord:
    return QueueRecord(
        path=path,
        source="engagement",
        pre_category=category,
        queue_index=0,
        build_id="test",
    )


def test_stratify_round_robin_balances_equal_buckets():
    records = (
        [_make_record(f"C:\\a{i}.kdbx", "credential_containers") for i in range(3)]
        + [_make_record(f"C:\\b{i}.bak", "db_files") for i in range(3)]
        + [_make_record(f"C:\\c{i}.pem", "private_keys_x509") for i in range(3)]
    )
    out = _stratify(records, seed=0)
    assert len(out) == 9
    cats = [r.pre_category for r in out]
    # With three equally-sized buckets, no two adjacent records share a category.
    same_neighbors = sum(1 for i in range(len(cats) - 1) if cats[i] == cats[i + 1])
    assert same_neighbors == 0


def test_stratify_deterministic_for_same_seed():
    records = [_make_record(f"C:\\a{i}.txt", "credential_containers") for i in range(5)] + [
        _make_record(f"C:\\b{i}.txt", "db_files") for i in range(5)
    ]
    a = _stratify(records, seed=42)
    b = _stratify(records, seed=42)
    assert [r.path for r in a] == [r.path for r in b]


def test_stratify_differs_across_seeds():
    records = (
        [_make_record(f"C:\\a{i}.txt", "credential_containers") for i in range(10)]
        + [_make_record(f"C:\\b{i}.txt", "db_files") for i in range(10)]
        + [_make_record(f"C:\\c{i}.txt", "iac") for i in range(10)]
    )
    a = _stratify(records, seed=0)
    b = _stratify(records, seed=1)
    assert [r.path for r in a] != [r.path for r in b]


def test_stratify_none_bucket_participates():
    records = [
        _make_record(r"C:\a.txt", "credential_containers"),
        _make_record(r"C:\b.txt", None),
        _make_record(r"C:\c.txt", None),
    ]
    out = _stratify(records, seed=0)
    assert len(out) == 3
    assert {r.pre_category for r in out} == {"credential_containers", None}


def test_stratify_empty_input_returns_empty():
    assert _stratify([], seed=0) == []


def test_stratify_handles_unequal_buckets_without_loss():
    records = (
        [_make_record(f"C:\\a{i}.txt", "credential_containers") for i in range(5)]
        + [_make_record(f"C:\\b{i}.txt", "db_files") for i in range(1)]
        + [_make_record(f"C:\\c{i}.txt", "iac") for i in range(2)]
    )
    out = _stratify(records, seed=0)
    # No record dropped; bucket counts preserved.
    assert len(out) == 8
    counts = {}
    for r in out:
        counts[r.pre_category] = counts.get(r.pre_category, 0) + 1
    assert counts == {"credential_containers": 5, "db_files": 1, "iac": 2}


# ============================================================================
# End-to-end
# ============================================================================


def test_end_to_end_record_shape_and_indices(tmp_path):
    src = tmp_path / "in.csv"
    src.write_text(
        "path,source\n"
        "C:\\Users\\admin\\secrets.kdbx,engagement\n"
        "\\\\dc01\\SYSVOL\\corp\\Policies\\{G}\\Groups.xml,engagement\n"
        "C:\\Backups\\big.bak,public\n",
        encoding="utf-8",
    )
    out = tmp_path / "queue.jsonl"
    stats = build_queue(
        src,
        out,
        source_default=None,
        eval_set_path=None,
        seed=0,
        build_id="20260524T000000-test",
    )
    assert stats.written == 3
    records = [
        QueueRecord.model_validate_json(line)
        for line in out.read_text(encoding="utf-8").splitlines()
    ]
    assert [r.queue_index for r in records] == [0, 1, 2]
    assert all(r.build_id == "20260524T000000-test" for r in records)
    assert {r.pre_category for r in records} == {
        "credential_containers",
        "windows_credential_artifacts",
        "db_files",
    }


def test_end_to_end_empty_input_writes_empty_file(tmp_path):
    src = tmp_path / "in.csv"
    src.write_text("path,source\n", encoding="utf-8")
    out = tmp_path / "queue.jsonl"
    stats = build_queue(src, out, source_default=None, eval_set_path=None)
    assert stats.read == 0
    assert stats.written == 0
    assert out.exists()
    assert out.read_text(encoding="utf-8") == ""


def test_build_id_default_format(tmp_path):
    src = tmp_path / "in.csv"
    src.write_text("path,source\nC:\\f.txt,engagement\n", encoding="utf-8")
    out = tmp_path / "queue.jsonl"
    build_queue(src, out, source_default=None, eval_set_path=None)
    record = QueueRecord.model_validate_json(out.read_text(encoding="utf-8").strip())
    parts = record.build_id.split("-")
    assert len(parts) == 2
    assert len(parts[0]) == 15  # YYYYMMDDTHHMMSS
    assert len(parts[1]) == 4  # token_hex(2) → 4 hex chars
    assert parts[0][8] == "T"


def test_build_id_override_used_when_provided(tmp_path):
    src = tmp_path / "in.csv"
    src.write_text("path,source\nC:\\f.txt,engagement\n", encoding="utf-8")
    out = tmp_path / "queue.jsonl"
    build_queue(
        src,
        out,
        source_default=None,
        eval_set_path=None,
        build_id="custom-build-id",
    )
    record = QueueRecord.model_validate_json(out.read_text(encoding="utf-8").strip())
    assert record.build_id == "custom-build-id"


def test_queue_record_rejects_bad_pre_category():
    with pytest.raises(Exception):
        QueueRecord(
            path=r"C:\f.txt",
            source="engagement",
            pre_category="not_a_real_category",
            queue_index=0,
            build_id="x",
        )


def test_queue_record_rejects_bad_source():
    with pytest.raises(Exception):
        QueueRecord(
            path=r"C:\f.txt",
            source="telepathy",
            pre_category=None,
            queue_index=0,
            build_id="x",
        )
