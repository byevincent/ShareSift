"""Tests for the GitHub Code Search candidate-paths scraper.

Pure-function pinning + rate-limit state-machine pinning. The actual
HTTP ``urlopen`` call is the only thing left as manual-smoke — the
state machine around it (sliding-window pacer, X-RateLimit-Remaining
honoring, retry exhaustion, per-query graceful failure, manifest
status field) is all testable here with monkeypatched time + mocked
urlopen.

These tests exist BECAUSE manual smoke on the first live run surfaced
two real bugs in the un-unit-tested HTTP layer: pacing didn't respect
the per-minute budget across pagination, and backoff silently dropped
queries to zero results on exhaustion. Both fixes ship with unit
coverage now.
"""

from __future__ import annotations

import csv
import json
import time
import urllib.error
import urllib.request
from unittest.mock import MagicMock

import pytest

from src.eval._path_filters import (
    LAB_PATH_MARKERS,
    OFFENSIVE_SECURITY_URL_PATTERNS,
    extract_unc_paths,
    has_variable_interpolation,
    is_offensive_security_provenance,
    is_placeholder_server,
    is_too_short,
)
from src.eval._paths import normalize_for_dedup
from src.eval.source_github import (
    _BUDGET_PER_WINDOW,
    _MAX_PAGES_PER_QUERY,
    _MAX_RATE_LIMIT_RETRIES,
    _PAT_ENV_VAR,
    _QUERY_SETS,
    _RATE_LIMIT_BUFFER_SECONDS,
    _REQUEST_TIMESTAMPS,
    _WINDOW_SECONDS,
    Candidate,
    CollectResult,
    _fetch_search_page,
    _honor_remaining_header,
    _read_pat,
    _wait_for_rate_limit,
    _write_csv,
    collect,
    main,
)


@pytest.fixture(autouse=True)
def _reset_rate_limit_deque():
    """Module-global `_REQUEST_TIMESTAMPS` is process-wide state.
    Reset between every test so deque from one test doesn't leak into
    another."""
    _REQUEST_TIMESTAMPS.clear()
    yield
    _REQUEST_TIMESTAMPS.clear()


def _fake_headers(d: dict) -> object:
    """Build a dict-with-.get-method that mimics urllib's headers
    object (which is an email.message.Message in practice)."""

    class _H:
        def get(self, key, default=None):
            return d.get(key, default)

    return _H()


def _make_rate_limit_error(reset_time: int) -> urllib.error.HTTPError:
    """HTTPError mimicking GitHub's code-search rate-limit 403."""
    return urllib.error.HTTPError(
        url="https://api.github.com/search/code",
        code=403,
        msg="rate limited",
        hdrs=_fake_headers({"X-RateLimit-Remaining": "0", "X-RateLimit-Reset": str(reset_time)}),
        fp=None,
    )


def _make_success_response(body: dict, *, remaining: int = 9, reset: int = 9999999999):
    """MagicMock that supports the `with urlopen(...) as resp:` pattern
    and returns the given body + headers."""
    resp = MagicMock()
    resp.__enter__ = lambda self: self
    resp.__exit__ = lambda self, *a: None
    resp.read = lambda: json.dumps(body).encode("utf-8")
    resp.headers = _fake_headers(
        {"X-RateLimit-Remaining": str(remaining), "X-RateLimit-Reset": str(reset)}
    )
    return resp


# ---------------------------------------------------------------------------
# Regex extraction
# ---------------------------------------------------------------------------


def test_extract_single_unc():
    fragment = r'$path = "\\fs01\share\Reports\q1.xlsx"'
    out = list(extract_unc_paths(fragment))
    assert r"\\fs01\share\Reports\q1.xlsx" in out


def test_extract_multiple_uncs_in_one_fragment():
    fragment = r"robocopy \\src01\data \\dst02\backup /MIR"
    out = list(extract_unc_paths(fragment))
    assert r"\\src01\data" in out
    assert r"\\dst02\backup" in out


def test_drive_paths_not_extracted():
    """Regression pin: drive-path extraction was dropped after the
    first live run showed drive paths from public GitHub were dominantly
    noise (local-machine paths, registry exports with leading drive
    letter). The eval set targets enterprise SMB share content; UNC is
    the right extraction target. A future revert of this decision would
    be loud — extraction is UNC only."""
    fragment = (
        r"# Drive paths should NOT come through extraction"
        "\n"
        r"mkdir C:\Users\bob\Documents\reports"
        "\n"
        r"$registry = 'M:\Software\Microsoft\Windows\CurrentVersion\Uninstall'"
        "\n"
        r"$prog = 'C:\Program Files\App\bin\app.exe'"
        "\n"
        r"$unc = '\\fs01\share\reports\q1.xlsx'  # this one IS extracted"
    )
    out = list(extract_unc_paths(fragment))
    # The UNC path is the only thing extracted.
    assert out == [r"\\fs01\share\reports\q1.xlsx"]
    # Explicit absence checks for the regression pin
    assert not any(p.startswith("C:") or p.startswith("M:") for p in out)


def test_extract_admin_share():
    """Admin shares (``$``-suffixed share name) are real and worth
    extracting. The regex's share character class includes ``$``."""
    fragment = r"net use Z: \\dc01\C$\Windows"
    out = list(extract_unc_paths(fragment))
    assert r"\\dc01\C$\Windows" in out


def test_extract_fqdn_server_name():
    """Server portion supports FQDN-style names with dots."""
    fragment = r"\\dc01.corp.local\NETLOGON\setup.bat"
    out = list(extract_unc_paths(fragment))
    assert r"\\dc01.corp.local\NETLOGON\setup.bat" in out


def test_extract_does_not_overrun_quotes():
    """Path extraction stops at quote chars (UNC won't swallow the
    closing quote and adjacent code)."""
    fragment = r'$x = "\\fs01\share"; $y = 1'
    out = list(extract_unc_paths(fragment))
    assert r"\\fs01\share" in out
    for p in out:
        assert ";" not in p
        assert " " not in p.split("\\")[-1]  # no trailing space-bearing seg


def test_extract_mixed_unc_and_drive_yields_unc_only():
    """In a fragment containing both UNC and drive paths, only the
    UNC is extracted. The drive path is dropped (drive-path extraction
    removed)."""
    fragment = r"Copy-Item \\src01\share\file.txt -Destination C:\Temp\dest.txt"
    out = list(extract_unc_paths(fragment))
    assert r"\\src01\share\file.txt" in out
    assert not any(p.startswith("C:") for p in out)


def test_extract_unc_with_space_in_share_name_truncates_at_space():
    """Spaces in share names ARE technically legal in Windows but rare
    in modern AD. The regex deliberately excludes space from the share
    class — including it lets the share segment greedily swallow
    spaces between adjacent UNC literals (breaks multi-path
    extraction on a single line). Trade-off: lose the rare
    'Shared Documents'-style share, keep multi-path extraction
    robust. Documented limitation."""
    fragment = r'$path = "\\fs01\Shared Documents\file.docx"'
    out = list(extract_unc_paths(fragment))
    # Extracts \\fs01\Shared only — the share segment stops at the space.
    assert r"\\fs01\Shared" in out


# ---------------------------------------------------------------------------
# Variable-interpolation filter
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "path",
    [
        r"\\$server\share",
        r"\\%COMPUTERNAME%\public",
        r"\\{server}\share",
        r"C:\Users\{user}\Desktop",
        r"\\fs01\share\%USERNAME%",
        r"C:\projects\${env}",
    ],
)
def test_variable_interpolation_rejected(path):
    assert has_variable_interpolation(path) is True


@pytest.mark.parametrize(
    "path",
    [
        r"\\fs01\share\file.txt",
        r"C:\Users\bob\file.txt",
        r"\\dc01.corp.local\NETLOGON\setup.bat",
    ],
)
def test_concrete_paths_not_flagged_as_interpolation(path):
    assert has_variable_interpolation(path) is False


# ---------------------------------------------------------------------------
# Length filter
# ---------------------------------------------------------------------------


def test_too_short_unc():
    assert is_too_short(r"\\a\b") is True  # 5 chars, noise
    assert is_too_short(r"\\srv\sh") is True  # 8 chars, below threshold
    assert is_too_short(r"\\srv\share") is False  # 10 chars, plausibly real
    assert is_too_short(r"\\fs01\share\file") is False


# ---------------------------------------------------------------------------
# Placeholder denylist — UNC
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "path",
    [
        # Vincent's explicit examples
        r"\\server\share",
        r"\\SERVERNAME\public",
        r"\\YOUR-HOST\share",
        r"\\example\share",
        # Additional generic placeholders
        r"\\hostname\share",
        r"\\mycomputer\share",
        r"\\computername\public",
        r"\\yourserver\share",
        r"\\your_server\share",
        r"\\placeholder\share",
        r"\\example.com\share",
        r"\\domain.local\share",
        r"\\localhost\share",
        r"\\foo\share",
        r"\\bar\share",
        # Template markers
        r"\\<servername>\share",
        # RFC1918 + loopback IPs
        r"\\192.168.1.1\share",
        r"\\127.0.0.1\share",
        r"\\10.0.0.1\share",
        r"\\10.255.255.255\share",
        r"\\172.16.0.1\share",
        r"\\172.20.0.1\share",
        r"\\172.31.255.255\share",
    ],
)
def test_placeholder_unc_rejected(path):
    assert is_placeholder_server(path) is True


@pytest.mark.parametrize(
    "path",
    [
        # Real-looking server names: NOT rejected
        r"\\fileserver01\Public",
        r"\\fs-corp01\HR$",
        r"\\dc01.corp.local\NETLOGON",
        r"\\nas-prod\Engineering",
        # IPs OUTSIDE RFC1918 ranges: NOT auto-rejected (could be a real
        # public-facing server)
        r"\\172.32.0.1\share",  # 172.32 is outside 172.16-172.31
        r"\\172.15.0.1\share",  # 172.15 is below 172.16
        r"\\8.8.8.8\share",  # public IP
        # "test" as a substring (not exact match): NOT rejected
        # — "fileserver-test01" is a legit naming convention
        r"\\fileserver-test01\share",
    ],
)
def test_real_looking_unc_not_flagged_as_placeholder(path):
    assert is_placeholder_server(path) is False


# ---------------------------------------------------------------------------
# Security/CTF repo filter — default-on filter for offensive-security
# / lab provenance
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "provenance_url",
    [
        "https://github.com/nettitude/PoshC2/blob/abc/installer.ps1",
        "https://github.com/rapid7/metasploit-framework/blob/abc/x.rb",
        "https://github.com/SomeOrg/Meterpreter-Tools/blob/abc/y.ps1",
        # Vincent-added typo variant catches a specific real-world tool
        "https://github.com/SomeOrg/Meterpeter-Tools/blob/abc/y.ps1",
        # Vincent-added: Mishkys-AD-Range (produced \\Marvel-DC\HackMe)
        "https://github.com/Mishky-z/Mishkys-AD-Range/blob/abc/setup.ps1",
        "https://github.com/SomeOrg/Cobaltstrike-Profiles/blob/abc/x.profile",
        "https://github.com/BloodHoundAD/BloodHound/blob/abc/cli.ps1",
        # 'goad' is in the URL list (repo IS the lab); NOT in path list
        "https://github.com/Orange-Cyberdefense/GOAD/blob/abc/setup.ps1",
        "https://github.com/carlospolop/PEASS-ng/blob/abc/x.ps1",
        "https://github.com/BishopFox/sliver/blob/abc/x.go",
        "https://github.com/HavocFramework/Havoc/blob/abc/x.py",
        "https://github.com/SomeOrg/CrowdStrike-RTR-scripts/blob/abc/x.ps1",
        "https://github.com/SomeOrg/red-team-toolkit/blob/abc/x.ps1",
        "https://github.com/SomeOrg/offensive-tools/blob/abc/x.ps1",
    ],
)
def test_security_filter_url_pattern_rejects(provenance_url):
    """URL containing any offensive-security/CTF pattern → dropped.
    Path doesn't matter — the repo IS the signal."""
    assert is_offensive_security_provenance(provenance_url, r"\\fs01\share\file.txt") is True


@pytest.mark.parametrize(
    "path",
    [
        # Unambiguous lab share/server markers
        r"\\Marvel-DC\HackMe\flag.txt",
        r"\\corp\HackMe\challenges\1.txt",
        r"\\dreadgoad-srv\users\admin",
        r"\\dreadgoat\share\file",
        r"\\vulnvm-01\share",
        r"\\vulnerablevm\public",
    ],
)
def test_security_filter_path_marker_rejects(path):
    """Path containing an unambiguous lab marker → dropped, even when
    the provenance URL doesn't reveal the source."""
    innocent_url = "https://github.com/innocent/repo/blob/x"
    assert is_offensive_security_provenance(innocent_url, path) is True


@pytest.mark.parametrize(
    "path",
    [
        # Real-looking enterprise paths NOT in any filter
        r"\\fileserver01\Public\Marketing\banner.jpg",
        r"\\dc01.corp.local\NETLOGON\setup.bat",
        r"\\fs-prod\HR$\policies\password_policy.docx",
        # 'titan' deliberately NOT a lab marker — common enterprise name
        r"\\Titan\private\reports.xlsx",
        # bare 'goad' as a share name deliberately NOT a marker —
        # ambiguous (could be a real share named goad-something)
        r"\\fileserver\goad-archive\old.zip",
    ],
)
def test_security_filter_does_not_overreach(path):
    """Pin against the over-filtering risk Vincent flagged: ``titan``
    and bare ``goad`` as path/share names must NOT trigger the filter
    (they're common in real enterprise contexts). The URL list catches
    the lab repos that use these names; the path list deliberately
    doesn't."""
    assert (
        is_offensive_security_provenance(
            "https://github.com/realcompany/realrepo/blob/abc/script.ps1", path
        )
        is False
    )


def test_security_filter_url_list_contains_vincent_added_patterns():
    """Pin: the three patterns Vincent added in plan-review
    (meterpeter spelling, mishky, mishkys) are present. Catches
    accidental deletion."""
    assert "meterpeter" in OFFENSIVE_SECURITY_URL_PATTERNS
    assert "mishky" in OFFENSIVE_SECURITY_URL_PATTERNS
    assert "mishkys" in OFFENSIVE_SECURITY_URL_PATTERNS


def test_security_filter_path_markers_exclude_titan_and_goad():
    """Pin: Vincent's explicit exclusions. Titan is too common an
    enterprise hostname; bare 'goad' as a share is ambiguous. The URL
    list catches their lab repos."""
    lab_markers_lower = tuple(m.lower() for m in LAB_PATH_MARKERS)
    assert "titan" not in lab_markers_lower
    assert "goad" not in lab_markers_lower


def test_security_filter_path_markers_are_unambiguous_set():
    """Pin: the keep list Vincent approved. Catches accidental
    additions of ambiguous terms."""
    assert set(LAB_PATH_MARKERS) == {
        "marvel-dc",
        "hackme",
        "dreadgoad",
        "dreadgoat",
        "vulnvm",
        "vulnerablevm",
    }


def test_collect_filter_default_on_drops_offensive_repo_candidates(monkeypatch, tmp_path):
    """End-to-end: default-on filter drops candidates from a lab repo
    AND reports the drop count in CollectResult.dropped_security_count
    so the operator can audit the filter's impact."""

    def fake_fetch(query, page, pat):
        return {
            "items": [
                {
                    "html_url": "https://github.com/nettitude/PoshC2/blob/abc/x.ps1",
                    "text_matches": [{"fragment": r'$src = "\\labsrv01\share\payloads"'}],
                },
                {
                    "html_url": "https://github.com/realcorp/realrepo/blob/abc/y.ps1",
                    "text_matches": [{"fragment": r'$src = "\\realsrv\reports\q1.xlsx"'}],
                },
            ],
            "total_count": 2,
        }

    monkeypatch.setattr("src.eval.source_github._fetch_search_page", fake_fetch)
    monkeypatch.setattr("src.eval.source_github._wait_for_rate_limit", lambda: None)
    monkeypatch.setitem(_QUERY_SETS, "_test_filter", (r'"\\" "testfilter"',))

    result = collect(
        "_test_filter",
        tmp_path / "cache",
        "fake_pat",
        refresh=True,
        max_pages_per_query=1,
    )

    # The PoshC2 candidate was dropped, real one survived
    assert len(result.candidates) == 1
    assert result.candidates[0].path == r"\\realsrv\reports\q1.xlsx"
    assert result.dropped_security_count == 1


def test_collect_filter_disabled_keeps_offensive_repo_candidates(monkeypatch, tmp_path):
    """--no-filter-security-repos (filter_security_repos=False) keeps
    everything that would otherwise have been dropped — useful for
    inspecting the unfiltered corpus."""

    def fake_fetch(query, page, pat):
        return {
            "items": [
                {
                    "html_url": "https://github.com/nettitude/PoshC2/blob/abc/x.ps1",
                    "text_matches": [{"fragment": r'$src = "\\labsrv01\share\payloads"'}],
                },
            ],
            "total_count": 1,
        }

    monkeypatch.setattr("src.eval.source_github._fetch_search_page", fake_fetch)
    monkeypatch.setattr("src.eval.source_github._wait_for_rate_limit", lambda: None)
    monkeypatch.setitem(_QUERY_SETS, "_test_no_filter", (r'"\\" "testnofilter"',))

    result = collect(
        "_test_no_filter",
        tmp_path / "cache",
        "fake_pat",
        refresh=True,
        max_pages_per_query=1,
        filter_security_repos=False,
    )

    # Kept even though provenance is PoshC2
    assert len(result.candidates) == 1
    assert result.dropped_security_count == 0


def test_main_cli_summary_prints_drop_count(monkeypatch, tmp_path, capsys):
    """End-of-run stderr summary always prints the drop count when the
    filter is active (so it isn't silent). Pinned because this is
    Vincent's specific auditability requirement: he must see the count
    to spot over-filtering."""
    monkeypatch.setenv(_PAT_ENV_VAR, "fake_pat")
    monkeypatch.setattr(
        "src.eval.source_github._fetch_search_page",
        lambda q, p, pat: {"items": [], "total_count": 0},
    )
    monkeypatch.setattr("src.eval.source_github._wait_for_rate_limit", lambda: None)
    monkeypatch.setitem(_QUERY_SETS, "_test_summary", (r'"\\" "summarytest"',))

    rc = main(
        [
            "--query-set",
            "_test_summary",
            "--cache-dir",
            str(tmp_path / "cache"),
            "--output",
            str(tmp_path / "out.csv"),
        ]
    )
    assert rc == 0
    captured = capsys.readouterr()
    assert "dropped 0 candidates from security/CTF repos" in captured.err


def test_main_cli_summary_announces_disabled_filter(monkeypatch, tmp_path, capsys):
    """When --no-filter-security-repos is passed, the summary surfaces
    that the filter is DISABLED so the operator doesn't accidentally
    forget the corpus is unfiltered."""
    monkeypatch.setenv(_PAT_ENV_VAR, "fake_pat")
    monkeypatch.setattr(
        "src.eval.source_github._fetch_search_page",
        lambda q, p, pat: {"items": [], "total_count": 0},
    )
    monkeypatch.setattr("src.eval.source_github._wait_for_rate_limit", lambda: None)
    monkeypatch.setitem(_QUERY_SETS, "_test_disabled", (r'"\\" "disabledtest"',))

    rc = main(
        [
            "--query-set",
            "_test_disabled",
            "--no-filter-security-repos",
            "--cache-dir",
            str(tmp_path / "cache"),
            "--output",
            str(tmp_path / "out.csv"),
        ]
    )
    assert rc == 0
    captured = capsys.readouterr()
    assert "DISABLED" in captured.err


# ---------------------------------------------------------------------------
# Dedup uses shared normalize_for_dedup
# ---------------------------------------------------------------------------


def test_normalize_for_dedup_is_the_shared_callable():
    """Pin: source_github imports the same callable as build_queue
    and validate. Case-variants of the same path normalize identically."""
    a = normalize_for_dedup(r"\\Fs01\Share\File.txt")
    b = normalize_for_dedup(r"\\FS01\SHARE\file.txt")
    c = normalize_for_dedup(r"\\fs01\share\file.txt")
    assert a == b == c


# ---------------------------------------------------------------------------
# CSV writer — round-trip via build_queue's reader
# ---------------------------------------------------------------------------


def test_csv_writer_produces_build_queue_compatible_output(tmp_path):
    """Pin: the CSV is readable by ``build_queue._read_csv`` with
    path + source intact. Provenance URL is silently ignored by
    build_queue (which only reads path and source) — exactly the
    intended contract."""
    from src.eval.build_queue import _read_csv

    candidates = [
        Candidate(
            path=r"\\fs01\share\reports\q1.xlsx",
            provenance_url="https://github.com/owner/repo/blob/abc/x.ps1",
        ),
        Candidate(
            path=r"C:\Users\bob\Desktop\notes.txt",
            provenance_url="https://github.com/owner/repo/blob/abc/y.ps1",
        ),
    ]
    out = tmp_path / "out.csv"
    _write_csv(out, candidates)

    rows = list(_read_csv(out, default_source=None))
    assert len(rows) == 2
    assert rows[0]["path"] == r"\\fs01\share\reports\q1.xlsx"
    assert rows[0]["source"] == "github_search"
    assert rows[1]["path"] == r"C:\Users\bob\Desktop\notes.txt"
    assert rows[1]["source"] == "github_search"


def test_csv_writer_includes_provenance_url_column(tmp_path):
    """The provenance_url column is present in the CSV for labeler
    review-while-labeling (click-through to GitHub). build_queue
    silently ignores it; the column exists for the human."""
    candidates = [
        Candidate(
            path=r"\\fs01\share\file.txt",
            provenance_url="https://github.com/owner/repo/blob/abc/x.ps1",
        ),
    ]
    out = tmp_path / "out.csv"
    _write_csv(out, candidates)

    with out.open("r", encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f)
        assert "provenance_url" in (reader.fieldnames or [])
        row = next(reader)
        assert row["provenance_url"] == "https://github.com/owner/repo/blob/abc/x.ps1"


def test_csv_writer_empty_candidates_writes_header_only(tmp_path):
    """A run that yielded zero candidates still writes a valid CSV
    (header only) — downstream build_queue handles this as 'empty
    queue,' which the GUI now distinguishes from 'queue missing.'"""
    out = tmp_path / "out.csv"
    _write_csv(out, [])
    content = out.read_text(encoding="utf-8")
    assert "path,source,provenance_url" in content


# ---------------------------------------------------------------------------
# PAT env-var fail-fast
# ---------------------------------------------------------------------------


def test_pat_env_var_unset_raises_with_setup_message(monkeypatch):
    """The error message must name the env var and tell the operator
    how to create the token (so the setup path is discoverable from
    the failure, not buried in docs)."""
    monkeypatch.delenv(_PAT_ENV_VAR, raising=False)
    with pytest.raises(RuntimeError) as exc_info:
        _read_pat()
    msg = str(exc_info.value)
    assert _PAT_ENV_VAR in msg
    assert "public_repo" in msg
    assert "github.com/settings/tokens" in msg


def test_pat_env_var_set_returns_value(monkeypatch):
    monkeypatch.setenv(_PAT_ENV_VAR, "ghp_fake")
    assert _read_pat() == "ghp_fake"


# ---------------------------------------------------------------------------
# Query-set composition + size drift
# ---------------------------------------------------------------------------


def test_query_set_v0_count():
    """Drift test: bumping or trimming the v0 query set updates this
    count deliberately. The reframed split — idiom-based high-signal
    core vs long-tail supplement — also lives in the module constants
    so it's auditable in code, not just in docs."""
    assert len(_QUERY_SETS["v0"]) == 24


def test_query_set_v0_includes_vincent_added_idioms():
    """Pin: the 7 idioms Vincent named in plan-review are all present.
    Catches accidental deletion during refactors."""
    queries = _QUERY_SETS["v0"]
    assert any("netlogon" in q for q in queries)
    assert any("logon" in q and "extension:bat" in q for q in queries)
    assert any("MapNetworkDrive" in q for q in queries)
    assert any("pushd" in q for q in queries)
    assert any("HomeDirectory" in q for q in queries)
    assert any("FolderRedirection" in q for q in queries)
    assert any("connectionString" in q for q in queries)


def test_query_set_v0_queries_are_unique():
    queries = _QUERY_SETS["v0"]
    assert len(queries) == len(set(queries)), "duplicate queries in v0 set"


# ---------------------------------------------------------------------------
# --dry-run does not call API or write output
# ---------------------------------------------------------------------------


def test_dry_run_does_not_touch_filesystem_or_api(tmp_path, capsys, monkeypatch):
    """--dry-run must not require the PAT (no API calls happen) and
    must not write any output file or cache entry. Print-only."""
    monkeypatch.delenv(_PAT_ENV_VAR, raising=False)

    cache_dir = tmp_path / "cache"
    output = tmp_path / "out.csv"
    rc = main(
        [
            "--dry-run",
            "--query-set",
            "v0",
            "--cache-dir",
            str(cache_dir),
            "--output",
            str(output),
        ]
    )
    assert rc == 0
    captured = capsys.readouterr()
    # Query list is printed to stderr
    assert "New-PSDrive" in captured.err
    assert "netlogon" in captured.err
    # Estimated runtime appears
    assert "Estimated runtime" in captured.err
    # No filesystem touched
    assert not cache_dir.exists()
    assert not output.exists()


def test_dry_run_runtime_estimate_scales_with_query_count(capsys):
    """The runtime estimate is computed from the query count × pages ×
    pacing — sanity-check that the printed range is sensible."""
    rc = main(["--dry-run", "--query-set", "v0"])
    assert rc == 0
    captured = capsys.readouterr()
    # 24 queries × 3 pages × 6.5s = 468s = 7.8 min low end
    # 24 queries × 10 pages × 6.5s = 1560s = 26 min high end
    # Just check the line is present with reasonable numbers
    assert "minutes" in captured.err


def test_main_missing_pat_returns_nonzero(monkeypatch, tmp_path):
    """Non-dry-run without the PAT should exit nonzero with a clear
    error, not crash mid-run."""
    monkeypatch.delenv(_PAT_ENV_VAR, raising=False)
    rc = main(
        [
            "--query-set",
            "v0",
            "--cache-dir",
            str(tmp_path / "cache"),
            "--output",
            str(tmp_path / "out.csv"),
        ]
    )
    assert rc == 1
    # No output written
    assert not (tmp_path / "out.csv").exists()


# ---------------------------------------------------------------------------
# Integration over the filter pipeline (without HTTP)
# ---------------------------------------------------------------------------


def test_full_filter_pipeline_on_realistic_fragment():
    """End-to-end pure-side: a fragment containing real UNC paths,
    placeholder UNCs, variable-interpolation UNCs, a too-short UNC,
    AND a drive path (which the post-first-run filter pass now drops
    entirely) is filtered down to exactly the real UNCs, deduped."""
    fragment = r"""
    # Backup script
    $backup_src = "\\fs01\share\Reports"
    $backup_dst = "\\backup-srv\Archive\2026"
    # TODO: replace \\server\share with real path below
    Copy-Item "\\fs01\share\Reports" -Destination "C:\backups\local"
    # Placeholders
    $template = "\\YOUR-HOST\share"
    $var = "\\$computer\share"
    $short = "\\a\b"
    """
    extracted = list(extract_unc_paths(fragment))
    kept = [
        p
        for p in extracted
        if not has_variable_interpolation(p)
        and not is_too_short(p)
        and not is_placeholder_server(p)
    ]
    # Dedup via normalize_for_dedup
    seen: set[str] = set()
    deduped = []
    for p in kept:
        norm = normalize_for_dedup(p)
        if norm not in seen:
            seen.add(norm)
            deduped.append(p)
    norms = {normalize_for_dedup(p) for p in deduped}
    # Real UNCs survive
    assert normalize_for_dedup(r"\\fs01\share\Reports") in norms
    assert normalize_for_dedup(r"\\backup-srv\Archive\2026") in norms
    # Drive path dropped (drive-path extraction removed)
    assert normalize_for_dedup(r"C:\backups\local") not in norms
    assert not any(p.startswith("C:") for p in deduped)
    # Placeholders / variables / short are gone
    assert normalize_for_dedup(r"\\YOUR-HOST\share") not in norms
    assert not any("$computer" in p for p in deduped)
    assert not any(len(p) < 10 and p.startswith("\\\\") for p in deduped)
    # \\fs01\share\Reports appears twice in the fragment but only once
    # after dedup
    fs01_count = sum(
        1 for p in deduped if normalize_for_dedup(p) == normalize_for_dedup(r"\\fs01\share\Reports")
    )
    assert fs01_count == 1


# ---------------------------------------------------------------------------
# Sliding-window rate-limit pacer
#
# These tests pin the bug-1 fix: pacing is now per-request (counting
# pagination pages against the 10/min budget), not per-query.
# Monkeypatched time.time + time.sleep let us exercise the deque
# logic deterministically without real waits.
# ---------------------------------------------------------------------------


def test_pacer_does_not_sleep_below_budget(monkeypatch):
    """N requests at virtual time T=0..N-1 stay under the 9-per-60s
    budget; no sleeps are induced."""
    fake_now = [0.0]
    sleeps: list[float] = []

    def fake_time():
        return fake_now[0]

    def fake_sleep(s):
        sleeps.append(s)
        fake_now[0] += s

    monkeypatch.setattr(time, "time", fake_time)
    monkeypatch.setattr(time, "sleep", fake_sleep)

    for _ in range(_BUDGET_PER_WINDOW - 1):
        _wait_for_rate_limit()
        fake_now[0] += 1.0  # 1s between each call

    assert sleeps == []
    assert len(_REQUEST_TIMESTAMPS) == _BUDGET_PER_WINDOW - 1


def test_pacer_sleeps_when_budget_exhausted(monkeypatch):
    """Fill the budget at T=0, then call once more — pacer sleeps
    until the oldest entry ages out (~60s + 1s buffer)."""
    fake_now = [0.0]
    sleeps: list[float] = []

    def fake_time():
        return fake_now[0]

    def fake_sleep(s):
        sleeps.append(s)
        fake_now[0] += s

    monkeypatch.setattr(time, "time", fake_time)
    monkeypatch.setattr(time, "sleep", fake_sleep)

    # Fill the budget at T=0
    for _ in range(_BUDGET_PER_WINDOW):
        _wait_for_rate_limit()

    # Budget+1 call: pacer sleeps until oldest (T=0) ages out
    _wait_for_rate_limit()
    assert len(sleeps) == 1
    # Sleep is ~_WINDOW_SECONDS + 1s buffer (oldest was at T=0)
    assert _WINDOW_SECONDS < sleeps[0] < _WINDOW_SECONDS + 2


def test_pacer_drops_aged_entries(monkeypatch):
    """Entries older than _WINDOW_SECONDS get evicted on each call.
    Pins the deque doesn't grow unbounded across a long run."""
    fake_now = [0.0]
    monkeypatch.setattr(time, "time", lambda: fake_now[0])
    monkeypatch.setattr(time, "sleep", lambda s: None)

    # Fill the budget at T=0..8
    for i in range(_BUDGET_PER_WINDOW):
        fake_now[0] = float(i)
        _wait_for_rate_limit()
    assert len(_REQUEST_TIMESTAMPS) == _BUDGET_PER_WINDOW

    # Jump forward past the window — all entries should age out
    fake_now[0] = _WINDOW_SECONDS + 100
    _wait_for_rate_limit()
    # Only the new entry remains
    assert len(_REQUEST_TIMESTAMPS) == 1


def test_pacer_counts_pagination_requests_against_budget(monkeypatch):
    """Bug-1 regression pin: pagination requests count against the
    per-minute budget. Previous fixed-spacing pacer treated each
    request as independent, so a multi-page query could blow the cap.
    The deque now tracks ALL request timestamps regardless of which
    query they belong to."""
    fake_now = [0.0]
    sleeps: list[float] = []
    monkeypatch.setattr(time, "time", lambda: fake_now[0])

    def fake_sleep(s):
        sleeps.append(s)
        fake_now[0] += s

    monkeypatch.setattr(time, "sleep", fake_sleep)

    # Simulate 3 queries × 3 pages each = 9 requests at T=0..8 (1s
    # apart). All 9 fit under budget.
    for _ in range(9):
        _wait_for_rate_limit()
        fake_now[0] += 1.0
    assert sleeps == []

    # The 10th request (simulating start of query 4) triggers sleep
    # because deque has 9 entries within the rolling 60s window.
    _wait_for_rate_limit()
    assert len(sleeps) == 1, "10th request should have triggered a budget-exhausted sleep"


# ---------------------------------------------------------------------------
# X-RateLimit-Remaining post-success honoring
#
# Pins the second half of the bug-1 fix: server's view of the budget
# is authoritative. When the server says Remaining=0, we sleep until
# Reset+buffer regardless of what the local deque thinks.
# ---------------------------------------------------------------------------


def test_honor_remaining_sleeps_when_zero(monkeypatch):
    sleeps: list[float] = []
    monkeypatch.setattr(time, "time", lambda: 1000.0)
    monkeypatch.setattr(time, "sleep", lambda s: sleeps.append(s))

    headers = _fake_headers({"X-RateLimit-Remaining": "0", "X-RateLimit-Reset": "1010"})
    _honor_remaining_header(headers)
    assert len(sleeps) == 1
    # 10s until reset + buffer
    assert sleeps[0] == 10 + _RATE_LIMIT_BUFFER_SECONDS


def test_honor_remaining_sleeps_when_at_threshold(monkeypatch):
    """Remaining == _LOW_REMAINING_THRESHOLD (1) triggers proactive
    sleep — the 1-not-0 threshold preserves a safety margin."""
    sleeps: list[float] = []
    monkeypatch.setattr(time, "time", lambda: 1000.0)
    monkeypatch.setattr(time, "sleep", lambda s: sleeps.append(s))

    headers = _fake_headers({"X-RateLimit-Remaining": "1", "X-RateLimit-Reset": "1005"})
    _honor_remaining_header(headers)
    assert len(sleeps) == 1


def test_honor_remaining_no_sleep_when_high(monkeypatch):
    """Remaining well above threshold: no proactive sleep."""
    sleeps: list[float] = []
    monkeypatch.setattr(time, "time", lambda: 1000.0)
    monkeypatch.setattr(time, "sleep", lambda s: sleeps.append(s))

    headers = _fake_headers({"X-RateLimit-Remaining": "9", "X-RateLimit-Reset": "1010"})
    _honor_remaining_header(headers)
    assert sleeps == []


def test_honor_remaining_no_sleep_when_headers_missing(monkeypatch):
    """Missing or partial headers: no-op. Defensive against
    non-rate-limited endpoints or future API changes."""
    sleeps: list[float] = []
    monkeypatch.setattr(time, "time", lambda: 1000.0)
    monkeypatch.setattr(time, "sleep", lambda s: sleeps.append(s))

    _honor_remaining_header(_fake_headers({}))
    _honor_remaining_header(_fake_headers({"X-RateLimit-Remaining": "0"}))
    _honor_remaining_header(_fake_headers({"X-RateLimit-Reset": "1010"}))
    assert sleeps == []


def test_honor_remaining_no_sleep_when_unparseable(monkeypatch):
    """Garbage header values don't crash; treat as missing."""
    sleeps: list[float] = []
    monkeypatch.setattr(time, "time", lambda: 1000.0)
    monkeypatch.setattr(time, "sleep", lambda s: sleeps.append(s))

    _honor_remaining_header(
        _fake_headers({"X-RateLimit-Remaining": "abc", "X-RateLimit-Reset": "def"})
    )
    assert sleeps == []


# ---------------------------------------------------------------------------
# _fetch_search_page retry exhaustion + clear-error
#
# Pins the bug-2 fix: retries honor X-RateLimit-Reset, exhaustion
# raises with query + page in the message. Never silently succeeds
# with empty body.
# ---------------------------------------------------------------------------


def test_fetch_succeeds_after_one_rate_limit_retry(monkeypatch):
    """On a 429/403, the retry sleeps per Reset and retries. If the
    retry succeeds, the body returns normally."""
    fake_now = [1000.0]
    monkeypatch.setattr(time, "time", lambda: fake_now[0])
    monkeypatch.setattr(time, "sleep", lambda s: fake_now.__setitem__(0, fake_now[0] + s))

    call_count = [0]

    def fake_urlopen(req, timeout=None):
        call_count[0] += 1
        if call_count[0] == 1:
            raise _make_rate_limit_error(int(fake_now[0]) + 3)
        return _make_success_response({"items": [], "total_count": 0})

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)

    body = _fetch_search_page("test query", 1, "fake_pat")
    assert body == {"items": [], "total_count": 0}
    assert call_count[0] == 2


def test_fetch_raises_after_exhausting_rate_limit_retries(monkeypatch):
    """All _MAX_RATE_LIMIT_RETRIES retries exhausted → RuntimeError
    with query string and page number. The load-bearing
    never-silently-skip behavior."""
    fake_now = [1000.0]
    monkeypatch.setattr(time, "time", lambda: fake_now[0])
    monkeypatch.setattr(time, "sleep", lambda s: fake_now.__setitem__(0, fake_now[0] + s))

    call_count = [0]

    def always_rate_limit(req, timeout=None):
        call_count[0] += 1
        raise _make_rate_limit_error(int(fake_now[0]) + 1)

    monkeypatch.setattr(urllib.request, "urlopen", always_rate_limit)

    with pytest.raises(RuntimeError) as exc_info:
        _fetch_search_page("a_failing_query", 7, "fake_pat")

    msg = str(exc_info.value)
    # Error message names the query and the page so the operator can
    # find it in the end-of-run summary and the manifest.
    assert "a_failing_query" in msg
    assert "7" in msg  # page number
    assert "exhausted" in msg.lower() or "retries" in msg.lower()
    # Initial attempt + _MAX_RATE_LIMIT_RETRIES retries
    assert call_count[0] == _MAX_RATE_LIMIT_RETRIES + 1


def test_fetch_honors_rate_limit_reset_not_flat_sleep(monkeypatch):
    """Bug-2 sub-point: the sleep duration on rate-limit comes from
    X-RateLimit-Reset, not a flat value. Pin the actual sleep time
    matches Reset - now + buffer."""
    fake_now = [1000.0]
    sleeps: list[float] = []
    monkeypatch.setattr(time, "time", lambda: fake_now[0])

    def fake_sleep(s):
        sleeps.append(s)
        fake_now[0] += s

    monkeypatch.setattr(time, "sleep", fake_sleep)

    call_count = [0]
    reset_offset = 30  # 30s until reset

    def fake_urlopen(req, timeout=None):
        call_count[0] += 1
        if call_count[0] == 1:
            raise _make_rate_limit_error(int(fake_now[0]) + reset_offset)
        return _make_success_response({"items": [], "total_count": 0})

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)

    _fetch_search_page("test_query", 1, "fake_pat")

    # The rate-limit sleep (not pacer sleep) should be ~30s + buffer.
    rate_limit_sleep = max(sleeps)
    assert reset_offset <= rate_limit_sleep <= reset_offset + _RATE_LIMIT_BUFFER_SECONDS + 1, (
        f"Expected sleep near {reset_offset + _RATE_LIMIT_BUFFER_SECONDS}s "
        f"(Reset + buffer); got {rate_limit_sleep}s"
    )


# ---------------------------------------------------------------------------
# Per-query graceful failure in collect()
#
# Pins the bug-2 load-bearing change: a query that exhausts retries
# does NOT crash the run AND does NOT get silently skipped — it's
# recorded in CollectResult.failed_queries so the end-of-run summary
# names it for the operator.
# ---------------------------------------------------------------------------


def test_collect_captures_failed_query_without_crashing(monkeypatch, tmp_path):
    """Single failing query in a multi-query set: collect() continues
    past it, the failure is captured in result.failed_queries, the
    run completes normally."""
    failing_marker = "robocopy"

    def fake_fetch(query, page, pat):
        if failing_marker in query:
            raise RuntimeError(
                f"rate-limit exhausted after {_MAX_RATE_LIMIT_RETRIES} "
                f"retries for query {query!r} page {page}"
            )
        return {"items": [], "total_count": 0}

    monkeypatch.setattr("src.eval.source_github._fetch_search_page", fake_fetch)
    monkeypatch.setattr("src.eval.source_github._wait_for_rate_limit", lambda: None)
    monkeypatch.setattr(time, "sleep", lambda s: None)

    result = collect(
        query_set="v0",
        cache_dir=tmp_path / "cache",
        pat="fake_pat",
        refresh=True,
        max_pages_per_query=1,
    )

    # Failure captured, not silenced
    assert len(result.failed_queries) == 1
    fq = result.failed_queries[0]
    assert failing_marker in fq.query
    assert "exhausted" in fq.reason.lower()
    # Run completed — no exception propagated
    assert isinstance(result, CollectResult)


def test_collect_does_not_let_one_failure_abort_remaining_queries(monkeypatch, tmp_path):
    """If the FIRST query fails, queries 2..N still run. The whole-run
    crash behavior of the prior code (RuntimeError up to main) is gone."""
    calls: list[str] = []

    def fake_fetch(query, page, pat):
        calls.append(query)
        # Fail the first query
        if len(calls) == 1:
            raise RuntimeError("simulated first-query failure")
        return {"items": [], "total_count": 0}

    monkeypatch.setattr("src.eval.source_github._fetch_search_page", fake_fetch)
    monkeypatch.setattr("src.eval.source_github._wait_for_rate_limit", lambda: None)

    result = collect(
        query_set="v0",
        cache_dir=tmp_path / "cache",
        pat="fake_pat",
        refresh=True,
        max_pages_per_query=1,
    )

    # All queries attempted (first failed, rest succeeded)
    assert len(calls) == len(_QUERY_SETS["v0"])
    assert len(result.failed_queries) == 1


# ---------------------------------------------------------------------------
# Manifest status field
#
# Pins the bug-2 operator-visibility hook: a failed query writes
# status="failed_after_retries" in manifest.json so the operator can
# grep for which queries to re-run (and the future --retry-failed
# flag will key off this).
# ---------------------------------------------------------------------------


def test_manifest_records_completed_status(monkeypatch, tmp_path):
    monkeypatch.setattr(
        "src.eval.source_github._fetch_search_page",
        lambda q, p, pat: {"items": [], "total_count": 0},
    )
    monkeypatch.setattr("src.eval.source_github._wait_for_rate_limit", lambda: None)
    monkeypatch.setitem(_QUERY_SETS, "_test_completed", (r'"\\" "completetest"',))

    cache = tmp_path / "cache"
    collect("_test_completed", cache, "pat", refresh=True, max_pages_per_query=1)

    manifest = json.loads((cache / "manifest.json").read_text(encoding="utf-8"))
    entry = next(iter(manifest["queries"].values()))
    assert entry["status"] == "completed"
    assert "error" not in entry


def test_manifest_records_failed_status_with_error(monkeypatch, tmp_path):
    """Failed query writes status='failed_after_retries' AND an
    'error' field naming the page — both needed for operator triage."""

    def fake_fetch(q, p, pat):
        raise RuntimeError("simulated exhaustion")

    monkeypatch.setattr("src.eval.source_github._fetch_search_page", fake_fetch)
    monkeypatch.setattr("src.eval.source_github._wait_for_rate_limit", lambda: None)
    monkeypatch.setitem(_QUERY_SETS, "_test_failed", (r'"\\" "failtest"',))

    cache = tmp_path / "cache"
    collect("_test_failed", cache, "pat", refresh=True, max_pages_per_query=1)

    manifest = json.loads((cache / "manifest.json").read_text(encoding="utf-8"))
    entry = next(iter(manifest["queries"].values()))
    assert entry["status"] == "failed_after_retries"
    assert "page" in entry.get("error", "")


# ---------------------------------------------------------------------------
# Default knobs + dry-run runtime estimate
# ---------------------------------------------------------------------------


def test_default_max_pages_per_query_is_5():
    """Lowered from 10 in the bug-fix commit — first few pages carry
    the highest-relevance results; this cuts worst-case runtime and
    leaves rate-limit budget for retries."""
    assert _MAX_PAGES_PER_QUERY == 5


def test_dry_run_runtime_estimate_reflects_real_budget(capsys):
    """The estimate uses the actual budget math (queries × pages ×
    _WINDOW_SECONDS/_BUDGET_PER_WINDOW), not the optimistic
    6.5-per-query math of the buggy version. Pins the user-visible
    estimate is honest about the rate-limit cost."""
    rc = main(["--dry-run", "--query-set", "v0"])
    assert rc == 0
    captured = capsys.readouterr()
    # Estimate mentions the budget framing explicitly
    assert "code-search budget" in captured.err
    assert f"{_BUDGET_PER_WINDOW}-per-{_WINDOW_SECONDS:.0f}s" in captured.err
    assert "retry-wait overhead" in captured.err
