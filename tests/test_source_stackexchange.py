"""Tests for the Stack Exchange data-dump candidate-paths scraper.

Pure-function pinning + end-to-end fixture coverage. No real-XML files —
synthetic Posts.xml fragments built per-test to exercise the streaming
parse + filter pipeline.
"""

from __future__ import annotations

import csv
from pathlib import Path

import pytest

from src.eval.categories import SOURCES
from src.eval.source_stackexchange import (
    Candidate,
    CollectResult,
    _body_might_contain_unc,
    _write_csv,
    build_provenance_url,
    collect,
    extract_candidates_from_row,
    main,
)

# ---------------------------------------------------------------------------
# SOURCES drift
# ---------------------------------------------------------------------------


def test_stackexchange_in_sources_enum():
    """The new source identifier must be in the SOURCES tuple so
    EvalRecord/QueueRecord schemas accept it. Pinned here so a future
    rename or removal is loud."""
    assert "stackexchange" in SOURCES


# ---------------------------------------------------------------------------
# Provenance URL construction
# ---------------------------------------------------------------------------


def test_question_url_uses_q_prefix():
    """PostTypeId=1 is a question; URL uses /q/ prefix."""
    assert build_provenance_url("serverfault.com", "1", "12345") == (
        "https://serverfault.com/q/12345"
    )


def test_answer_url_uses_a_prefix():
    """PostTypeId=2 is an answer; URL uses /a/ which redirects to the
    parent question with the answer anchor."""
    assert build_provenance_url("serverfault.com", "2", "67890") == (
        "https://serverfault.com/a/67890"
    )


def test_unknown_post_type_falls_back_to_posts_prefix():
    """Stack Exchange has additional PostTypeIds (3=orphaned-tag-wiki,
    4=tag-wiki-excerpt, 5=tag-wiki). For anything other than 1/2 we
    use /posts/ which is the site-internal redirect endpoint."""
    assert build_provenance_url("serverfault.com", "5", "111") == (
        "https://serverfault.com/posts/111"
    )


def test_different_site_changes_url_host():
    """Site host is parametric so the same module works for
    stackoverflow, superuser, etc."""
    assert build_provenance_url("stackoverflow.com", "1", "42") == (
        "https://stackoverflow.com/q/42"
    )


# ---------------------------------------------------------------------------
# Body-substring pre-filter
# ---------------------------------------------------------------------------


def test_body_without_backslash_skipped_by_prefilter():
    """The pre-filter is the cheap O(n) check that runs before HTML
    unescape + regex. Bodies without literal ``\\\\`` can't yield a
    UNC and must be skipped."""
    assert _body_might_contain_unc("<p>This is a regular sysadmin question.</p>") is False


def test_body_with_backslash_passes_prefilter():
    assert _body_might_contain_unc(r"<code>\\fileserver\share</code>") is True


def test_body_with_single_backslash_skipped():
    """Single backslash is not a UNC prefix; pre-filter rejects."""
    assert _body_might_contain_unc(r"path = '\fileserver'") is False


# ---------------------------------------------------------------------------
# extract_candidates_from_row — filter pipeline integration
# ---------------------------------------------------------------------------


def test_extract_yields_clean_unc():
    body = r"<p>We map <code>\\fs01\share\reports</code> on logon.</p>"
    out = list(
        extract_candidates_from_row(
            body, site="serverfault.com", post_type_id="1", post_id="100",
            filter_security_repos=True,
        )
    )
    paths = [c.path for c, dropped in out if not dropped]
    assert r"\\fs01\share\reports" in paths


def test_extract_html_entities_unescaped():
    r"""Code blocks in Posts.xml have ``<`` / ``>`` / ``&`` as HTML
    entities. After unescape, the placeholder-server filter catches
    ``\\<server>\share`` patterns even though the raw body contains
    ``&lt;server&gt;``."""
    body = r"<pre><code>\\&lt;server&gt;\share</code></pre>"
    out = list(
        extract_candidates_from_row(
            body, site="serverfault.com", post_type_id="1", post_id="200",
            filter_security_repos=True,
        )
    )
    # ``\\<server>\share`` — server portion has '<'/'>', regex rejects
    # at extraction time (server class doesn't include those chars).
    assert out == []


def test_extract_rejects_placeholder_server_after_unescape():
    """A path with a placeholder server (``\\\\example\\share``) is
    extracted by the regex but dropped by the placeholder filter."""
    body = r"<p>For example: <code>\\example\share\file</code></p>"
    out = list(
        extract_candidates_from_row(
            body, site="serverfault.com", post_type_id="1", post_id="300",
            filter_security_repos=True,
        )
    )
    assert out == []


def test_extract_rejects_variable_interpolation():
    body = r"<code>\\$server\$share\$path</code>"
    out = list(
        extract_candidates_from_row(
            body, site="serverfault.com", post_type_id="1", post_id="400",
            filter_security_repos=True,
        )
    )
    assert out == []


def test_extract_returns_question_url_for_post_type_1():
    body = r"<code>\\fs01\share\test</code>"
    out = list(
        extract_candidates_from_row(
            body, site="serverfault.com", post_type_id="1", post_id="500",
            filter_security_repos=True,
        )
    )
    assert out
    candidate, dropped = out[0]
    assert candidate.provenance_url == "https://serverfault.com/q/500"
    assert dropped is False


def test_extract_returns_answer_url_for_post_type_2():
    body = r"<code>\\fs01\share\test</code>"
    out = list(
        extract_candidates_from_row(
            body, site="serverfault.com", post_type_id="2", post_id="600",
            filter_security_repos=True,
        )
    )
    assert out
    candidate, _ = out[0]
    assert candidate.provenance_url == "https://serverfault.com/a/600"


def test_extract_flags_lab_path_marker_as_dropped():
    """``hackme`` is in LAB_PATH_MARKERS — security filter drops it
    when enabled, but yields with dropped=True so caller can count."""
    body = r"<code>\\corp01\HackMe\flag.txt</code>"
    out = list(
        extract_candidates_from_row(
            body, site="serverfault.com", post_type_id="1", post_id="700",
            filter_security_repos=True,
        )
    )
    # Single candidate, marked dropped — caller counts but doesn't emit
    assert len(out) == 1
    _, dropped = out[0]
    assert dropped is True


def test_extract_does_not_drop_lab_marker_when_filter_disabled():
    body = r"<code>\\corp01\HackMe\flag.txt</code>"
    out = list(
        extract_candidates_from_row(
            body, site="serverfault.com", post_type_id="1", post_id="800",
            filter_security_repos=False,
        )
    )
    assert len(out) == 1
    _, dropped = out[0]
    assert dropped is False


# ---------------------------------------------------------------------------
# End-to-end: synthetic Posts.xml → collect()
# ---------------------------------------------------------------------------


def _write_posts_xml(path: Path, rows: list[dict]) -> None:
    """Build a minimal Posts.xml fixture from a list of row dicts.
    Each row dict has keys matching Posts.xml attribute names
    (Id, PostTypeId, Body, etc.). Values are XML-attribute-escaped
    minimally — fixtures shouldn't include quote chars in attribute
    values to keep this simple."""
    parts = ['<?xml version="1.0" encoding="utf-8"?>', "<posts>"]
    for row in rows:
        attrs = " ".join(f'{k}="{v}"' for k, v in row.items())
        parts.append(f"  <row {attrs} />")
    parts.append("</posts>")
    path.write_text("\n".join(parts), encoding="utf-8")


def test_collect_extracts_paths_from_synthetic_dump(tmp_path):
    xml_path = tmp_path / "Posts.xml"
    _write_posts_xml(
        xml_path,
        [
            {"Id": "1", "PostTypeId": "1", "Title": "Q1",
             "Body": r"&lt;p&gt;Mount \\fs01\share\reports on logon.&lt;/p&gt;"},
            {"Id": "2", "PostTypeId": "2", "ParentId": "1",
             "Body": r"Use \\dc01\NETLOGON\map.bat in the GPO."},
            {"Id": "3", "PostTypeId": "1", "Title": "Q3",
             "Body": "No backslash content here at all."},  # filtered by pre-filter
        ],
    )

    result = collect(xml_path, site="serverfault.com")

    paths = sorted(c.path for c in result.candidates)
    assert r"\\dc01\NETLOGON\map.bat" in paths
    assert r"\\fs01\share\reports" in paths
    assert result.posts_seen == 3
    assert result.posts_with_backslash == 2  # row 3 skipped by pre-filter


def test_collect_dedups_repeated_paths_across_posts(tmp_path):
    """Same UNC appearing in multiple posts dedups to one Candidate.
    Uses normalize_for_dedup — the same shared callable build_queue
    uses — so case variants also collapse."""
    xml_path = tmp_path / "Posts.xml"
    _write_posts_xml(
        xml_path,
        [
            {"Id": "1", "PostTypeId": "1",
             "Body": r"\\fs01\share\test"},
            {"Id": "2", "PostTypeId": "1",
             "Body": r"\\FS01\SHARE\TEST"},  # case variant
            {"Id": "3", "PostTypeId": "2", "ParentId": "1",
             "Body": r"\\fs01\share\test"},  # exact duplicate
        ],
    )
    result = collect(xml_path, site="serverfault.com")
    assert len(result.candidates) == 1
    assert result.candidates[0].path == r"\\fs01\share\test"


def test_collect_respects_max_posts(tmp_path):
    """Debug knob: stop after N rows so operator can sanity-check on
    a slice. Posts seen reflects the rows actually processed."""
    xml_path = tmp_path / "Posts.xml"
    _write_posts_xml(
        xml_path,
        [
            {"Id": str(i), "PostTypeId": "1",
             "Body": rf"\\fs01\share\file{i}.txt"}
            for i in range(1, 11)
        ],
    )
    result = collect(xml_path, site="serverfault.com", max_posts=3)
    assert result.posts_seen == 4  # 3 processed + the 4th that triggers break
    assert len(result.candidates) <= 3


def test_collect_drops_offensive_security_paths(tmp_path):
    """Default-on security filter drops lab-marker paths."""
    xml_path = tmp_path / "Posts.xml"
    _write_posts_xml(
        xml_path,
        [
            {"Id": "1", "PostTypeId": "1",
             "Body": r"\\fs01\share\realfile.txt"},
            {"Id": "2", "PostTypeId": "1",
             "Body": r"\\corp01\HackMe\flag.txt"},  # lab marker
        ],
    )
    result = collect(xml_path, site="serverfault.com")
    paths = [c.path for c in result.candidates]
    assert r"\\fs01\share\realfile.txt" in paths
    assert r"\\corp01\HackMe\flag.txt" not in paths
    assert result.dropped_security_count == 1


def test_collect_keeps_offensive_paths_when_filter_disabled(tmp_path):
    xml_path = tmp_path / "Posts.xml"
    _write_posts_xml(
        xml_path,
        [
            {"Id": "1", "PostTypeId": "1",
             "Body": r"\\corp01\HackMe\flag.txt"},
        ],
    )
    result = collect(
        xml_path, site="serverfault.com", filter_security_repos=False
    )
    assert len(result.candidates) == 1
    assert result.dropped_security_count == 0


# ---------------------------------------------------------------------------
# Tag parsing + tag-filter end-to-end
# ---------------------------------------------------------------------------


def test_parse_tags_canonical_shape():
    """Stack Exchange tag format is ``<x><y><z>`` after entity unescape."""
    from src.eval.source_stackexchange import parse_tags
    assert parse_tags("<windows><powershell>") == frozenset(
        {"windows", "powershell"}
    )


def test_parse_tags_empty_input():
    from src.eval.source_stackexchange import parse_tags
    assert parse_tags("") == frozenset()
    assert parse_tags("<>") == frozenset()


def test_parse_tags_single_tag():
    from src.eval.source_stackexchange import parse_tags
    assert parse_tags("<windows>") == frozenset({"windows"})


def test_parse_tags_no_substring_false_match():
    """``<windows>`` must not match against a tag set containing
    ``windows-server`` — the split-on-``><`` design avoids substring
    collisions that a naive ``in`` check would hit."""
    from src.eval.source_stackexchange import parse_tags
    parsed = parse_tags("<windows-server>")
    assert "windows" not in parsed
    assert "windows-server" in parsed


def test_parse_tags_pipe_format_stackoverflow_2024():
    """Stack Overflow's 2024+ data dumps emit pipe-delimited tags
    (``|windows|powershell|`` rather than ``<windows><powershell>``).
    Detected by leading char; both formats must parse identically.
    Discovered after a full-SO run returned 0 hits because the
    angle-bracket parser saw 60M pipe-format tag strings."""
    from src.eval.source_stackexchange import parse_tags
    assert parse_tags("|windows|powershell|") == frozenset(
        {"windows", "powershell"}
    )
    assert parse_tags("|wcf|security|spn|") == frozenset(
        {"wcf", "security", "spn"}
    )


def test_parse_tags_pipe_format_single_tag():
    from src.eval.source_stackexchange import parse_tags
    assert parse_tags("|windows|") == frozenset({"windows"})


def test_parse_tags_pipe_format_no_substring_false_match():
    """Pipe-format equivalent of the angle-bracket false-substring
    test: ``c#`` must not match ``c#-7.0``."""
    from src.eval.source_stackexchange import parse_tags
    parsed = parse_tags("|c#-7.0|")
    assert "c#" not in parsed
    assert "c#-7.0" in parsed


def test_collect_with_tag_filter_drops_non_matching_question(tmp_path):
    """Question whose Tags don't intersect include_tags is skipped
    entirely (body never even hits the backslash pre-filter)."""
    xml_path = tmp_path / "Posts.xml"
    _write_posts_xml(
        xml_path,
        [
            {"Id": "1", "PostTypeId": "1", "Tags": "&lt;python&gt;",
             "Body": r"\\fs01\share\file1"},
            {"Id": "2", "PostTypeId": "1", "Tags": "&lt;windows&gt;",
             "Body": r"\\fs01\share\file2"},
        ],
    )
    result = collect(
        xml_path,
        site="stackoverflow.com",
        include_tags=frozenset({"windows"}),
    )
    paths = [c.path for c in result.candidates]
    assert r"\\fs01\share\file1" not in paths
    assert r"\\fs01\share\file2" in paths


def test_collect_with_tag_filter_keeps_answer_to_matching_question(tmp_path):
    """Answer's processing is gated by its parent question's tags, not
    its own (answers carry empty Tags in real SE dumps)."""
    xml_path = tmp_path / "Posts.xml"
    _write_posts_xml(
        xml_path,
        [
            {"Id": "1", "PostTypeId": "1", "Tags": "&lt;windows&gt;",
             "Body": "no backslash in question body at all"},
            {"Id": "2", "PostTypeId": "2", "ParentId": "1",
             "Body": r"\\fs01\share\answer_path"},
        ],
    )
    result = collect(
        xml_path,
        site="stackoverflow.com",
        include_tags=frozenset({"windows"}),
    )
    assert any(c.path == r"\\fs01\share\answer_path" for c in result.candidates)


def test_collect_with_tag_filter_drops_answer_to_non_matching_question(tmp_path):
    """If a question's Tags don't match, its answers are also skipped —
    parent_id lookup misses because the question wasn't recorded."""
    xml_path = tmp_path / "Posts.xml"
    _write_posts_xml(
        xml_path,
        [
            {"Id": "1", "PostTypeId": "1", "Tags": "&lt;python&gt;",
             "Body": "nothing"},
            {"Id": "2", "PostTypeId": "2", "ParentId": "1",
             "Body": r"\\fs01\share\orphan_answer"},
        ],
    )
    result = collect(
        xml_path,
        site="stackoverflow.com",
        include_tags=frozenset({"windows"}),
    )
    assert not result.candidates


def test_collect_without_tag_filter_keeps_serverfault_behavior(tmp_path):
    """include_tags=None (default) processes all post types — the right
    posture for SF/SU where the whole site is sysadmin-relevant."""
    xml_path = tmp_path / "Posts.xml"
    _write_posts_xml(
        xml_path,
        [
            {"Id": "1", "PostTypeId": "1", "Tags": "&lt;python&gt;",
             "Body": r"\\fs01\share\file1"},
        ],
    )
    result = collect(xml_path, site="serverfault.com")  # no include_tags
    assert len(result.candidates) == 1


def test_collect_skips_rows_with_empty_body(tmp_path):
    """Some PostTypeId values (tag wiki excerpts) can have no body.
    Rows without a Body attribute are silently skipped, not crashed."""
    xml_path = tmp_path / "Posts.xml"
    _write_posts_xml(
        xml_path,
        [
            {"Id": "1", "PostTypeId": "5"},  # no Body
            {"Id": "2", "PostTypeId": "1",
             "Body": r"\\fs01\share\file"},
        ],
    )
    result = collect(xml_path, site="serverfault.com")
    assert result.posts_seen == 1  # row 1 skipped (no body)
    assert len(result.candidates) == 1


# ---------------------------------------------------------------------------
# CSV output
# ---------------------------------------------------------------------------


def test_write_csv_header_and_row_shape(tmp_path):
    out = tmp_path / "out.csv"
    candidates = [
        Candidate(path=r"\\fs01\share\a", provenance_url="https://serverfault.com/q/1"),
        Candidate(path=r"\\fs02\share\b", provenance_url="https://serverfault.com/a/2"),
    ]
    _write_csv(out, candidates)
    rows = list(csv.reader(out.open(encoding="utf-8")))
    assert rows[0] == ["path", "source", "provenance_url"]
    assert rows[1] == [r"\\fs01\share\a", "stackexchange", "https://serverfault.com/q/1"]
    assert rows[2] == [r"\\fs02\share\b", "stackexchange", "https://serverfault.com/a/2"]


def test_write_csv_empty_candidates_writes_header_only(tmp_path):
    """Empty result still writes header so downstream tools see a
    consistently-shaped file."""
    out = tmp_path / "out.csv"
    _write_csv(out, [])
    rows = list(csv.reader(out.open(encoding="utf-8")))
    assert rows == [["path", "source", "provenance_url"]]


def test_write_csv_uses_atomic_temp_then_replace(tmp_path):
    """No partial-write artifact on success — tempfile is replaced
    atomically; only the final file exists post-call."""
    out = tmp_path / "out.csv"
    _write_csv(out, [Candidate(path=r"\\fs01\share\x", provenance_url="https://serverfault.com/q/1")])
    assert out.exists()
    assert not (tmp_path / "out.csv.tmp").exists()


def test_csv_is_build_queue_compatible(tmp_path):
    """Round-trip: write a CSV with this module, read it back with
    build_queue._read_csv. Shared callable can't disagree."""
    from src.eval.build_queue import _read_csv

    out = tmp_path / "out.csv"
    _write_csv(
        out,
        [
            Candidate(path=r"\\fs01\share\file", provenance_url="https://serverfault.com/q/1"),
        ],
    )
    rows = list(_read_csv(out, default_source=None))
    assert rows == [{"path": r"\\fs01\share\file", "source": "stackexchange"}]


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def test_dry_run_does_not_create_output_file(tmp_path, capsys):
    """Dry run prints plan, does not touch the filesystem (beyond
    stat-ing the input)."""
    xml = tmp_path / "Posts.xml"
    _write_posts_xml(xml, [{"Id": "1", "PostTypeId": "1", "Body": r"\\fs\sh\f"}])
    out = tmp_path / "out.csv"

    rc = main(["--input", str(xml), "--output", str(out), "--dry-run"])

    assert rc == 0
    assert not out.exists()
    captured = capsys.readouterr()
    assert "Input:" in captured.err
    assert "Re-run without --dry-run" in captured.err


def test_dry_run_warns_on_missing_input(tmp_path, capsys):
    """Missing input is a warning in dry-run (not an error) so the
    operator can preview the plan before downloading the dump."""
    rc = main(["--input", str(tmp_path / "absent.xml"), "--dry-run"])
    assert rc == 0
    captured = capsys.readouterr()
    assert "does not exist" in captured.err


def test_main_fails_on_missing_input(tmp_path, capsys):
    """Real run with a missing file is a hard error."""
    rc = main(["--input", str(tmp_path / "absent.xml")])
    assert rc == 1
    captured = capsys.readouterr()
    assert "does not exist" in captured.err


def test_main_end_to_end_writes_csv(tmp_path):
    xml = tmp_path / "Posts.xml"
    _write_posts_xml(
        xml,
        [
            {"Id": "1", "PostTypeId": "1",
             "Body": r"Mount \\fs01\share\reports for logon."},
        ],
    )
    out = tmp_path / "out.csv"
    rc = main(["--input", str(xml), "--output", str(out)])
    assert rc == 0
    assert out.exists()
    rows = list(csv.reader(out.open(encoding="utf-8")))
    assert rows[0] == ["path", "source", "provenance_url"]
    assert any(r"\\fs01\share\reports" in r for r in rows[1:])


def test_main_handles_malformed_xml_gracefully(tmp_path, capsys):
    """ParseError → return 1, print message — don't crash with a
    raw traceback at the user."""
    xml = tmp_path / "Posts.xml"
    xml.write_text("<posts><row id='1' unterminated", encoding="utf-8")
    out = tmp_path / "out.csv"
    rc = main(["--input", str(xml), "--output", str(out)])
    assert rc == 1
    captured = capsys.readouterr()
    assert "malformed XML" in captured.err


def test_main_site_argument_changes_provenance_url(tmp_path):
    """--site flag flows through to the provenance URL host. Tags
    attribute includes ``windows`` so the SO auto-default tag filter
    accepts the post (the filter is the intended new behavior for SO;
    this test isolates the URL-host behavior from it)."""
    xml = tmp_path / "Posts.xml"
    _write_posts_xml(
        xml,
        [{"Id": "42", "PostTypeId": "1", "Tags": "&lt;windows&gt;",
          "Body": r"\\fs01\share\f"}],
    )
    out = tmp_path / "out.csv"
    rc = main(["--input", str(xml), "--output", str(out), "--site", "stackoverflow.com"])
    assert rc == 0
    rows = list(csv.reader(out.open(encoding="utf-8")))
    # Header + 1 row
    assert len(rows) == 2
    assert rows[1][2] == "https://stackoverflow.com/q/42"


def test_main_no_tag_filter_disables_so_auto_default(tmp_path):
    """--no-tag-filter on a stackoverflow.com run restores the
    unfiltered SF/SU behavior (every backslash-containing post hit)."""
    xml = tmp_path / "Posts.xml"
    _write_posts_xml(
        xml,
        [{"Id": "1", "PostTypeId": "1", "Tags": "&lt;python&gt;",
          "Body": r"\\fs01\share\f"}],
    )
    out = tmp_path / "out.csv"
    rc = main([
        "--input", str(xml), "--output", str(out),
        "--site", "stackoverflow.com", "--no-tag-filter",
    ])
    assert rc == 0
    rows = list(csv.reader(out.open(encoding="utf-8")))
    assert len(rows) == 2


def test_main_include_tags_overrides_so_auto_default(tmp_path):
    """Explicit --include-tags wins over the auto-default tag set."""
    xml = tmp_path / "Posts.xml"
    _write_posts_xml(
        xml,
        [
            {"Id": "1", "PostTypeId": "1", "Tags": "&lt;windows&gt;",
             "Body": r"\\fs01\share\windows_path"},
            {"Id": "2", "PostTypeId": "1", "Tags": "&lt;haskell&gt;",
             "Body": r"\\fs01\share\haskell_path"},
        ],
    )
    out = tmp_path / "out.csv"
    rc = main([
        "--input", str(xml), "--output", str(out),
        "--site", "stackoverflow.com", "--include-tags", "haskell",
    ])
    assert rc == 0
    rows = list(csv.reader(out.open(encoding="utf-8")))
    paths = [r[0] for r in rows[1:]]
    assert r"\\fs01\share\haskell_path" in paths
    assert r"\\fs01\share\windows_path" not in paths


# ---------------------------------------------------------------------------
# CollectResult fields drift
# ---------------------------------------------------------------------------


def test_collect_result_default_fields():
    """Drift pin: CollectResult shape stays compatible with main()
    summary expectations."""
    r = CollectResult()
    assert r.candidates == []
    assert r.posts_seen == 0
    assert r.posts_with_backslash == 0
    assert r.dropped_security_count == 0


@pytest.mark.parametrize(
    "post_type,expected_prefix",
    [
        ("1", "q"),
        ("2", "a"),
        ("3", "posts"),
        ("4", "posts"),
        ("5", "posts"),
        ("", "posts"),
    ],
)
def test_provenance_url_drift_all_post_types(post_type, expected_prefix):
    """Drift pin for the URL-prefix mapping — covers all Posts.xml
    PostTypeId values we currently know about."""
    url = build_provenance_url("serverfault.com", post_type, "1")
    assert f"/{expected_prefix}/" in url
