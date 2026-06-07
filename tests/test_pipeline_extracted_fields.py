"""Scanner emits structured-parser output as extracted_fields."""

from __future__ import annotations

from sharesift.parsers.dispatch import ExtractedField, parse_file
from sharesift.pipeline import ScanResult, _run_parsers


def test_scan_result_omits_empty_extracted_fields_from_record():
    r = ScanResult(
        path="/foo.txt",
        path_probability=0.1,
        path_tier=None,
        content_check=None,
        content_excerpt=None,
        raw_content_response=None,
        extracted_fields=[],
    )
    rec = r.as_record()
    assert "extracted_fields" not in rec


def test_scan_result_includes_non_empty_extracted_fields():
    r = ScanResult(
        path="/sysvol/unattend.xml",
        path_probability=0.95,
        path_tier="Black",
        content_check="yes",
        content_excerpt="<...>",
        raw_content_response=None,
        extracted_fields=[
            {"field_name": "Password", "value": "P@ss", "confidence": 0.95, "parser": "unattend", "context": ""},
        ],
    )
    rec = r.as_record()
    assert rec["extracted_fields"][0]["field_name"] == "Password"


def test_run_parsers_returns_empty_for_no_content():
    assert _run_parsers("/foo.txt", None) == []
    assert _run_parsers("/foo.txt", "") == []


def test_run_parsers_dispatches_to_pgpass_parser():
    """pgpass content with a real-shaped line should yield ExtractedField."""
    content = "localhost:5432:mydb:dbuser:dbpass123"
    fields = _run_parsers("/home/op/.pgpass", content)
    assert any(f["parser"] == "pgpass" for f in fields), fields


def test_run_parsers_returns_empty_on_unmatched_filename():
    fields = _run_parsers("/foo/bar.txt", "random text content")
    assert fields == []
