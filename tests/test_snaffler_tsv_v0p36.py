"""v0.36 step 4 — Snaffler-compatible TSV output tests.

Validates the 11-column line format matches Snaffler's
``SnaffleRunner.cs::FileResultLogFromMessage`` so that
SnafflerParser / Efflanrs / Parsler / snafflepy parse our output
without code changes.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from sharesift.output import (
    iter_snaffler_tsv_lines,
    record_to_snaffler_tsv,
)


_FIXED_TS = "2026-06-09 12:34:56Z"


# --- Field count + separator semantics -----------------------------


def test_line_has_12_tab_separated_fields():
    """Snaffler's format is 11 fields (triage..context) prefixed by
    a timestamp[File] marker — 12 fields total when split on tab."""
    rec = {"path": "/share/secrets.cfg", "path_tier": "Red"}
    line = record_to_snaffler_tsv(rec, line_timestamp=_FIXED_TS)
    fields = line.split("\t")
    assert len(fields) == 12


def test_first_field_is_timestamp_with_file_marker():
    rec = {"path": "/share/x"}
    line = record_to_snaffler_tsv(rec, line_timestamp=_FIXED_TS)
    assert line.startswith(f"{_FIXED_TS}[File]\t")


def test_default_timestamp_is_now_utc():
    """Smoke check: no explicit timestamp → use current UTC time."""
    line = record_to_snaffler_tsv({"path": "/share/x"})
    first = line.split("\t")[0]
    assert "[File]" in first
    # ISO-ish: starts with year
    assert first[:4].isdigit()


# --- Triage / rule_name / matched_string extraction ---------------


def test_content_match_takes_precedence_over_path_tier():
    rec = {
        "path": "/share/secrets.cfg",
        "path_tier": "Yellow",
        "content_tier": "Red",
        "content_matches": [
            {"tier": "Black", "rule_name": "ShareSiftKeepVaultToken",
             "matched_text": "hvs.AbCdEf"}
        ],
    }
    line = record_to_snaffler_tsv(rec, line_timestamp=_FIXED_TS)
    fields = line.split("\t")
    assert fields[1] == "Black"
    assert fields[2] == "ShareSiftKeepVaultToken"
    assert fields[6] == "hvs.AbCdEf"


def test_falls_back_to_path_tier_when_no_content_match():
    rec = {"path": "/share/whatever.txt", "path_tier": "Red"}
    line = record_to_snaffler_tsv(rec, line_timestamp=_FIXED_TS)
    fields = line.split("\t")
    assert fields[1] == "Red"
    assert fields[2] == "PathClassifier"


def test_extracted_field_produces_parser_rule_name():
    rec = {
        "path": "/share/cred.json",
        "path_tier": "Red",
        "extracted_fields": [
            {"parser": "gcloud_credentials", "value": "ya29.AbCdEf..."}
        ],
    }
    line = record_to_snaffler_tsv(rec, line_timestamp=_FIXED_TS)
    fields = line.split("\t")
    assert fields[2] == "Parser:gcloud_credentials"
    assert fields[6].startswith("ya29.")


def test_extracted_field_value_truncated_to_80_chars():
    long = "x" * 200
    rec = {
        "path": "/share/y",
        "path_tier": "Red",
        "extracted_fields": [{"parser": "p", "value": long}],
    }
    line = record_to_snaffler_tsv(rec, line_timestamp=_FIXED_TS)
    matched = line.split("\t")[6]
    assert len(matched) == 80


def test_no_signal_at_all_uses_green_default():
    """A record with neither content_match nor path_tier is treated
    as Green (Snaffler's catch-all relay tier)."""
    rec = {"path": "/share/nothing.txt"}
    fields = record_to_snaffler_tsv(rec, line_timestamp=_FIXED_TS).split("\t")
    assert fields[1] == "Green"
    assert fields[2] == "PathClassifier"


# --- R/W/M permission columns -------------------------------------


def test_read_column_always_R():
    """The cascade scored the file, so it was readable."""
    rec = {"path": "/share/x"}
    fields = record_to_snaffler_tsv(rec, line_timestamp=_FIXED_TS).split("\t")
    assert fields[3] == "R"


def test_write_and_modify_columns_empty_until_step_3():
    """W/M wait on v0.36 step 3 (share-writability probing)."""
    rec = {"path": "/share/x"}
    fields = record_to_snaffler_tsv(rec, line_timestamp=_FIXED_TS).split("\t")
    assert fields[4] == ""
    assert fields[5] == ""


# --- Size + modified columns --------------------------------------


def test_size_and_modified_filled_for_local_path(tmp_path):
    target = tmp_path / "thing.txt"
    target.write_text("abc")
    rec = {"path": str(target), "path_tier": "Red"}
    fields = record_to_snaffler_tsv(rec, line_timestamp=_FIXED_TS).split("\t")
    assert fields[7] == "3"  # size in bytes
    # Modified is a UTC timestamp string
    assert fields[8].endswith("Z")
    assert len(fields[8]) == 20  # "2026-06-09 12:34:56Z"


def test_size_empty_for_unc_path():
    """UNC paths — the SMB session is closed at format time, so we
    don't try to re-open. Emit empty for size and modified."""
    rec = {"path": r"\\10.0.0.5\Finance\secrets.cfg", "path_tier": "Red"}
    fields = record_to_snaffler_tsv(rec, line_timestamp=_FIXED_TS).split("\t")
    assert fields[7] == ""
    assert fields[8] == ""


def test_size_empty_for_nonexistent_path():
    rec = {"path": "/no/such/file", "path_tier": "Red"}
    fields = record_to_snaffler_tsv(rec, line_timestamp=_FIXED_TS).split("\t")
    assert fields[7] == ""
    assert fields[8] == ""


# --- Path / altname -----------------------------------------------


def test_path_column_preserved_verbatim():
    rec = {"path": r"\\10.0.0.5\Finance\subdir\secrets.cfg", "path_tier": "Red"}
    fields = record_to_snaffler_tsv(rec, line_timestamp=_FIXED_TS).split("\t")
    assert fields[9] == r"\\10.0.0.5\Finance\subdir\secrets.cfg"


def test_altname_column_empty():
    """ShareSift doesn't track SCCM-style alt names; emit empty."""
    rec = {"path": "/share/x"}
    fields = record_to_snaffler_tsv(rec, line_timestamp=_FIXED_TS).split("\t")
    assert fields[10] == ""


# --- Match context escaping ---------------------------------------


def test_newlines_in_context_escaped_to_literal_n():
    rec = {
        "path": "/share/x",
        "path_tier": "Red",
        "content_matches": [
            {"rule_name": "R", "tier": "Red",
             "match_context": "line one\nline two\rline three"}
        ],
    }
    fields = record_to_snaffler_tsv(rec, line_timestamp=_FIXED_TS).split("\t")
    assert "\n" not in fields[11]
    assert "\r" not in fields[11]
    assert "\\n" in fields[11]


def test_tabs_in_field_values_replaced_with_space():
    """Embedded tabs would break TSV parsing downstream — replace
    them with spaces in every field."""
    rec = {
        "path": "/share/file\twith\ttabs.txt",
        "path_tier": "Red",
        "content_matches": [
            {"rule_name": "R", "tier": "Red",
             "match_context": "match\twith\ttabs"}
        ],
    }
    line = record_to_snaffler_tsv(rec, line_timestamp=_FIXED_TS)
    fields = line.split("\t")
    assert len(fields) == 12  # No extra fields from embedded tabs
    assert "\t" not in fields[9]
    assert "\t" not in fields[11]


def test_control_chars_stripped_from_context():
    """Null bytes, ANSI escapes, etc. in the context snippet should
    not survive into the TSV output."""
    rec = {
        "path": "/share/x",
        "path_tier": "Red",
        "content_matches": [
            {"rule_name": "R", "tier": "Red",
             "match_context": "abc\x00\x1b[31mred\x1b[0m def"}
        ],
    }
    fields = record_to_snaffler_tsv(rec, line_timestamp=_FIXED_TS).split("\t")
    assert "\x00" not in fields[11]
    assert "\x1b" not in fields[11]
    assert "abc" in fields[11]
    assert "def" in fields[11]


def test_content_excerpt_fallback_when_no_match_context():
    rec = {
        "path": "/share/x",
        "path_tier": "Red",
        "content_excerpt": "raw content excerpt",
        "content_matches": [
            {"rule_name": "R", "tier": "Red"}  # no match_context
        ],
    }
    fields = record_to_snaffler_tsv(rec, line_timestamp=_FIXED_TS).split("\t")
    assert "raw content excerpt" in fields[11]


# --- iter_snaffler_tsv_lines streaming ----------------------------


def test_iter_yields_one_line_per_record():
    records = [
        {"path": "/share/a", "path_tier": "Red"},
        {"path": "/share/b", "path_tier": "Yellow"},
        {"path": "/share/c", "path_tier": "Green"},
    ]
    lines = list(iter_snaffler_tsv_lines(records, line_timestamp=_FIXED_TS))
    assert len(lines) == 3
    assert "Red" in lines[0]
    assert "Yellow" in lines[1]
    assert "Green" in lines[2]


def test_iter_works_with_generator_input():
    def gen():
        yield {"path": "/share/x", "path_tier": "Red"}
        yield {"path": "/share/y", "path_tier": "Black"}

    lines = list(iter_snaffler_tsv_lines(gen(), line_timestamp=_FIXED_TS))
    assert len(lines) == 2
