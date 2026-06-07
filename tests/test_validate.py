"""Tests for the post-label integrity checker."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from src.eval import validate as validate_mod
from src.eval._paths import normalize_for_dedup as paths_normalize
from src.eval.build_queue import (  # exercise shared-helper guarantee
    normalize_for_dedup as build_queue_normalize,
)
from src.eval.validate import (
    HeuristicStats,
    IntegrityWarning,
    _check_duplicates,
    _check_validator_warnings_names,
    _compute_stats,
    _format_report,
    _main,
    validate_file,
)

# ---------------------------------------------------------------------------
# Fixture helpers
# ---------------------------------------------------------------------------


def _juicy_dict(**overrides) -> dict:
    base = {
        "path": r"C:\Users\admin\secrets.kdbx",
        "label": "juicy",
        "tier": "Red",
        "category": "credential_containers",
        "source": "engagement",
        "notes": "KeePass vault on admin profile.",
        "added_date": "2026-05-23",
    }
    base.update(overrides)
    return base


def _not_juicy_dict(**overrides) -> dict:
    base = {
        "path": r"C:\Windows\System32\notepad.exe",
        "label": "not_juicy",
        "category": "decoy_docs",
        "source": "engagement",
        "notes": "System binary; not credential material.",
        "added_date": "2026-05-23",
    }
    base.update(overrides)
    return base


def _write_records(tmp_path: Path, records: list[dict]) -> Path:
    f = tmp_path / "eval_set.jsonl"
    body = "\n".join(json.dumps(r) for r in records)
    f.write_text(body + ("\n" if body else ""), encoding="utf-8")
    return f


# ---------------------------------------------------------------------------
# Shared-helper invariant
# ---------------------------------------------------------------------------


def test_shared_normalization_helper_is_one_function():
    """``build_queue`` and ``_paths`` must expose the same callable
    (re-exported, not duplicated). If this ever breaks, the two
    modules will disagree about path identity."""
    assert build_queue_normalize is paths_normalize


# ---------------------------------------------------------------------------
# Hard errors
# ---------------------------------------------------------------------------


def test_clean_file_has_no_errors_or_warnings(tmp_path):
    src = _write_records(tmp_path, [_juicy_dict(), _not_juicy_dict()])
    report = validate_file(src)
    assert report.hard_errors == []
    assert report.integrity_warnings == []
    assert report.stats.record_count == 2


def test_empty_file_is_clean(tmp_path):
    src = tmp_path / "eval_set.jsonl"
    src.write_text("", encoding="utf-8")
    report = validate_file(src)
    assert report.hard_errors == []
    assert report.integrity_warnings == []
    assert report.stats.record_count == 0


def test_missing_file_raises(tmp_path):
    with pytest.raises(FileNotFoundError):
        validate_file(tmp_path / "no_such_file.jsonl")


def test_malformed_json_is_hard_error_with_line_number(tmp_path):
    src = tmp_path / "eval_set.jsonl"
    src.write_text(
        json.dumps(_juicy_dict()) + "\n{not valid json\n",
        encoding="utf-8",
    )
    report = validate_file(src)
    assert len(report.hard_errors) == 1
    assert report.hard_errors[0].line_num == 2
    assert "invalid JSON" in report.hard_errors[0].message


@pytest.mark.parametrize(
    "bad_field,bad_value",
    [
        ("tier", "Purple"),
        ("category", "made_up_category"),
        ("source", "telepathy"),
        ("notes", "x"),  # below MIN_NOTES_LEN
    ],
)
def test_schema_violations_are_hard_errors(tmp_path, bad_field, bad_value):
    bad = _juicy_dict()
    bad[bad_field] = bad_value
    src = _write_records(tmp_path, [bad])
    report = validate_file(src)
    assert len(report.hard_errors) == 1
    assert bad_field in report.hard_errors[0].message


def test_missing_required_field_is_hard_error(tmp_path):
    bad = _juicy_dict()
    del bad["label"]
    src = _write_records(tmp_path, [bad])
    report = validate_file(src)
    assert len(report.hard_errors) == 1


# ---------------------------------------------------------------------------
# Enum drift (load-bearing fields)
# ---------------------------------------------------------------------------


def test_enum_drift_source(monkeypatch, tmp_path):
    src = _write_records(tmp_path, [_juicy_dict()])
    # Patch SOURCES in validate's namespace only. Schema (in its own
    # namespace) still validates against the original constant, so the
    # record passes schema; the drift check should flag it.
    monkeypatch.setattr(validate_mod, "SOURCES", ("synthetic", "public"))
    report = validate_file(src)
    drift = [w for w in report.integrity_warnings if w.kind == "enum_drift"]
    assert len(drift) == 1
    assert "source" in drift[0].message
    assert "engagement" in drift[0].message


def test_enum_drift_category(monkeypatch, tmp_path):
    src = _write_records(tmp_path, [_juicy_dict()])
    monkeypatch.setattr(validate_mod, "CATEGORY_SLUGS", ("other_category",))
    report = validate_file(src)
    drift = [w for w in report.integrity_warnings if w.kind == "enum_drift"]
    assert any("category" in w.message for w in drift)


def test_enum_drift_sub_type(monkeypatch, tmp_path):
    rec = _juicy_dict(category="modern_saas_tokens", sub_type="ai_llm")
    src = _write_records(tmp_path, [rec])
    monkeypatch.setattr(validate_mod, "MODERN_SAAS_SUBTYPES", ("payments",))
    report = validate_file(src)
    drift = [w for w in report.integrity_warnings if w.kind == "enum_drift"]
    assert any("sub_type" in w.message for w in drift)


def test_enum_drift_tier(monkeypatch, tmp_path):
    src = _write_records(tmp_path, [_juicy_dict()])
    monkeypatch.setattr(validate_mod, "SEVERITY_TIERS", ("Black", "Purple"))
    report = validate_file(src)
    drift = [w for w in report.integrity_warnings if w.kind == "enum_drift"]
    assert any("tier" in w.message for w in drift)


# ---------------------------------------------------------------------------
# pre_category drift (distinct kind, lower severity)
# ---------------------------------------------------------------------------


def test_pre_category_drift_uses_its_own_kind(monkeypatch, tmp_path):
    rec = _juicy_dict(pre_category="credential_containers")
    src = _write_records(tmp_path, [rec])
    monkeypatch.setattr(validate_mod, "CATEGORY_SLUGS", ("other_category",))
    report = validate_file(src)
    pcd = [w for w in report.integrity_warnings if w.kind == "pre_category_drift"]
    assert len(pcd) == 1
    assert "pre_category" in pcd[0].message
    # And the message identifies its lower-severity nature.
    assert "lower severity" in pcd[0].message


def test_pre_category_null_does_not_trigger_drift(monkeypatch, tmp_path):
    rec = _juicy_dict()  # pre_category not set, defaults to None
    src = _write_records(tmp_path, [rec])
    monkeypatch.setattr(validate_mod, "CATEGORY_SLUGS", ("anything",))
    report = validate_file(src)
    pcd = [w for w in report.integrity_warnings if w.kind == "pre_category_drift"]
    assert pcd == []


# ---------------------------------------------------------------------------
# validator_warnings namespace
# ---------------------------------------------------------------------------


def test_validator_warnings_known_heuristic_is_ok(tmp_path):
    rec = _not_juicy_dict(
        path=r"C:\Users\admin\secrets.kdbx",
        category="credential_containers",
        validator_warnings=["kdbx_extension"],
    )
    src = _write_records(tmp_path, [rec])
    report = validate_file(src)
    unk = [w for w in report.integrity_warnings if w.kind == "unknown_heuristic_name"]
    assert unk == []


def test_validator_warnings_labeler_flag_is_ok(tmp_path):
    rec = _not_juicy_dict(validator_warnings=["uncertainty_prior"])
    src = _write_records(tmp_path, [rec])
    report = validate_file(src)
    unk = [w for w in report.integrity_warnings if w.kind == "unknown_heuristic_name"]
    assert unk == []


def test_validator_warnings_mixed_namespaces_ok(tmp_path):
    rec = _not_juicy_dict(
        path=r"C:\Users\admin\secrets.kdbx",
        category="credential_containers",
        validator_warnings=["kdbx_extension", "uncertainty_prior"],
    )
    src = _write_records(tmp_path, [rec])
    report = validate_file(src)
    unk = [w for w in report.integrity_warnings if w.kind == "unknown_heuristic_name"]
    assert unk == []


def test_validator_warnings_unknown_name_is_warning(tmp_path):
    rec = _not_juicy_dict(validator_warnings=["typo_heurstic_name"])
    src = _write_records(tmp_path, [rec])
    report = validate_file(src)
    unk = [w for w in report.integrity_warnings if w.kind == "unknown_heuristic_name"]
    assert len(unk) == 1
    assert "typo_heurstic_name" in unk[0].message


# ---------------------------------------------------------------------------
# Validator firing consistency (with direction in the message)
# ---------------------------------------------------------------------------


def test_validator_drift_skipped_for_juicy_records(tmp_path):
    # juicy records never ran the validator at label time; no consistency
    # check should apply.
    rec = _juicy_dict(
        path=r"C:\Users\admin\secrets.kdbx",
        category="credential_containers",
    )
    src = _write_records(tmp_path, [rec])
    report = validate_file(src)
    drift = [w for w in report.integrity_warnings if w.kind == "validator_drift"]
    assert drift == []


def test_validator_drift_no_warning_when_consistent(tmp_path):
    rec = _not_juicy_dict(
        path=r"C:\Users\admin\secrets.kdbx",
        category="credential_containers",
        validator_warnings=["kdbx_extension"],
    )
    src = _write_records(tmp_path, [rec])
    report = validate_file(src)
    drift = [w for w in report.integrity_warnings if w.kind == "validator_drift"]
    assert drift == []


def test_validator_drift_record_predates_heuristic(tmp_path):
    # The record has no validator_warnings, but the current registry
    # fires kdbx_extension on this path → record predates the
    # heuristic (or its predicate was broadened).
    rec = _not_juicy_dict(
        path=r"C:\Users\admin\secrets.kdbx",
        category="credential_containers",
        validator_warnings=[],
    )
    src = _write_records(tmp_path, [rec])
    report = validate_file(src)
    drift = [w for w in report.integrity_warnings if w.kind == "validator_drift"]
    assert len(drift) == 1
    msg = drift[0].message
    assert "record was labeled before" in msg or "broadened" in msg
    assert "kdbx_extension" in msg


def test_validator_drift_heuristic_predicate_narrowed(monkeypatch, tmp_path):
    # Record references a known heuristic that no longer fires on this
    # path. We simulate by leaving the path safe (notepad.exe doesn't
    # fire any heuristic) but giving it a known-heuristic name in
    # validator_warnings — current check_path returns empty, recorded
    # has one name, so it's an "extra only" drift.
    rec = _not_juicy_dict(
        path=r"C:\Windows\System32\notepad.exe",
        validator_warnings=["kdbx_extension"],
    )
    src = _write_records(tmp_path, [rec])
    report = validate_file(src)
    drift = [w for w in report.integrity_warnings if w.kind == "validator_drift"]
    assert len(drift) == 1
    msg = drift[0].message
    assert "no longer fires" in msg or "narrowed" in msg
    assert "kdbx_extension" in msg


def test_validator_drift_both_directions(monkeypatch, tmp_path):
    # path fires kdbx_extension; record claims an unrelated known
    # heuristic. Both directions of drift.
    rec = _not_juicy_dict(
        path=r"C:\Users\admin\secrets.kdbx",
        category="credential_containers",
        validator_warnings=["ssh_private_key_filename"],
    )
    src = _write_records(tmp_path, [rec])
    report = validate_file(src)
    drift = [w for w in report.integrity_warnings if w.kind == "validator_drift"]
    assert len(drift) == 1
    msg = drift[0].message
    assert "both directions" in msg
    assert "kdbx_extension" in msg
    assert "ssh_private_key_filename" in msg


# ---------------------------------------------------------------------------
# Duplicates (cross-record)
# ---------------------------------------------------------------------------


def test_duplicate_paths_warning(tmp_path):
    records = [
        _juicy_dict(path=r"C:\Users\bob\file.kdbx"),
        _juicy_dict(path=r"c:\users\bob\file.kdbx"),  # different casing
    ]
    src = _write_records(tmp_path, records)
    report = validate_file(src)
    dupes = [w for w in report.integrity_warnings if w.kind == "duplicate_path"]
    assert len(dupes) == 1
    assert "lines 1, 2" in dupes[0].message


def test_duplicates_group_three_lines_in_one_warning(tmp_path):
    records = [
        _juicy_dict(path=r"C:\Users\bob\file.kdbx"),
        _juicy_dict(path=r"c:\users\bob\FILE.kdbx"),
        _juicy_dict(path="C:/Users/bob/file.kdbx"),
    ]
    src = _write_records(tmp_path, records)
    report = validate_file(src)
    dupes = [w for w in report.integrity_warnings if w.kind == "duplicate_path"]
    assert len(dupes) == 1
    assert "lines 1, 2, 3" in dupes[0].message


def test_no_duplicates_no_warning(tmp_path):
    records = [
        _juicy_dict(path=r"C:\a.kdbx"),
        _juicy_dict(path=r"C:\b.kdbx"),
        _juicy_dict(path=r"C:\c.kdbx"),
    ]
    src = _write_records(tmp_path, records)
    report = validate_file(src)
    dupes = [w for w in report.integrity_warnings if w.kind == "duplicate_path"]
    assert dupes == []


# ---------------------------------------------------------------------------
# Stats
# ---------------------------------------------------------------------------


def test_stats_counts_and_distributions(tmp_path):
    records = [
        _juicy_dict(path=r"C:\a.kdbx", category="credential_containers"),
        _juicy_dict(path=r"C:\b.kdbx", category="credential_containers"),
        _not_juicy_dict(path=r"C:\c.txt", category="decoy_docs"),
        _juicy_dict(
            path=r"C:\d.kdbx",
            category="credential_containers",
            source="public",
            validator_warnings=["uncertainty_prior"],
        ),
    ]
    src = _write_records(tmp_path, records)
    report = validate_file(src)
    s = report.stats
    assert s.record_count == 4
    assert s.label_dist["juicy"] == 3
    assert s.label_dist["not_juicy"] == 1
    assert s.category_hist["credential_containers"] == 3
    assert s.category_hist["decoy_docs"] == 1
    assert s.source_dist["engagement"] == 3
    assert s.source_dist["public"] == 1
    assert s.uncertainty_count == 1


def test_per_heuristic_stats_compute_correctly(tmp_path):
    # 12 records that all fire kdbx_extension; 10 are juicy (no warning
    # entries), 2 are not_juicy with kdbx_extension in validator_warnings.
    # Expected: fires=12, juicy=10, not_juicy=2, overrides=2,
    # rate=2/12 ≈ 16.7% — below threshold, no ⚠.
    juicy_records = [_juicy_dict(path=f"C:\\Users\\admin\\juicy_{i}.kdbx") for i in range(10)]
    not_juicy_records = [
        _not_juicy_dict(
            path=f"C:\\Users\\admin\\nj_{i}.kdbx",
            validator_warnings=["kdbx_extension"],
        )
        for i in range(2)
    ]
    src = _write_records(tmp_path, juicy_records + not_juicy_records)
    report = validate_file(src)
    kdbx = next(h for h in report.stats.per_heuristic if h.name == "kdbx_extension")
    assert kdbx.fires_count == 12
    assert kdbx.juicy_count == 10
    assert kdbx.not_juicy_count == 2
    assert kdbx.override_count == 2
    assert abs(kdbx.override_rate - 2 / 12) < 1e-9
    assert kdbx.warn is False


def test_per_heuristic_warn_marker_above_threshold(tmp_path):
    # 14 records that all fire kdbx_extension, 11 not_juicy with the
    # heuristic listed (overrides). Rate = 11/14 ≈ 78.6% with
    # fires_count >= 10 → warn=True.
    juicy_records = [_juicy_dict(path=f"C:\\Users\\admin\\j_{i}.kdbx") for i in range(3)]
    not_juicy_records = [
        _not_juicy_dict(
            path=f"C:\\Users\\admin\\nj_{i}.kdbx",
            validator_warnings=["kdbx_extension"],
        )
        for i in range(11)
    ]
    src = _write_records(tmp_path, juicy_records + not_juicy_records)
    report = validate_file(src)
    kdbx = next(h for h in report.stats.per_heuristic if h.name == "kdbx_extension")
    assert kdbx.fires_count == 14
    assert kdbx.warn is True


def test_per_heuristic_no_warn_below_min_fires(tmp_path):
    # 9 records, all not_juicy with kdbx_extension. Rate = 100% but
    # fires_count = 9 < OVERRIDE_WARN_MIN_FIRES (10) → no ⚠.
    not_juicy_records = [
        _not_juicy_dict(
            path=f"C:\\Users\\admin\\nj_{i}.kdbx",
            validator_warnings=["kdbx_extension"],
        )
        for i in range(9)
    ]
    src = _write_records(tmp_path, not_juicy_records)
    report = validate_file(src)
    kdbx = next(h for h in report.stats.per_heuristic if h.name == "kdbx_extension")
    assert kdbx.fires_count == 9
    assert abs(kdbx.override_rate - 1.0) < 1e-9
    assert kdbx.warn is False, (
        "below OVERRIDE_WARN_MIN_FIRES, the marker must be suppressed "
        "regardless of rate — this is the canary protection for "
        "low-volume heuristics like registry_hive_extensionless"
    )


def test_per_heuristic_zero_fires_does_not_warn():
    h = HeuristicStats(
        name="never_fires",
        fires_count=0,
        juicy_count=0,
        not_juicy_count=0,
        override_count=0,
    )
    assert h.override_rate == 0.0
    assert h.warn is False


def test_empty_file_still_enumerates_every_heuristic(tmp_path):
    """Per-heuristic table shape must be the same for empty vs populated
    so the report layout is consistent. Important for downstream
    tooling that might parse the output."""
    from src.eval.negative_validator import _HEURISTICS

    src = tmp_path / "eval_set.jsonl"
    src.write_text("", encoding="utf-8")
    report = validate_file(src)
    names_in_stats = {h.name for h in report.stats.per_heuristic}
    names_in_registry = {n for n, _ in _HEURISTICS}
    assert names_in_stats == names_in_registry


# ---------------------------------------------------------------------------
# Report formatting
# ---------------------------------------------------------------------------


def test_format_report_groups_warnings_by_kind(tmp_path):
    # A record with multiple different kinds of warning at once:
    # - validator_drift (kdbx fires but not listed)
    # - unknown_heuristic_name (typo in validator_warnings)
    rec = _not_juicy_dict(
        path=r"C:\Users\admin\secrets.kdbx",
        category="credential_containers",
        validator_warnings=["typo_name"],
    )
    src = _write_records(tmp_path, [rec])
    report = validate_file(src)
    text = _format_report(report, src, use_color=False)
    # Headers per kind should be present, in alphabetical order.
    assert "unknown_heuristic_name (1):" in text
    assert "validator_drift (1):" in text
    # Group headers ordered alphabetically — unknown_h... before validator_d...
    assert text.index("unknown_heuristic_name") < text.index("validator_drift")


def test_format_report_emits_warn_marker_in_text(tmp_path):
    juicy_records = [_juicy_dict(path=f"C:\\Users\\admin\\j_{i}.kdbx") for i in range(3)]
    not_juicy_records = [
        _not_juicy_dict(
            path=f"C:\\Users\\admin\\nj_{i}.kdbx",
            validator_warnings=["kdbx_extension"],
        )
        for i in range(11)
    ]
    src = _write_records(tmp_path, juicy_records + not_juicy_records)
    report = validate_file(src)
    text = _format_report(report, src, use_color=False)
    # Find the kdbx row and confirm the marker is present.
    kdbx_line = next(line for line in text.splitlines() if "kdbx_extension" in line)
    assert "⚠" in kdbx_line


def test_format_report_annotates_low_volume_canary(tmp_path):
    not_juicy_records = [
        _not_juicy_dict(
            path=f"C:\\Users\\admin\\nj_{i}.kdbx",
            validator_warnings=["kdbx_extension"],
        )
        for i in range(9)
    ]
    src = _write_records(tmp_path, not_juicy_records)
    report = validate_file(src)
    text = _format_report(report, src, use_color=False)
    kdbx_line = next(line for line in text.splitlines() if "kdbx_extension" in line)
    assert "(n<10)" in kdbx_line
    assert "⚠" not in kdbx_line  # marker suppressed despite high rate


def test_format_report_color_only_on_warn_rows(tmp_path):
    juicy_records = [_juicy_dict(path=f"C:\\Users\\admin\\j_{i}.kdbx") for i in range(3)]
    not_juicy_records = [
        _not_juicy_dict(
            path=f"C:\\Users\\admin\\nj_{i}.kdbx",
            validator_warnings=["kdbx_extension"],
        )
        for i in range(11)
    ]
    src = _write_records(tmp_path, juicy_records + not_juicy_records)
    report = validate_file(src)
    colored = _format_report(report, src, use_color=True)
    plain = _format_report(report, src, use_color=False)
    assert "\033[33m" in colored
    assert "\033[33m" not in plain
    # Non-warn heuristic rows (e.g. ssh_private_key_filename with 0 fires)
    # must not be wrapped in color.
    ssh_line = next(line for line in colored.splitlines() if "ssh_private_key_filename" in line)
    assert "\033[33m" not in ssh_line


def test_format_report_clean_summary(tmp_path):
    src = _write_records(tmp_path, [_juicy_dict()])
    report = validate_file(src)
    text = _format_report(report, src, use_color=False)
    assert "RESULT: clean" in text


def test_format_report_states_brokenness_on_hard_error(tmp_path):
    bad = _juicy_dict(tier="Purple")
    src = _write_records(tmp_path, [bad])
    report = validate_file(src)
    text = _format_report(report, src, use_color=False)
    assert "FILE IS BROKEN" in text


# ---------------------------------------------------------------------------
# CLI exit codes
# ---------------------------------------------------------------------------


def test_cli_exits_zero_on_clean_file(tmp_path, capsys):
    src = _write_records(tmp_path, [_juicy_dict()])
    code = _main(["--input", str(src), "--no-color"])
    assert code == 0


def test_cli_exits_one_on_hard_error(tmp_path, capsys):
    bad = _juicy_dict(tier="Purple")
    src = _write_records(tmp_path, [bad])
    code = _main(["--input", str(src), "--no-color"])
    assert code == 1


def test_cli_default_lenient_on_integrity_warnings(tmp_path, capsys):
    rec = _not_juicy_dict(validator_warnings=["typo_name"])
    src = _write_records(tmp_path, [rec])
    code = _main(["--input", str(src), "--no-color"])
    assert code == 0  # default mode tolerates warnings


def test_cli_strict_fails_on_integrity_warnings(tmp_path, capsys):
    rec = _not_juicy_dict(validator_warnings=["typo_name"])
    src = _write_records(tmp_path, [rec])
    code = _main(["--input", str(src), "--strict", "--no-color"])
    assert code == 1


def test_cli_strict_still_fails_on_hard_errors(tmp_path, capsys):
    bad = _juicy_dict(tier="Purple")
    src = _write_records(tmp_path, [bad])
    code = _main(["--input", str(src), "--strict", "--no-color"])
    assert code == 1


def test_cli_missing_file_exits_one(tmp_path, capsys):
    code = _main(["--input", str(tmp_path / "missing.jsonl"), "--no-color"])
    assert code == 1


# ---------------------------------------------------------------------------
# Direct check-function unit tests (exercising functions without IO)
# ---------------------------------------------------------------------------


def test_check_duplicates_returns_one_warning_per_group():
    from src.eval.schema import EvalRecord

    records = [
        (1, EvalRecord(**_juicy_dict(path=r"C:\a.kdbx"))),
        (2, EvalRecord(**_juicy_dict(path=r"c:\A.kdbx"))),
        (3, EvalRecord(**_juicy_dict(path=r"C:\b.kdbx"))),
        (4, EvalRecord(**_juicy_dict(path=r"C:/b.kdbx"))),
    ]
    warnings = _check_duplicates(records)
    assert len(warnings) == 2
    assert all(isinstance(w, IntegrityWarning) for w in warnings)


def test_check_validator_warnings_names_returns_empty_for_all_known():
    from src.eval.schema import EvalRecord

    rec = EvalRecord(
        **_not_juicy_dict(
            path=r"C:\Users\admin\secrets.kdbx",
            category="credential_containers",
            validator_warnings=["kdbx_extension", "uncertainty_prior"],
        )
    )
    assert _check_validator_warnings_names(rec, line_num=1) == []


def test_compute_stats_handles_empty_input():
    s = _compute_stats([])
    assert s.record_count == 0
    assert s.label_dist == {}
    assert all(h.fires_count == 0 for h in s.per_heuristic)
