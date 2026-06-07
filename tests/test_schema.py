from datetime import date

import pytest
from pydantic import ValidationError

from src.eval.categories import SOURCES
from src.eval.schema import MIN_NOTES_LEN, EvalRecord


def _base_juicy() -> dict:
    return {
        "path": r"C:\Users\admin\Documents\secrets.kdbx",
        "label": "juicy",
        "tier": "Red",
        "category": "credential_containers",
        "source": "engagement",
        "notes": "KeePass vault on admin profile.",
        "added_date": date(2026, 5, 17),
    }


def _base_not_juicy() -> dict:
    return {
        "path": r"C:\Windows\System32\notepad.exe",
        "label": "not_juicy",
        "category": "decoy_docs",
        "source": "engagement",
        "notes": "System binary; not credential material.",
        "added_date": date(2026, 5, 17),
    }


def test_minimal_juicy_record_validates():
    EvalRecord(**_base_juicy())


def test_minimal_not_juicy_record_validates():
    EvalRecord(**_base_not_juicy())


def test_juicy_without_tier_fails():
    data = _base_juicy()
    del data["tier"]
    with pytest.raises(ValidationError, match="tier is required when label is 'juicy'"):
        EvalRecord(**data)


def test_not_juicy_with_tier_fails():
    data = _base_not_juicy()
    data["tier"] = "Red"
    with pytest.raises(ValidationError, match="tier must be omitted"):
        EvalRecord(**data)


def test_modern_saas_with_subtype_validates():
    data = _base_juicy()
    data["category"] = "modern_saas_tokens"
    data["sub_type"] = "ai_llm"
    record = EvalRecord(**data)
    assert record.sub_type == "ai_llm"


def test_modern_saas_without_subtype_fails():
    data = _base_juicy()
    data["category"] = "modern_saas_tokens"
    with pytest.raises(ValidationError, match="sub_type is required"):
        EvalRecord(**data)


def test_non_modern_category_with_subtype_fails():
    data = _base_juicy()
    data["sub_type"] = "ai_llm"
    with pytest.raises(ValidationError, match="sub_type must be None"):
        EvalRecord(**data)


@pytest.mark.parametrize(
    "field,bad_value",
    [
        ("label", "very_juicy"),
        ("tier", "Purple"),
        ("category", "made_up_category"),
        ("sub_type", "fake_subtype"),
        ("source", "telepathy"),
    ],
)
def test_invalid_enum_values_fail(field, bad_value):
    data = _base_juicy()
    if field == "sub_type":
        data["category"] = "modern_saas_tokens"
    data[field] = bad_value
    with pytest.raises(ValidationError):
        EvalRecord(**data)


@pytest.mark.parametrize(
    "bad_path",
    [
        "",
        " C:\\file.txt",
        "C:\\file.txt ",
        "C:\\file\nwith\nnewlines.txt",
        "C:\\file\twith\ttabs.txt",
    ],
)
def test_malformed_paths_fail(bad_path):
    data = _base_juicy()
    data["path"] = bad_path
    with pytest.raises(ValidationError):
        EvalRecord(**data)


@pytest.mark.parametrize(
    "good_path",
    [
        r"C:\Users\admin\Documents\file.kdbx",
        r"\\fileserver\share$\folder\file.txt",
        r"D:\backups\db.bak",
        r"file.txt",
    ],
)
def test_well_formed_paths_validate(good_path):
    data = _base_juicy()
    data["path"] = good_path
    EvalRecord(**data)


def test_notes_below_threshold_fails():
    data = _base_juicy()
    data["notes"] = "x" * (MIN_NOTES_LEN - 1)
    with pytest.raises(ValidationError, match="notes must be at least"):
        EvalRecord(**data)


def test_notes_at_threshold_validates():
    data = _base_juicy()
    data["notes"] = "x" * MIN_NOTES_LEN
    EvalRecord(**data)


def test_notes_whitespace_only_below_threshold_fails():
    data = _base_juicy()
    data["notes"] = "   short notes   "  # 11 non-whitespace chars
    with pytest.raises(ValidationError, match="notes must be at least"):
        EvalRecord(**data)


def test_defaults_applied():
    record = EvalRecord(**_base_juicy())
    assert record.added_by == "vincent"
    assert record.validator_warnings == []
    assert record.pre_category is None
    assert record.sub_type is None


@pytest.mark.parametrize("source", SOURCES)
def test_each_source_value_validates(source):
    data = _base_juicy()
    data["source"] = source
    record = EvalRecord(**data)
    assert record.source == source


def test_record_with_pre_category_and_warnings():
    data = _base_juicy()
    data["pre_category"] = "credential_containers"
    data["validator_warnings"] = ["ext_kdbx_but_labeled_not_juicy"]
    record = EvalRecord(**data)
    assert record.pre_category == "credential_containers"
    assert record.validator_warnings == ["ext_kdbx_but_labeled_not_juicy"]
