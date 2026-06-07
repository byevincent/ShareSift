"""End-to-end runner skip + dry-run paths."""

from __future__ import annotations

from sharesift.verify import VerifyConfig, verify_records


def test_skips_record_without_content_excerpt():
    records = [{"path": "/foo", "content_excerpt": None}]
    out = verify_records(records, VerifyConfig(dry_run=True))
    assert out[0]["verification_status"] == "skipped"
    assert out[0]["extracted_credential_types"] == []


def test_skips_record_without_extractable_credential():
    records = [{"path": "/foo", "content_excerpt": "lorem ipsum"}]
    out = verify_records(records, VerifyConfig(dry_run=True))
    assert out[0]["verification_status"] == "skipped"


def test_dry_run_reports_skipped_with_specific_credential_type():
    suffix = "A" * 47 + "B" * 46
    records = [
        {"path": "/foo", "content_excerpt": f"sk-ant-api03-{suffix}AA"},
    ]
    out = verify_records(records, VerifyConfig(dry_run=True))
    assert out[0]["verification_status"] == "skipped"
    assert "anthropic_api_key" in out[0]["extracted_credential_types"]
    results = out[0]["verification_results"]
    assert all(r["status"] == "skipped" for r in results)
    assert all(r["metadata"]["reason"] == "dry_run" for r in results)


def test_only_filter_restricts_dispatch():
    """--only foo limits which credential types are sent to verifiers."""
    suffix = "A" * 47 + "B" * 46
    excerpt = (
        f"ANTHROPIC=sk-ant-api03-{suffix}AA\n"
        "GITHUB=ghp_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789"
    )
    records = [{"path": "/foo", "content_excerpt": excerpt}]
    out = verify_records(
        records,
        VerifyConfig(dry_run=True, only={"github_pat_classic"}),
    )
    assert out[0]["extracted_credential_types"] == ["github_pat_classic"]


def test_passes_through_unrelated_record_fields():
    suffix = "A" * 47 + "B" * 46
    records = [
        {
            "path": "/p",
            "path_tier": "Black",
            "path_probability": 0.99,
            "content_check": "yes",
            "content_excerpt": f"sk-ant-api03-{suffix}AA",
            "custom_operator_tag": "engagement_xyz",
        }
    ]
    out = verify_records(records, VerifyConfig(dry_run=True))
    assert out[0]["custom_operator_tag"] == "engagement_xyz"
    assert out[0]["path_tier"] == "Black"
