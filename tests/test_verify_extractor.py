"""Regex extraction across the supported credential formats."""

from __future__ import annotations

from sharesift.verify.extractor import extract_credentials


def test_extracts_anthropic_api_key():
    suffix = "A" * 47 + "B" * 46
    excerpt = f"ANTHROPIC_API_KEY=sk-ant-api03-{suffix}AA"
    found = extract_credentials(excerpt)
    types = {c.credential_type for c in found}
    assert "anthropic_api_key" in types


def test_extracts_openai_api_key_legacy():
    excerpt = "OPENAI_API_KEY=sk-" + "A" * 48
    found = extract_credentials(excerpt)
    types = {c.credential_type for c in found}
    assert "openai_api_key" in types


def test_extracts_openai_api_key_modern():
    cred = "sk-proj-" + "X" * 25 + "T3BlbkFJ" + "Y" * 25
    excerpt = f"OPENAI_API_KEY={cred}"
    found = extract_credentials(excerpt)
    types = {c.credential_type for c in found}
    assert "openai_api_key" in types


def test_extracts_aws_access_key():
    excerpt = "aws_access_key_id=AKIAIOSFODNN7EXAMPLE\naws_secret_access_key=..."
    found = extract_credentials(excerpt)
    types = {c.credential_type for c in found}
    assert "aws_access_key" in types


def test_extracts_github_pat_classic():
    excerpt = "GITHUB_TOKEN=ghp_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789"
    found = extract_credentials(excerpt)
    types = {c.credential_type for c in found}
    assert "github_pat_classic" in types


def test_extracts_slack_bot_token():
    excerpt = "SLACK_BOT_TOKEN=xoxb-12345-67890-abc123def456ghi789"
    found = extract_credentials(excerpt)
    types = {c.credential_type for c in found}
    assert "slack_bot_token" in types


def test_extracts_huggingface_token():
    excerpt = "HF_TOKEN=hf_" + "A" * 34
    found = extract_credentials(excerpt)
    types = {c.credential_type for c in found}
    assert "huggingface_token" in types


def test_extracts_databricks_pat():
    excerpt = "DATABRICKS_TOKEN=dapi" + "a" * 32
    found = extract_credentials(excerpt)
    types = {c.credential_type for c in found}
    assert "databricks_pat" in types


def test_empty_excerpt_returns_empty():
    assert extract_credentials("") == []
    assert extract_credentials(None) == []  # type: ignore[arg-type]


def test_no_credentials_returns_empty():
    excerpt = "This file has nothing interesting in it."
    assert extract_credentials(excerpt) == []


def test_dedup_same_credential_in_one_excerpt():
    """Same string matched by multiple patterns should yield distinct
    (type, value) tuples — the runner dedupes at dispatch time."""
    cred = "sk-" + "A" * 48
    excerpt = f"a={cred} b={cred}"
    found = extract_credentials(excerpt)
    # Same (type, value) appears once even though the pattern matches twice
    keys = [(c.credential_type, c.value) for c in found]
    assert keys.count(("openai_api_key", cred)) == 1


def test_extracts_multiple_distinct_credentials():
    suffix = "A" * 47 + "B" * 46
    excerpt = (
        f"ANTHROPIC={suffix and 'sk-ant-api03-' + suffix + 'AA'}\n"
        "AWS=AKIAIOSFODNN7EXAMPLE\n"
        "GITHUB=ghp_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789\n"
    )
    found = extract_credentials(excerpt)
    types = {c.credential_type for c in found}
    assert {"anthropic_api_key", "aws_access_key", "github_pat_classic"} <= types
