"""Mocked HTTP verifier sanity tests.

Uses ``unittest.mock`` to swap out ``requests.request`` so we exercise
the ``_http.http_verify`` mapping logic without touching the network.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from sharesift.verify.anthropic import AnthropicVerifier
from sharesift.verify.base import VerifyConfig
from sharesift.verify.github import GitHubVerifier


def _fake_response(status: int, body: dict | None = None) -> MagicMock:
    resp = MagicMock()
    resp.status_code = status
    resp.json.return_value = body or {}
    resp.text = ""
    return resp


def test_anthropic_passed_extracts_model_count():
    cfg = VerifyConfig(timeout_sec=5.0)
    with patch("requests.request") as req:
        req.return_value = _fake_response(200, {"data": [{"id": "claude-3"}]})
        result = AnthropicVerifier().verify("sk-ant-fake", cfg)
    assert result.status == "passed"
    assert result.metadata.get("model_count") == 1


def test_anthropic_failed_401():
    cfg = VerifyConfig(timeout_sec=5.0)
    with patch("requests.request") as req:
        req.return_value = _fake_response(401, {"error": {"message": "invalid"}})
        result = AnthropicVerifier().verify("sk-ant-fake", cfg)
    assert result.status == "failed"
    assert result.error == "http_401"


def test_github_passed_extracts_login():
    cfg = VerifyConfig(timeout_sec=5.0)
    with patch("requests.request") as req:
        req.return_value = _fake_response(
            200, {"login": "octocat", "id": 1, "type": "User"}
        )
        result = GitHubVerifier().verify("ghp_fake", cfg)
    assert result.status == "passed"
    assert result.metadata.get("login") == "octocat"
    assert result.metadata.get("user_id") == 1


def test_github_inconclusive_on_502():
    cfg = VerifyConfig(timeout_sec=5.0)
    with patch("requests.request") as req:
        req.return_value = _fake_response(502)
        result = GitHubVerifier().verify("ghp_fake", cfg)
    assert result.status == "inconclusive"


def test_dry_run_short_circuits_before_http():
    cfg = VerifyConfig(dry_run=True)
    with patch("requests.request") as req:
        result = AnthropicVerifier().verify("sk-ant-fake", cfg)
    assert result.status == "skipped"
    assert req.call_count == 0
