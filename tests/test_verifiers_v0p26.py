"""v0.26: read-only verifiers for Stripe / SendGrid / Mailgun / Twilio.

All HTTP is mocked — we never make real outbound calls in CI. Tests
validate:
  - Auth header shape (Bearer / Basic)
  - URL chosen
  - Success path returns 'passed'
  - 401 path returns 'failed'
  - Metadata extraction
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from sharesift.verify.base import VerifyConfig


def _make_response(status_code: int, body: dict | None = None) -> MagicMock:
    r = MagicMock()
    r.status_code = status_code
    r.json.return_value = body or {}
    r.headers = {"content-type": "application/json"}
    r.text = ""
    return r


# --- Stripe -----------------------------------------------------------


def test_stripe_verifier_sends_bearer_token():
    from sharesift.verify.stripe import StripeVerifier
    with patch("requests.request") as mock_req:
        mock_req.return_value = _make_response(200, {
            "id": "acct_test123",
            "country": "US",
            "livemode": False,
        })
        result = StripeVerifier().verify(
            credential="sk_live_" + "X" * 28,
            config=VerifyConfig(),
            context={"credential_type": "stripe_live_secret"},
        )
        assert mock_req.call_count == 1
        # requests.request(method, url, ...) — URL is positional arg 1.
        call = mock_req.call_args
        assert call.args[1] == "https://api.stripe.com/v1/account"
        headers = call.kwargs.get("headers", {})
        assert headers["Authorization"].startswith("Bearer ")
        assert result.status == "passed"
        assert result.metadata["account_id"] == "acct_test123"


def test_stripe_verifier_returns_failed_on_401():
    from sharesift.verify.stripe import StripeVerifier
    with patch("requests.request") as mock_req:
        mock_req.return_value = _make_response(401, {})
        result = StripeVerifier().verify(
            credential="sk_live_" + "X" * 28,
            config=VerifyConfig(),
            context={"credential_type": "stripe_live_secret"},
        )
        assert result.status == "failed"


# --- SendGrid ---------------------------------------------------------


def test_sendgrid_verifier_passes_on_200():
    from sharesift.verify.sendgrid import SendGridVerifier
    with patch("requests.request") as mock_req:
        mock_req.return_value = _make_response(200, {
            "username": "alice",
            "first_name": "Alice",
        })
        result = SendGridVerifier().verify(
            credential="SG.test.fake",
            config=VerifyConfig(),
            context={"credential_type": "sendgrid_api_key"},
        )
        assert result.status == "passed"
        assert result.metadata["username"] == "alice"


# --- Mailgun ----------------------------------------------------------


def test_mailgun_verifier_uses_http_basic():
    """Mailgun uses Basic auth with 'api' as username, key as password."""
    from sharesift.verify.mailgun import MailgunVerifier
    with patch("requests.request") as mock_req:
        mock_req.return_value = _make_response(200, {
            "items": [{"name": "mg.example.com"}],
            "total_count": 1,
        })
        result = MailgunVerifier().verify(
            credential="key-" + "a" * 32,
            config=VerifyConfig(),
            context={"credential_type": "mailgun_api_key"},
        )
        assert result.status == "passed"
        # The Authorization header should be Basic.
        call = mock_req.call_args
        headers = call.kwargs.get("headers") or {}
        assert headers["Authorization"].startswith("Basic ")
        assert result.metadata["domain_count"] == 1


# --- Twilio -----------------------------------------------------------


def test_twilio_verifier_skips_without_account_sid():
    """Twilio needs the Account SID via context. No SID → skipped."""
    from sharesift.verify.twilio import TwilioVerifier
    result = TwilioVerifier().verify(
        credential="testauthtoken123",
        config=VerifyConfig(),
        context={"credential_type": "twilio_account_sid"},
    )
    assert result.status == "skipped"
    assert result.metadata["reason"] == "no_account_sid_in_context"


def test_twilio_verifier_passes_when_account_sid_supplied():
    from sharesift.verify.twilio import TwilioVerifier
    with patch("requests.request") as mock_req:
        mock_req.return_value = _make_response(200, {
            "friendly_name": "test account",
            "status": "active",
            "type": "Full",
        })
        result = TwilioVerifier().verify(
            credential="auth_token_abc",
            config=VerifyConfig(),
            context={
                "credential_type": "twilio_account_sid",
                "username": "AC" + "a" * 32,
            },
        )
        assert result.status == "passed"
        # URL contains the SID (positional arg 1).
        url = mock_req.call_args.args[1]
        assert ("AC" + "a" * 32) in url


# --- Registry integration ---------------------------------------------


def test_v0p26_credential_types_have_registered_verifiers():
    """The 4 new verifiers must be reachable via get_verifier."""
    from sharesift.verify.registry import get_verifier
    for ct in (
        "stripe_live_secret", "stripe_live_restricted",
        "sendgrid_api_key", "mailgun_api_key",
        "twilio_account_sid", "twilio_api_key_sid",
    ):
        v = get_verifier(ct)
        assert v is not None, f"no verifier for {ct}"
