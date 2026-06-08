"""v0.23: new credential-format extractors.

Each test uses a synthetic example matching the documented credential
shape — NOT a real CredData / MSF3 string. We're testing "extractor
recognises documented Stripe key shape," not "extractor happens to
catch what's in the benchmark."
"""

from __future__ import annotations

from sharesift.verify.extractor import extract_credentials


def _types_in(text: str) -> set[str]:
    return {c.credential_type for c in extract_credentials(text)}


def test_stripe_live_secret_matches_documented_shape():
    # Obviously-synthetic — all X's, no entropy. Tests regex shape only.
    text = "STRIPE_SECRET = sk_live_" + "X" * 28
    assert "stripe_live_secret" in _types_in(text)


def test_stripe_live_restricted_matches():
    text = "key=rk_live_" + "Y" * 28
    assert "stripe_live_restricted" in _types_in(text)


def test_stripe_live_publishable_matches():
    text = "PUBLIC_KEY = pk_live_" + "Z" * 28
    assert "stripe_live_publishable" in _types_in(text)


def test_sendgrid_matches_dotted_shape():
    text = "SG_API = SG.AAAAAAAAAAAAAAAAAAAAAA.BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
    assert "sendgrid_api_key" in _types_in(text)


def test_mailgun_matches_key_hex_shape():
    # Obviously-synthetic — all 'a' chars satisfy [a-f0-9]{32}.
    text = "MAILGUN_API = key-" + "a" * 32
    assert "mailgun_api_key" in _types_in(text)


def test_twilio_account_sid_matches():
    text = "TWILIO_ACCOUNT = AC" + "a" * 32
    assert "twilio_account_sid" in _types_in(text)


def test_twilio_api_key_sid_matches():
    text = "API_KEY_SID = SK" + "b" * 32
    assert "twilio_api_key_sid" in _types_in(text)


def test_azure_storage_connection_string_matches():
    text = (
        "CONN_STR = DefaultEndpointsProtocol=https;"
        "AccountName=fakeaccount;"
        "AccountKey=" + "A" * 88 + "=="
    )
    assert "azure_storage_connection_string" in _types_in(text)


def test_gcp_service_account_email_matches():
    text = (
        '{"type": "service_account",'
        ' "client_email": "compute@my-project.iam.gserviceaccount.com"}'
    )
    assert "gcp_service_account_email" in _types_in(text)


def test_extractor_does_not_false_positive_on_plain_prose():
    """A document mentioning 'stripe payment' as English prose
    shouldn't fire the Stripe key pattern."""
    text = (
        "We use Stripe for payments. Our publishable key is stored "
        "in the environment configuration."
    )
    types = _types_in(text)
    for t in (
        "stripe_live_secret",
        "stripe_live_restricted",
        "stripe_live_publishable",
        "sendgrid_api_key",
        "mailgun_api_key",
    ):
        assert t not in types, f"false positive on prose: {t}"
