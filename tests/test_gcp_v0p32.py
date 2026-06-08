"""v0.32: GCP service-account JSON — extractor (full JSON capture) +
structural verifier.

The v0.31 release found that the v0.23 ``gcp_service_account_email``
extractor caught only the email match, not the full JSON needed to
verify. v0.32 adds:

* ``gcp_service_account_json`` credential type — extractor captures
  the entire ``{...}`` block.
* ``GcpServiceAccountVerifier`` — structural validation (required
  fields, PEM-shaped private key, well-formed email).
* Documentation that live OAuth verification is v0.33+ work.
"""

from __future__ import annotations

import json

from sharesift.verify.base import VerifyConfig
from sharesift.verify.extractor import extract_credentials


# Synthetic SA JSON — only-PEM-shape private_key, obviously fake values.
_SYNTHETIC_SA = {
    "type": "service_account",
    "project_id": "my-test-project",
    "private_key_id": "fakeb0fakeb0fakeb0fakeb0fakeb0fakeb0fakeb",
    "private_key": (
        "-----BEGIN PRIVATE KEY-----\n"
        "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCfakeb0\n"
        "fakeb0fakeb0fakeb0fakeb0fakeb0fakeb0fakeb0fakeb0fakeb0fak\n"
        "fakeb0fakeb0fakeb0fakeb0fakeb0fakeb0fakeb0fakeb0fakeb0fak\n"
        "-----END PRIVATE KEY-----\n"
    ),
    "client_email": "synthetic-sa@my-test-project.iam.gserviceaccount.com",
    "client_id": "111111111111111111111",
    "auth_uri": "https://accounts.google.com/o/oauth2/auth",
    "token_uri": "https://oauth2.googleapis.com/token",
    "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
    "client_x509_cert_url": "https://www.googleapis.com/robot/v1/metadata/x509/synthetic-sa%40my-test-project.iam.gserviceaccount.com",
}


def _sa_json_blob() -> str:
    """Single-line JSON without nested objects — what the extractor regex expects."""
    # Use ensure_ascii=False so embedded newlines in private_key stay literal.
    payload = dict(_SYNTHETIC_SA)
    # Inline the private_key newlines as \n escapes so the JSON is a single { ... } block.
    payload["private_key"] = (
        "-----BEGIN PRIVATE KEY-----\\n"
        "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCfakeb0\\n"
        "fakeb0fakeb0fakeb0fakeb0fakeb0fakeb0fakeb0fakeb0fakeb0fak\\n"
        "-----END PRIVATE KEY-----\\n"
    )
    return json.dumps(payload, separators=(",", ":"))


# --- Extractor -------------------------------------------------------


def test_extractor_captures_full_sa_json():
    """The v0.32 multi-field regex captures the whole JSON object, not
    just the email."""
    blob = _sa_json_blob()
    creds = extract_credentials(blob)
    types = {c.credential_type for c in creds}
    assert "gcp_service_account_json" in types
    # Find the SA JSON match and confirm it contains all three signature fields.
    sa_match = next(c for c in creds if c.credential_type == "gcp_service_account_json")
    assert "service_account" in sa_match.value
    assert "private_key" in sa_match.value
    assert "client_email" in sa_match.value


def test_extractor_preserves_legacy_email_type():
    """The v0.23 ``gcp_service_account_email`` shape stays catchable —
    we kept it for back-compat with older scan outputs."""
    blob = _sa_json_blob()
    types = {c.credential_type for c in extract_credentials(blob)}
    assert "gcp_service_account_email" in types


def test_extractor_does_not_match_partial_sa_json():
    """A JSON with the email but missing private_key shouldn't fire the
    full-JSON credential type (the legacy email-only matcher will)."""
    partial = json.dumps({
        "type": "service_account",
        "client_email": "compute@my-project.iam.gserviceaccount.com",
    }, separators=(",", ":"))
    types = {c.credential_type for c in extract_credentials(partial)}
    assert "gcp_service_account_json" not in types
    assert "gcp_service_account_email" in types


# --- Verifier --------------------------------------------------------


def test_verifier_passes_on_well_formed_sa_json():
    from sharesift.verify.gcp_service_account import GcpServiceAccountVerifier
    result = GcpServiceAccountVerifier().verify(
        credential=_sa_json_blob(),
        config=VerifyConfig(),
        context={"credential_type": "gcp_service_account_json"},
    )
    assert result.status == "passed"
    assert result.metadata["validation_mode"] == "structural"
    assert result.metadata["client_email"] == _SYNTHETIC_SA["client_email"]


def test_verifier_fails_on_missing_required_field():
    from sharesift.verify.gcp_service_account import GcpServiceAccountVerifier
    broken = json.dumps({
        "type": "service_account",
        "client_email": "x@y.iam.gserviceaccount.com",
        # missing private_key, project_id, token_uri
    }, separators=(",", ":"))
    result = GcpServiceAccountVerifier().verify(
        credential=broken,
        config=VerifyConfig(),
        context={"credential_type": "gcp_service_account_json"},
    )
    assert result.status == "failed"
    assert "missing_fields" in (result.error or "")


def test_verifier_fails_on_non_service_account_type():
    from sharesift.verify.gcp_service_account import GcpServiceAccountVerifier
    user_creds = json.dumps({
        "type": "authorized_user",
        "project_id": "x",
        "private_key": "-----BEGIN PRIVATE KEY-----\\nfake\\n-----END PRIVATE KEY-----",
        "client_email": "x@y.iam.gserviceaccount.com",
        "token_uri": "https://oauth2.googleapis.com/token",
    }, separators=(",", ":"))
    result = GcpServiceAccountVerifier().verify(
        credential=user_creds,
        config=VerifyConfig(),
        context={"credential_type": "gcp_service_account_json"},
    )
    assert result.status == "failed"
    assert "wrong_type" in (result.error or "")


def test_verifier_fails_on_malformed_email():
    from sharesift.verify.gcp_service_account import GcpServiceAccountVerifier
    broken = dict(_SYNTHETIC_SA)
    broken["client_email"] = "not-an-iam-email"
    result = GcpServiceAccountVerifier().verify(
        credential=json.dumps(broken, separators=(",", ":")),
        config=VerifyConfig(),
        context={"credential_type": "gcp_service_account_json"},
    )
    assert result.status == "failed"
    assert "malformed_client_email" in (result.error or "")


def test_verifier_fails_on_non_pem_private_key():
    from sharesift.verify.gcp_service_account import GcpServiceAccountVerifier
    broken = dict(_SYNTHETIC_SA)
    broken["private_key"] = "not_a_pem_key"
    result = GcpServiceAccountVerifier().verify(
        credential=json.dumps(broken, separators=(",", ":")),
        config=VerifyConfig(),
        context={"credential_type": "gcp_service_account_json"},
    )
    assert result.status == "failed"
    assert "private_key_not_pem_shaped" in (result.error or "")


def test_verifier_fails_on_invalid_json():
    from sharesift.verify.gcp_service_account import GcpServiceAccountVerifier
    result = GcpServiceAccountVerifier().verify(
        credential="not json at all",
        config=VerifyConfig(),
        context={"credential_type": "gcp_service_account_json"},
    )
    assert result.status == "failed"
    assert "not_valid_json" in (result.error or "")


def test_verifier_registered_in_verifier_registry():
    from sharesift.verify.registry import get_verifier
    v = get_verifier("gcp_service_account_json")
    assert v is not None
