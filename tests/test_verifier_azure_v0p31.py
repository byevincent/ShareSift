"""v0.31: Azure Storage Shared Key verifier."""

from __future__ import annotations

import base64
from unittest.mock import MagicMock, patch

from sharesift.verify.base import VerifyConfig


def _make_response(status_code: int, body: dict | None = None) -> MagicMock:
    r = MagicMock()
    r.status_code = status_code
    r.json.return_value = body or {}
    r.headers = {"content-type": "application/xml"}
    r.text = ""
    return r


def test_azure_storage_skips_on_garbage_connection_string():
    from sharesift.verify.azure_storage import AzureStorageVerifier
    result = AzureStorageVerifier().verify(
        credential="not_a_connection_string",
        config=VerifyConfig(),
        context={"credential_type": "azure_storage_connection_string"},
    )
    assert result.status == "skipped"
    assert "parse" in (result.metadata.get("reason") or "")


def test_azure_storage_passes_on_200():
    """Valid connection string → 200 from ListContainers → passed."""
    from sharesift.verify.azure_storage import AzureStorageVerifier
    # Synthetic connection string with a base64-decodable key
    # (32 bytes b64-encoded = 44 chars). 'A' * 44 decodes cleanly.
    cred = (
        "DefaultEndpointsProtocol=https;"
        "AccountName=fakeaccount;"
        "AccountKey=" + "A" * 88 + "=="
    )
    with patch("requests.request") as mock_req:
        mock_req.return_value = _make_response(200)
        result = AzureStorageVerifier().verify(
            credential=cred,
            config=VerifyConfig(),
            context={"credential_type": "azure_storage_connection_string"},
        )
        assert result.status == "passed"
        # URL contains the account name (positional arg 1).
        url = mock_req.call_args.args[1]
        assert "fakeaccount.blob.core.windows.net" in url
        # Authorization header is SharedKey-shaped.
        headers = mock_req.call_args.kwargs.get("headers", {})
        assert headers["Authorization"].startswith("SharedKey fakeaccount:")


def test_azure_storage_fails_on_403():
    from sharesift.verify.azure_storage import AzureStorageVerifier
    cred = (
        "AccountName=fakeaccount;"
        "AccountKey=" + base64.b64encode(b"x" * 32).decode()
    )
    with patch("requests.request") as mock_req:
        mock_req.return_value = _make_response(403)
        result = AzureStorageVerifier().verify(
            credential=cred,
            config=VerifyConfig(),
            context={"credential_type": "azure_storage_connection_string"},
        )
        assert result.status == "failed"


def test_azure_storage_signature_is_deterministic():
    """Same key + same date string → same signature. Sanity check that
    the Shared Key signing logic is doing HMAC-SHA256 over the documented
    canonicalized string."""
    from sharesift.verify.azure_storage import _shared_key_signature
    key = base64.b64encode(b"x" * 32).decode()
    sig1 = _shared_key_signature("acct", key, "/acct/\ncomp:list", "Sun, 08 Jun 2026 12:00:00 GMT")
    sig2 = _shared_key_signature("acct", key, "/acct/\ncomp:list", "Sun, 08 Jun 2026 12:00:00 GMT")
    assert sig1 == sig2
    # Signature is base64 of a 32-byte HMAC-SHA256.
    decoded = base64.b64decode(sig1)
    assert len(decoded) == 32


def test_azure_storage_signature_changes_with_date():
    from sharesift.verify.azure_storage import _shared_key_signature
    key = base64.b64encode(b"x" * 32).decode()
    s1 = _shared_key_signature("acct", key, "/acct/\ncomp:list", "Sun, 08 Jun 2026 12:00:00 GMT")
    s2 = _shared_key_signature("acct", key, "/acct/\ncomp:list", "Sun, 08 Jun 2026 13:00:00 GMT")
    assert s1 != s2


def test_azure_storage_registered_in_verifier_registry():
    from sharesift.verify.registry import get_verifier
    v = get_verifier("azure_storage_connection_string")
    assert v is not None
