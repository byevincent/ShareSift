"""v0.34: end-to-end smoke — the DiskForge-planted GCP SA JSON
flows correctly through the v0.32 extractor and the v0.33 verifier.

This is the integration check that complements the unit tests in
``test_gcp_v0p32.py`` and ``test_gcp_live_v0p33.py``. Those mock the
verifier's inputs; this one reads the actual planted file the v0.31
build_manifest.py generates (committed at
``tools/diskforge_v0p31/files/plant/gcp_service_account.json``).
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
PLANTED_SA_PATH = (
    REPO_ROOT
    / "tools"
    / "diskforge_v0p31"
    / "files"
    / "plant"
    / "gcp_service_account.json"
)


def test_planted_sa_json_exists():
    """The planted file is the source the v0.31 build_manifest.py
    reproduces from. If it's missing, the whole DiskForge GCP smoke
    falls through."""
    assert PLANTED_SA_PATH.exists(), (
        f"planted SA JSON missing at {PLANTED_SA_PATH}; "
        f"run `uv run python tools/diskforge_v0p31/build_manifest.py` "
        f"after `uv sync --group verify` to regenerate"
    )


def test_planted_sa_json_is_caught_by_extractor():
    """The v0.32 multi-field regex captures the whole JSON object from
    the planted file's content."""
    from sharesift.verify.extractor import extract_credentials

    content = PLANTED_SA_PATH.read_text(encoding="utf-8")
    creds = extract_credentials(content)
    cred_types = {c.credential_type for c in creds}
    assert "gcp_service_account_json" in cred_types, (
        f"extractor failed to catch planted SA JSON; got types: {cred_types}"
    )


def test_planted_sa_json_passes_structural_verifier(monkeypatch):
    """The planted SA JSON should pass structural validation. We
    monkeypatch the live helper to None so the test doesn't depend on
    pyjwt being installed in CI."""
    from sharesift.verify import gcp_service_account as gcp_sa
    from sharesift.verify.base import VerifyConfig
    from sharesift.verify.extractor import extract_credentials

    monkeypatch.setattr(gcp_sa, "_try_live_verification", lambda data, config: None)

    content = PLANTED_SA_PATH.read_text(encoding="utf-8")
    creds = extract_credentials(content)
    sa_cred = next(c for c in creds if c.credential_type == "gcp_service_account_json")

    result = gcp_sa.GcpServiceAccountVerifier().verify(
        credential=sa_cred.value,
        config=VerifyConfig(),
        context={"credential_type": "gcp_service_account_json"},
    )
    assert result.status == "passed"
    assert result.metadata["validation_mode"] == "structural"
    assert "synthetic-v0p34" in (result.metadata.get("client_email") or "")


def test_planted_sa_json_signs_real_jwt_in_live_path():
    """When the live OAuth path runs (pyjwt[crypto] installed), the
    planted SA's RSA private key actually signs a JWT. We mock the
    OAuth POST to return 200; the JWT signing itself uses the real key."""
    from sharesift.verify.base import VerifyConfig
    from sharesift.verify.extractor import extract_credentials
    from sharesift.verify.gcp_service_account import GcpServiceAccountVerifier

    content = PLANTED_SA_PATH.read_text(encoding="utf-8")
    creds = extract_credentials(content)
    sa_cred = next(c for c in creds if c.credential_type == "gcp_service_account_json")

    with patch("requests.post") as mock_post:
        ok = MagicMock()
        ok.status_code = 200
        ok.json.return_value = {
            "access_token": "ya29.synthetic-from-diskforge-plant",
            "token_type": "Bearer",
            "expires_in": 3599,
        }
        mock_post.return_value = ok

        result = GcpServiceAccountVerifier().verify(
            credential=sa_cred.value,
            config=VerifyConfig(),
            context={"credential_type": "gcp_service_account_json"},
        )
        assert result.status == "passed"
        assert result.metadata["validation_mode"] == "live"
        # Confirm the JWT we sent was non-trivial (real signing happened).
        assertion = mock_post.call_args.kwargs["data"]["assertion"]
        assert len(assertion) > 200
