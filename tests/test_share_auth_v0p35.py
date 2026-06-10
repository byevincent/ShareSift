"""v0.35 Sprint 2 — Auth dataclass + credential dispatch tests.

Validates the pure-Python dispatch path that the SmbShare backend
hands to ``smbprotocol.session.Session``. Lab-validated against
Samba 4.12 on 2026-06-08.
"""

from __future__ import annotations

import pytest

# These tests exercise the smbprotocol-backed Auth path, which depends
# on spnego (transitive via smbprotocol). CI runs without the [smb]
# extra, so collect-skip the module when spnego isn't installed.
pytest.importorskip("spnego")

from spnego._credential import NTLMHash  # noqa: E402

from sharesift.share import Auth, build_credential  # noqa: E402
from sharesift.share.auth import BLANK_LM_HASH, _parse_hash  # noqa: E402


class TestAuthValidation:
    def test_requires_at_least_one_mode(self):
        with pytest.raises(ValueError, match="one of"):
            Auth(user="u")

    def test_rejects_two_modes_together(self):
        with pytest.raises(ValueError, match="mutually exclusive"):
            Auth(user="u", password="p", hash="aa" * 16)

    def test_kerberos_with_password_rejected(self):
        with pytest.raises(ValueError, match="mutually exclusive"):
            Auth(user="u", password="p", kerberos=True)

    def test_anonymous_with_password_rejected(self):
        with pytest.raises(ValueError, match="mutually exclusive"):
            Auth(user="u", password="p", anonymous=True)

    def test_password_mode_requires_user(self):
        with pytest.raises(ValueError, match="user"):
            Auth(password="pw")

    def test_anonymous_does_not_require_user(self):
        a = Auth(anonymous=True)
        assert a.user is None
        assert a.anonymous is True


class TestParseHash:
    def test_lm_nt_form(self):
        lm, nt = _parse_hash("aad3b435b51404eeaad3b435b51404ee:27c433245e4763d074d30a05aae0af2c")
        assert lm == "aad3b435b51404eeaad3b435b51404ee"
        assert nt == "27c433245e4763d074d30a05aae0af2c"

    def test_bare_nt_form_fills_blank_lm(self):
        lm, nt = _parse_hash("27c433245e4763d074d30a05aae0af2c")
        assert lm == BLANK_LM_HASH
        assert nt == "27c433245e4763d074d30a05aae0af2c"

    def test_uppercase_normalized_to_lower(self):
        lm, nt = _parse_hash("27C433245E4763D074D30A05AAE0AF2C")
        assert nt == "27c433245e4763d074d30a05aae0af2c"

    def test_leading_colon_means_blank_lm(self):
        lm, nt = _parse_hash(":27c433245e4763d074d30a05aae0af2c")
        assert lm == BLANK_LM_HASH
        assert nt == "27c433245e4763d074d30a05aae0af2c"

    def test_whitespace_stripped(self):
        lm, nt = _parse_hash("  aad3b435b51404eeaad3b435b51404ee : 27c433245e4763d074d30a05aae0af2c  ")
        assert lm == "aad3b435b51404eeaad3b435b51404ee"
        assert nt == "27c433245e4763d074d30a05aae0af2c"

    def test_short_nt_rejected(self):
        with pytest.raises(ValueError, match="32 hex"):
            _parse_hash("27c4")

    def test_non_hex_rejected(self):
        with pytest.raises(ValueError, match="32 hex"):
            _parse_hash("zz" * 16)

    def test_empty_after_colon_rejected(self):
        with pytest.raises(ValueError, match="NT"):
            _parse_hash("aad3:")


class TestBuildCredential:
    def test_password_auth_returns_user_password_tuple(self):
        auth = Auth(user="msfadmin", password="msfadmin")
        username, password, protocol = build_credential(auth)
        assert username == "msfadmin"
        assert password == "msfadmin"
        assert protocol == "ntlm"

    def test_password_auth_with_domain_qualifies_user(self):
        auth = Auth(user="alice", password="pw", domain="CORP")
        username, _, _ = build_credential(auth)
        assert username == "CORP\\alice"

    def test_hash_auth_returns_ntlmhash_object(self):
        nt = "27c433245e4763d074d30a05aae0af2c"
        auth = Auth(user="msfadmin", hash=nt)
        username, password, protocol = build_credential(auth)
        assert isinstance(username, NTLMHash)
        assert username.nt_hash == nt
        assert username.lm_hash == BLANK_LM_HASH
        assert password is None
        assert protocol == "ntlm"

    def test_hash_auth_with_lm_nt_form(self):
        lm = "aad3b435b51404eeaad3b435b51404ee"
        nt = "27c433245e4763d074d30a05aae0af2c"
        auth = Auth(user="msfadmin", hash=f"{lm}:{nt}")
        username, _, _ = build_credential(auth)
        assert isinstance(username, NTLMHash)
        assert username.lm_hash == lm
        assert username.nt_hash == nt

    def test_kerberos_auth_no_password_uses_kerberos_protocol(self):
        auth = Auth(user="alice", kerberos=True, domain="CORP")
        username, password, protocol = build_credential(auth)
        assert username == "CORP\\alice"
        assert password is None
        assert protocol == "kerberos"

    def test_anonymous_returns_empty_strings(self):
        auth = Auth(anonymous=True)
        username, password, protocol = build_credential(auth)
        assert username == ""
        assert password == ""
        assert protocol == "ntlm"
