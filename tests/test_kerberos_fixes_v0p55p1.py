"""v0.55.1: Kerberos ccache path fixes from HTB Sauna smoke test.

Three real findings surfaced on 2026-06-11 against HTB Sauna
(EGOTISTICAL-BANK.LOCAL):

1. ``Auth(kerberos=True)`` raised ``Auth requires a user`` even
   though the user principal lives in the ccache.
2. impacket's ``kerberosLogin`` was called without ``kdcHost``,
   so it tried to resolve ``<realm>:88`` via DNS and failed.
3. HTB lab DCs run with clocks ~7h ahead of attacker-box time;
   ``KRB_AP_ERR_SKEW(Clock skew too great)`` killed every AP-REQ.
   Fixed via a surgical monkey-patch of impacket's krb5 datetime
   module that adds the ccache-derived offset to all
   ``datetime.datetime.now(tz)`` calls.
"""

from __future__ import annotations

import importlib.util
import struct
import tempfile
import time
from pathlib import Path
from unittest.mock import patch

import pytest

from sharesift.share import Auth


_HAS_IMPACKET = importlib.util.find_spec("impacket") is not None
_needs_impacket = pytest.mark.skipif(
    not _HAS_IMPACKET, reason="needs network-enum extra (impacket)",
)


# --- Auth user-optional for Kerberos -----------------------------


class TestAuthKerberosUserOptional:
    def test_kerberos_no_user_is_allowed(self):
        # Pre-v0.55.1 this raised "Auth requires a user".
        auth = Auth(kerberos=True)
        assert auth.kerberos is True
        assert auth.user is None

    def test_password_still_requires_user(self):
        with pytest.raises(ValueError, match="Auth requires a user"):
            Auth(password="pw")

    def test_hash_still_requires_user(self):
        with pytest.raises(ValueError, match="Auth requires a user"):
            Auth(hash="aad3b435b51404eeaad3b435b51404ee:" + "a" * 32)

    def test_kerberos_with_user_still_valid(self):
        # Both forms are valid: with user (explicit principal) and
        # without (read from ccache).
        auth = Auth(kerberos=True, user="alice")
        assert auth.user == "alice"


# --- Auth.kdc_host field -----------------------------------------


class TestAuthKdcHost:
    def test_kdc_host_default_none(self):
        auth = Auth(kerberos=True)
        assert auth.kdc_host is None

    def test_kdc_host_explicit(self):
        auth = Auth(kerberos=True, kdc_host="10.129.13.53")
        assert auth.kdc_host == "10.129.13.53"


# --- impacket dispatch passes kdc_host -----------------------------


@_needs_impacket
class TestKerberosKdcHostPassthrough:
    """The impacket login dispatch (share.discovery + share.smb_impacket)
    forwards Auth.kdc_host to kerberosLogin; falls back to the target
    host when None."""

    def test_discovery_passes_explicit_kdc_host(self):
        from unittest.mock import MagicMock

        from sharesift.share.discovery import _do_login

        conn = MagicMock()
        auth = Auth(kerberos=True, kdc_host="10.0.0.5")
        _do_login(conn, auth, host="10.99.99.99")
        call_kwargs = conn.kerberosLogin.call_args.kwargs
        assert call_kwargs["kdcHost"] == "10.0.0.5"

    def test_discovery_falls_back_to_host_when_kdc_host_none(self):
        from unittest.mock import MagicMock

        from sharesift.share.discovery import _do_login

        conn = MagicMock()
        auth = Auth(kerberos=True)
        _do_login(conn, auth, host="10.129.13.53")
        call_kwargs = conn.kerberosLogin.call_args.kwargs
        assert call_kwargs["kdcHost"] == "10.129.13.53"

    def test_smb_impacket_walker_passes_kdc_host(self):
        from unittest.mock import MagicMock

        from sharesift.share.smb_impacket import ImpacketSmbWalker
        from sharesift.share.target import SmbTarget

        target = SmbTarget(host="10.0.0.5", share="X", port=445)
        walker = ImpacketSmbWalker(
            target, Auth(kerberos=True, kdc_host="10.99.99.99"),
        )
        with patch("impacket.smbconnection.SMBConnection") as MockConn:
            inst = MagicMock()
            MockConn.return_value = inst
            walker._ensure_connected()
            call_kwargs = inst.kerberosLogin.call_args.kwargs
            assert call_kwargs["kdcHost"] == "10.99.99.99"


# --- install_kerberos_clock_offset --------------------------------


@_needs_impacket
class TestClockOffsetShim:
    def test_returns_none_when_no_ccache(self, monkeypatch):
        from sharesift.share.auth import install_kerberos_clock_offset

        monkeypatch.delenv("KRB5CCNAME", raising=False)
        result = install_kerberos_clock_offset()
        assert result is None

    def test_returns_none_when_ccache_path_missing(self, tmp_path):
        from sharesift.share.auth import install_kerberos_clock_offset

        nonexistent = tmp_path / "does-not-exist.ccache"
        result = install_kerberos_clock_offset(str(nonexistent))
        assert result is None

    def test_zero_offset_within_tolerance(self, tmp_path):
        """authtime ≈ now → no shim installed."""
        from sharesift.share.auth import install_kerberos_clock_offset

        # Build a minimal valid-looking ccache that loads via
        # impacket.krb5.ccache.CCache. We mock at the loader level
        # because constructing a full ccache by hand is fragile.
        from unittest.mock import MagicMock, patch as _patch
        fake_ccache = MagicMock()
        fake_cred = MagicMock()
        fake_cred.__getitem__.return_value = {"authtime": int(time.time())}
        fake_ccache.credentials = [fake_cred]

        with _patch("impacket.krb5.ccache.CCache.loadFile",
                    return_value=fake_ccache):
            ccache_path = tmp_path / "fake.ccache"
            ccache_path.write_bytes(b"placeholder")
            result = install_kerberos_clock_offset(str(ccache_path))
        assert result == 0

    def test_large_offset_patches_impacket(self, tmp_path):
        """authtime way ahead of now → shim installed, offset returned."""
        from sharesift.share.auth import install_kerberos_clock_offset
        from unittest.mock import MagicMock, patch as _patch

        future_authtime = int(time.time()) + 25_000  # +7h
        fake_ccache = MagicMock()
        fake_cred = MagicMock()
        fake_cred.__getitem__.return_value = {"authtime": future_authtime}
        fake_ccache.credentials = [fake_cred]

        # Reset any prior shim
        import impacket.krb5.kerberosv5 as krbmod
        if hasattr(krbmod, "_sharesift_clock_offset"):
            del krbmod._sharesift_clock_offset

        with _patch("impacket.krb5.ccache.CCache.loadFile",
                    return_value=fake_ccache):
            ccache_path = tmp_path / "fake.ccache"
            ccache_path.write_bytes(b"placeholder")
            result = install_kerberos_clock_offset(str(ccache_path))
        assert result > 20_000
        # Shim marker installed
        assert hasattr(krbmod, "_sharesift_clock_offset")
        # Clean up
        delattr(krbmod, "_sharesift_clock_offset")
        # Restore original datetime module for other tests
        import datetime as _dt
        krbmod.datetime = _dt

    def test_idempotent_does_not_double_wrap(self, tmp_path):
        from sharesift.share.auth import install_kerberos_clock_offset
        from unittest.mock import MagicMock, patch as _patch

        future = int(time.time()) + 10_000
        fake_ccache = MagicMock()
        fake_cred = MagicMock()
        fake_cred.__getitem__.return_value = {"authtime": future}
        fake_ccache.credentials = [fake_cred]

        import impacket.krb5.kerberosv5 as krbmod
        if hasattr(krbmod, "_sharesift_clock_offset"):
            del krbmod._sharesift_clock_offset

        with _patch("impacket.krb5.ccache.CCache.loadFile",
                    return_value=fake_ccache):
            ccache_path = tmp_path / "fake.ccache"
            ccache_path.write_bytes(b"placeholder")
            first = install_kerberos_clock_offset(str(ccache_path))
            second = install_kerberos_clock_offset(str(ccache_path))
        assert first == second
        # Clean
        delattr(krbmod, "_sharesift_clock_offset")
        import datetime as _dt
        krbmod.datetime = _dt
