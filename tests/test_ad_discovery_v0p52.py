"""v0.52: LDAP-based AD computer discovery tests."""

from __future__ import annotations

import importlib.util
from unittest.mock import MagicMock, patch

import pytest

from sharesift.share import Auth
from sharesift.share.ad import (
    ComputerObject,
    _decode_entry,
    _domain_to_base_dn,
    discover_computers,
)


_HAS_LDAP3 = importlib.util.find_spec("ldap3") is not None
_needs_ldap3 = pytest.mark.skipif(
    not _HAS_LDAP3, reason="needs verify extra (ldap3)",
)


# --- pure-function helpers ----------------------------------------


class TestDomainToBaseDN:
    def test_two_label_domain(self):
        assert _domain_to_base_dn("corp.local") == "DC=corp,DC=local"

    def test_three_label_domain(self):
        assert _domain_to_base_dn("ad.corp.example") == "DC=ad,DC=corp,DC=example"

    def test_single_label_domain(self):
        assert _domain_to_base_dn("corp") == "DC=corp"

    def test_strips_trailing_dot(self):
        assert _domain_to_base_dn("corp.local.") == "DC=corp,DC=local"

    def test_empty_string(self):
        assert _domain_to_base_dn("") == ""


# --- ComputerObject behavior --------------------------------------


class TestComputerObject:
    def test_host_prefers_dns_hostname(self):
        c = ComputerObject(
            sam_account_name="WS01$",
            dns_hostname="ws01.corp.local",
            operating_system="Windows 10",
            enabled=True,
        )
        assert c.host == "ws01.corp.local"

    def test_host_falls_back_to_sam(self):
        c = ComputerObject(
            sam_account_name="WS01$",
            dns_hostname=None,
            operating_system=None,
            enabled=True,
        )
        # The trailing $ is stripped — bare NetBIOS form
        assert c.host == "WS01"

    def test_host_none_when_both_missing(self):
        c = ComputerObject(
            sam_account_name="",
            dns_hostname=None,
            operating_system=None,
            enabled=True,
        )
        assert c.host is None

    def test_frozen_dataclass(self):
        c = ComputerObject(
            sam_account_name="X", dns_hostname=None,
            operating_system=None, enabled=True,
        )
        with pytest.raises(Exception):
            c.sam_account_name = "Y"  # type: ignore[misc]


# --- _decode_entry --------------------------------------------------


class TestDecodeEntry:
    def test_decodes_full_entry(self):
        entry = {
            "type": "searchResEntry",
            "attributes": {
                "sAMAccountName": "WS01$",
                "dnsHostName": "ws01.corp.local",
                "operatingSystem": "Windows 10 Enterprise",
                "userAccountControl": 4096,  # WORKSTATION_TRUST_ACCOUNT
            },
        }
        c = _decode_entry(entry)
        assert c.sam_account_name == "WS01$"
        assert c.dns_hostname == "ws01.corp.local"
        assert c.operating_system == "Windows 10 Enterprise"
        assert c.enabled is True

    def test_decodes_disabled_account(self):
        entry = {
            "type": "searchResEntry",
            "attributes": {
                "sAMAccountName": "WS02$",
                # 0x1002 = ACCOUNTDISABLE | LOCKOUT
                "userAccountControl": 0x1002,
            },
        }
        c = _decode_entry(entry)
        assert c.enabled is False

    def test_handles_missing_dns_hostname(self):
        entry = {
            "type": "searchResEntry",
            "attributes": {
                "sAMAccountName": "WS03$",
                "userAccountControl": 4096,
            },
        }
        c = _decode_entry(entry)
        assert c.dns_hostname is None
        assert c.host == "WS03"

    def test_handles_list_valued_attrs(self):
        # ldap3 sometimes returns single-valued attrs as
        # single-element lists.
        entry = {
            "type": "searchResEntry",
            "attributes": {
                "sAMAccountName": ["DC01$"],
                "dnsHostName": ["dc01.corp.local"],
                "userAccountControl": [532480],  # SERVER_TRUST_ACCOUNT
            },
        }
        c = _decode_entry(entry)
        assert c.sam_account_name == "DC01$"
        assert c.dns_hostname == "dc01.corp.local"

    def test_handles_bad_uac_string(self):
        entry = {
            "type": "searchResEntry",
            "attributes": {
                "sAMAccountName": "WS04$",
                "userAccountControl": "not-an-int",
            },
        }
        c = _decode_entry(entry)
        # Falls back to 0 → enabled
        assert c.enabled is True


# --- discover_computers — mocked ldap3 -----------------------------


@_needs_ldap3
class TestDiscoverComputers:
    def _make_mock_ldap3(self):
        """Set up a fake ldap3 module with a working Server +
        Connection pair. Returns (mock_module, mock_connection)."""
        mock_ldap3 = MagicMock()
        # Constants the call-site references
        mock_ldap3.NONE = "NONE"
        mock_ldap3.NTLM = "NTLM"
        mock_ldap3.SASL = "SASL"
        mock_ldap3.GSSAPI = "GSSAPI"
        mock_ldap3.ANONYMOUS = "ANONYMOUS"

        mock_conn = MagicMock()
        mock_conn.bind.return_value = True
        # Default — empty paged search
        mock_conn.extend.standard.paged_search.return_value = iter([])
        mock_ldap3.Connection.return_value = mock_conn
        return mock_ldap3, mock_conn

    def test_password_auth_builds_ntlm_connection(self):
        mock_ldap3, mock_conn = self._make_mock_ldap3()
        with patch.dict("sys.modules", {"ldap3": mock_ldap3}):
            discover_computers(
                "corp.local",
                Auth(user="alice", password="PW", domain="CORP"),
                dc="dc01.corp.local",
            )
            call_kwargs = mock_ldap3.Connection.call_args.kwargs
            assert call_kwargs["authentication"] == "NTLM"
            assert call_kwargs["user"] == "CORP\\alice"
            assert call_kwargs["password"] == "PW"

    def test_hash_auth_passes_lm_nt_as_password(self):
        mock_ldap3, mock_conn = self._make_mock_ldap3()
        with patch.dict("sys.modules", {"ldap3": mock_ldap3}):
            discover_computers(
                "corp.local",
                Auth(
                    user="alice",
                    hash="27c433245e4763d074d30a05aae0af2c",
                    domain="CORP",
                ),
            )
            call_kwargs = mock_ldap3.Connection.call_args.kwargs
            assert call_kwargs["authentication"] == "NTLM"
            # Default LM hash + provided NT, lowercase
            assert call_kwargs["password"] == (
                "aad3b435b51404eeaad3b435b51404ee:"
                "27c433245e4763d074d30a05aae0af2c"
            )

    def test_kerberos_auth_uses_sasl_gssapi(self):
        mock_ldap3, mock_conn = self._make_mock_ldap3()
        with patch.dict("sys.modules", {"ldap3": mock_ldap3}):
            discover_computers(
                "corp.local",
                Auth(user="alice", kerberos=True, domain="CORP"),
            )
            call_kwargs = mock_ldap3.Connection.call_args.kwargs
            assert call_kwargs["authentication"] == "SASL"
            assert call_kwargs["sasl_mechanism"] == "GSSAPI"
            # No password in Kerberos mode
            assert "password" not in call_kwargs or call_kwargs.get("password") is None

    def test_anonymous_auth_uses_anonymous(self):
        mock_ldap3, mock_conn = self._make_mock_ldap3()
        with patch.dict("sys.modules", {"ldap3": mock_ldap3}):
            discover_computers("corp.local", Auth(anonymous=True))
            call_kwargs = mock_ldap3.Connection.call_args.kwargs
            assert call_kwargs["authentication"] == "ANONYMOUS"

    def test_default_dc_falls_back_to_domain(self):
        mock_ldap3, mock_conn = self._make_mock_ldap3()
        with patch.dict("sys.modules", {"ldap3": mock_ldap3}):
            discover_computers(
                "corp.local", Auth(user="u", password="p"),
            )
            server_call = mock_ldap3.Server.call_args
            url = server_call.args[0] if server_call.args else server_call.kwargs.get("url", "")
            assert "corp.local" in url

    def test_explicit_dc_overrides_domain(self):
        mock_ldap3, mock_conn = self._make_mock_ldap3()
        with patch.dict("sys.modules", {"ldap3": mock_ldap3}):
            discover_computers(
                "corp.local", Auth(user="u", password="p"),
                dc="dc02.adcorp.example",
            )
            server_call = mock_ldap3.Server.call_args
            url = server_call.args[0] if server_call.args else ""
            assert "dc02.adcorp.example" in url

    def test_ldaps_when_port_636(self):
        mock_ldap3, mock_conn = self._make_mock_ldap3()
        with patch.dict("sys.modules", {"ldap3": mock_ldap3}):
            discover_computers(
                "corp.local", Auth(user="u", password="p"), port=636,
            )
            url = mock_ldap3.Server.call_args.args[0]
            assert url.startswith("ldaps://")

    def test_returns_decoded_results(self):
        mock_ldap3, mock_conn = self._make_mock_ldap3()
        mock_conn.extend.standard.paged_search.return_value = iter([
            {
                "type": "searchResEntry",
                "attributes": {
                    "sAMAccountName": "WS01$",
                    "dnsHostName": "ws01.corp.local",
                    "operatingSystem": "Windows 10",
                    "userAccountControl": 4096,
                },
            },
            {
                "type": "searchResEntry",
                "attributes": {
                    "sAMAccountName": "WS02$",
                    "userAccountControl": 0x1002,  # disabled
                },
            },
        ])
        with patch.dict("sys.modules", {"ldap3": mock_ldap3}):
            results = discover_computers(
                "corp.local", Auth(user="u", password="p"),
            )
            # Disabled one filtered out by default
            assert len(results) == 1
            assert results[0].dns_hostname == "ws01.corp.local"

    def test_only_enabled_false_includes_disabled(self):
        mock_ldap3, mock_conn = self._make_mock_ldap3()
        mock_conn.extend.standard.paged_search.return_value = iter([
            {
                "type": "searchResEntry",
                "attributes": {
                    "sAMAccountName": "WS01$", "userAccountControl": 4096,
                },
            },
            {
                "type": "searchResEntry",
                "attributes": {
                    "sAMAccountName": "WS02$", "userAccountControl": 0x1002,
                },
            },
        ])
        with patch.dict("sys.modules", {"ldap3": mock_ldap3}):
            results = discover_computers(
                "corp.local", Auth(user="u", password="p"),
                only_enabled=False,
            )
            assert len(results) == 2

    def test_bind_failure_raises_runtime_error(self):
        mock_ldap3, mock_conn = self._make_mock_ldap3()
        mock_conn.bind.return_value = False
        mock_conn.last_error = "invalidCredentials"
        with patch.dict("sys.modules", {"ldap3": mock_ldap3}):
            with pytest.raises(RuntimeError, match="bind"):
                discover_computers(
                    "corp.local", Auth(user="u", password="bad"),
                )

    def test_unbind_called_even_on_search_exception(self):
        mock_ldap3, mock_conn = self._make_mock_ldap3()
        # Returning a generator that raises mid-iteration
        def _raising_gen():
            yield {
                "type": "searchResEntry",
                "attributes": {"sAMAccountName": "WS01$", "userAccountControl": 4096},
            }
            raise RuntimeError("server cut connection")
        mock_conn.extend.standard.paged_search.return_value = _raising_gen()
        with patch.dict("sys.modules", {"ldap3": mock_ldap3}):
            with pytest.raises(RuntimeError):
                discover_computers("corp.local", Auth(user="u", password="p"))
            mock_conn.unbind.assert_called_once()


# --- missing-extra friendliness ----------------------------------


def test_missing_ldap3_yields_friendly_error():
    """Mirrors the v0.37/v0.39 pattern — clear install guide
    instead of raw ImportError."""
    import sys
    saved = sys.modules.pop("ldap3", None)
    import builtins
    real_import = builtins.__import__

    def block(name, *a, **kw):
        if name == "ldap3" or name.startswith("ldap3."):
            raise ImportError(f"No module named '{name}'", name=name)
        return real_import(name, *a, **kw)

    try:
        with patch("builtins.__import__", side_effect=block):
            with pytest.raises(SystemExit) as exc_info:
                discover_computers(
                    "corp.local", Auth(user="u", password="p"),
                )
            msg = str(exc_info.value)
            assert "verify extra" in msg
            assert "pipx install" in msg or "pip install" in msg
    finally:
        if saved is not None:
            sys.modules["ldap3"] = saved
