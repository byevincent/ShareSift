"""v0.39 step 1 — NetrShareEnum-backed share discovery tests."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from sharesift.share import Auth
from sharesift.share.discovery import (
    ShareSummary,
    _classify_type,
    _decode_share,
    _strip_terminator,
    enumerate_shares,
)


# --- type classification (pure function) ----------------------------


class TestClassifyType:
    def test_disktree_is_disk(self):
        assert _classify_type(0x00000000) == "disk"

    def test_printq_is_printer(self):
        assert _classify_type(0x00000001) == "printer"

    def test_device_is_device(self):
        assert _classify_type(0x00000002) == "device"

    def test_ipc_is_ipc(self):
        assert _classify_type(0x00000003) == "ipc"

    def test_special_ipc(self):
        """IPC$ on Samba returns 0x80000003 — special bit + IPC base."""
        assert _classify_type(0x80000003) == "special-ipc"

    def test_special_disk(self):
        """Admin shares (C$, ADMIN$) typically come back as
        ``0x80000000`` (special + disk)."""
        assert _classify_type(0x80000000) == "special-disk"

    def test_unknown_base(self):
        assert _classify_type(0x99) == "unknown"


# --- string decoding ----------------------------------------------


class TestStripTerminator:
    def test_strips_trailing_null(self):
        assert _strip_terminator("public\x00") == "public"

    def test_handles_no_terminator(self):
        assert _strip_terminator("public") == "public"

    def test_handles_bytes(self):
        assert _strip_terminator(b"public\x00") == "public"

    def test_empty_string(self):
        assert _strip_terminator("") == ""


# --- ShareSummary semantics ---------------------------------------


class TestShareSummary:
    def test_disk_is_file_share(self):
        assert ShareSummary("public", "disk", "").is_file_share() is True

    def test_special_disk_is_file_share(self):
        """Admin shares are still file shares for our purposes."""
        assert ShareSummary("C$", "special-disk", "").is_file_share() is True

    def test_ipc_is_not_file_share(self):
        assert ShareSummary("IPC$", "special-ipc", "").is_file_share() is False

    def test_printer_is_not_file_share(self):
        assert ShareSummary("printer", "printer", "").is_file_share() is False

    def test_dataclass_is_frozen(self):
        s = ShareSummary("x", "disk", "")
        with pytest.raises(Exception):
            s.name = "y"  # type: ignore[misc]


# --- _decode_share field extraction -------------------------------


class TestDecodeShare:
    def test_extracts_name_type_comment(self):
        # impacket returns dict-like with null-terminated strings
        raw = {
            "shi1_netname": "Finance\x00",
            "shi1_type": 0,
            "shi1_remark": "Quarterly reports\x00",
        }
        result = _decode_share(raw)
        assert result == ShareSummary(
            name="Finance", type="disk", comment="Quarterly reports",
        )

    def test_handles_special_ipc_share(self):
        raw = {
            "shi1_netname": "IPC$\x00",
            "shi1_type": 0x80000003,
            "shi1_remark": "IPC Service (Samba Server)\x00",
        }
        result = _decode_share(raw)
        assert result.type == "special-ipc"
        assert result.is_file_share() is False


# --- enumerate_shares (full mocked impacket) ----------------------


class TestEnumerateShares:
    def test_password_auth_invokes_login_correctly(self):
        with patch("impacket.smbconnection.SMBConnection") as MockConn:
            instance = MagicMock()
            instance.listShares.return_value = []
            MockConn.return_value = instance

            enumerate_shares(
                "10.0.0.5",
                Auth(user="alice", password="pw", domain="CORP"),
            )

            MockConn.assert_called_once_with(
                "10.0.0.5", "10.0.0.5", sess_port=445, timeout=15.0,
            )
            instance.login.assert_called_once_with("alice", "pw", domain="CORP")

    def test_anonymous_auth_invokes_null_login(self):
        with patch("impacket.smbconnection.SMBConnection") as MockConn:
            instance = MagicMock()
            instance.listShares.return_value = []
            MockConn.return_value = instance

            enumerate_shares("10.0.0.5", Auth(anonymous=True))

            instance.login.assert_called_once_with("", "", domain="")

    def test_hash_auth_invokes_pth_login(self):
        with patch("impacket.smbconnection.SMBConnection") as MockConn:
            instance = MagicMock()
            instance.listShares.return_value = []
            MockConn.return_value = instance

            enumerate_shares(
                "10.0.0.5",
                Auth(user="alice", hash="27c433245e4763d074d30a05aae0af2c"),
            )

            call_kwargs = instance.login.call_args.kwargs
            # PtH passes the hash via lmhash/nthash kwargs
            assert "lmhash" in call_kwargs
            assert "nthash" in call_kwargs
            assert call_kwargs["nthash"] == "27c433245e4763d074d30a05aae0af2c"

    def test_kerberos_auth_invokes_kerberos_login(self):
        with patch("impacket.smbconnection.SMBConnection") as MockConn:
            instance = MagicMock()
            instance.listShares.return_value = []
            MockConn.return_value = instance

            enumerate_shares(
                "10.0.0.5",
                Auth(user="alice", kerberos=True, domain="CORP"),
            )

            instance.kerberosLogin.assert_called_once()
            instance.login.assert_not_called()
            assert instance.kerberosLogin.call_args.kwargs["useCache"] is True

    def test_returns_typed_share_summaries(self):
        with patch("impacket.smbconnection.SMBConnection") as MockConn:
            instance = MagicMock()
            instance.listShares.return_value = [
                {"shi1_netname": "public\x00", "shi1_type": 0,
                 "shi1_remark": "Public stuff\x00"},
                {"shi1_netname": "IPC$\x00", "shi1_type": 0x80000003,
                 "shi1_remark": "IPC Service\x00"},
            ]
            MockConn.return_value = instance

            result = enumerate_shares(
                "10.0.0.5", Auth(user="alice", password="pw"),
            )

            assert len(result) == 2
            assert result[0] == ShareSummary("public", "disk", "Public stuff")
            assert result[1].type == "special-ipc"

    def test_close_called_even_when_listShares_raises(self):
        with patch("impacket.smbconnection.SMBConnection") as MockConn:
            instance = MagicMock()
            instance.listShares.side_effect = RuntimeError("rpc error")
            MockConn.return_value = instance

            with pytest.raises(RuntimeError):
                enumerate_shares(
                    "10.0.0.5", Auth(user="alice", password="pw"),
                )
            instance.close.assert_called_once()

    def test_custom_port_passed_to_connection(self):
        with patch("impacket.smbconnection.SMBConnection") as MockConn:
            instance = MagicMock()
            instance.listShares.return_value = []
            MockConn.return_value = instance

            enumerate_shares(
                "10.0.0.5", Auth(user="alice", password="pw"), port=1445,
            )

            assert MockConn.call_args.kwargs["sess_port"] == 1445


# --- missing-extra friendliness ----------------------------------


def test_missing_impacket_extra_yields_friendly_error():
    """Same pattern as the v0.37 smb extra: clear install guide
    instead of raw ImportError."""
    import sys
    saved = sys.modules.pop("impacket", None)
    saved_smbconn = sys.modules.pop("impacket.smbconnection", None)
    import builtins
    real_import = builtins.__import__

    def block(name, *a, **kw):
        if name == "impacket" or name.startswith("impacket."):
            raise ImportError(f"No module named '{name}'", name=name)
        return real_import(name, *a, **kw)

    try:
        with patch("builtins.__import__", side_effect=block):
            with pytest.raises(SystemExit) as exc_info:
                enumerate_shares("10.0.0.5", Auth(user="u", password="p"))
            msg = str(exc_info.value)
            assert "network-enum extra" in msg
            assert "pipx install" in msg or "pip install" in msg
    finally:
        if saved is not None:
            sys.modules["impacket"] = saved
        if saved_smbconn is not None:
            sys.modules["impacket.smbconnection"] = saved_smbconn
