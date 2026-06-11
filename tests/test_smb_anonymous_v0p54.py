"""v0.54.3: anonymous SMB via impacket fallback.

Surfaced on HTB Active 2026-06-11: smbprotocol+pyspnego raises
SpnegoError on empty credentials. impacket's null-session login
works. SmbShare now detects auth.anonymous=True at construction
and delegates walk/read_bytes/probe_share_access to an
ImpacketSmbWalker.
"""

from __future__ import annotations

import importlib.util
from unittest.mock import MagicMock, patch

import pytest


_HAS_IMPACKET = importlib.util.find_spec("impacket") is not None
_HAS_SMB = importlib.util.find_spec("smbprotocol") is not None
_needs_impacket = pytest.mark.skipif(
    not _HAS_IMPACKET, reason="needs network-enum extra (impacket)",
)
_needs_smb = pytest.mark.skipif(
    not _HAS_SMB, reason="needs smb extra (smbprotocol)",
)


@_needs_impacket
@_needs_smb
class TestAnonymousDispatch:
    """SmbShare with auth.anonymous=True routes to ImpacketSmbWalker."""

    def test_anonymous_auth_installs_impacket_backend(self):
        from sharesift.share import Auth
        from sharesift.share.smb import SmbShare
        from sharesift.share.smb_impacket import ImpacketSmbWalker
        from sharesift.share.target import SmbTarget

        target = SmbTarget(host="dc01", share="Public", port=445)
        share = SmbShare(target, Auth(anonymous=True), encrypt=False)
        # Backend is lazy — instantiate to verify type
        share._ensure_impacket_backend()
        assert isinstance(share._impacket_backend, ImpacketSmbWalker)

    def test_authenticated_auth_does_not_install_impacket_backend(self):
        from sharesift.share import Auth
        from sharesift.share.smb import SmbShare
        from sharesift.share.target import SmbTarget

        target = SmbTarget(host="dc01", share="Public", port=445)
        share = SmbShare(
            target, Auth(user="alice", password="pw"), encrypt=False,
        )
        assert share._impacket_backend is None

    def test_probe_share_access_delegates_to_impacket(self):
        from sharesift.share import Auth
        from sharesift.share.smb import ShareAccess, SmbShare
        from sharesift.share.target import SmbTarget

        target = SmbTarget(host="dc01", share="Public", port=445)
        share = SmbShare(target, Auth(anonymous=True), encrypt=False)
        share._ensure_impacket_backend()

        # Replace the backend's probe to return a known value
        fake_access = ShareAccess(can_read=True, can_write=False)
        share._impacket_backend.probe_share_access = MagicMock(
            return_value=fake_access,
        )
        result = share.probe_share_access()
        assert result is fake_access
        # Caching still works
        share._impacket_backend.probe_share_access.assert_called_once()

    def test_walk_delegates_to_impacket(self):
        from sharesift.share import Auth, ShareEntry
        from sharesift.share.smb import SmbShare
        from sharesift.share.target import SmbTarget

        target = SmbTarget(host="dc01", share="Public", port=445)
        share = SmbShare(target, Auth(anonymous=True), encrypt=False)
        share._ensure_impacket_backend()

        fake_entries = [
            ShareEntry(path=r"\\dc01\Public\a.txt", size=100),
            ShareEntry(path=r"\\dc01\Public\b.txt", size=200),
        ]
        share._impacket_backend.walk = MagicMock(
            return_value=iter(fake_entries),
        )
        result = list(share.walk())
        assert result == fake_entries

    def test_read_bytes_delegates_to_impacket(self):
        from sharesift.share import Auth
        from sharesift.share.smb import SmbShare
        from sharesift.share.target import SmbTarget

        target = SmbTarget(host="dc01", share="Public", port=445)
        share = SmbShare(target, Auth(anonymous=True), encrypt=False)
        share._ensure_impacket_backend()
        share._impacket_backend.read_bytes = MagicMock(
            return_value=b"file content",
        )
        result = share.read_bytes(
            r"\\dc01\Public\a.txt", max_bytes=100,
        )
        assert result == b"file content"
        share._impacket_backend.read_bytes.assert_called_once_with(
            r"\\dc01\Public\a.txt", max_bytes=100,
        )

    def test_close_delegates_to_impacket(self):
        from sharesift.share import Auth
        from sharesift.share.smb import SmbShare
        from sharesift.share.target import SmbTarget

        target = SmbTarget(host="dc01", share="Public", port=445)
        share = SmbShare(target, Auth(anonymous=True), encrypt=False)
        share._ensure_impacket_backend()
        backend = share._impacket_backend
        backend.close = MagicMock()
        share.close()
        backend.close.assert_called_once()
        # close() clears the backend reference (idempotent re-close)
        assert share._impacket_backend is None


@_needs_impacket
class TestImpacketWalker:
    """ImpacketSmbWalker directly — null-session login + walk + read."""

    def _build_walker(self, auth_kwargs):
        from sharesift.share import Auth
        from sharesift.share.smb_impacket import ImpacketSmbWalker
        from sharesift.share.target import SmbTarget

        target = SmbTarget(host="10.0.0.5", share="Public", port=445)
        return ImpacketSmbWalker(target, Auth(**auth_kwargs))

    def test_anonymous_login_passes_empty_creds(self):
        walker = self._build_walker({"anonymous": True})
        with patch("impacket.smbconnection.SMBConnection") as MockConn:
            instance = MagicMock()
            MockConn.return_value = instance
            walker._ensure_connected()
            instance.login.assert_called_once_with("", "", domain="")

    def test_password_login(self):
        walker = self._build_walker({"user": "alice", "password": "PW"})
        with patch("impacket.smbconnection.SMBConnection") as MockConn:
            instance = MagicMock()
            MockConn.return_value = instance
            walker._ensure_connected()
            instance.login.assert_called_once_with(
                "alice", "PW", domain="",
            )

    def test_hash_login(self):
        walker = self._build_walker({
            "user": "alice",
            "hash": "27c433245e4763d074d30a05aae0af2c",
        })
        with patch("impacket.smbconnection.SMBConnection") as MockConn:
            instance = MagicMock()
            MockConn.return_value = instance
            walker._ensure_connected()
            call_kwargs = instance.login.call_args.kwargs
            assert "nthash" in call_kwargs

    def test_kerberos_login_uses_cache(self):
        walker = self._build_walker({"user": "alice", "kerberos": True})
        with patch("impacket.smbconnection.SMBConnection") as MockConn:
            instance = MagicMock()
            MockConn.return_value = instance
            walker._ensure_connected()
            instance.kerberosLogin.assert_called_once()
            assert instance.kerberosLogin.call_args.kwargs["useCache"] is True

    def test_probe_share_access_returns_r_when_listpath_succeeds(self):
        walker = self._build_walker({"anonymous": True})
        with patch("impacket.smbconnection.SMBConnection") as MockConn:
            instance = MagicMock()
            instance.listPath.return_value = []
            MockConn.return_value = instance
            access = walker.probe_share_access()
            assert access.can_read is True
            assert access.can_write is False

    def test_probe_share_access_returns_false_on_access_denied(self):
        walker = self._build_walker({"anonymous": True})
        with patch("impacket.smbconnection.SMBConnection") as MockConn:
            instance = MagicMock()
            instance.listPath.side_effect = RuntimeError(
                "STATUS_ACCESS_DENIED",
            )
            MockConn.return_value = instance
            access = walker.probe_share_access()
            assert access.can_read is False

    def test_walk_yields_sorted_files(self):
        from sharesift.share import ShareEntry

        walker = self._build_walker({"anonymous": True})

        def make_entry(name, is_dir, size):
            f = MagicMock()
            f.get_longname.return_value = name
            f.is_directory.return_value = is_dir
            f.get_filesize.return_value = size
            return f

        root_listing = [
            make_entry(".", True, 0),
            make_entry("..", True, 0),
            make_entry("z.txt", False, 100),
            make_entry("a.txt", False, 50),
            make_entry("subdir", True, 0),
        ]
        subdir_listing = [
            make_entry(".", True, 0),
            make_entry("..", True, 0),
            make_entry("nested.cfg", False, 30),
        ]

        with patch("impacket.smbconnection.SMBConnection") as MockConn:
            instance = MagicMock()
            instance.listPath.side_effect = [
                root_listing, subdir_listing,
            ]
            MockConn.return_value = instance
            entries = list(walker.walk())

        # Sorted by UNC path
        assert [e.path for e in entries] == [
            r"\\10.0.0.5\Public\a.txt",
            r"\\10.0.0.5\Public\subdir\nested.cfg",
            r"\\10.0.0.5\Public\z.txt",
        ]

    def test_read_bytes_via_getfile(self):
        walker = self._build_walker({"anonymous": True})
        with patch("impacket.smbconnection.SMBConnection") as MockConn:
            instance = MagicMock()

            def fake_getfile(share, path, callback):
                callback(b"hello ")
                callback(b"world")
            instance.getFile.side_effect = fake_getfile
            MockConn.return_value = instance
            data = walker.read_bytes(r"\\10.0.0.5\Public\f.txt")
            assert data == b"hello world"

    def test_read_bytes_respects_max_bytes(self):
        walker = self._build_walker({"anonymous": True})
        with patch("impacket.smbconnection.SMBConnection") as MockConn:
            instance = MagicMock()

            def fake_getfile(share, path, callback):
                callback(b"x" * 1000)
            instance.getFile.side_effect = fake_getfile
            MockConn.return_value = instance
            data = walker.read_bytes(
                r"\\10.0.0.5\Public\f.txt", max_bytes=100,
            )
            assert len(data) == 100

    def test_read_bytes_returns_none_for_unrelated_unc(self):
        walker = self._build_walker({"anonymous": True})
        result = walker.read_bytes(r"\\other.host\share\f.txt")
        assert result is None

    def test_missing_impacket_extra_yields_friendly_error(self):
        from sharesift.share.smb_impacket import ImpacketSmbWalker
        from sharesift.share import Auth
        from sharesift.share.target import SmbTarget
        import sys
        import builtins

        target = SmbTarget(host="10.0.0.5", share="Public", port=445)
        walker = ImpacketSmbWalker(target, Auth(anonymous=True))

        saved = sys.modules.pop("impacket", None)
        saved_smbconn = sys.modules.pop("impacket.smbconnection", None)
        real_import = builtins.__import__

        def block(name, *a, **kw):
            if name == "impacket" or name.startswith("impacket."):
                raise ImportError(f"No module named '{name}'", name=name)
            return real_import(name, *a, **kw)

        try:
            with patch("builtins.__import__", side_effect=block):
                with pytest.raises(SystemExit) as exc_info:
                    walker._ensure_connected()
                assert "network-enum extra" in str(exc_info.value)
        finally:
            if saved is not None:
                sys.modules["impacket"] = saved
            if saved_smbconn is not None:
                sys.modules["impacket.smbconnection"] = saved_smbconn
