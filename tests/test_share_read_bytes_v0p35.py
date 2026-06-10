"""v0.35 Sprint 3.5 — Share.read_bytes contract tests.

Covers LocalShare and SmbShare (mocked) ``read_bytes`` behavior.
Live SMB integration tests against ``dperson/samba`` are Sprint 4.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from sharesift.share import Auth, LocalShare, ShareEntry, SmbShare, SmbTarget

_HAS_SMBPROTOCOL = importlib.util.find_spec("smbprotocol") is not None
_needs_smbprotocol = pytest.mark.skipif(
    not _HAS_SMBPROTOCOL,
    reason="needs [smb] extra (smbprotocol)",
)


# --------------------------------------------------------------------
# LocalShare.read_bytes
# --------------------------------------------------------------------


class TestLocalShareReadBytes:
    def test_reads_full_file_when_no_cap(self, tmp_path):
        p = tmp_path / "f.txt"
        p.write_bytes(b"hello world")
        assert LocalShare().read_bytes(str(p)) == b"hello world"

    def test_caps_at_max_bytes(self, tmp_path):
        p = tmp_path / "f.txt"
        p.write_bytes(b"0123456789ABCDEF")
        assert LocalShare().read_bytes(str(p), max_bytes=5) == b"01234"

    def test_returns_none_for_nonexistent(self):
        assert LocalShare().read_bytes("/nope/missing.txt") is None

    def test_returns_none_for_directory(self, tmp_path):
        assert LocalShare().read_bytes(str(tmp_path)) is None

    def test_returns_none_on_oserror(self, tmp_path, monkeypatch):
        p = tmp_path / "f.txt"
        p.write_bytes(b"x")

        def boom(*args, **kwargs):
            raise PermissionError("denied")

        monkeypatch.setattr(Path, "open", boom)
        assert LocalShare().read_bytes(str(p), max_bytes=10) is None

    def test_default_root_is_cwd(self):
        """LocalShare() must be constructible without a root — needed
        by cmd_scan_files standalone where reads happen against
        whatever paths are in the file list."""
        share = LocalShare()
        assert share.root == "."

    def test_read_bytes_works_outside_root(self, tmp_path):
        """read_bytes operates on any path, not just paths under
        ``root`` — root constrains walk(), not reads."""
        target = tmp_path / "inside.txt"
        target.write_text("content")
        share = LocalShare(root="/tmp/some-other-dir")
        assert share.read_bytes(str(target)) == b"content"


# --------------------------------------------------------------------
# SmbShare.read_bytes (mocked smbprotocol)
# --------------------------------------------------------------------


def _smb_share() -> SmbShare:
    return SmbShare(
        target=SmbTarget(host="10.0.0.5", share="Finance"),
        auth=Auth(user="alice", password="pw"),
    )


class TestSmbShareUncToRel:
    def test_matching_unc_returns_rel(self):
        share = _smb_share()
        assert share._unc_to_rel(r"\\10.0.0.5\Finance\sub\file.txt") == r"sub\file.txt"

    def test_unc_at_share_root_returns_none(self):
        """An empty rel means the share root, which isn't a file."""
        share = _smb_share()
        assert share._unc_to_rel(r"\\10.0.0.5\Finance") is None
        assert share._unc_to_rel(r"\\10.0.0.5\Finance\\") is None

    def test_non_matching_unc_returns_none(self):
        share = _smb_share()
        assert share._unc_to_rel(r"\\other.host\Finance\f.txt") is None
        assert share._unc_to_rel(r"\\10.0.0.5\OtherShare\f.txt") is None

    def test_case_insensitive_match(self):
        """SMB hostnames and share names are case-insensitive."""
        share = _smb_share()
        assert share._unc_to_rel(r"\\10.0.0.5\FINANCE\f.txt") == "f.txt"
        assert share._unc_to_rel(r"\\10.0.0.5\Finance\F.TXT") == "F.TXT"


@_needs_smbprotocol
class TestSmbShareReadBytes:
    def test_returns_none_for_non_matching_unc(self):
        share = _smb_share()
        # No connection happens, no smbprotocol calls — short-circuits
        with patch("smbprotocol.open.Open") as MockOpen:
            assert share.read_bytes(r"\\other.host\Finance\f.txt") is None
            MockOpen.assert_not_called()

    def _wire_share(self, share, max_read_size: int = 8 * 1024 * 1024) -> None:
        """Stub the bits read_bytes touches: tree (for Open ctor) and
        connection.max_read_size (for the cap clamp)."""
        share._ensure_connected = MagicMock()  # type: ignore[method-assign]
        share._tree = MagicMock()
        share._connection = MagicMock()
        share._connection.max_read_size = max_read_size

    def test_calls_smbprotocol_open_with_relative_path(self):
        share = _smb_share()
        self._wire_share(share)

        with patch("smbprotocol.open.Open") as MockOpen:
            mock_handle = MagicMock()
            mock_handle.read.return_value = b"file content"
            MockOpen.return_value = mock_handle

            result = share.read_bytes(r"\\10.0.0.5\Finance\sub\f.txt", max_bytes=4096)

            assert result == b"file content"
            MockOpen.assert_called_once_with(share._tree, r"sub\f.txt")
            mock_handle.create.assert_called_once()
            mock_handle.read.assert_called_once_with(0, 4096)
            mock_handle.close.assert_called_once_with(False)

    def test_uses_1mb_default_cap_when_no_max_bytes(self):
        """SMB credit-based flow control limits cold-connection
        reads. Default cap is 1MB to stay safe; v0.36 will chunk."""
        share = _smb_share()
        self._wire_share(share)

        with patch("smbprotocol.open.Open") as MockOpen:
            mock_handle = MagicMock()
            mock_handle.read.return_value = b""
            MockOpen.return_value = mock_handle

            share.read_bytes(r"\\10.0.0.5\Finance\f.txt")

            assert mock_handle.read.call_args.args == (0, 1 * 1024 * 1024)

    def test_cap_clamped_to_negotiated_max_read_size(self):
        """If server negotiated a smaller max_read_size than the
        caller's request, the actual read uses the smaller value."""
        share = _smb_share()
        self._wire_share(share, max_read_size=512 * 1024)  # 512 KB

        with patch("smbprotocol.open.Open") as MockOpen:
            mock_handle = MagicMock()
            mock_handle.read.return_value = b""
            MockOpen.return_value = mock_handle

            share.read_bytes(r"\\10.0.0.5\Finance\f.txt", max_bytes=10 * 1024 * 1024)

            # min(10MB, 1MB hard cap, 512KB server cap) → 512KB
            assert mock_handle.read.call_args.args == (0, 512 * 1024)

    def test_returns_none_on_read_failure(self):
        share = _smb_share()
        self._wire_share(share)

        with patch("smbprotocol.open.Open") as MockOpen:
            mock_handle = MagicMock()
            mock_handle.create.side_effect = RuntimeError("STATUS_ACCESS_DENIED")
            MockOpen.return_value = mock_handle

            assert share.read_bytes(r"\\10.0.0.5\Finance\f.txt") is None
            mock_handle.close.assert_called_once_with(False)

    def test_close_called_even_when_read_raises(self):
        share = _smb_share()
        self._wire_share(share)

        with patch("smbprotocol.open.Open") as MockOpen:
            mock_handle = MagicMock()
            mock_handle.read.side_effect = RuntimeError("disconnect")
            MockOpen.return_value = mock_handle

            assert share.read_bytes(r"\\10.0.0.5\Finance\f.txt") is None
            mock_handle.close.assert_called_once_with(False)
