r"""v0.55: DFS-aware walk for namespace roots.

Surfaced on HTB Multimaster 2026-06-11. After v0.54.1's probe fix
let the ``dfs`` share enter cmd_hunt's target list, the walker
itself failed with ``STATUS_INVALID_PARAMETER`` when listing the
namespace root. Smbprotocol's regular Open + query_directory
doesn't work on a DFS namespace root even with the DFS flag set
on the SMB header — the namespace root isn't a real directory,
only a referral table.

Fix: when ``_list_directory`` hits ``STATUS_INVALID_PARAMETER``
on a tree where ``is_dfs_share=True``, fall back to
``smbclient.scandir`` which handles the namespace-root listing
internally via ``_resolve_dfs``.

Walking INTO a DFS link returns ``STATUS_PATH_NOT_COVERED``;
the v0.55 walk() catches this and skips the link gracefully
(connecting to the resolved fileserver requires operator-managed
DNS — `/etc/hosts` entry or DNS server pointing at the engagement
DC).
"""

from __future__ import annotations

import importlib.util
from unittest.mock import MagicMock, patch

import pytest


_HAS_SMB = importlib.util.find_spec("smbprotocol") is not None
_needs_smb = pytest.mark.skipif(
    not _HAS_SMB, reason="needs smb extra (smbprotocol)",
)


@_needs_smb
class TestImportRealSmbclient:
    """v0.55 uses a path-shadow-aware importer because impacket
    ships a ``smbclient.py`` script in venv ``bin/`` that
    shadows the smbprotocol package under ``uv run``."""

    def test_returns_module_with_clientconfig(self):
        from sharesift.share.smb import _import_real_smbclient

        mod = _import_real_smbclient()
        assert hasattr(mod, "ClientConfig")
        assert hasattr(mod, "scandir")

    def test_idempotent(self):
        from sharesift.share.smb import _import_real_smbclient

        m1 = _import_real_smbclient()
        m2 = _import_real_smbclient()
        assert m1 is m2


@_needs_smb
class TestListDirectoryDfsFallback:
    """v0.55: STATUS_INVALID_PARAMETER on a DFS share root listing
    falls back to smbclient.scandir."""

    def _build_share(self, *, is_dfs_share: bool):
        from sharesift.share import Auth
        from sharesift.share.smb import SmbShare
        from sharesift.share.target import SmbTarget

        target = SmbTarget(host="dc01", share="dfs", port=445)
        share = SmbShare(
            target, Auth(user="u", password="p"), encrypt=False,
        )
        share._tree = MagicMock()
        share._tree.is_dfs_share = is_dfs_share
        return share

    def test_invalid_param_on_dfs_share_falls_back_to_smbclient(self):
        share = self._build_share(is_dfs_share=True)

        # Mock Open to raise InvalidParameter
        mock_handle = MagicMock()
        mock_handle.create.side_effect = RuntimeError(
            "STATUS_INVALID_PARAMETER 0xc000000d"
        )

        # Mock smbclient.scandir to return one Development link
        fake_entry = MagicMock()
        fake_entry.name = "Development"
        fake_entry.is_dir.return_value = True
        fake_entry.stat.return_value = MagicMock(st_size=0)

        with patch(
            "smbprotocol.open.Open", MagicMock(return_value=mock_handle),
        ), patch(
            "sharesift.share.smb._import_real_smbclient",
        ) as mock_import:
            mock_smbclient = MagicMock()
            mock_smbclient.scandir.return_value = [fake_entry]
            mock_import.return_value = mock_smbclient

            entries = share._list_directory("")

        assert len(entries) == 1
        assert entries[0]["name"] == "Development"
        assert entries[0]["is_directory"] is True

    def test_invalid_param_on_non_dfs_share_raises(self):
        """v0.55 fallback only kicks in for DFS shares. Non-DFS
        shares get the original InvalidParameter."""
        share = self._build_share(is_dfs_share=False)

        mock_handle = MagicMock()
        mock_handle.create.side_effect = RuntimeError(
            "STATUS_INVALID_PARAMETER"
        )
        with patch(
            "smbprotocol.open.Open", MagicMock(return_value=mock_handle),
        ):
            with pytest.raises(RuntimeError, match="INVALID_PARAMETER"):
                share._list_directory("")

    def test_other_exceptions_still_propagate(self):
        share = self._build_share(is_dfs_share=True)

        mock_handle = MagicMock()
        mock_handle.create.side_effect = PermissionError(
            "STATUS_ACCESS_DENIED"
        )
        with patch(
            "smbprotocol.open.Open", MagicMock(return_value=mock_handle),
        ):
            with pytest.raises(PermissionError):
                share._list_directory("")


@_needs_smb
class TestWalkSkipsDfsLinks:
    """v0.55 walk() catches STATUS_PATH_NOT_COVERED on link descent
    and skips with a warning instead of crashing the share scan."""

    def test_path_not_covered_skips_link(self):
        from sharesift.share import Auth
        from sharesift.share.smb import SmbShare
        from sharesift.share.target import SmbTarget

        target = SmbTarget(host="dc01", share="dfs", port=445)
        share = SmbShare(
            target, Auth(user="u", password="p"), encrypt=False,
        )

        # Skip the actual tree-connect
        share._tree = MagicMock()
        share._tree.is_dfs_share = True

        # Track which directories were listed; first call returns
        # ['Development']; second call (into Development) raises
        # PathNotCovered.
        call_count = {"n": 0}

        def _fake_list(rel_dir):
            call_count["n"] += 1
            if call_count["n"] == 1:
                # Root listing: one link
                return [
                    {"name": "Development", "size": 0, "is_directory": True},
                ]
            # Descending into Development → PATH_NOT_COVERED
            raise RuntimeError("STATUS_PATH_NOT_COVERED 0xc0000257")

        share._list_directory = _fake_list
        share._ensure_connected = lambda: None  # no-op

        entries = list(share.walk())
        assert entries == []  # No files (only an unwalked DFS link)
        # The skip was tracked
        assert hasattr(share, "_skipped_dfs_links")
        assert any(
            "Development" in s for s in share._skipped_dfs_links
        )

    def test_other_errors_propagate_through_walk(self):
        from sharesift.share import Auth
        from sharesift.share.smb import SmbShare
        from sharesift.share.target import SmbTarget

        target = SmbTarget(host="fs01", share="X", port=445)
        share = SmbShare(
            target, Auth(user="u", password="p"), encrypt=False,
        )
        share._tree = MagicMock()
        share._tree.is_dfs_share = False
        share._list_directory = MagicMock(
            side_effect=ConnectionError("network down"),
        )
        share._ensure_connected = lambda: None

        with pytest.raises(ConnectionError):
            list(share.walk())
