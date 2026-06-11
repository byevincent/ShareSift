r"""v0.54.1: DFS-namespace-root probe fix.

Surfaced on HTB Multimaster 2026-06-11: `\\<dc>\dfs` is a literal
DFS namespace root that rejects regular SMB2 CREATE with
STATUS_INVALID_PARAMETER (DFS-aware Open required). cmd_hunt's
share-root R/W probe was filtering these shares out before the
walker could reach the DFS links.

Fix: in `_probe_access_mask`, treat STATUS_INVALID_PARAMETER as
probe-inconclusive with caller-supplied fallback (True for read,
False for write — DFS namespace roots are walkable but not
writable).
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
class TestProbeInvalidParameterFallback:
    """v0.54.1: STATUS_INVALID_PARAMETER on share-root CREATE means
    we hit a DFS namespace root. Treat as probe-inconclusive."""

    def _build_share(self):
        from sharesift.share import Auth
        from sharesift.share.smb import SmbShare
        from sharesift.share.target import SmbTarget

        target = SmbTarget(host="dc01", share="dfs", port=445)
        return SmbShare(
            target, Auth(user="u", password="p"), encrypt=False,
        )

    def test_invalid_parameter_read_probe_returns_fallback_true(self):
        """Read probe with invalid_param_fallback=True returns True
        on STATUS_INVALID_PARAMETER — share is walkable."""
        share = self._build_share()
        share._tree = MagicMock()

        # Mock the Open instance to raise InvalidParameter on create
        from smbprotocol.exceptions import InvalidParameter as _IP

        mock_handle = MagicMock()
        # Construct InvalidParameter with whatever args its current
        # smbprotocol version takes — InvalidParameter requires header
        # + message in newer versions. Fall through to a RuntimeError
        # with the right string if constructor is fussy.
        try:
            exc = _IP()
        except TypeError:
            try:
                exc = _IP(MagicMock(), "STATUS_INVALID_PARAMETER")
            except TypeError:
                exc = RuntimeError("STATUS_INVALID_PARAMETER 0xc000000d")
        mock_handle.create.side_effect = exc

        with patch("smbprotocol.open.Open", MagicMock(return_value=mock_handle)):
            result = share._probe_access_mask(
                "FILE_LIST_DIRECTORY", invalid_param_fallback=True,
            )
            assert result is True

    def test_invalid_parameter_write_probe_returns_fallback_false(self):
        """Write probe with invalid_param_fallback=False returns
        False on STATUS_INVALID_PARAMETER — namespace roots aren't
        writable."""
        share = self._build_share()
        share._tree = MagicMock()

        mock_handle = MagicMock()
        mock_handle.create.side_effect = RuntimeError(
            "STATUS_INVALID_PARAMETER 0xc000000d"
        )

        with patch("smbprotocol.open.Open", MagicMock(return_value=mock_handle)):
            result = share._probe_access_mask(
                "FILE_ADD_FILE", invalid_param_fallback=False,
            )
            assert result is False

    def test_access_denied_still_returns_false(self):
        """Existing behavior preserved — STATUS_ACCESS_DENIED is
        an authoritative 'no'."""
        share = self._build_share()
        share._tree = MagicMock()

        mock_handle = MagicMock()
        mock_handle.create.side_effect = RuntimeError(
            "STATUS_ACCESS_DENIED 0xc0000022"
        )

        with patch("smbprotocol.open.Open", MagicMock(return_value=mock_handle)):
            assert share._probe_access_mask(
                "FILE_LIST_DIRECTORY", invalid_param_fallback=True,
            ) is False
            assert share._probe_access_mask(
                "FILE_ADD_FILE", invalid_param_fallback=False,
            ) is False

    def test_unrelated_error_still_propagates(self):
        """STATUS_NETWORK_NAME_DELETED / NETWORK_UNREACHABLE etc.
        should still bubble up as 'probe inconclusive' rather than
        being misclassified as no-access."""
        share = self._build_share()
        share._tree = MagicMock()

        mock_handle = MagicMock()
        mock_handle.create.side_effect = ConnectionError(
            "STATUS_NETWORK_NAME_DELETED"
        )

        with patch("smbprotocol.open.Open", MagicMock(return_value=mock_handle)):
            with pytest.raises(ConnectionError):
                share._probe_access_mask(
                    "FILE_LIST_DIRECTORY", invalid_param_fallback=True,
                )

    def test_dfs_root_share_access_is_r_minus(self):
        """End-to-end semantics: a DFS namespace root probes as
        readable + non-writable. Display marker should be 'R'."""
        share = self._build_share()
        share._tree = MagicMock()

        mock_handle = MagicMock()
        mock_handle.create.side_effect = RuntimeError(
            "STATUS_INVALID_PARAMETER"
        )

        with patch("smbprotocol.open.Open", MagicMock(return_value=mock_handle)):
            # probe_share_access calls _probe_access_mask twice
            # (read + write); both should hit the fallback path.
            access = share.probe_share_access()
            assert access.can_read is True
            assert access.can_write is False
            assert access.display == "R"
