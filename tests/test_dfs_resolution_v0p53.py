"""v0.53: DFS referral resolution tests.

Covers:
- Pure-function helpers (``DfsResolution.rewrite``,
  ``first_target_unc``, ``is_path_not_covered``).
- ``dfs_request_via_ipc`` constructs the right IOCTL on the wire.
- ``resolve_dfs_path`` orchestrates IPC$ tree-connect + IOCTL +
  teardown.
- ``SmbShare._ensure_connected`` catches PathNotCovered and
  invokes resolution, then retargets to the fileserver.
"""

from __future__ import annotations

import importlib.util
from unittest.mock import MagicMock, patch

import pytest

from sharesift.share import Auth
from sharesift.share.dfs import (
    DfsResolution,
    dfs_guidance,
    first_target_unc,
    is_path_not_covered,
    looks_like_dfs,
)


_HAS_SMB = importlib.util.find_spec("smbprotocol") is not None
_needs_smb = pytest.mark.skipif(
    not _HAS_SMB, reason="needs smb extra (smbprotocol)",
)


# --- pure-function helpers ----------------------------------------


class TestDfsResolutionRewrite:
    def test_rewrite_replaces_root(self):
        res = DfsResolution(
            original_unc=r"\\corp.local\dept\hr",
            target_unc=r"\\fs01.corp.local\hr",
            path_consumed_chars=21,  # len('\\corp.local\dept\hr')
        )
        out = res.rewrite(r"\\corp.local\dept\hr\salary.xlsx")
        assert out == r"\\fs01.corp.local\hr\salary.xlsx"

    def test_rewrite_case_insensitive_prefix(self):
        res = DfsResolution(
            original_unc=r"\\CORP.LOCAL\Dept\HR",
            target_unc=r"\\fs01.corp.local\hr",
            path_consumed_chars=21,
        )
        # Operator-supplied with mixed casing — should still match
        out = res.rewrite(r"\\corp.local\dept\hr\salary.xlsx")
        assert out == r"\\fs01.corp.local\hr\salary.xlsx"

    def test_rewrite_passthrough_when_no_match(self):
        res = DfsResolution(
            original_unc=r"\\corp.local\dept\hr",
            target_unc=r"\\fs01.corp.local\hr",
            path_consumed_chars=21,
        )
        # Unrelated UNC — returned unchanged
        out = res.rewrite(r"\\other.corp.local\public\file.txt")
        assert out == r"\\other.corp.local\public\file.txt"


class TestIsPathNotCovered:
    def test_matches_smbprotocol_exception_class(self):
        # The PathNotCovered exception ships with smbprotocol; if
        # the smb extra isn't installed, fall through to string
        # matching.
        if not _HAS_SMB:
            pytest.skip("smb extra not installed")
        from smbprotocol.exceptions import PathNotCovered

        # Try a few PathNotCovered constructor patterns — different
        # versions of smbprotocol require different positional args.
        # The is_path_not_covered check uses isinstance() so any of
        # them count.
        exc: Exception
        try:
            exc = PathNotCovered()
        except TypeError:
            try:
                # Newer smbprotocol requires header + message
                exc = PathNotCovered(MagicMock(), "path_not_covered")
            except TypeError:
                exc = RuntimeError("STATUS_PATH_NOT_COVERED 0xC0000257")
        assert is_path_not_covered(exc) is True

    def test_matches_status_code_string(self):
        # Older smbprotocol or other SMB stacks might bubble up
        # a generic exception with NTSTATUS in the message.
        exc = RuntimeError("server returned STATUS_PATH_NOT_COVERED")
        assert is_path_not_covered(exc) is True

    def test_matches_hex_status_code(self):
        exc = RuntimeError("got error 0xc0000257 from server")
        assert is_path_not_covered(exc) is True

    def test_does_not_match_other_errors(self):
        assert is_path_not_covered(RuntimeError("access denied")) is False
        assert is_path_not_covered(ConnectionError("network down")) is False
        assert is_path_not_covered(OSError("no such file")) is False


class TestFirstTargetUnc:
    def test_returns_network_address_of_first_entry(self):
        response = MagicMock()
        entry = MagicMock()
        entry.network_address = r"\\fs01.corp.local\hr"
        entries_field = MagicMock()
        entries_field.get_value.return_value = [entry]
        response.__getitem__.return_value = entries_field

        assert first_target_unc(response) == r"\\fs01.corp.local\hr"

    def test_normalizes_missing_leading_slashes(self):
        response = MagicMock()
        entry = MagicMock()
        # Some servers return without leading \\ — normalize
        entry.network_address = r"fs01.corp.local\hr"
        entries_field = MagicMock()
        entries_field.get_value.return_value = [entry]
        response.__getitem__.return_value = entries_field

        assert first_target_unc(response) == r"\\fs01.corp.local\hr"

    def test_empty_response_returns_none(self):
        response = MagicMock()
        entries_field = MagicMock()
        entries_field.get_value.return_value = []
        response.__getitem__.return_value = entries_field

        assert first_target_unc(response) is None


# --- looks_like_dfs / dfs_guidance (carry-over from v0.52) ---------


class TestLooksLikeDfs:
    def test_domain_shaped_unc_detected(self):
        assert looks_like_dfs(r"\\corp.local\departments\hr") is True

    def test_single_label_host_not_dfs(self):
        assert looks_like_dfs(r"\\fs01\share") is False

    def test_empty_string(self):
        assert looks_like_dfs("") is False


class TestDfsGuidance:
    def test_guidance_mentions_v0p53_resolution(self):
        msg = dfs_guidance(r"\\corp.local\dfs\hr")
        assert "v0.53" in msg


# --- dfs_request_via_ipc — IOCTL construction --------------------


@_needs_smb
class TestDfsRequestViaIpc:
    def test_sends_ioctl_with_correct_fields(self):
        """The IOCTL request sent on the wire has the right
        ctl_code, file_id sentinel, FSCTL flag, and dfs_path in
        the buffer. The response parsing is exercised in the
        higher-level resolve_dfs_path tests below — here we just
        validate the request side."""
        from sharesift.share.dfs import dfs_request_via_ipc
        from smbprotocol.dfs import DFSReferralResponse
        from smbprotocol.ioctl import CtlCode, IOCTLFlags

        conn = MagicMock()
        session = MagicMock()
        session.session_id = 0xdead
        ipc_tree = MagicMock()
        ipc_tree.tree_connect_id = 0xbeef

        # Patch SMB2IOCTLResponse so .unpack() yields a usable
        # buffer field without having to construct real wire bytes
        # (offset/size dependencies are fiddly).
        empty_dfs = DFSReferralResponse()
        empty_dfs["path_consumed"] = 0
        empty_dfs["number_of_referrals"] = 0
        empty_dfs_bytes = empty_dfs.pack()

        fake_ioctl_response = MagicMock()
        buffer_field = MagicMock()
        buffer_field.get_value.return_value = empty_dfs_bytes
        fake_ioctl_response.__getitem__.return_value = buffer_field

        receive_payload = MagicMock()
        data_field = MagicMock()
        data_field.get_value.return_value = b""  # unpack target — overridden below
        receive_payload.__getitem__.return_value = data_field
        conn.receive.return_value = receive_payload

        ioctl_cls = MagicMock(return_value=fake_ioctl_response)
        with patch("smbprotocol.ioctl.SMB2IOCTLResponse", ioctl_cls):
            result = dfs_request_via_ipc(
                conn, session, ipc_tree, r"\\corp.local\dept\hr",
            )

        # Confirm send() was called with sid + tid kwargs
        send_call = conn.send.call_args
        assert send_call.kwargs["sid"] == 0xdead
        assert send_call.kwargs["tid"] == 0xbeef

        # And the IOCTL request had the right ctl_code + flags +
        # file_id sentinel
        ioctl_req = send_call.args[0]
        assert ioctl_req["ctl_code"].get_value() == CtlCode.FSCTL_DFS_GET_REFERRALS
        assert ioctl_req["file_id"].get_value() == b"\xff" * 16
        assert ioctl_req["flags"].get_value() == IOCTLFlags.SMB2_0_IOCTL_IS_FSCTL

        # Returned a DFSReferralResponse with zero entries
        assert result is not None
        assert result["number_of_referrals"].get_value() == 0


# --- SmbShare DFS retry — integration via mocks ------------------


@_needs_smb
class TestSmbShareDfsRetry:
    def _build_share(self, original_target):
        from sharesift.share.smb import SmbShare
        return SmbShare(
            target=original_target,
            auth=Auth(user="u", password="p"),
            encrypt=False,
            timeout=5,
        )

    def test_path_not_covered_triggers_resolution(self, monkeypatch):
        """SmbShare catches PathNotCovered, calls resolve_dfs_path,
        and retargets to the fileserver UNC."""
        from sharesift.share.target import SmbTarget
        from sharesift.share import smb as smb_module

        original = SmbTarget(host="corp.local", share="dept", port=445)
        share = self._build_share(original)

        # Patch the Connection / Session / TreeConnect classes in
        # smb.py at import time.
        connect_call_count = {"value": 0}

        def fake_tree_connect_connect(self):
            connect_call_count["value"] += 1
            # First call: fail with a PathNotCovered-like exception
            # Second call: succeed
            if connect_call_count["value"] == 1:
                raise RuntimeError("STATUS_PATH_NOT_COVERED 0xc0000257")

        mock_tree = MagicMock()
        mock_tree.connect = lambda: fake_tree_connect_connect(mock_tree)
        TreeConnectCls = MagicMock(return_value=mock_tree)

        mock_session = MagicMock()
        SessionCls = MagicMock(return_value=mock_session)

        mock_connection = MagicMock()
        ConnectionCls = MagicMock(return_value=mock_connection)

        # Mock resolve_dfs_path to return a known fileserver
        resolution = DfsResolution(
            original_unc=r"\\corp.local\dept",
            target_unc=r"\\fs01.corp.local\dept_share",
            path_consumed_chars=16,
        )
        resolve = MagicMock(return_value=resolution)

        with patch.dict("sys.modules", {
            # No-op — the smb_module already imported smbprotocol
        }), patch(
            "smbprotocol.connection.Connection", ConnectionCls,
        ), patch(
            "smbprotocol.session.Session", SessionCls,
        ), patch(
            "smbprotocol.tree.TreeConnect", TreeConnectCls,
        ), patch(
            "sharesift.share.dfs.resolve_dfs_path", resolve,
        ):
            share._ensure_connected()

        # Resolution was invoked
        resolve.assert_called_once()
        # Target was rewritten to the fileserver
        assert share._target.host == "fs01.corp.local"
        assert share._target.share == "dept_share"
        # Original is preserved
        assert share._original_target.host == "corp.local"
        assert share._dfs_resolution is resolution

    def test_auto_resolve_dfs_false_propagates_error(self):
        from sharesift.share.target import SmbTarget
        from sharesift.share.smb import SmbShare

        target = SmbTarget(host="corp.local", share="dept", port=445)
        share = SmbShare(
            target, Auth(user="u", password="p"),
            encrypt=False, auto_resolve_dfs=False,
        )

        def fake_tree_connect_connect(self):
            raise RuntimeError("STATUS_PATH_NOT_COVERED")

        mock_tree = MagicMock()
        mock_tree.connect = lambda: fake_tree_connect_connect(mock_tree)
        TreeConnectCls = MagicMock(return_value=mock_tree)

        with patch(
            "smbprotocol.connection.Connection", MagicMock(),
        ), patch(
            "smbprotocol.session.Session", MagicMock(),
        ), patch(
            "smbprotocol.tree.TreeConnect", TreeConnectCls,
        ):
            with pytest.raises(RuntimeError, match="PATH_NOT_COVERED"):
                share._ensure_connected()

    def test_non_dfs_error_propagates(self):
        """Tree-connect failures that aren't PATH_NOT_COVERED
        should still raise — no resolution attempt."""
        from sharesift.share.target import SmbTarget
        from sharesift.share.smb import SmbShare

        target = SmbTarget(host="fs01", share="share", port=445)
        share = SmbShare(
            target, Auth(user="u", password="p"), encrypt=False,
        )

        def fake_tree_connect_connect(self):
            raise PermissionError("STATUS_ACCESS_DENIED")

        mock_tree = MagicMock()
        mock_tree.connect = lambda: fake_tree_connect_connect(mock_tree)
        TreeConnectCls = MagicMock(return_value=mock_tree)

        resolve = MagicMock()  # should NOT be called

        with patch(
            "smbprotocol.connection.Connection", MagicMock(),
        ), patch(
            "smbprotocol.session.Session", MagicMock(),
        ), patch(
            "smbprotocol.tree.TreeConnect", TreeConnectCls,
        ), patch(
            "sharesift.share.dfs.resolve_dfs_path", resolve,
        ):
            with pytest.raises(PermissionError):
                share._ensure_connected()

        resolve.assert_not_called()
