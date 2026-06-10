"""v0.36 step 3 — share-level R/W access probe (Snaffler #184).

Snaffler reports writable shares as ``R`` due to a bug in its
effective-access calculation. ShareSift probes both rights
explicitly via two cheap SMB2 CREATE round-trips on the share
root, returning a ``ShareAccess(can_read, can_write)`` verdict.

These tests cover the probe logic with mocked smbprotocol. Live
integration is exercised by the conftest Samba fixture's existing
tests; an explicit RW-vs-R-only Samba test could be added in a
v0.36.1 follow-up alongside record-level plumbing.
"""

from __future__ import annotations

import importlib.util
from unittest.mock import MagicMock, patch

import pytest

from sharesift.share import Auth, ShareAccess, SmbShare, SmbTarget

_HAS_SMBPROTOCOL = importlib.util.find_spec("smbprotocol") is not None
_needs_smbprotocol = pytest.mark.skipif(
    not _HAS_SMBPROTOCOL,
    reason="needs [smb] extra (smbprotocol)",
)


def _share() -> SmbShare:
    return SmbShare(
        target=SmbTarget(host="10.0.0.5", share="Finance"),
        auth=Auth(user="alice", password="pw"),
    )


def _wire(share: SmbShare) -> None:
    share._ensure_connected = MagicMock()  # type: ignore[method-assign]
    share._tree = MagicMock()
    share._connection = MagicMock()
    share._connection.max_read_size = 8 * 1024 * 1024


# --- ShareAccess dataclass ----------------------------------------


class TestShareAccessDisplay:
    def test_read_only_displays_R(self):
        assert ShareAccess(can_read=True, can_write=False).display == "R"

    def test_writable_displays_RW(self):
        assert ShareAccess(can_read=True, can_write=True).display == "RW"

    def test_write_only_displays_W(self):
        """Bizarre but possible — anonymous write-only share."""
        assert ShareAccess(can_read=False, can_write=True).display == "W"

    def test_no_access_displays_dash(self):
        assert ShareAccess(can_read=False, can_write=False).display == "-"

    def test_dataclass_is_frozen(self):
        access = ShareAccess(can_read=True, can_write=False)
        with pytest.raises(Exception):
            access.can_read = False  # type: ignore[misc]


# --- probe_share_access ------------------------------------------


@_needs_smbprotocol
class TestProbeShareAccess:
    def test_both_opens_succeed_yields_RW(self):
        share = _share()
        _wire(share)
        with patch("smbprotocol.open.Open") as MockOpen:
            handle = MagicMock()
            # Both create() calls succeed → both rights granted
            MockOpen.return_value = handle

            access = share.probe_share_access()

            assert access == ShareAccess(can_read=True, can_write=True)
            assert MockOpen.call_count == 2
            # Both handles closed
            assert handle.close.call_count == 2

    def test_write_denied_yields_read_only(self):
        share = _share()
        _wire(share)

        with patch("smbprotocol.open.Open") as MockOpen:
            read_handle = MagicMock()
            write_handle = MagicMock()
            # write probe raises AccessDenied
            from smbprotocol.exceptions import SMBResponseException
            write_handle.create.side_effect = type(
                "AccessDenied", (Exception,),
                {"__init__": lambda self: Exception.__init__(self, "STATUS_ACCESS_DENIED")},
            )()
            # Alternate handles: first call (read) returns read_handle,
            # second (write) returns write_handle
            MockOpen.side_effect = [read_handle, write_handle]

            access = share.probe_share_access()

            assert access == ShareAccess(can_read=True, can_write=False)

    def test_both_denied_yields_no_access(self):
        share = _share()
        _wire(share)

        with patch("smbprotocol.open.Open") as MockOpen:
            handle1 = MagicMock()
            handle1.create.side_effect = type(
                "AccessDenied", (Exception,),
                {"__init__": lambda self: Exception.__init__(self, "STATUS_ACCESS_DENIED")},
            )()
            handle2 = MagicMock()
            handle2.create.side_effect = type(
                "AccessDenied", (Exception,),
                {"__init__": lambda self: Exception.__init__(self, "STATUS_ACCESS_DENIED")},
            )()
            MockOpen.side_effect = [handle1, handle2]

            access = share.probe_share_access()

            assert access == ShareAccess(can_read=False, can_write=False)

    def test_probe_is_idempotent(self):
        share = _share()
        _wire(share)
        with patch("smbprotocol.open.Open") as MockOpen:
            handle = MagicMock()
            MockOpen.return_value = handle

            a1 = share.probe_share_access()
            a2 = share.probe_share_access()

            assert a1 is a2
            # Second call uses cached value — no new SMB exchanges
            assert MockOpen.call_count == 2  # only the initial probe

    def test_share_access_property_none_before_probe(self):
        share = _share()
        assert share.share_access is None

    def test_share_access_property_populated_after_probe(self):
        share = _share()
        _wire(share)
        with patch("smbprotocol.open.Open") as MockOpen:
            MockOpen.return_value = MagicMock()
            share.probe_share_access()
            assert share.share_access is not None
            assert share.share_access.can_read is True

    def test_non_access_denied_exception_propagates(self):
        """If the probe hits something other than STATUS_ACCESS_DENIED
        — connection drop, timeout, malformed response — we don't lie
        and say 'no access.' The exception bubbles for the caller to
        handle. Honest > convenient."""
        share = _share()
        _wire(share)

        with patch("smbprotocol.open.Open") as MockOpen:
            handle = MagicMock()
            handle.create.side_effect = ConnectionError("network broke")
            MockOpen.return_value = handle

            with pytest.raises(ConnectionError):
                share.probe_share_access()
