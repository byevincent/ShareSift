"""v0.52: end-to-end ``sharesift hunt`` command tests.

The full pipeline depends on impacket + ldap3 + smbprotocol which
can't be reliably exercised against a real DC in CI. These tests
mock the I/O surface (LDAP + NetrShareEnum + SmbShare probe +
cmd_batch) and verify the orchestration:

- argument validation (target XOR --ad-domain, auth required)
- LDAP discovery path is taken when --ad-domain is set
- CIDR/host expansion path is taken otherwise
- DFS-shaped UNCs are skipped with operator guidance
- Per-share R/W probe filters non-readable shares
- --writable-only filters R-only shares
- Targets file is written before cmd_batch is invoked
"""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from sharesift import cli


@pytest.fixture(autouse=True)
def _reset_output_state():
    """Restore the module-global Output verbosity to NORMAL after each
    test. cmd_hunt's argument validation runs synchronously and mutates
    the singleton via cli.out.configure; without this fixture, later
    tests in the suite see Verbosity.QUIET as the default."""
    yield
    cli.out.configure(verbosity=cli.Verbosity.NORMAL, json=False)


def _common_hunt_args(tmp_path, **overrides):
    """Build a hunt argparse-namespace with sensible defaults."""
    defaults = dict(
        target=None,
        domain_filter=None,
        dc=None,
        ldap_port=None,
        use_ldaps=False,
        port=None,
        output_dir=tmp_path,
        writable_only=False,
        detect_dfs=False,
        skip_verify=True,
        skip_report=True,
        read_threads=1,
        db=None,
        # Auth flags
        user="alice",
        password="pw",
        hash=None,
        kerberos=False,
        use_kcache=False,
        domain="CORP",
        anonymous=False,
        encrypt=True,
        check=False,
        # Top-level
        quiet=True,
        verbose=False,
        json=False,
    )
    defaults.update(overrides)
    return SimpleNamespace(**defaults)


class TestHuntArgValidation:
    def test_no_target_no_ad_domain_errors(self, tmp_path):
        cli.out.configure(verbosity=cli.Verbosity.QUIET, json=False)
        args = _common_hunt_args(tmp_path)
        with pytest.raises(SystemExit, match="target"):
            cli.cmd_hunt(args)

    def test_target_and_ad_domain_errors(self, tmp_path):
        cli.out.configure(verbosity=cli.Verbosity.QUIET, json=False)
        args = _common_hunt_args(
            tmp_path, target="//10.0.0.5", domain_filter="corp.local",
        )
        with pytest.raises(SystemExit, match="mutually exclusive"):
            cli.cmd_hunt(args)

    def test_no_auth_errors(self, tmp_path):
        cli.out.configure(verbosity=cli.Verbosity.QUIET, json=False)
        args = _common_hunt_args(
            tmp_path, target="//10.0.0.5",
            user=None, password=None, hash=None,
            kerberos=False, use_kcache=False, anonymous=False,
        )
        with pytest.raises(SystemExit, match="auth required"):
            cli.cmd_hunt(args)


class TestHuntDiscoveryDispatch:
    """LDAP vs CIDR/host dispatch + DFS skip."""

    def _setup_mocks(self):
        """Common mock setup: live host, one disk share, R-only access."""
        mock_share = MagicMock()
        mock_share.name = "Finance"
        mock_share.is_file_share.return_value = True
        mock_share.type = "disk"

        enumerate_shares = MagicMock(return_value=[mock_share])
        probe_smb_alive = MagicMock(return_value=True)

        # SmbShare context manager returning R-only access
        mock_smb_inst = MagicMock()
        access = MagicMock(can_read=True, can_write=False)
        mock_smb_inst.__enter__ = MagicMock(return_value=mock_smb_inst)
        mock_smb_inst.__exit__ = MagicMock(return_value=False)
        mock_smb_inst.probe_share_access = MagicMock(return_value=access)
        SmbShare = MagicMock(return_value=mock_smb_inst)

        # cmd_batch always succeeds
        cmd_batch = MagicMock(return_value=0)
        return enumerate_shares, probe_smb_alive, SmbShare, cmd_batch

    def test_ad_domain_calls_ldap_discover(self, tmp_path):
        cli.out.configure(verbosity=cli.Verbosity.QUIET, json=False)
        enumerate_shares, probe_smb_alive, SmbShare, cmd_batch = (
            self._setup_mocks()
        )
        ldap_discover = MagicMock(return_value=["ws01.corp.local"])

        args = _common_hunt_args(
            tmp_path, domain_filter="corp.local", dc="dc01.corp.local",
        )

        with patch.multiple(
            "sharesift.cli",
            _ldap_discover_hosts=ldap_discover,
            cmd_batch=cmd_batch,
        ), patch.multiple(
            "sharesift.share.discovery",
            enumerate_shares=enumerate_shares,
            probe_smb_alive=probe_smb_alive,
        ), patch("sharesift.share.SmbShare", SmbShare):
            rc = cli.cmd_hunt(args)

        assert rc == 0
        ldap_discover.assert_called_once()
        # Targets file should exist and contain the share UNC
        targets_file = tmp_path / "hunt_targets.txt"
        assert targets_file.exists()
        assert "ws01.corp.local" in targets_file.read_text()
        assert "Finance" in targets_file.read_text()

    def test_cidr_target_uses_expansion(self, tmp_path):
        cli.out.configure(verbosity=cli.Verbosity.QUIET, json=False)
        enumerate_shares, probe_smb_alive, SmbShare, cmd_batch = (
            self._setup_mocks()
        )
        expand = MagicMock(return_value=["10.0.0.5"])

        args = _common_hunt_args(tmp_path, target="//10.0.0.5")

        with patch.multiple(
            "sharesift.cli",
            cmd_batch=cmd_batch,
        ), patch.multiple(
            "sharesift.share.discovery",
            enumerate_shares=enumerate_shares,
            probe_smb_alive=probe_smb_alive,
            expand_target_to_hosts=expand,
        ), patch("sharesift.share.SmbShare", SmbShare):
            rc = cli.cmd_hunt(args)

        assert rc == 0
        expand.assert_called_once_with("//10.0.0.5")
        targets_file = tmp_path / "hunt_targets.txt"
        assert "10.0.0.5" in targets_file.read_text()

    def test_dead_hosts_filtered_by_liveness_probe(self, tmp_path):
        cli.out.configure(verbosity=cli.Verbosity.QUIET, json=False)
        enumerate_shares, probe_smb_alive, SmbShare, cmd_batch = (
            self._setup_mocks()
        )
        expand = MagicMock(return_value=["10.0.0.5", "10.0.0.6"])
        # Only one alive
        probe_smb_alive.side_effect = lambda h, port=445: h == "10.0.0.5"

        args = _common_hunt_args(tmp_path, target="//10.0.0.0/24")

        with patch.multiple(
            "sharesift.cli", cmd_batch=cmd_batch,
        ), patch.multiple(
            "sharesift.share.discovery",
            enumerate_shares=enumerate_shares,
            probe_smb_alive=probe_smb_alive,
            expand_target_to_hosts=expand,
        ), patch("sharesift.share.SmbShare", SmbShare):
            cli.cmd_hunt(args)

        # enumerate_shares called once (for the alive host only)
        assert enumerate_shares.call_count == 1

    def test_no_live_hosts_returns_error(self, tmp_path):
        cli.out.configure(verbosity=cli.Verbosity.QUIET, json=False)
        enumerate_shares, probe_smb_alive, SmbShare, cmd_batch = (
            self._setup_mocks()
        )
        expand = MagicMock(return_value=["10.0.0.5"])
        probe_smb_alive.return_value = False
        cmd_batch_called = MagicMock()

        args = _common_hunt_args(tmp_path, target="//10.0.0.5")

        with patch.multiple(
            "sharesift.cli", cmd_batch=cmd_batch_called,
        ), patch.multiple(
            "sharesift.share.discovery",
            enumerate_shares=enumerate_shares,
            probe_smb_alive=probe_smb_alive,
            expand_target_to_hosts=expand,
        ), patch("sharesift.share.SmbShare", SmbShare):
            rc = cli.cmd_hunt(args)

        assert rc == 1
        cmd_batch_called.assert_not_called()


class TestHuntShareFiltering:
    """Per-share R/W probe + DFS detection."""

    def _setup_basic(self):
        """Live host, share enumerator with one disk + one IPC share."""
        disk = MagicMock(name="Finance", type="disk")
        disk.name = "Finance"
        disk.is_file_share.return_value = True
        ipc = MagicMock(name="IPC$", type="special-ipc")
        ipc.name = "IPC$"
        ipc.is_file_share.return_value = False
        enumerate_shares = MagicMock(return_value=[disk, ipc])
        probe_smb_alive = MagicMock(return_value=True)
        cmd_batch = MagicMock(return_value=0)
        return enumerate_shares, probe_smb_alive, cmd_batch

    def test_non_file_shares_skipped(self, tmp_path):
        cli.out.configure(verbosity=cli.Verbosity.QUIET, json=False)
        enumerate_shares, probe_smb_alive, cmd_batch = self._setup_basic()
        expand = MagicMock(return_value=["10.0.0.5"])

        # R-only access on probed share
        access = MagicMock(can_read=True, can_write=False)
        mock_smb = MagicMock()
        mock_smb.__enter__ = MagicMock(return_value=mock_smb)
        mock_smb.__exit__ = MagicMock(return_value=False)
        mock_smb.probe_share_access = MagicMock(return_value=access)
        SmbShare = MagicMock(return_value=mock_smb)

        args = _common_hunt_args(tmp_path, target="//10.0.0.5")

        with patch.multiple(
            "sharesift.cli", cmd_batch=cmd_batch,
        ), patch.multiple(
            "sharesift.share.discovery",
            enumerate_shares=enumerate_shares,
            probe_smb_alive=probe_smb_alive,
            expand_target_to_hosts=expand,
        ), patch("sharesift.share.SmbShare", SmbShare):
            cli.cmd_hunt(args)

        targets_file = tmp_path / "hunt_targets.txt"
        contents = targets_file.read_text()
        # Disk share in, IPC out
        assert "Finance" in contents
        assert "IPC$" not in contents

    def test_unreadable_shares_skipped(self, tmp_path):
        cli.out.configure(verbosity=cli.Verbosity.QUIET, json=False)
        enumerate_shares, probe_smb_alive, cmd_batch = self._setup_basic()
        expand = MagicMock(return_value=["10.0.0.5"])

        # No-access on probed share
        access = MagicMock(can_read=False, can_write=False)
        mock_smb = MagicMock()
        mock_smb.__enter__ = MagicMock(return_value=mock_smb)
        mock_smb.__exit__ = MagicMock(return_value=False)
        mock_smb.probe_share_access = MagicMock(return_value=access)
        SmbShare = MagicMock(return_value=mock_smb)

        args = _common_hunt_args(tmp_path, target="//10.0.0.5")

        with patch.multiple(
            "sharesift.cli", cmd_batch=cmd_batch,
        ), patch.multiple(
            "sharesift.share.discovery",
            enumerate_shares=enumerate_shares,
            probe_smb_alive=probe_smb_alive,
            expand_target_to_hosts=expand,
        ), patch("sharesift.share.SmbShare", SmbShare):
            rc = cli.cmd_hunt(args)

        # No readable shares → exit 1
        assert rc == 1

    def test_writable_only_filters_readonly(self, tmp_path):
        cli.out.configure(verbosity=cli.Verbosity.QUIET, json=False)
        enumerate_shares, probe_smb_alive, cmd_batch = self._setup_basic()
        expand = MagicMock(return_value=["10.0.0.5"])

        # R-only access; --writable-only should filter it out
        access = MagicMock(can_read=True, can_write=False)
        mock_smb = MagicMock()
        mock_smb.__enter__ = MagicMock(return_value=mock_smb)
        mock_smb.__exit__ = MagicMock(return_value=False)
        mock_smb.probe_share_access = MagicMock(return_value=access)
        SmbShare = MagicMock(return_value=mock_smb)

        args = _common_hunt_args(
            tmp_path, target="//10.0.0.5", writable_only=True,
        )

        with patch.multiple(
            "sharesift.cli", cmd_batch=cmd_batch,
        ), patch.multiple(
            "sharesift.share.discovery",
            enumerate_shares=enumerate_shares,
            probe_smb_alive=probe_smb_alive,
            expand_target_to_hosts=expand,
        ), patch("sharesift.share.SmbShare", SmbShare):
            rc = cli.cmd_hunt(args)

        assert rc == 1  # nothing writable → no targets


class TestHuntDfsHandling:
    """v0.53: DFS-shaped UNCs are passed through to SmbShare for
    automatic referral resolution. --detect-dfs is informational
    only — does not skip."""

    def test_dfs_unc_not_skipped_with_detect_dfs(self, tmp_path):
        """v0.53 change from v0.52: --detect-dfs only logs, never skips."""
        cli.out.configure(verbosity=cli.Verbosity.QUIET, json=False)

        # The mocked enumerate returns ONE disk share on a domain-shaped
        # host — \\corp.local\Finance, which looks_like_dfs() flags.
        disk = MagicMock()
        disk.name = "Finance"
        disk.is_file_share.return_value = True
        disk.type = "disk"
        enumerate_shares = MagicMock(return_value=[disk])
        probe_smb_alive = MagicMock(return_value=True)
        expand = MagicMock(return_value=["corp.local"])
        cmd_batch = MagicMock(return_value=0)

        access = MagicMock(can_read=True, can_write=False)
        mock_smb = MagicMock()
        mock_smb.__enter__ = MagicMock(return_value=mock_smb)
        mock_smb.__exit__ = MagicMock(return_value=False)
        mock_smb.probe_share_access = MagicMock(return_value=access)
        SmbShare = MagicMock(return_value=mock_smb)

        args = _common_hunt_args(
            tmp_path, target="//corp.local", detect_dfs=True,
        )

        with patch.multiple(
            "sharesift.cli", cmd_batch=cmd_batch,
        ), patch.multiple(
            "sharesift.share.discovery",
            enumerate_shares=enumerate_shares,
            probe_smb_alive=probe_smb_alive,
            expand_target_to_hosts=expand,
        ), patch("sharesift.share.SmbShare", SmbShare):
            rc = cli.cmd_hunt(args)

        # v0.53: DFS UNC goes through to SmbShare (which handles
        # resolution); rc 0 since at least one target was kept.
        assert rc == 0
        # SmbShare IS invoked — the DFS resolution happens inside it
        SmbShare.assert_called_once()
        targets_file = tmp_path / "hunt_targets.txt"
        assert "Finance" in targets_file.read_text()
