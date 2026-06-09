"""v0.35 Sprint 3 — CLI first-arg dispatch + SMB auth flags tests.

Covers the implicit-scan argv rewriter, ``_build_auth_from_args``,
the target precedence rules in ``cmd_scan``, and the ``--check``
preflight mode.

Network-using tests (live SMB) are Sprint 4. These tests mock the
SmbShare lifecycle and verify the wiring.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from sharesift.cli import (
    _build_auth_from_args,
    _rewrite_argv_for_implicit_scan,
)


# --------------------------------------------------------------------
# _rewrite_argv_for_implicit_scan
# --------------------------------------------------------------------


class TestArgvRewriter:
    def test_unc_target_gets_scan_injected(self):
        argv = ["//host/share", "-u", "u", "-p", "p"]
        assert _rewrite_argv_for_implicit_scan(argv) == [
            "scan", "//host/share", "-u", "u", "-p", "p",
        ]

    def test_double_backslash_unc_recognized(self):
        argv = [r"\\host\share", "-u", "u"]
        assert _rewrite_argv_for_implicit_scan(argv) == [
            "scan", r"\\host\share", "-u", "u",
        ]

    def test_explicit_scan_subcommand_left_alone(self):
        argv = ["scan", "--share", "/mnt/foo"]
        assert _rewrite_argv_for_implicit_scan(argv) == argv

    def test_explicit_score_paths_left_alone(self):
        argv = ["score-paths", "--input", "files.txt"]
        assert _rewrite_argv_for_implicit_scan(argv) == argv

    def test_explicit_verify_left_alone(self):
        argv = ["verify", "--input", "hits.jsonl"]
        assert _rewrite_argv_for_implicit_scan(argv) == argv

    def test_top_level_flags_before_target_preserved(self):
        argv = ["-v", "//host/share", "-u", "u"]
        assert _rewrite_argv_for_implicit_scan(argv) == [
            "-v", "scan", "//host/share", "-u", "u",
        ]

    def test_local_path_not_auto_detected(self):
        """Local paths like ``./output`` look indistinguishable from
        filenames — the rewriter is conservative and only fires on
        UNC shapes."""
        argv = ["/mnt/finance", "-u", "u"]
        assert _rewrite_argv_for_implicit_scan(argv) == argv
        # argparse will then error on "/mnt/finance" not being a known
        # subcommand — operator uses ``scan --share /mnt/finance``.

    def test_empty_argv(self):
        assert _rewrite_argv_for_implicit_scan([]) == []

    def test_only_flags(self):
        argv = ["-v", "--json"]
        assert _rewrite_argv_for_implicit_scan(argv) == argv


# --------------------------------------------------------------------
# _build_auth_from_args
# --------------------------------------------------------------------


def _ns(**kwargs):
    """Build a Namespace-like with defaults matching cli's auth flags."""
    import argparse
    defaults = {
        "user": None, "password": None, "hash": None,
        "kerberos": False, "use_kcache": False,
        "domain": None, "anonymous": False,
    }
    defaults.update(kwargs)
    return argparse.Namespace(**defaults)


class TestBuildAuthFromArgs:
    def test_returns_none_when_no_auth_flags_set(self):
        assert _build_auth_from_args(_ns(user="alice")) is None

    def test_password_auth(self):
        auth = _build_auth_from_args(_ns(user="alice", password="pw"))
        assert auth is not None
        assert auth.user == "alice"
        assert auth.password == "pw"
        assert auth.hash is None

    def test_hash_auth(self):
        auth = _build_auth_from_args(_ns(
            user="alice",
            hash="27c433245e4763d074d30a05aae0af2c",
        ))
        assert auth is not None
        assert auth.hash == "27c433245e4763d074d30a05aae0af2c"
        assert auth.password is None

    def test_kerberos_auth(self):
        auth = _build_auth_from_args(_ns(user="alice", kerberos=True))
        assert auth.kerberos is True

    def test_use_kcache_alias_sets_kerberos(self):
        auth = _build_auth_from_args(_ns(user="alice", use_kcache=True))
        assert auth.kerberos is True

    def test_anonymous_auth(self):
        auth = _build_auth_from_args(_ns(anonymous=True))
        assert auth is not None
        assert auth.anonymous is True
        assert auth.user is None

    def test_domain_passed_through(self):
        auth = _build_auth_from_args(_ns(
            user="alice", password="pw", domain="CORP",
        ))
        assert auth.domain == "CORP"


# --------------------------------------------------------------------
# Integration: cmd_scan with SMB target dispatch
# --------------------------------------------------------------------


class TestCmdScanSmbDispatch:
    """Verify cmd_scan wires UNC targets through to SmbShare correctly.

    Network calls are mocked; we test the dispatch glue, not the wire
    protocol. Live integration is Sprint 4.
    """

    def _scan_ns(self, **kwargs):
        import argparse
        defaults = {
            "target": None,
            "share": None,
            "output_dir": None,
            "user": None, "password": None, "hash": None,
            "kerberos": False, "use_kcache": False,
            "domain": None, "anonymous": False,
            "encrypt": True, "check": False,
            "skip_verify": False, "skip_report": False,
            "windows_model_dir": None, "linux_model_dir": None,
            "content_model_dir": None, "device": None,
            "max_snippet_bytes": 4096, "force_content": False,
            "target_file": None, "rate_limit": 1.0, "timeout": 10.0,
            "dry_run": False, "title": None,
        }
        defaults.update(kwargs)
        return argparse.Namespace(**defaults)

    def test_smb_target_requires_auth_flags(self):
        from sharesift.cli import cmd_scan
        ns = self._scan_ns(target="//host/share")
        with pytest.raises(SystemExit, match="auth"):
            cmd_scan(ns)

    def test_target_and_share_mutually_exclusive(self, tmp_path):
        from sharesift.cli import cmd_scan
        ns = self._scan_ns(
            target="//host/share",
            share=tmp_path,
            user="u", password="p",
        )
        with pytest.raises(SystemExit, match="mutually exclusive"):
            cmd_scan(ns)

    def test_no_target_no_share_errors(self):
        from sharesift.cli import cmd_scan
        with pytest.raises(SystemExit, match="target required"):
            cmd_scan(self._scan_ns())

    def test_check_mode_calls_smbshare_context(self, tmp_path):
        from sharesift.cli import cmd_scan
        ns = self._scan_ns(
            target="//host/share",
            user="alice", password="pw",
            check=True,
        )
        with patch("sharesift.share.smb.SmbShare._ensure_connected") as mock_conn:
            mock_conn.return_value = None
            with patch("sharesift.share.smb.SmbShare.close") as mock_close:
                rc = cmd_scan(ns)
                assert rc == 0
                mock_conn.assert_called_once()
                mock_close.assert_called_once()

    def test_check_mode_returns_1_on_auth_failure(self):
        from sharesift.cli import cmd_scan
        ns = self._scan_ns(
            target="//host/share",
            user="alice", password="wrong",
            check=True,
        )
        with patch("sharesift.share.smb.SmbShare._ensure_connected") as mock_conn:
            mock_conn.side_effect = RuntimeError("auth fail")
            rc = cmd_scan(ns)
            assert rc == 1

    def test_check_mode_rejected_for_local_target(self, tmp_path):
        from sharesift.cli import cmd_scan
        ns = self._scan_ns(
            share=tmp_path,
            check=True,
        )
        with pytest.raises(SystemExit, match="--check only applies to SMB"):
            cmd_scan(ns)

    def test_smb_walk_produces_files_txt_with_unc_paths(self, tmp_path):
        from sharesift.cli import cmd_scan
        from sharesift.share import ShareEntry

        fake_entries = [
            ShareEntry(path=r"\\10.0.0.5\Finance\a.txt", size=10),
            ShareEntry(path=r"\\10.0.0.5\Finance\sub\b.txt", size=20),
        ]

        ns = self._scan_ns(
            target="//10.0.0.5/Finance",
            user="alice", password="pw",
            output_dir=tmp_path,
        )

        with (
            patch("sharesift.share.smb.SmbShare._ensure_connected"),
            patch("sharesift.share.smb.SmbShare.close"),
            patch("sharesift.share.smb.SmbShare.walk", return_value=iter(fake_entries)),
            patch("sharesift.cli.cmd_score_paths", return_value=0),
        ):
            rc = cmd_scan(ns)
            assert rc == 0
            files_txt = (tmp_path / "files.txt").read_text()
            assert r"\\10.0.0.5\Finance\a.txt" in files_txt
            assert r"\\10.0.0.5\Finance\sub\b.txt" in files_txt

    def test_smb_default_output_dir_uses_host_and_share(self, tmp_path, monkeypatch):
        """Default output dir for SMB is ``./sharesift-<host>-<share>/``."""
        from sharesift.cli import cmd_scan
        from sharesift.share import ShareEntry

        monkeypatch.chdir(tmp_path)
        ns = self._scan_ns(
            target="//10.0.0.5/Finance",
            user="alice", password="pw",
            # output_dir explicitly None
        )
        with (
            patch("sharesift.share.smb.SmbShare._ensure_connected"),
            patch("sharesift.share.smb.SmbShare.close"),
            patch("sharesift.share.smb.SmbShare.walk", return_value=iter([])),
            patch("sharesift.cli.cmd_score_paths", return_value=0),
        ):
            cmd_scan(ns)
            assert (tmp_path / "sharesift-10.0.0.5-Finance").exists()

    def test_smb_skips_content_stage_in_sprint_3(self, tmp_path):
        """v0.35 Sprint 3 ships path-triage only for SMB; Sprint 3.5
        closes the cascade. Confirm scan-files and verify don't run."""
        from sharesift.cli import cmd_scan
        from sharesift.share import ShareEntry

        ns = self._scan_ns(
            target="//host/share",
            user="alice", password="pw",
            output_dir=tmp_path,
        )

        with (
            patch("sharesift.share.smb.SmbShare._ensure_connected"),
            patch("sharesift.share.smb.SmbShare.close"),
            patch("sharesift.share.smb.SmbShare.walk", return_value=iter([])),
            patch("sharesift.cli.cmd_score_paths", return_value=0) as mock_sp,
            patch("sharesift.cli.cmd_scan_files", return_value=0) as mock_sf,
            patch("sharesift.cli.cmd_verify", return_value=0) as mock_v,
            patch("sharesift.cli.cmd_render_report", return_value=0) as mock_r,
        ):
            cmd_scan(ns)
            mock_sp.assert_called_once()
            mock_sf.assert_not_called()
            mock_v.assert_not_called()
            mock_r.assert_not_called()


class TestCmdScanLocalDispatchPreserved:
    """v0.35 must not regress the v0.18 local-share flow."""

    def _scan_ns(self, **kwargs):
        import argparse
        defaults = {
            "target": None, "share": None, "output_dir": None,
            "user": None, "password": None, "hash": None,
            "kerberos": False, "use_kcache": False,
            "domain": None, "anonymous": False,
            "encrypt": True, "check": False,
            "skip_verify": False, "skip_report": False,
            "windows_model_dir": None, "linux_model_dir": None,
            "content_model_dir": None, "device": None,
            "max_snippet_bytes": 4096, "force_content": False,
            "target_file": None, "rate_limit": 1.0, "timeout": 10.0,
            "dry_run": False, "title": None,
        }
        defaults.update(kwargs)
        return argparse.Namespace(**defaults)

    def test_legacy_share_flag_still_works(self, tmp_path):
        """The v0.18 ``--share`` flag continues to dispatch to
        LocalShare and runs all cascade stages."""
        from sharesift.cli import cmd_scan

        (tmp_path / "f.txt").write_text("content")
        out_dir = tmp_path / "out"

        ns = self._scan_ns(
            share=tmp_path,
            output_dir=out_dir,
            skip_verify=True, skip_report=True,
        )
        with (
            patch("sharesift.cli.cmd_score_paths", return_value=0) as mock_sp,
            patch("sharesift.cli.cmd_scan_files", return_value=0) as mock_sf,
        ):
            cmd_scan(ns)
            mock_sp.assert_called_once()
            mock_sf.assert_called_once()

    def test_local_positional_target_works(self, tmp_path):
        """v0.35 also accepts a local path as positional target."""
        from sharesift.cli import cmd_scan

        (tmp_path / "f.txt").write_text("content")
        out_dir = tmp_path / "out"

        ns = self._scan_ns(
            target=str(tmp_path),
            output_dir=out_dir,
            skip_verify=True, skip_report=True,
        )
        with (
            patch("sharesift.cli.cmd_score_paths", return_value=0) as mock_sp,
            patch("sharesift.cli.cmd_scan_files", return_value=0) as mock_sf,
        ):
            cmd_scan(ns)
            mock_sp.assert_called_once()
            mock_sf.assert_called_once()
