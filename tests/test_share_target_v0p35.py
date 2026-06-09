"""v0.35 Sprint 2 — UNC / SMB target parser tests.

Covers the shapes pentesters actually paste, port handling, root
path under a share, and the conservative ``is_smb_target`` gate
that the CLI dispatch uses.
"""

from __future__ import annotations

import pytest

from sharesift.share import SmbTarget, is_smb_target, parse_target


class TestParseTarget:
    def test_unc_double_backslash(self):
        t = parse_target(r"\\10.0.0.5\Finance")
        assert t == SmbTarget(host="10.0.0.5", share="Finance", port=445, root_path="")

    def test_unc_forward_slash(self):
        t = parse_target("//10.0.0.5/Finance")
        assert t == SmbTarget(host="10.0.0.5", share="Finance", port=445, root_path="")

    def test_unc_with_dollar_share(self):
        t = parse_target(r"\\dc01.corp.local\SYSVOL$")
        assert t.host == "dc01.corp.local"
        assert t.share == "SYSVOL$"

    def test_unc_with_explicit_port(self):
        t = parse_target("//10.0.0.5:1445/Finance")
        assert t.host == "10.0.0.5"
        assert t.share == "Finance"
        assert t.port == 1445

    def test_unc_with_root_path_forward_slash(self):
        t = parse_target("//host/share/Sub/Dir")
        assert t.host == "host"
        assert t.share == "share"
        # Root path normalized to backslash for SMB layer
        assert t.root_path == "Sub\\Dir"

    def test_unc_with_root_path_backslash(self):
        t = parse_target(r"\\host\share\Sub\Dir")
        assert t.root_path == "Sub\\Dir"

    def test_bare_form_host_share(self):
        t = parse_target("host/share")
        assert t == SmbTarget(host="host", share="share", port=445, root_path="")

    def test_bare_form_with_port(self):
        t = parse_target("host:445/share")
        assert t.port == 445

    def test_unc_property(self):
        t = SmbTarget(host="h", share="s", root_path="a\\b")
        assert t.unc == r"\\h\s\a\b"

    def test_unc_property_no_root_path(self):
        t = SmbTarget(host="h", share="s")
        assert t.unc == r"\\h\s"

    def test_empty_input_raises(self):
        with pytest.raises(ValueError, match="empty"):
            parse_target("")

    def test_local_path_not_recognized(self):
        with pytest.raises(ValueError, match="not a UNC"):
            parse_target("/mnt/finance")

    def test_just_host_no_share_rejected(self):
        with pytest.raises(ValueError, match="not a UNC"):
            parse_target(r"\\10.0.0.5")

    def test_port_out_of_range_rejected(self):
        with pytest.raises(ValueError, match="port"):
            parse_target("//host:99999/share")

    def test_trailing_slash_dropped_from_root(self):
        # Trailing slash → empty root_path
        t = parse_target("//host/share/")
        assert t.root_path == ""


class TestIsSmbTarget:
    def test_double_backslash_is_smb(self):
        assert is_smb_target(r"\\host\share") is True

    def test_double_forward_slash_is_smb(self):
        assert is_smb_target("//host/share") is True

    def test_local_absolute_path_is_not_smb(self):
        assert is_smb_target("/mnt/finance") is False

    def test_local_relative_path_is_not_smb(self):
        assert is_smb_target("./out") is False

    def test_bare_host_share_is_not_smb(self):
        """Conservative — ``host/share`` could be a local relative
        path; the CLI shouldn't auto-detect it as SMB."""
        assert is_smb_target("host/share") is False

    def test_empty_is_not_smb(self):
        assert is_smb_target("") is False
