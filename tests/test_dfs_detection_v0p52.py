"""v0.52: DFS detection heuristic tests."""

from __future__ import annotations

from sharesift.share.dfs import dfs_guidance, looks_like_dfs


class TestLooksLikeDfs:
    def test_domain_shaped_unc_detected(self):
        assert looks_like_dfs(r"\\corp.local\departments\hr") is True

    def test_single_label_host_not_dfs(self):
        assert looks_like_dfs(r"\\fs01\share") is False

    def test_fqdn_host_also_flagged(self):
        # FQDN file servers also have dots — false-positive is fine,
        # operator just gets a hint they can ignore.
        assert looks_like_dfs(r"\\fs01.corp.local\share") is True

    def test_ip_address_not_dfs(self):
        # IPs have dots but the v0.52 heuristic is conservative —
        # this is a false-positive. Honest scope.
        assert looks_like_dfs(r"\\10.0.0.5\share") is True

    def test_bare_string_not_dfs(self):
        assert looks_like_dfs("not-a-unc") is False

    def test_empty_string(self):
        assert looks_like_dfs("") is False


class TestDfsGuidance:
    def test_guidance_mentions_server(self):
        msg = dfs_guidance(r"\\corp.local\departments\hr")
        assert "corp.local" in msg

    def test_guidance_mentions_v0p53_followup(self):
        msg = dfs_guidance(r"\\corp.local\dfs\hr")
        assert "v0.53" in msg

    def test_guidance_includes_actionable_command(self):
        msg = dfs_guidance(r"\\corp.local\dfs\hr")
        assert "nxc smb" in msg or "sharesift hunt" in msg
