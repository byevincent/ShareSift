r"""v0.55.2: four engagement fixes from HTB Cascade smoke test.

1. Walker ACCESS_DENIED on subdirectory crashed the whole share
   scan. Fix: catch ACCESS_DENIED in walk(), record skip, continue.
2. UTF-16LE files (typical .reg exports) were UTF-8-decoded which
   garbled them. Fix: BOM-aware decode in extract.extract_text.
3. New rule ShareSiftKeepVncPasswordHex (live-validated Cascade).
4. New rules from audit: registry AutoLogon/EncMasterPassword +
   Gitleaks high-confidence prefix bundle.
"""

from __future__ import annotations

import importlib.util
from unittest.mock import MagicMock

import pytest


_HAS_IMPACKET = importlib.util.find_spec("impacket") is not None
_HAS_SMB = importlib.util.find_spec("smbprotocol") is not None


class TestUtf16BomDecode:
    def test_utf16le_with_bom_decoded_correctly(self):
        from sharesift.extract import extract_text

        original = '"Password"=hex:6b,cf,2a,4b'
        data = b"\xff\xfe" + original.encode("utf-16-le")
        text = extract_text(data, ".reg")
        assert text is not None
        assert '"Password"=hex:6b,cf,2a,4b' in text
        assert "\x00" not in text

    def test_utf16be_with_bom_decoded_correctly(self):
        from sharesift.extract import extract_text
        data = b"\xfe\xff" + "Hello World".encode("utf-16-be")
        assert extract_text(data, ".txt") == "Hello World"

    def test_utf8_bom_stripped(self):
        from sharesift.extract import extract_text
        assert extract_text(b"\xef\xbb\xbfHello UTF-8", ".txt") == "Hello UTF-8"

    def test_no_bom_falls_back_to_utf8(self):
        from sharesift.extract import extract_text
        assert extract_text(b"plain utf-8 text", ".txt") == "plain utf-8 text"


class TestVncRule:
    def test_vnc_hex_password_caught_red(self):
        from sharesift.content_rules import ContentRuleEngine

        eng = ContentRuleEngine()
        content = (
            'Windows Registry Editor Version 5.00\n'
            '[HKLM\\SOFTWARE\\TightVNC\\Server]\n'
            '"Password"=hex:6b,cf,2a,4b,6e,5a,ca,0f\n'
        )
        result = eng.evaluate(
            path=r"\\host\share\VNC Install.reg", content=content,
        )
        assert result.tier == "Red"
        assert any(
            m.rule_name == "ShareSiftKeepVncPasswordHex"
            for m in result.matches
        )

    def test_short_hex_does_not_match(self):
        from sharesift.content_rules import ContentRuleEngine
        eng = ContentRuleEngine()
        result = eng.evaluate(
            path=r"\\host\share\x.reg",
            content='"Foo"=hex:01,02',
        )
        assert not any(
            m.rule_name == "ShareSiftKeepVncPasswordHex"
            for m in result.matches
        )


class TestRegistryAutoLogonRule:
    def test_default_password_caught(self):
        from sharesift.content_rules import ContentRuleEngine

        eng = ContentRuleEngine()
        content = (
            '"AutoAdminLogon"="1"\n'
            '"DefaultPassword"="SecretLoginPw2026!"\n'
        )
        result = eng.evaluate(
            path=r"\\host\share\AutoLogon.reg", content=content,
        )
        assert any(
            m.rule_name == "ShareSiftKeepRegistryAutoLogonPassword"
            for m in result.matches
        )

    def test_encmasterpassword_caught(self):
        from sharesift.content_rules import ContentRuleEngine
        eng = ContentRuleEngine()
        result = eng.evaluate(
            path=r"\\host\share\WinSCP.reg",
            content='"EncMasterPassword"="A35C1234abcdef"\n',
        )
        assert any(
            m.rule_name == "ShareSiftKeepRegistryAutoLogonPassword"
            for m in result.matches
        )


class TestGitleaksBundle:
    # Token strings are built via concatenation so the literal regex-
    # matching form never appears in source — otherwise GitHub push
    # protection blocks the commit even with EXAMPLE markers.
    @pytest.mark.parametrize("token,label", [
        ("xo" + "xb-" + "1234567890-1234567890-EXAMPLE" + "F" * 24, "Slack bot"),
        ("gh" + "p_" + "EXAMPLE" + "f" * 29, "GitHub PAT"),
        ("github_" + "pat_" + "EXAMPLE" + "x" * 75, "GitHub fine-grained PAT"),
        ("sk_" + "live_" + "EXAMPLE" + "f" * 20, "Stripe live"),
        ("hv" + "s." + "EXAMPLE" + "v" * 100, "Vault hvs"),
        ("sh" + "pat_" + "ef" * 16, "Shopify"),  # 32 hex chars
        ("S" + "K" + "ef" * 16, "Twilio"),  # 32 hex chars
        ("S" + "G." + "f" * 22 + "." + "g" * 43, "SendGrid"),
        ("np" + "m_" + "EXAMPLE" + "n" * 29, "npm"),
    ])
    def test_token_caught_red(self, token, label):
        from sharesift.content_rules import ContentRuleEngine
        eng = ContentRuleEngine()
        content = f"# {label}\nAPI_TOKEN={token}\n"
        result = eng.evaluate(
            path=r"\\host\share\creds.txt", content=content,
        )
        assert any(
            m.rule_name == "ShareSiftKeepGitleaksHighConfidencePrefixes"
            for m in result.matches
        ), f"{label} not caught"


@pytest.mark.skipif(not _HAS_SMB, reason="needs smb extra")
class TestSmbProtocolWalkerAccessDeniedSkip:
    def test_access_denied_on_subdir_does_not_crash_walk(self):
        from sharesift.share import Auth
        from sharesift.share.smb import SmbShare
        from sharesift.share.target import SmbTarget

        target = SmbTarget(host="dc01", share="Data", port=445)
        share = SmbShare(
            target, Auth(user="u", password="p"), encrypt=False,
        )
        share._tree = MagicMock()
        share._tree.is_dfs_share = False
        share._ensure_connected = lambda: None

        call_count = {"n": 0}

        def fake_list(rel_dir):
            call_count["n"] += 1
            if call_count["n"] == 1:
                return [
                    {"name": "Denied", "size": 0, "is_directory": True},
                    {"name": "Readable", "size": 0, "is_directory": True},
                ]
            if call_count["n"] == 2:
                raise PermissionError("STATUS_ACCESS_DENIED 0xc0000022")
            return [
                {"name": "secret.txt", "size": 100, "is_directory": False},
            ]

        share._list_directory = fake_list
        entries = list(share.walk())
        assert len(entries) == 1
        assert "Readable" in entries[0].path
        assert hasattr(share, "_skipped_denied")


@pytest.mark.skipif(not _HAS_IMPACKET, reason="needs network-enum extra")
class TestImpacketWalkerAccessDeniedSkip:
    def test_access_denied_on_subdir_does_not_crash_walk(self):
        from sharesift.share import Auth
        from sharesift.share.smb_impacket import ImpacketSmbWalker
        from sharesift.share.target import SmbTarget

        target = SmbTarget(host="dc01", share="Data", port=445)
        walker = ImpacketSmbWalker(target, Auth(user="u", password="p"))
        walker._ensure_connected = lambda: None
        walker._conn = MagicMock()

        call_count = {"n": 0}

        def fake_list(rel_dir):
            call_count["n"] += 1
            if call_count["n"] == 1:
                return [
                    {"name": "Denied", "size": 0, "is_directory": True},
                    {"name": "Readable", "size": 0, "is_directory": True},
                ]
            if call_count["n"] == 2:
                raise PermissionError("STATUS_ACCESS_DENIED 0xc0000022")
            return [
                {"name": "log.txt", "size": 100, "is_directory": False},
            ]

        walker._list_directory = fake_list
        entries = list(walker.walk())
        assert len(entries) == 1
        assert hasattr(walker, "_skipped_denied")
