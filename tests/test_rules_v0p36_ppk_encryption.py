"""v0.36 step 2 — .ppk encryption-aware tier resolution.

Closes Snaffler issue #191: Snaffler flags every .ppk file as worth
investigating, but most are passphrase-protected and not actionable
without the passphrase. ShareSift distinguishes the two:

  - Extension-only match (any .ppk) → Yellow floor
  - Content match (``Encryption: none``) → Black promotion

Operators triaging by tier see only the immediately-usable unencrypted
keys in their Black queue, while passphrase-protected keys stay
visible in Yellow for the "if you crack the passphrase later" pile.
"""

from __future__ import annotations

from sharesift.content_rules import get_default_engine


# Sample PPK file bodies. Public-key body / private-key body content
# is irrelevant for the encryption-status check — only the header +
# Encryption field matter for tier resolution.

_UNENCRYPTED_PPK_V3 = """PuTTY-User-Key-File-3: ssh-ed25519
Encryption: none
Comment: alice@workstation
Public-Lines: 2
AAAAC3NzaC1lZDI1NTE5AAAAIAbcdef0123456789
abcdefghijklmnopqrstuvwxyz
Private-Lines: 1
private-key-base64-data-here
Private-MAC: 0a1b2c3d4e5f
"""

_UNENCRYPTED_PPK_V2 = """PuTTY-User-Key-File-2: ssh-rsa
Encryption: none
Comment: legacy-server-key
Public-Lines: 6
AAAAB3NzaC1yc2EAAAADAQABAAABAQDA1234567890
"""

_ENCRYPTED_PPK_V3 = """PuTTY-User-Key-File-3: ssh-rsa
Encryption: aes256-cbc
Comment: bob@prod-server
Public-Lines: 6
AAAAB3NzaC1yc2EAAAADAQABAAABAQDA1234567890
"""

_ENCRYPTED_PPK_V2_GCM = """PuTTY-User-Key-File-2: ssh-rsa
Encryption: aes128-cbc
Comment: ops-jumpbox
Public-Lines: 6
AAAAB3NzaC1yc2EAAAADAQABAAABAQDA1234567890
"""


def _verdict(path: str, content: str | None):
    return get_default_engine().evaluate(path, content=content)


def _matches_named(path: str, name: str, content: str | None = None):
    return [m for m in _verdict(path, content).matches if name in m.rule_name]


# --- Yellow floor: any .ppk extension hits the legacy rule ----------


def test_any_ppk_extension_hits_yellow_floor():
    """Extension match fires even without content (path-only triage
    case). The Snaffler-ported ``KeepSSHKeysByFileExtension`` rule
    handles the Yellow floor — it was demoted from Black to Yellow
    in v0.36 step 2 so encrypted .ppk files don't spam Black."""
    v = _verdict("/home/alice/keys/server.ppk", content=None)
    by_extension = [
        m for m in v.matches if "KeepSSHKeysByFileExtension" in m.rule_name
    ]
    assert len(by_extension) == 1
    assert by_extension[0].tier == "Yellow"


def test_extension_match_alone_keeps_overall_tier_yellow():
    """Without content (no encryption status known), the worst we can
    say is Yellow."""
    v = _verdict("/home/alice/keys/unknown.ppk", content=None)
    assert v.tier == "Yellow"


# --- Black promotion: Encryption: none content matches --------------


def test_unencrypted_ppk_v3_promotes_to_black():
    matches = _matches_named(
        "/home/alice/keys/server.ppk", "PuttyPpkUnencrypted",
        content=_UNENCRYPTED_PPK_V3,
    )
    assert len(matches) == 1
    assert matches[0].tier == "Black"


def test_unencrypted_ppk_v2_promotes_to_black():
    matches = _matches_named(
        "/home/alice/keys/legacy.ppk", "PuttyPpkUnencrypted",
        content=_UNENCRYPTED_PPK_V2,
    )
    assert len(matches) == 1
    assert matches[0].tier == "Black"


def test_unencrypted_ppk_highest_tier_is_black():
    """Engine resolves max(matches): Yellow extension + Black content
    → Black overall."""
    v = _verdict("/home/alice/keys/server.ppk", content=_UNENCRYPTED_PPK_V3)
    assert v.tier == "Black"


# --- Encrypted PPK stays Yellow (the Snaffler #191 fix) -------------


def test_encrypted_ppk_aes256_does_not_promote():
    matches = _matches_named(
        "/home/bob/keys/prod.ppk", "PuttyPpkUnencrypted",
        content=_ENCRYPTED_PPK_V3,
    )
    assert matches == []


def test_encrypted_ppk_aes128_does_not_promote():
    matches = _matches_named(
        "/home/bob/keys/jumpbox.ppk", "PuttyPpkUnencrypted",
        content=_ENCRYPTED_PPK_V2_GCM,
    )
    assert matches == []


def test_encrypted_ppk_overall_tier_stays_yellow():
    """The whole point of the issue: encrypted .ppk files shouldn't
    crowd the high-priority tiers."""
    v = _verdict("/home/bob/keys/prod.ppk", content=_ENCRYPTED_PPK_V3)
    assert v.tier == "Yellow"


# --- False-positive guards ------------------------------------------


def test_non_ppk_with_encryption_none_string_does_not_promote():
    """A random file that just contains ``Encryption: none`` somewhere
    in its body but isn't a PPK shouldn't trigger the Black promotion.
    The pattern requires the PPK header within 500 chars of
    ``Encryption: none``."""
    content = (
        "# Application config\n"
        "[database]\n"
        "host = localhost\n"
        "Encryption: none\n"
        "username = appuser\n"
    )
    matches = _matches_named(
        "/etc/app.conf", "PuttyPpkUnencrypted", content=content,
    )
    assert matches == []


def test_ppk_header_far_from_encryption_field_does_not_match():
    """Header + Encryption field separated by >500 chars shouldn't
    match — the pattern's distance limit guards against accidental
    matches in concatenated logs / multi-key bundles."""
    # 600 chars of filler between header and Encryption: none
    content = (
        "PuTTY-User-Key-File-3: ssh-rsa\n"
        + ("# " + "x" * 296 + "\n") * 2
        + "Encryption: none\n"
    )
    matches = _matches_named(
        "/home/alice/keys/server.ppk", "PuttyPpkUnencrypted",
        content=content,
    )
    assert matches == []


def test_unrelated_file_with_ppk_extension_only_stays_yellow():
    """A file ending in .ppk that doesn't have the PuTTY header at all
    (e.g. someone renamed something) stays Yellow — extension rule
    fires, content rule doesn't."""
    v = _verdict(
        "/share/random.ppk", content="this isn't a PuTTY key file at all"
    )
    assert v.tier == "Yellow"
    assert _matches_named(
        "/share/random.ppk", "PuttyPpkUnencrypted",
        content="this isn't a PuTTY key file at all"
    ) == []
