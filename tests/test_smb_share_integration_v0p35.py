"""v0.35 Sprint 4 — SmbShare live integration tests.

Runs against the ``samba_container`` session fixture (dperson/samba
4.x, SMB2/3-capable). Gated behind ``SHARESIFT_SMB_TESTS=1``; skip
cleanly when Docker isn't available.

These tests are the validation that the mocked Sprint 2 SmbShare
behavior matches the real wire protocol. If they pass, the v0.35
SMB-direct backend is operationally validated end-to-end.
"""

from __future__ import annotations

import pytest

from sharesift.share import Auth, ShareEntry, SmbShare, SmbTarget


# All tests in this file require the live container fixture
pytestmark = pytest.mark.usefixtures("samba_container")


def _target(fixture) -> SmbTarget:
    return SmbTarget(host=fixture.host, port=fixture.port, share=fixture.share)


# --------------------------------------------------------------------
# Auth modes — password, PtH (LM:NT), PtH (bare NT)
# --------------------------------------------------------------------


def test_password_auth_lists_share_root(samba_container):
    auth = Auth(user=samba_container.user, password=samba_container.password)
    share = SmbShare(_target(samba_container), auth, encrypt=False)
    try:
        entries = list(share.walk())
    finally:
        share.close()

    names = {e.path.rsplit("\\", 1)[-1] for e in entries}
    assert "hello.txt" in names
    assert "secrets.cfg" in names
    assert "binary.bin" in names


def test_pth_lm_nt_form_lists_share_root(samba_container):
    auth = Auth(
        user=samba_container.user,
        hash=f"aad3b435b51404eeaad3b435b51404ee:{samba_container.nt_hash}",
    )
    share = SmbShare(_target(samba_container), auth, encrypt=False)
    try:
        entries = list(share.walk())
    finally:
        share.close()

    assert any(e.path.endswith("hello.txt") for e in entries)


def test_pth_bare_nt_form_lists_share_root(samba_container):
    auth = Auth(user=samba_container.user, hash=samba_container.nt_hash)
    share = SmbShare(_target(samba_container), auth, encrypt=False)
    try:
        entries = list(share.walk())
    finally:
        share.close()

    assert any(e.path.endswith("hello.txt") for e in entries)


# --------------------------------------------------------------------
# walk() — recursion, sort, file-only
# --------------------------------------------------------------------


def test_walk_recurses_into_subdirectories(samba_container):
    auth = Auth(user=samba_container.user, password=samba_container.password)
    share = SmbShare(_target(samba_container), auth, encrypt=False)
    try:
        paths = [e.path for e in share.walk()]
    finally:
        share.close()

    assert any(p.endswith(r"sub\nested.txt") for p in paths)
    assert any(p.endswith(r"sub\deeper\deep.txt") for p in paths)


def test_walk_excludes_directories(samba_container):
    auth = Auth(user=samba_container.user, password=samba_container.password)
    share = SmbShare(_target(samba_container), auth, encrypt=False)
    try:
        paths = [e.path for e in share.walk()]
    finally:
        share.close()

    # ``sub`` and ``empty_subdir`` are directories — they should not appear
    assert not any(p.endswith(r"\sub") for p in paths)
    assert not any(p.endswith(r"\empty_subdir") for p in paths)


def test_walk_yields_size_metadata(samba_container):
    auth = Auth(user=samba_container.user, password=samba_container.password)
    share = SmbShare(_target(samba_container), auth, encrypt=False)
    try:
        entries = {e.path.rsplit("\\", 1)[-1]: e for e in share.walk()}
    finally:
        share.close()

    assert entries["hello.txt"].size == len("hello world\n")
    assert entries["binary.bin"].size == 256 * 4


def test_walk_output_is_sorted(samba_container):
    auth = Auth(user=samba_container.user, password=samba_container.password)
    share = SmbShare(_target(samba_container), auth, encrypt=False)
    try:
        paths = [e.path for e in share.walk()]
    finally:
        share.close()

    assert paths == sorted(paths)


# --------------------------------------------------------------------
# read_bytes — files of various shapes
# --------------------------------------------------------------------


def test_read_bytes_returns_file_content(samba_container):
    auth = Auth(user=samba_container.user, password=samba_container.password)
    share = SmbShare(_target(samba_container), auth, encrypt=False)
    try:
        unc = rf"\\{samba_container.host}\{samba_container.share}\hello.txt"
        data = share.read_bytes(unc)
    finally:
        share.close()

    assert data == b"hello world\n"


def test_read_bytes_nested_file(samba_container):
    auth = Auth(user=samba_container.user, password=samba_container.password)
    share = SmbShare(_target(samba_container), auth, encrypt=False)
    try:
        unc = rf"\\{samba_container.host}\{samba_container.share}\sub\deeper\deep.txt"
        data = share.read_bytes(unc)
    finally:
        share.close()

    assert data == b"deeply nested\n"


def test_read_bytes_binary_content(samba_container):
    auth = Auth(user=samba_container.user, password=samba_container.password)
    share = SmbShare(_target(samba_container), auth, encrypt=False)
    try:
        unc = rf"\\{samba_container.host}\{samba_container.share}\binary.bin"
        data = share.read_bytes(unc)
    finally:
        share.close()

    assert data == bytes(range(256)) * 4


def test_read_bytes_honors_max_bytes(samba_container):
    auth = Auth(user=samba_container.user, password=samba_container.password)
    share = SmbShare(_target(samba_container), auth, encrypt=False)
    try:
        unc = rf"\\{samba_container.host}\{samba_container.share}\binary.bin"
        data = share.read_bytes(unc, max_bytes=16)
    finally:
        share.close()

    assert data == bytes(range(16))


def test_read_bytes_returns_none_for_nonexistent(samba_container):
    auth = Auth(user=samba_container.user, password=samba_container.password)
    share = SmbShare(_target(samba_container), auth, encrypt=False)
    try:
        unc = rf"\\{samba_container.host}\{samba_container.share}\nope.txt"
        data = share.read_bytes(unc)
    finally:
        share.close()

    assert data is None


def test_read_bytes_returns_none_for_other_share(samba_container):
    auth = Auth(user=samba_container.user, password=samba_container.password)
    share = SmbShare(_target(samba_container), auth, encrypt=False)
    try:
        unc = rf"\\{samba_container.host}\OtherShare\f.txt"
        data = share.read_bytes(unc)
    finally:
        share.close()

    assert data is None


# --------------------------------------------------------------------
# Session reuse — multiple reads on one connection
# --------------------------------------------------------------------


def test_multiple_read_bytes_reuse_session(samba_container):
    """One Session, multiple reads — the v0.35 cascade scans 50k+
    files on one connection. Verify the session stays alive."""
    auth = Auth(user=samba_container.user, password=samba_container.password)
    share = SmbShare(_target(samba_container), auth, encrypt=False)
    try:
        results = {}
        for fname, expected in [
            ("hello.txt", b"hello world\n"),
            ("secrets.cfg", b"password=hunter2\napi_key=abc123\n"),
            ("sub/nested.txt", b"nested content\n"),
            ("sub/deeper/deep.txt", b"deeply nested\n"),
        ]:
            unc = rf"\\{samba_container.host}\{samba_container.share}\{fname.replace('/', chr(92))}"
            results[fname] = share.read_bytes(unc)
        # Verify everything came back correctly — single connection
        # served all four reads.
        assert results["hello.txt"] == b"hello world\n"
        assert results["secrets.cfg"] == b"password=hunter2\napi_key=abc123\n"
        assert results["sub/nested.txt"] == b"nested content\n"
        assert results["sub/deeper/deep.txt"] == b"deeply nested\n"
    finally:
        share.close()


# --------------------------------------------------------------------
# Auth failure modes
# --------------------------------------------------------------------


def test_wrong_password_raises_auth_error(samba_container):
    from smbprotocol.exceptions import SMBAuthenticationError, SMBException

    auth = Auth(user=samba_container.user, password="wrong-password")
    share = SmbShare(_target(samba_container), auth, encrypt=False)
    with pytest.raises((SMBAuthenticationError, SMBException)):
        try:
            list(share.walk())
        finally:
            share.close()


def test_wrong_port_raises_connection_error(samba_container):
    """A port nothing's listening on → either ValueError (smbprotocol
    wraps the underlying refused) or ConnectionRefusedError."""
    bad_target = SmbTarget(
        host=samba_container.host, port=59999, share=samba_container.share
    )
    auth = Auth(user=samba_container.user, password=samba_container.password)
    share = SmbShare(bad_target, auth, encrypt=False)
    with pytest.raises((ValueError, ConnectionError, OSError)):
        try:
            list(share.walk())
        finally:
            share.close()


# --------------------------------------------------------------------
# SMB3 encryption — the production default
# --------------------------------------------------------------------


def test_encrypt_true_works_against_modern_samba(samba_container):
    """``encrypt=True`` is the SmbShare default. Operators should
    get SMB3 message encryption against any SMB3-capable server
    without flag wrangling. Validates that what the docs promise
    actually works against Samba 4.x."""
    auth = Auth(user=samba_container.user, password=samba_container.password)
    share = SmbShare(_target(samba_container), auth)  # default encrypt=True
    try:
        entries = list(share.walk())
        unc = rf"\\{samba_container.host}\{samba_container.share}\hello.txt"
        data = share.read_bytes(unc)
    finally:
        share.close()

    assert any(e.path.endswith("hello.txt") for e in entries)
    assert data == b"hello world\n"


def test_encrypt_true_works_with_pth(samba_container):
    """PtH + SMB3 encryption together — the production pentester
    workflow."""
    auth = Auth(user=samba_container.user, hash=samba_container.nt_hash)
    share = SmbShare(_target(samba_container), auth)  # default encrypt=True
    try:
        entries = list(share.walk())
    finally:
        share.close()

    assert any(e.path.endswith("hello.txt") for e in entries)


# --------------------------------------------------------------------
# End-to-end with load_content_from_share — the real production path
# --------------------------------------------------------------------


def test_load_content_from_share_reads_and_extracts_text(samba_container):
    """The full integration: SmbShare.read_bytes →
    extract_text → text. Same path the cascade follows in cmd_scan."""
    from sharesift.extract import load_content_from_share

    auth = Auth(user=samba_container.user, password=samba_container.password)
    share = SmbShare(_target(samba_container), auth, encrypt=False)
    try:
        unc = rf"\\{samba_container.host}\{samba_container.share}\secrets.cfg"
        text = load_content_from_share(share, unc)
    finally:
        share.close()

    assert text is not None
    assert "password=hunter2" in text
    assert "api_key=abc123" in text


def test_load_content_from_share_respects_max_bytes(samba_container):
    from sharesift.extract import load_content_from_share

    auth = Auth(user=samba_container.user, password=samba_container.password)
    share = SmbShare(_target(samba_container), auth, encrypt=False)
    try:
        unc = rf"\\{samba_container.host}\{samba_container.share}\hello.txt"
        text = load_content_from_share(share, unc, max_bytes=5)
    finally:
        share.close()

    assert text == "hello"


# --------------------------------------------------------------------
# Walk → read loop — the cmd_scan workflow shape
# --------------------------------------------------------------------


def test_walk_then_read_each_file(samba_container):
    """The cmd_scan pattern: enumerate files, then read each one's
    contents through the same connection. End-to-end validation."""
    auth = Auth(user=samba_container.user, password=samba_container.password)
    share = SmbShare(_target(samba_container), auth, encrypt=False)
    try:
        entries = list(share.walk())
        contents: dict[str, bytes] = {}
        for e in entries:
            data = share.read_bytes(e.path)
            if data is not None:
                contents[e.path.rsplit("\\", 1)[-1]] = data
    finally:
        share.close()

    assert b"hello world\n" == contents["hello.txt"]
    assert b"nested content\n" == contents["nested.txt"]
    assert b"deeply nested\n" == contents["deep.txt"]
