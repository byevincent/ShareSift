"""v0.35 Sprint 2 — SmbShare unit tests (mocked smbprotocol).

The live integration tests against ``dperson/samba`` arrive in
Sprint 4. These tests verify the wiring without touching the network:

  - ``walk()`` recursion + sort + yield logic (mocking
    ``_list_directory`` directly)
  - ``_ensure_connected()`` constructs Connection/Session/TreeConnect
    with the right args derived from target + auth
  - ``close()`` / ``__exit__`` tears down in reverse order
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

# These tests mock smbprotocol but still import NTLMHash from spnego at
# the module level. CI runs without the [smb] extra, so collect-skip
# the module when spnego isn't installed.
pytest.importorskip("spnego")

from spnego._credential import NTLMHash  # noqa: E402

from sharesift.share import Auth, ShareEntry, SmbShare, SmbTarget  # noqa: E402


# --------------------------------------------------------------------
# walk() — recursion, sort, yield. _list_directory is monkeypatched.
# --------------------------------------------------------------------


def _patch_list_directory(share: SmbShare, directory_tree: dict[str, list[dict]]):
    """Stub _list_directory to return a fixed tree.

    ``directory_tree`` maps relative directory path → list of entries.
    Each entry is ``{"name": str, "size": int, "is_directory": bool}``.
    """

    def fake_list(rel_dir: str) -> list[dict]:
        return directory_tree.get(rel_dir, [])

    share._list_directory = fake_list  # type: ignore[method-assign]
    share._ensure_connected = lambda: None  # type: ignore[method-assign]


def _share() -> SmbShare:
    return SmbShare(
        target=SmbTarget(host="10.0.0.5", share="Finance"),
        auth=Auth(user="alice", password="pw"),
    )


def test_walk_yields_files_only_at_root():
    share = _share()
    _patch_list_directory(share, {
        "": [
            {"name": "a.txt", "size": 3, "is_directory": False},
            {"name": "b.txt", "size": 5, "is_directory": False},
        ],
    })
    entries = list(share.walk())
    assert entries == [
        ShareEntry(path=r"\\10.0.0.5\Finance\a.txt", size=3),
        ShareEntry(path=r"\\10.0.0.5\Finance\b.txt", size=5),
    ]


def test_walk_recurses_into_subdirectories():
    share = _share()
    _patch_list_directory(share, {
        "": [
            {"name": "a.txt", "size": 1, "is_directory": False},
            {"name": "sub", "size": 0, "is_directory": True},
        ],
        "sub": [
            {"name": "b.txt", "size": 2, "is_directory": False},
            {"name": "nested", "size": 0, "is_directory": True},
        ],
        "sub\\nested": [
            {"name": "c.txt", "size": 3, "is_directory": False},
        ],
    })
    paths = [e.path for e in share.walk()]
    assert paths == [
        r"\\10.0.0.5\Finance\a.txt",
        r"\\10.0.0.5\Finance\sub\b.txt",
        r"\\10.0.0.5\Finance\sub\nested\c.txt",
    ]


def test_walk_skips_dot_and_dotdot_entries():
    """SMB query_directory includes ``.`` and ``..``; they shouldn't
    appear in walk output (would otherwise infinite-loop on
    recursion)."""
    share = _share()
    _patch_list_directory(share, {
        "": [
            {"name": ".", "size": 0, "is_directory": True},
            {"name": "..", "size": 0, "is_directory": True},
            {"name": "f.txt", "size": 1, "is_directory": False},
        ],
    })
    paths = [e.path for e in share.walk()]
    assert paths == [r"\\10.0.0.5\Finance\f.txt"]


def test_walk_output_is_sorted():
    share = _share()
    _patch_list_directory(share, {
        "": [
            {"name": "z.txt", "size": 1, "is_directory": False},
            {"name": "a.txt", "size": 1, "is_directory": False},
            {"name": "m.txt", "size": 1, "is_directory": False},
        ],
    })
    paths = [e.path for e in share.walk()]
    assert paths == sorted(paths)


def test_walk_starts_at_target_root_path():
    """When the target specifies a subdir, walk only emits that
    subtree."""
    target = SmbTarget(host="h", share="s", root_path="Finance\\Q3")
    share = SmbShare(target=target, auth=Auth(anonymous=True))
    _patch_list_directory(share, {
        "Finance\\Q3": [
            {"name": "report.docx", "size": 100, "is_directory": False},
        ],
    })
    paths = [e.path for e in share.walk()]
    assert paths == [r"\\h\s\Finance\Q3\report.docx"]


def test_root_property_returns_target_unc():
    share = SmbShare(
        target=SmbTarget(host="h", share="s", root_path="sub"),
        auth=Auth(anonymous=True),
    )
    assert share.root == r"\\h\s\sub"


# --------------------------------------------------------------------
# _ensure_connected — Connection/Session/TreeConnect wiring
# --------------------------------------------------------------------


def test_ensure_connected_passes_target_to_connection():
    target = SmbTarget(host="10.0.0.5", share="Finance", port=1445)
    auth = Auth(user="alice", password="pw")
    share = SmbShare(target=target, auth=auth)

    with (
        patch("smbprotocol.connection.Connection") as MockConn,
        patch("smbprotocol.session.Session") as MockSession,
        patch("smbprotocol.tree.TreeConnect") as MockTree,
    ):
        share._ensure_connected()

        # Connection constructed with host + port
        conn_args = MockConn.call_args
        assert conn_args.args[1] == "10.0.0.5"
        assert conn_args.args[2] == 1445
        MockConn.return_value.connect.assert_called_once()

        # Session constructed with credential + protocol
        session_kwargs = MockSession.call_args.kwargs
        assert session_kwargs["username"] == "alice"
        assert session_kwargs["password"] == "pw"
        assert session_kwargs["auth_protocol"] == "ntlm"
        assert session_kwargs["require_encryption"] is True
        MockSession.return_value.connect.assert_called_once()

        # Tree constructed with \\host\share UNC
        tree_args = MockTree.call_args.args
        assert tree_args[1] == r"\\10.0.0.5\Finance"
        MockTree.return_value.connect.assert_called_once()


def test_ensure_connected_passes_hash_credential_for_pth():
    target = SmbTarget(host="h", share="s")
    auth = Auth(user="msfadmin", hash="27c433245e4763d074d30a05aae0af2c")
    share = SmbShare(target=target, auth=auth)

    with (
        patch("smbprotocol.connection.Connection"),
        patch("smbprotocol.session.Session") as MockSession,
        patch("smbprotocol.tree.TreeConnect"),
    ):
        share._ensure_connected()
        sk = MockSession.call_args.kwargs
        assert isinstance(sk["username"], NTLMHash)
        assert sk["password"] is None
        assert sk["auth_protocol"] == "ntlm"


def test_ensure_connected_uses_kerberos_protocol():
    target = SmbTarget(host="h", share="s")
    auth = Auth(user="alice", kerberos=True, domain="CORP")
    share = SmbShare(target=target, auth=auth)

    with (
        patch("smbprotocol.connection.Connection"),
        patch("smbprotocol.session.Session") as MockSession,
        patch("smbprotocol.tree.TreeConnect"),
    ):
        share._ensure_connected()
        sk = MockSession.call_args.kwargs
        assert sk["auth_protocol"] == "kerberos"
        assert sk["username"] == "CORP\\alice"


def test_ensure_connected_honors_encrypt_false():
    share = SmbShare(
        target=SmbTarget(host="h", share="s"),
        auth=Auth(user="u", password="p"),
        encrypt=False,
    )
    with (
        patch("smbprotocol.connection.Connection"),
        patch("smbprotocol.session.Session") as MockSession,
        patch("smbprotocol.tree.TreeConnect"),
    ):
        share._ensure_connected()
        assert MockSession.call_args.kwargs["require_encryption"] is False


def test_ensure_connected_idempotent():
    """Second call when tree is already set shouldn't re-create."""
    share = SmbShare(
        target=SmbTarget(host="h", share="s"),
        auth=Auth(user="u", password="p"),
    )
    share._tree = MagicMock()
    with patch("smbprotocol.connection.Connection") as MockConn:
        share._ensure_connected()
        MockConn.assert_not_called()


# --------------------------------------------------------------------
# close() / __exit__ — teardown order
# --------------------------------------------------------------------


def test_close_disconnects_tree_session_connection():
    share = SmbShare(
        target=SmbTarget(host="h", share="s"),
        auth=Auth(user="u", password="p"),
    )
    share._tree = MagicMock()
    share._session = MagicMock()
    share._connection = MagicMock()

    share.close()

    share._tree is None
    assert share._tree is None
    assert share._session is None
    assert share._connection is None


def test_close_is_idempotent():
    share = SmbShare(
        target=SmbTarget(host="h", share="s"),
        auth=Auth(user="u", password="p"),
    )
    share.close()  # Nothing to disconnect; should not raise
    share.close()  # Second call also fine


def test_close_swallows_disconnect_exceptions():
    share = SmbShare(
        target=SmbTarget(host="h", share="s"),
        auth=Auth(user="u", password="p"),
    )
    share._tree = MagicMock()
    share._tree.disconnect.side_effect = RuntimeError("broken")
    share._session = MagicMock()
    share._connection = MagicMock()

    share.close()  # must not raise

    assert share._tree is None
    assert share._session is None


def test_context_manager_connects_and_closes():
    share = SmbShare(
        target=SmbTarget(host="h", share="s"),
        auth=Auth(user="u", password="p"),
    )
    with (
        patch("smbprotocol.connection.Connection"),
        patch("smbprotocol.session.Session"),
        patch("smbprotocol.tree.TreeConnect"),
    ):
        with share as ctx:
            assert ctx is share
            assert share._tree is not None
        assert share._tree is None


# --------------------------------------------------------------------
# Protocol membership
# --------------------------------------------------------------------


def test_smbshare_satisfies_share_protocol():
    from sharesift.share import Share

    share = SmbShare(
        target=SmbTarget(host="h", share="s"),
        auth=Auth(anonymous=True),
    )
    assert isinstance(share, Share)
