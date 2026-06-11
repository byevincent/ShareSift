r"""v0.54.2: SMB3 encryption auto-fallback.

Surfaced on HTB Active (Server 2008 R2) 2026-06-11: the default
``--encrypt=True`` failed with "SMB encryption is required but
the connection does not support it" because the server only
supports SMB 2.0/2.1.

Fix: in ``SmbShare._ensure_connected``, after ``Connection.connect()``
inspect the negotiated dialect. If it's below SMB 3.0 (0x0300) AND
the operator didn't pass ``require_encrypt=True``, downgrade to an
unencrypted session. Operators who need encryption pass
``--require-encrypt`` and get a clean failure when the server can't
provide it.
"""

from __future__ import annotations

import importlib.util
from unittest.mock import MagicMock, patch

import pytest


_HAS_SMB = importlib.util.find_spec("smbprotocol") is not None
_needs_smb = pytest.mark.skipif(
    not _HAS_SMB, reason="needs smb extra (smbprotocol)",
)


@_needs_smb
class TestEncryptionAutoFallback:
    """When the negotiated dialect is < SMB 3.0, require_encryption
    is automatically downgraded to False unless require_encrypt=True."""

    def _setup(self, *, dialect: int, encrypt: bool, require_encrypt: bool):
        from sharesift.share import Auth
        from sharesift.share.smb import SmbShare
        from sharesift.share.target import SmbTarget

        target = SmbTarget(host="dc01", share="C$", port=445)
        share = SmbShare(
            target, Auth(user="u", password="p"),
            encrypt=encrypt, require_encrypt=require_encrypt,
        )

        # Mock connection / session / tree classes
        mock_conn = MagicMock()
        mock_conn.dialect = dialect
        ConnectionCls = MagicMock(return_value=mock_conn)

        mock_session = MagicMock()
        SessionCls = MagicMock(return_value=mock_session)

        mock_tree = MagicMock()
        TreeConnectCls = MagicMock(return_value=mock_tree)

        return share, ConnectionCls, SessionCls, TreeConnectCls, mock_session

    def test_smb2_negotiated_falls_back_when_encrypt_default(self):
        """SMB 2.1 server with default --encrypt: auto-downgrade."""
        share, Conn, Sess, Tree, sess_inst = self._setup(
            dialect=0x0210, encrypt=True, require_encrypt=False,
        )
        with patch(
            "smbprotocol.connection.Connection", Conn,
        ), patch(
            "smbprotocol.session.Session", Sess,
        ), patch(
            "smbprotocol.tree.TreeConnect", Tree,
        ):
            share._ensure_connected()
        # require_encryption was passed False because of fallback
        session_kwargs = Sess.call_args.kwargs
        assert session_kwargs["require_encryption"] is False
        assert share._encryption_fallback_applied is True

    def test_smb3_negotiated_keeps_encryption(self):
        """SMB 3.0 server: encryption stays enabled."""
        share, Conn, Sess, Tree, sess_inst = self._setup(
            dialect=0x0300, encrypt=True, require_encrypt=False,
        )
        with patch(
            "smbprotocol.connection.Connection", Conn,
        ), patch(
            "smbprotocol.session.Session", Sess,
        ), patch(
            "smbprotocol.tree.TreeConnect", Tree,
        ):
            share._ensure_connected()
        session_kwargs = Sess.call_args.kwargs
        assert session_kwargs["require_encryption"] is True
        assert share._encryption_fallback_applied is False

    def test_smb3_1_1_negotiated_keeps_encryption(self):
        """SMB 3.1.1: still encrypted."""
        share, Conn, Sess, Tree, sess_inst = self._setup(
            dialect=0x0311, encrypt=True, require_encrypt=False,
        )
        with patch(
            "smbprotocol.connection.Connection", Conn,
        ), patch(
            "smbprotocol.session.Session", Sess,
        ), patch(
            "smbprotocol.tree.TreeConnect", Tree,
        ):
            share._ensure_connected()
        assert Sess.call_args.kwargs["require_encryption"] is True
        assert share._encryption_fallback_applied is False

    def test_require_encrypt_skips_fallback(self):
        """SMB 2.1 + --require-encrypt: no fallback. require_encryption
        stays True so the Session.connect() raises the expected error."""
        share, Conn, Sess, Tree, sess_inst = self._setup(
            dialect=0x0210, encrypt=True, require_encrypt=True,
        )
        with patch(
            "smbprotocol.connection.Connection", Conn,
        ), patch(
            "smbprotocol.session.Session", Sess,
        ), patch(
            "smbprotocol.tree.TreeConnect", Tree,
        ):
            share._ensure_connected()
        assert Sess.call_args.kwargs["require_encryption"] is True
        assert share._encryption_fallback_applied is False

    def test_no_encrypt_explicit_skips_check(self):
        """--no-encrypt: encrypt=False from the start; no fallback
        machinery needed."""
        share, Conn, Sess, Tree, sess_inst = self._setup(
            dialect=0x0210, encrypt=False, require_encrypt=False,
        )
        with patch(
            "smbprotocol.connection.Connection", Conn,
        ), patch(
            "smbprotocol.session.Session", Sess,
        ), patch(
            "smbprotocol.tree.TreeConnect", Tree,
        ):
            share._ensure_connected()
        assert Sess.call_args.kwargs["require_encryption"] is False
        assert share._encryption_fallback_applied is False
