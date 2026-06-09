"""v0.37 step 2 — pipx-install friendliness.

Verifies that:

  - Missing smb extra produces a clear, actionable error message
    (not a raw ``ModuleNotFoundError``) for pentesters who
    ``pipx install sharesift`` without the ``[smb]`` extra.
  - The package's ``[project.scripts]`` entry point resolves to
    ``sharesift.cli:main`` (which a fresh install validates by
    exposing the ``sharesift`` command).
"""

from __future__ import annotations

import sys
from unittest.mock import patch

import pytest


def test_missing_smb_extra_yields_actionable_error():
    """Simulate the pipx-install-without-extras case: smbprotocol
    isn't importable. The error should name the install command,
    not just say ``No module named 'smbprotocol'``."""
    from sharesift.share import Auth, SmbShare, SmbTarget

    share = SmbShare(
        target=SmbTarget(host="10.0.0.5", share="Finance"),
        auth=Auth(user="alice", password="pw"),
    )

    # Block smbprotocol imports so the lazy import inside
    # _ensure_connected raises ImportError, which our code should
    # catch and re-raise as SystemExit with install guidance.
    blocked = {"smbprotocol", "smbprotocol.connection",
               "smbprotocol.session", "smbprotocol.tree"}
    saved = {k: sys.modules[k] for k in list(sys.modules) if k in blocked}
    for k in blocked:
        sys.modules.pop(k, None)

    import builtins
    real_import = builtins.__import__

    def blocking_import(name, *args, **kwargs):
        if name in blocked or name.startswith("smbprotocol."):
            raise ImportError(f"No module named '{name}'", name=name)
        return real_import(name, *args, **kwargs)

    try:
        with patch("builtins.__import__", side_effect=blocking_import):
            with pytest.raises(SystemExit) as exc_info:
                share._ensure_connected()
            msg = str(exc_info.value)
            # Names the extra
            assert "smb extra" in msg
            # Names at least one install path operators recognize
            assert "pipx install" in msg or "pip install" in msg
    finally:
        sys.modules.update(saved)


def test_entry_point_registered():
    """The package's ``sharesift`` console script resolves to
    ``sharesift.cli:main``. A fresh pipx install reads this from
    pyproject.toml and creates the bin shim."""
    from importlib.metadata import entry_points

    scripts = entry_points(group="console_scripts")
    sharesift_scripts = [s for s in scripts if s.name == "sharesift"]
    assert len(sharesift_scripts) == 1
    assert sharesift_scripts[0].value == "sharesift.cli:main"
