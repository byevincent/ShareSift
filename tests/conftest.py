"""Shared pytest fixtures for the sharesift test suite.

v0.35 Sprint 4: ``samba_container`` fixture spins up a known Samba
4.x server (``dperson/samba``) for live SMB integration tests.
Gated behind ``SHARESIFT_SMB_TESTS=1`` and requires Docker — most
CI runs skip cleanly.
"""

from __future__ import annotations

import os
import shutil
import socket
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path

import pytest


@dataclass(frozen=True)
class SambaFixture:
    """Live Samba container connection params + known plant layout.

    ``nt_hash`` is the NT hash of ``password`` for PtH tests."""

    host: str
    port: int
    user: str
    password: str
    nt_hash: str
    share: str
    plant_dir: Path  # Host filesystem path bind-mounted into the share


_CONTAINER_NAME = "sharesift_test_samba"
_HOST_PORT = 11445


def _docker_available() -> bool:
    if shutil.which("docker") is None:
        return False
    try:
        result = subprocess.run(
            ["docker", "info", "--format", "{{.ServerVersion}}"],
            capture_output=True, timeout=5,
        )
        return result.returncode == 0
    except (subprocess.SubprocessError, OSError):
        return False


def _wait_for_port(host: str, port: int, *, timeout: float = 20.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with socket.create_connection((host, port), timeout=1.0):
                return True
        except OSError:
            time.sleep(0.5)
    return False


def _wait_for_samba_ready(timeout: float = 25.0) -> bool:
    """Wait until smbd is actually accepting SMB2 negotiates, not
    just TCP-accepting. dperson/samba prints
    ``daemon_ready: daemon 'smbd' finished starting up...`` once
    it's truly up."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            logs = subprocess.run(
                ["docker", "logs", _CONTAINER_NAME],
                capture_output=True, text=True, timeout=3,
            ).stdout
            if "daemon_ready" in logs and "smbd" in logs:
                # Give smbd one extra moment to start listening
                time.sleep(0.5)
                return True
        except (subprocess.SubprocessError, OSError):
            pass
        time.sleep(0.5)
    return False


def _remove_container_if_exists(name: str) -> None:
    subprocess.run(["docker", "rm", "-f", name], capture_output=True)


@pytest.fixture(scope="session")
def samba_container(tmp_path_factory):
    """Spin up dperson/samba with one user + one share. Plant a
    known directory tree for the tests to walk and read.

    Skipped unless ``SHARESIFT_SMB_TESTS=1`` AND Docker is reachable.
    """
    if os.environ.get("SHARESIFT_SMB_TESTS") != "1":
        pytest.skip("SMB integration tests gated behind SHARESIFT_SMB_TESTS=1")
    if not _docker_available():
        pytest.skip("Docker not available")

    # Compute the NT hash of the password for PtH tests
    from spnego._ntlm_raw.crypto import ntowfv1
    password = "testpass"
    nt_hash = ntowfv1(password).hex()

    # Plant directory — bind-mounted as the SMB share
    plant_dir = tmp_path_factory.mktemp("samba_share")
    _plant_test_files(plant_dir)

    # Clean up any leftover container from a previous failed run
    _remove_container_if_exists(_CONTAINER_NAME)

    # Start dperson/samba with one user + one share
    cmd = [
        "docker", "run", "-d", "-t",
        "--name", _CONTAINER_NAME,
        "-p", f"{_HOST_PORT}:445",
        "-v", f"{plant_dir}:/share",
        "dperson/samba",
        "-u", "testuser;testpass",
        # share def: name;path;browseable;readonly;guest;users
        "-s", "tmp;/share;yes;no;no;testuser",
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.returncode != 0:
        pytest.skip(
            f"failed to start samba container: {proc.stderr.strip()}"
        )

    try:
        if not _wait_for_port("127.0.0.1", _HOST_PORT, timeout=20):
            pytest.skip("samba container started but port 11445 didn't open")
        if not _wait_for_samba_ready(timeout=25):
            pytest.skip("samba smbd didn't log daemon_ready in time")

        yield SambaFixture(
            host="127.0.0.1",
            port=_HOST_PORT,
            user="testuser",
            password=password,
            nt_hash=nt_hash,
            share="tmp",
            plant_dir=plant_dir,
        )
    finally:
        _remove_container_if_exists(_CONTAINER_NAME)


def _plant_test_files(root: Path) -> None:
    """Lay down a known directory tree the tests walk + read.

    Files and dirs get world-readable perms because pytest's
    ``tmp_path_factory`` defaults to 700 and the dperson/samba
    container's ``testuser`` runs with a different UID — Samba can't
    read files it doesn't have permission for, even after auth.
    """
    (root / "hello.txt").write_text("hello world\n")
    (root / "secrets.cfg").write_text("password=hunter2\napi_key=abc123\n")

    sub = root / "sub"
    sub.mkdir()
    (sub / "nested.txt").write_text("nested content\n")

    deeper = sub / "deeper"
    deeper.mkdir()
    (deeper / "deep.txt").write_text("deeply nested\n")

    # Empty subdir — should not appear in walk output (walk yields files only)
    (root / "empty_subdir").mkdir()

    # Binary-ish file to exercise read_bytes on non-text content
    (root / "binary.bin").write_bytes(bytes(range(256)) * 4)

    # Open everything up so the container's ``testuser`` (different
    # UID than the pytest runner) can read.
    for p in root.rglob("*"):
        if p.is_dir():
            p.chmod(0o755)
        else:
            p.chmod(0o644)
    root.chmod(0o755)
