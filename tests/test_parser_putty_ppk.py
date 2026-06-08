"""v0.26: PuTTY .ppk parser — synthetic fixture covers documented format."""

from __future__ import annotations

from sharesift.parsers.dispatch import parse_file


def _fields(filename: str, content: str):
    return list(parse_file(filename, content))


def test_ppk_v2_unencrypted_yields_file_metadata_and_private_body():
    content = """PuTTY-User-Key-File-2: ssh-rsa
Encryption: none
Comment: my-server-key
Public-Lines: 2
AAAAB3NzaC1yc2EAAAADAQABAAABAQDfakefakefakefakefakefakefake
AAAAfakefakefakefakefakefakefakefakefakefakefakefakefakefakefake
Private-Lines: 2
AAABAQDpriv1priv1priv1priv1priv1priv1priv1priv1priv1priv1priv1
AAAApriv2priv2priv2priv2priv2priv2priv2priv2priv2priv2priv2priv2
Private-MAC: a1b2c3d4e5f6
"""
    fields = _fields("server.ppk", content)
    by_name = {f.field_name for f in fields}
    assert "ppk_v2_ssh-rsa" in by_name
    # Unencrypted → we extract the private body too.
    assert "private_key_body" in by_name


def test_ppk_v3_encrypted_surfaces_presence_only():
    content = """PuTTY-User-Key-File-3: ssh-ed25519
Encryption: aes256-gcm
Comment: my-encrypted-key
Key-Derivation: Argon2id
Argon2-Memory: 8192
Argon2-Passes: 13
Argon2-Parallelism: 1
Public-Lines: 1
AAAAfakepublic
Private-Lines: 4
encrypted1encrypted1encrypted1encrypted1encrypted1encrypted
encrypted2encrypted2encrypted2encrypted2encrypted2encrypted
encrypted3encrypted3encrypted3encrypted3encrypted3encrypted
encrypted4encrypted4encrypted4encrypted4encrypted4encrypted
Private-MAC: ffffffffffffffff
"""
    fields = _fields("locked.ppk", content)
    by_name = {f.field_name for f in fields}
    assert "ppk_v3_ssh-ed25519" in by_name
    # Encrypted → we do NOT emit the body (passphrase required offline).
    assert "private_key_body" not in by_name
    # The metadata field carries the encryption status.
    metadata_field = next(f for f in fields if f.field_name == "ppk_v3_ssh-ed25519")
    assert "aes256-gcm" in metadata_field.value


def test_ppk_silent_on_garbage_content():
    """A .ppk-named file that isn't a PPK shouldn't yield anything."""
    fields = _fields("not_really.ppk", "this is just random text\n")
    assert all(f.parser != "putty_ppk" for f in fields)
