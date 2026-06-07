"""SSH private-key extraction from content excerpts."""

from __future__ import annotations

from sharesift.verify.extractor import extract_credentials

OPENSSH_KEY = """-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAFwAAAAdzc2gtcn
NhAAAAAwEAAQAAAQEAyaB1KvKHfDQOAhO3aZ7+B5e0fa5o3vNGfVQQO0aOK6OkPyc12K1L
-----END OPENSSH PRIVATE KEY-----"""

RSA_KEY = """-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAyaB1KvKHfDQOAhO3aZ7+B5e0fa5o3vNGfVQQO0aOK6OkPyc1
2K1LdGKpKvVcCQqWQrEYvw8z+EzwLOL3F8h2VnJZ/gG+lZtVdHCNB05wQrkn+f2L
-----END RSA PRIVATE KEY-----"""

ED25519_KEY = """-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACDNxK0g8Q1XYtZxjjGgRzZSnHL+nL8qK7eiYbHQ8XxQpQ
-----END OPENSSH PRIVATE KEY-----"""


def test_extracts_openssh_key():
    found = extract_credentials(f"id_rsa contents:\n{OPENSSH_KEY}\nend.")
    types = {c.credential_type for c in found}
    assert "ssh_private_key" in types
    [cred] = [c for c in found if c.credential_type == "ssh_private_key"]
    assert "BEGIN OPENSSH PRIVATE KEY" in cred.value
    assert "END OPENSSH PRIVATE KEY" in cred.value


def test_extracts_rsa_key():
    found = extract_credentials(RSA_KEY)
    types = {c.credential_type for c in found}
    assert "ssh_private_key" in types


def test_extracts_ed25519_key():
    found = extract_credentials(ED25519_KEY)
    types = {c.credential_type for c in found}
    assert "ssh_private_key" in types


def test_extracts_multiple_keys_in_one_excerpt():
    excerpt = f"{OPENSSH_KEY}\n\n{RSA_KEY}"
    found = [c for c in extract_credentials(excerpt) if c.credential_type == "ssh_private_key"]
    assert len(found) == 2
