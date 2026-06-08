"""v0.25: structured parsers — .pypirc, gcloud user creds,
gh CLI hosts.yml, Python keyring file backends.

Each test uses a synthetic fixture matching the documented format.
"""

from __future__ import annotations

from sharesift.parsers.dispatch import parse_file


def _fields(filename: str, content: str):
    return list(parse_file(filename, content))


# --- .pypirc ----------------------------------------------------------


def test_pypirc_extracts_pypi_token():
    content = """[distutils]
index-servers = pypi testpypi

[pypi]
username = __token__
password = pypi-AgEIcHlwaS5vcmcCJDxxxxxxxxxxxxxxxxxxxxxxxxxxxx
"""
    fields = _fields(".pypirc", content)
    by_name = {f.field_name: f.value for f in fields}
    assert "[pypi].password" in by_name
    assert by_name["[pypi].password"].startswith("pypi-")


def test_pypirc_extracts_testpypi_section():
    content = """[testpypi]
repository = https://test.pypi.org/legacy/
username = __token__
password = pypi-AgENdGVzdC5weXBpLm9yZwIkAAAAA
"""
    fields = _fields(".pypirc", content)
    names = {f.field_name for f in fields}
    assert "[testpypi].password" in names


# --- gcloud credentials -----------------------------------------------


def test_gcloud_user_creds_extracts_refresh_token():
    content = """{
  "client_id": "32555940559.apps.googleusercontent.com",
  "client_secret": "ZmssLNjJy2998hD4CTg2ejr2",
  "refresh_token": "1//0abcdef-FAKE_REFRESH_TOKEN_FOR_TEST",
  "type": "authorized_user"
}"""
    fields = _fields("application_default_credentials.json", content)
    by_name = {f.field_name: f.value for f in fields}
    assert "refresh_token" in by_name
    assert "client_secret" in by_name


def test_gcloud_service_account_skipped():
    """Service-account JSON is caught by the v0.23 extractor; we
    don't double-emit here."""
    content = """{
  "type": "service_account",
  "client_email": "x@y.iam.gserviceaccount.com",
  "private_key": "-----BEGIN PRIVATE KEY-----\\nfake\\n-----END PRIVATE KEY-----"
}"""
    fields = _fields("adc.json", content)
    # The gcloud_credentials parser yields nothing for service_account.
    assert all(f.parser != "gcloud_credentials" for f in fields)


# --- gh CLI hosts.yml -------------------------------------------------


def test_gh_hosts_extracts_oauth_token():
    content = """github.com:
    oauth_token: gho_FAKE0123456789FAKE0123456789FAKEAB
    git_protocol: https
    user: alice
"""
    fields = _fields("hosts.yml", content)
    by_name = {f.field_name: f.value for f in fields}
    assert by_name.get("github.com.oauth_token", "").startswith("gho_")
    assert by_name.get("github.com.user") == "alice"


def test_gh_hosts_handles_multiple_hosts():
    content = """github.com:
    oauth_token: gho_TOKEN_ONE_REPEATING_TOKEN_VALUE_OK
    user: alice
github.enterprise.example.com:
    oauth_token: gho_TOKEN_TWO_REPEATING_TOKEN_VALUE_OK
    user: bob
"""
    fields = _fields("hosts.yml", content)
    by_name = {f.field_name: f.value for f in fields}
    assert "github.com.oauth_token" in by_name
    assert "github.enterprise.example.com.oauth_token" in by_name


# --- Python keyring ---------------------------------------------------


def test_keyring_pass_extracts_per_service_passwords():
    content = """[github.com]
user_alice = aGVsbG8taGVsbG8=
user_bob = d29ybGQtd29ybGQ=

[gitlab.example.com]
ci-bot = ZGVwbG95LWtleQ==
"""
    fields = _fields("keyring_pass.cfg", content)
    by_name = {f.field_name: f.value for f in fields}
    assert "[github.com].user_alice" in by_name
    assert "[gitlab.example.com].ci-bot" in by_name


def test_keyring_cryptfile_flags_encrypted_blob():
    content = """[github.com]
user_alice = AESENCRYPTEDBASE64BLOB1==
"""
    fields = _fields("keyring_cryptfile_pass.cfg", content)
    by_name = {f.field_name: f.value for f in fields}
    assert "[github.com].user_alice" in by_name
    # Value should describe the situation, not leak garbage
    val_field = next(f for f in fields if f.field_name == "[github.com].user_alice")
    assert "encrypted" in val_field.value.lower() or "encrypted" in (val_field.context or "").lower()


def test_keyringrc_flags_risky_backend():
    content = """[backend]
default-keyring = keyrings.alt.file.PlaintextKeyring
"""
    fields = _fields("keyringrc.cfg", content)
    names = {f.field_name for f in fields}
    assert "default-keyring" in names


def test_keyringrc_silent_on_safe_backend():
    """When default-keyring is an OS-native backend, don't yield."""
    content = """[backend]
default-keyring = keyring.backends.OS_X.Keyring
"""
    fields = _fields("keyringrc.cfg", content)
    assert all(f.parser != "keyringrc" for f in fields)
