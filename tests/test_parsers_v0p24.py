"""v0.24: structured parsers — wp-config.php, AWS CLI credentials,
.netrc, Maven settings.xml.

Each test uses a synthetic fixture matching the documented file format
(PHP define() for wp-config, INI for AWS credentials, token-stream
for netrc, XML <server> for Maven). NOT real captured files from any
benchmark — we're testing "parser recognises the format," not "happens
to extract what's in our benchmark."
"""

from __future__ import annotations

from sharesift.parsers.dispatch import parse_file


def _fields(filename: str, content: str):
    return list(parse_file(filename, content))


# --- wp-config.php ----------------------------------------------------


def test_wp_config_extracts_db_credentials():
    content = """<?php
define('DB_NAME', 'wordpress_prod');
define('DB_USER', 'wp_admin');
define('DB_PASSWORD', 'hunter2!');
define('DB_HOST', 'localhost');
"""
    fields = _fields("wp-config.php", content)
    by_name = {f.field_name: f.value for f in fields}
    assert by_name.get("DB_USER") == "wp_admin"
    assert by_name.get("DB_PASSWORD") == "hunter2!"
    assert by_name.get("DB_HOST") == "localhost"
    # DB_PASSWORD must be high-confidence.
    pw_field = next(f for f in fields if f.field_name == "DB_PASSWORD")
    assert pw_field.confidence >= 0.9


def test_wp_config_extracts_auth_keys():
    content = """<?php
define('AUTH_KEY',         'abc123def456');
define('NONCE_SALT',       'xyz789uvw012');
"""
    fields = _fields("wp-config.php", content)
    names = {f.field_name for f in fields}
    assert "AUTH_KEY" in names
    assert "NONCE_SALT" in names


def test_wp_config_skips_placeholder_values():
    """The default install template uses 'put your unique phrase here'
    as a placeholder — we shouldn't surface those."""
    content = """<?php
define('AUTH_KEY',     'put your unique phrase here');
define('NONCE_SALT',   'put your unique phrase here');
define('DB_PASSWORD',  'realpass');
"""
    fields = _fields("wp-config.php", content)
    names = {f.field_name for f in fields}
    assert "DB_PASSWORD" in names
    assert "AUTH_KEY" not in names
    assert "NONCE_SALT" not in names


# --- AWS CLI credentials ---------------------------------------------


def test_aws_credentials_extracts_default_section():
    content = """[default]
aws_access_key_id = AKIAIOSFODNN7EXAMPLE
aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
"""
    fields = _fields("credentials", content)
    values = {f.field_name: f.value for f in fields}
    assert "[default].aws_access_key_id" in values
    assert "[default].aws_secret_access_key" in values


def test_aws_credentials_extracts_named_profile():
    content = """[default]
aws_access_key_id = AAAAAAAAAAAAAAAAAAAA

[production]
aws_access_key_id = BBBBBBBBBBBBBBBBBBBB
aws_secret_access_key = SECRETSECRETSECRETSECRETSECRETSECRETSECRE
aws_session_token = AQoDYXdzEJrTOKEN
"""
    fields = _fields("credentials", content)
    names = {f.field_name for f in fields}
    assert "[default].aws_access_key_id" in names
    assert "[production].aws_access_key_id" in names
    assert "[production].aws_secret_access_key" in names
    assert "[production].aws_session_token" in names


# --- .netrc ----------------------------------------------------------


def test_netrc_extracts_multi_line_machine_block():
    content = """machine api.example.com
    login alice
    password wonderland
machine other.example.com
    login bob
    password builder
"""
    fields = _fields(".netrc", content)
    by_name = {f.field_name: f.value for f in fields}
    assert by_name.get("api.example.com.username") == "alice"
    assert by_name.get("api.example.com.password") == "wonderland"
    assert by_name.get("other.example.com.password") == "builder"


def test_netrc_extracts_single_line_form():
    content = "machine api.example.com login alice password wonderland\n"
    fields = _fields(".netrc", content)
    by_name = {f.field_name: f.value for f in fields}
    assert by_name.get("api.example.com.password") == "wonderland"


def test_netrc_default_block():
    content = "default login defaultuser password defaultpass\n"
    fields = _fields(".netrc", content)
    by_name = {f.field_name: f.value for f in fields}
    assert by_name.get("default.password") == "defaultpass"


# --- Maven settings.xml ----------------------------------------------


def test_maven_settings_extracts_server_password():
    content = """<?xml version="1.0" encoding="UTF-8"?>
<settings>
  <servers>
    <server>
      <id>nexus-releases</id>
      <username>deployer</username>
      <password>nexpass123</password>
    </server>
    <server>
      <id>artifactory-snapshots</id>
      <username>ci-bot</username>
      <password>artipass!</password>
    </server>
  </servers>
</settings>
"""
    fields = _fields("settings.xml", content)
    by_name = {f.field_name: f.value for f in fields}
    assert by_name.get("nexus-releases.username") == "deployer"
    assert by_name.get("nexus-releases.password") == "nexpass123"
    assert by_name.get("artifactory-snapshots.password") == "artipass!"


def test_maven_settings_ignores_xml_namespaces():
    """The real Maven schema uses xmlns="http://..." — our parser
    must walk by local-name, not the namespaced tag."""
    content = """<?xml version="1.0"?>
<settings xmlns="http://maven.apache.org/SETTINGS/1.0.0">
  <servers>
    <server>
      <id>repo</id>
      <password>nspassword</password>
    </server>
  </servers>
</settings>
"""
    fields = _fields("settings.xml", content)
    by_name = {f.field_name: f.value for f in fields}
    assert by_name.get("repo.password") == "nspassword"


def test_maven_settings_silent_on_non_maven_settings_xml():
    """Other apps use settings.xml too (e.g. VS Code). Parser should
    yield nothing when there's no <servers> block."""
    content = """<?xml version="1.0"?>
<settings>
  <theme>dark</theme>
</settings>
"""
    fields = _fields("settings.xml", content)
    # Maven parser yields nothing; other parsers (existing settings_xml
    # parser for Wix etc) may or may not fire — we only check ours did
    # not yield a Maven server credential.
    maven_yields = [f for f in fields if f.parser == "maven_settings_xml"]
    assert maven_yields == []
