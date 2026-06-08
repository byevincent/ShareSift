"""v0.30: backfilled filename / path rules for v0.24-v0.26 parser families.

The DiskForge benchmark in v0.29 surfaced the .pypirc miss — parsers
without paired rules don't contribute to the cascade's path-side
tier. v0.30 adds rules for each parser-family whose filename pattern
is documentation-distinctive enough to not false-positive on
unrelated filesystems.
"""

from __future__ import annotations

from sharesift.content_rules import get_default_engine


def _fires(path: str, expected_substring: str) -> bool:
    """Returns True if at least one rule whose name contains
    ``expected_substring`` fired on ``path``."""
    engine = get_default_engine()
    verdict = engine.evaluate(path, content=None)
    return any(expected_substring in m.rule_name for m in verdict.matches)


# --- v0.25 parser families ------------------------------------------


def test_pypirc_rule_fires_on_dotted_filename():
    assert _fires("/Users/alice/.pypirc", "Pypirc")


def test_pypirc_rule_fires_on_undotted_filename():
    assert _fires("/Users/Administrator/.pypirc/pypirc", "Pypirc")


def test_netrc_rule_fires():
    """Linux dotted form is the realistic case; the Windows ``_netrc``
    convention exists but the engine's filename extraction relies on
    ``pathlib.Path`` which doesn't split Windows drive paths on Linux.
    UNC and forward-slash forms work."""
    assert _fires("/home/alice/.netrc", "Netrc")
    assert _fires("/Users/Administrator/_netrc", "Netrc")


def test_gcloud_default_credentials_rule_fires():
    assert _fires(
        "/Users/alice/.config/gcloud/application_default_credentials.json",
        "Gcloud",
    )
    assert _fires(
        "/Users/alice/.config/gcloud/legacy_credentials/account/adc.json",
        "Gcloud",
    )


def test_python_keyring_rules_fire():
    assert _fires(
        "/home/dev/.local/share/python_keyring/keyring_pass.cfg",
        "KeyringFile",
    )
    assert _fires(
        "/home/dev/.local/share/python_keyring/keyringrc.cfg",
        "KeyringFile",
    )


# --- v0.24 path-context rules ---------------------------------------


def test_aws_cli_credentials_path_rule_fires():
    """Generic ``credentials`` is too ambiguous; rule requires
    ``.aws/credentials`` path context."""
    assert _fires("/Users/alice/.aws/credentials", "AwsCliCredentials")
    assert _fires(r"C:\Users\admin\.aws\credentials", "AwsCliCredentials")


def test_aws_cli_credentials_does_not_fire_on_bare_credentials_filename():
    """Bare ``credentials`` outside .aws/ shouldn't fire the v0.30 rule."""
    engine = get_default_engine()
    v = engine.evaluate("/home/alice/Documents/credentials", content=None)
    aws_matches = [m for m in v.matches if "AwsCliCredentials" in m.rule_name]
    assert aws_matches == []


def test_maven_settings_xml_path_rule_fires():
    """settings.xml is ambiguous (VS Code, many tools); rule requires
    ``.m2/`` or ``apache-maven/conf/`` path context."""
    assert _fires("/home/dev/.m2/settings.xml", "MavenSettings")


def test_maven_settings_xml_does_not_fire_on_vscode():
    """VS Code's settings.json is at /Users/alice/.vscode/settings.json
    — should NOT trip the Maven rule."""
    engine = get_default_engine()
    v = engine.evaluate("/Users/alice/.vscode/settings.json", content=None)
    mvn_matches = [m for m in v.matches if "MavenSettings" in m.rule_name]
    assert mvn_matches == []


def test_gh_cli_hosts_yml_path_rule_fires():
    """hosts.yml is ambiguous (Ansible inventory); rule requires
    ``.config/gh/`` path context."""
    assert _fires("/Users/alice/.config/gh/hosts.yml", "GhCliConfig")


def test_gh_cli_hosts_yml_does_not_fire_on_ansible_inventory():
    engine = get_default_engine()
    v = engine.evaluate("/etc/ansible/hosts.yml", content=None)
    gh_matches = [m for m in v.matches if "GhCliConfig" in m.rule_name]
    assert gh_matches == []


# --- v0.26 parser family --------------------------------------------


def test_putty_ppk_extension_rule_fires():
    assert _fires("/Users/alice/Documents/server.ppk", "PuttyPpk")
    assert _fires(r"C:\Users\admin\Downloads\corp-prod.ppk", "PuttyPpk")
