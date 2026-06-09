"""v0.36 — modern credential rule backfill.

7 new rules covering the credential surface that's appeared since
Snaffler's last default-rule update: Terraform state files, Vault
tokens, Pulumi / Terraform Cloud, modern Azure MSAL cache, AWS SSO
cache, Ansible Vault encrypted files.

Pattern follows v0.30 tests: each rule gets a positive (intended
path / content fires) and a negative (look-alike doesn't FP).
"""

from __future__ import annotations

from sharesift.content_rules import get_default_engine


def _fires(path: str, expected_substring: str, *, content: str | None = None) -> bool:
    engine = get_default_engine()
    verdict = engine.evaluate(path, content=content)
    return any(expected_substring in m.rule_name for m in verdict.matches)


def _matches_named(path: str, name: str, *, content: str | None = None) -> list:
    engine = get_default_engine()
    verdict = engine.evaluate(path, content=content)
    return [m for m in verdict.matches if name in m.rule_name]


# --- Terraform state files ------------------------------------------


def test_terraform_state_default_name_fires():
    assert _fires("/home/devops/proj/terraform.tfstate", "TerraformState")


def test_terraform_state_backup_fires():
    assert _fires("/home/devops/proj/terraform.tfstate.backup", "TerraformState")


def test_terraform_state_environment_prefix_fires():
    """``<env>.tfstate`` is the common pattern in multi-env repos
    (prod.tfstate, staging.tfstate)."""
    assert _fires("/srv/iac/prod.tfstate", "TerraformState")
    assert _fires(r"C:\iac\staging.tfstate.backup", "TerraformState")


def test_terraform_state_does_not_fire_on_dotfile():
    """``.tfstate`` as a bare hidden file (no name prefix) is the
    NOT-a-state-file case — the rule requires content before the
    extension."""
    matches = _matches_named("/home/alice/.tfstate", "TerraformState")
    assert matches == []


def test_terraform_state_does_not_fire_on_terraform_lock():
    """``.terraform.lock.hcl`` is a lockfile, not state. Shouldn't
    trigger the TerraformState rule."""
    matches = _matches_named(
        "/home/devops/proj/.terraform.lock.hcl", "TerraformState"
    )
    assert matches == []


# --- HashiCorp Vault token ------------------------------------------


def test_vault_token_dotfile_fires():
    assert _fires("/home/alice/.vault-token", "VaultToken")
    assert _fires("/root/.vault-token", "VaultToken")


def test_vault_token_windows_path_fires():
    assert _fires(r"C:\Users\alice\.vault-token", "VaultToken")


def test_vault_token_does_not_fire_on_vault_config_dir():
    """``.vault/config`` is a Vault config directory, not the token."""
    matches = _matches_named("/home/alice/.vault/config", "VaultToken")
    assert matches == []


def test_vault_token_does_not_fire_on_misnamed_token_file():
    """A file named ``vault-token`` (no leading dot) anywhere outside
    the user dotfile location shouldn't fire — too easy to confuse
    with a generic 'token' file."""
    matches = _matches_named("/var/lib/secrets/vault-token", "VaultToken")
    assert matches == []


# --- Pulumi credentials ---------------------------------------------


def test_pulumi_credentials_fires():
    assert _fires(
        "/home/devops/.pulumi/credentials.json", "PulumiCredentials"
    )
    assert _fires(
        r"C:\Users\devops\.pulumi\credentials.json", "PulumiCredentials"
    )


def test_pulumi_credentials_does_not_fire_on_bare_credentials_json():
    """A generic ``credentials.json`` outside .pulumi/ shouldn't fire."""
    matches = _matches_named(
        "/home/alice/Documents/credentials.json", "PulumiCredentials"
    )
    assert matches == []


def test_pulumi_credentials_does_not_fire_on_pulumi_stack_yaml():
    """Pulumi stack config files are public; only credentials.json
    is the cred file."""
    matches = _matches_named(
        "/home/devops/proj/Pulumi.prod.yaml", "PulumiCredentials"
    )
    assert matches == []


# --- Terraform Cloud (``terraform login`` output) -------------------


def test_terraform_cloud_credentials_fires():
    assert _fires(
        "/home/devops/.terraform.d/credentials.tfrc.json",
        "TerraformCloudCredentials",
    )
    assert _fires(
        r"C:\Users\devops\.terraform.d\credentials.tfrc.json",
        "TerraformCloudCredentials",
    )


def test_terraform_cloud_does_not_fire_on_terraform_lock():
    """Terraform's lockfile lives near projects, not under .terraform.d/."""
    matches = _matches_named(
        "/home/devops/proj/.terraform.lock.hcl", "TerraformCloudCredentials"
    )
    assert matches == []


def test_terraform_cloud_does_not_fire_on_terraform_state():
    matches = _matches_named(
        "/home/devops/proj/terraform.tfstate", "TerraformCloudCredentials"
    )
    assert matches == []


# --- Modern Azure CLI MSAL cache ------------------------------------


def test_azure_msal_token_cache_fires():
    assert _fires(
        "/home/alice/.azure/msal_token_cache.json", "AzureModernCliCache"
    )


def test_azure_service_principal_entries_fires():
    assert _fires(
        "/home/alice/.azure/service_principal_entries.json",
        "AzureModernCliCache",
    )


def test_azure_legacy_access_tokens_fires():
    """Legacy ``accessTokens.json`` from older Azure CLI versions —
    still appears in mixed-version environments."""
    assert _fires(
        "/home/alice/.azure/accessTokens.json", "AzureModernCliCache"
    )


def test_azure_modern_cache_windows_path_fires():
    assert _fires(
        r"C:\Users\alice\.azure\msal_token_cache.json",
        "AzureModernCliCache",
    )


def test_azure_modern_cache_does_not_fire_on_azure_config():
    """``.azure/config`` is the (mostly innocuous) settings file."""
    matches = _matches_named(
        "/home/alice/.azure/config", "AzureModernCliCache"
    )
    assert matches == []


def test_azure_modern_cache_does_not_fire_on_azureml():
    """``.azureml/`` (Azure ML SDK) is a different namespace."""
    matches = _matches_named(
        "/home/alice/.azureml/msal_token_cache.json",
        "AzureModernCliCache",
    )
    assert matches == []


# --- AWS SSO cache --------------------------------------------------


def test_aws_sso_cache_fires_on_sha1_named_json():
    """SSO cache files are SHA1-named JSONs under ~/.aws/sso/cache/."""
    assert _fires(
        "/home/alice/.aws/sso/cache/abc123def456deadbeef0123456789abcdef0123.json",
        "AwsSsoCache",
    )


def test_aws_sso_cache_windows_path_fires():
    assert _fires(
        r"C:\Users\alice\.aws\sso\cache\1234567890abcdef.json",
        "AwsSsoCache",
    )


def test_aws_sso_cache_does_not_fire_on_aws_credentials():
    """``.aws/credentials`` is the v0.25 AWS CLI rule, not SSO."""
    matches = _matches_named(
        "/home/alice/.aws/credentials", "AwsSsoCache"
    )
    assert matches == []


def test_aws_sso_cache_does_not_fire_on_random_aws_json():
    """A JSON file directly under ~/.aws/ that isn't in sso/cache/
    shouldn't trigger."""
    matches = _matches_named(
        "/home/alice/.aws/settings.json", "AwsSsoCache"
    )
    assert matches == []


# --- Ansible Vault encrypted file header ----------------------------


def test_ansible_vault_v11_header_fires_on_content():
    content = "$ANSIBLE_VAULT;1.1;AES256\n66386439653236...truncated"
    assert _fires("/etc/ansible/vault.yml", "AnsibleVault", content=content)


def test_ansible_vault_v12_header_fires():
    content = "$ANSIBLE_VAULT;1.2;AES256;production\n3132633437..."
    assert _fires("/etc/ansible/group_vars/prod.yml", "AnsibleVault", content=content)


def test_ansible_vault_does_not_fire_without_header():
    """A regular YAML file under an ansible directory shouldn't FP."""
    content = "vars:\n  password: hunter2\n  api_key: abc\n"
    matches = _matches_named(
        "/etc/ansible/group_vars/prod.yml", "AnsibleVault",
        content=content,
    )
    assert matches == []


def test_ansible_vault_does_not_fire_on_partial_header_mention():
    """A YAML file that *mentions* ANSIBLE_VAULT in comments
    shouldn't trigger; only files that literally start with the
    header should."""
    content = (
        "# Encrypted with ANSIBLE_VAULT 1.1 — see vault.yml for the\n"
        "# actual encrypted content.\n"
        "include_vars: vault.yml\n"
    )
    matches = _matches_named(
        "/etc/ansible/playbook.yml", "AnsibleVault",
        content=content,
    )
    assert matches == []
