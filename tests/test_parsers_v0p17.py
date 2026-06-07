"""Tests for the six v0.17 structured parsers."""

from __future__ import annotations

from sharesift.parsers.dispatch import parse_file


# ----------- terraform.tfstate -----------------------------------------

TFSTATE_FIXTURE = """{
  "version": 4,
  "terraform_version": "1.5.0",
  "resources": [
    {
      "type": "aws_iam_access_key",
      "instances": [
        {
          "attributes": {
            "id": "AKIAIOSFODNN7EXAMPLE",
            "secret": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
          }
        }
      ]
    }
  ],
  "outputs": {
    "db_password": {"value": "supersecret", "sensitive": true}
  }
}"""


def test_terraform_tfstate_extracts_secret():
    fields = parse_file("terraform.tfstate", TFSTATE_FIXTURE)
    assert any(f.parser == "terraform_tfstate" for f in fields)
    secrets = [f for f in fields if "secret" in f.field_name.lower()]
    assert any("wJalr" in f.value for f in secrets)


def test_terraform_tfstate_extracts_sensitive_output():
    fields = parse_file("terraform.tfstate", TFSTATE_FIXTURE)
    outs = [f for f in fields if "db_password" in f.field_name]
    assert outs and outs[0].value == "supersecret"


def test_terraform_tfstate_malformed_json_returns_empty():
    assert parse_file("terraform.tfstate", "not json") == []


# ----------- docker config.json ---------------------------------------

DOCKER_CONFIG_FIXTURE = """{
  "auths": {
    "registry.example.com": {
      "auth": "YWRtaW46c2VjcmV0MTIz"
    },
    "docker.io": {
      "identitytoken": "tok_ABCDEFG12345"
    }
  }
}"""


def test_docker_config_extracts_user_password():
    fields = parse_file("config.json", DOCKER_CONFIG_FIXTURE)
    parsers = {f.parser for f in fields}
    assert "docker_config_json" in parsers
    users = [f for f in fields if f.field_name == "username"]
    passwords = [f for f in fields if f.field_name == "password"]
    assert users and users[0].value == "admin"
    assert passwords and passwords[0].value == "secret123"


def test_docker_config_extracts_identity_token():
    fields = parse_file("config.json", DOCKER_CONFIG_FIXTURE)
    tokens = [f for f in fields if f.field_name == "identitytoken"]
    assert tokens and tokens[0].value == "tok_ABCDEFG12345"


# ----------- kube config ----------------------------------------------

KUBE_CONFIG_FIXTURE = """apiVersion: v1
kind: Config
clusters:
  - name: prod
    cluster:
      server: https://k8s.example.com
users:
  - name: admin
    user:
      token: eyJhbGciOiJSUzI1NiJ9.fake.token
      username: admin
      password: kubepass
contexts: []
"""


def test_kube_config_extracts_token():
    fields = parse_file("config", KUBE_CONFIG_FIXTURE)
    tokens = [f for f in fields if f.field_name == "token" and f.parser == "kube_config"]
    assert tokens, fields
    assert tokens[0].value.startswith("eyJhbGc")


def test_kube_config_extracts_username_password():
    fields = parse_file("kubeconfig", KUBE_CONFIG_FIXTURE)
    users = [f for f in fields if f.field_name == "username" and f.parser == "kube_config"]
    passwords = [f for f in fields if f.field_name == "password" and f.parser == "kube_config"]
    assert users and users[0].value == "admin"
    assert passwords and passwords[0].value == "kubepass"


def test_kube_config_skips_non_kube_yaml():
    fields = parse_file("kubeconfig", "key: value\nfoo: bar")
    assert all(f.parser != "kube_config" for f in fields)


# ----------- cisco running-config -------------------------------------

CISCO_FIXTURE = """version 15.1
no service password-encryption
hostname Router1
enable secret 5 $1$mERr$gK7l5p2vxYAH7uJoX0o.4/
enable password 7 0822455D0A16544541
username admin privilege 15 secret 5 $1$abcd$fghi
snmp-server community s3cr3tC0mm RO
interface GigabitEthernet0/0
 ip address 10.0.0.1 255.255.255.0
crypto isakmp key 0 IPsecP@ss address 10.0.0.2
line vty 0 4
 password 7 1234567890ABCDEF
"""


def test_cisco_extracts_enable_secret():
    fields = parse_file("running-config", CISCO_FIXTURE)
    secrets = [f for f in fields if "enable_secret" in f.field_name]
    assert secrets


def test_cisco_extracts_username_and_password():
    fields = parse_file("running-config", CISCO_FIXTURE)
    users = [f for f in fields if f.field_name == "username" and f.parser == "cisco_running_config"]
    passwords = [f for f in fields if "password_type" in f.field_name]
    assert users and users[0].value == "admin"
    assert passwords


def test_cisco_extracts_snmp_community():
    fields = parse_file("running-config", CISCO_FIXTURE)
    snmp = [f for f in fields if f.field_name == "snmp_community"]
    assert snmp and snmp[0].value == "s3cr3tC0mm"


def test_cisco_extracts_crypto_isakmp_key():
    fields = parse_file("running-config", CISCO_FIXTURE)
    keys = [f for f in fields if f.field_name == "crypto_isakmp_key"]
    assert keys and keys[0].value == "IPsecP@ss"


def test_cisco_sniff_on_generic_cfg():
    """A .cfg file should only invoke cisco parser when it looks cisco-y."""
    fields = parse_file("router.cfg", CISCO_FIXTURE)
    assert any(f.parser == "cisco_running_config" for f in fields)
    # Non-cisco cfg → no cisco hits
    fields = parse_file("server.cfg", "key=value\nfoo=bar")
    assert all(f.parser != "cisco_running_config" for f in fields)


# ----------- veeam config ---------------------------------------------

VEEAM_FIXTURE = """<?xml version="1.0"?>
<Config>
  <RepositoryCredentials>
    <Account>BACKUP\\veeam_svc</Account>
    <EncryptedPassword>RXJ8NQ==encryptedblob</EncryptedPassword>
  </RepositoryCredentials>
</Config>"""


def test_veeam_extracts_encrypted_password():
    fields = parse_file("veeam.config", VEEAM_FIXTURE)
    pw = [f for f in fields if "Password" in f.field_name]
    assert pw and pw[0].value == "RXJ8NQ==encryptedblob"


def test_veeam_extracts_account():
    fields = parse_file("veeambackup.xml", VEEAM_FIXTURE)
    accounts = [f for f in fields if f.field_name == "username"]
    assert accounts and accounts[0].value == "BACKUP\\veeam_svc"


# ----------- ansible-vault --------------------------------------------

VAULT_FIXTURE = """$ANSIBLE_VAULT;1.2;AES256;prod
33396166373262656566353039396535363539383837323564646230653236323436633435613266
3439613634316233373533633633353861356636633038310a363266393439646330636165343837
3437373261373733343334396534346165333030626264346561656432663539366663623862393633"""


def test_ansible_vault_extracts_header():
    fields = parse_file("secrets.vault", VAULT_FIXTURE)
    headers = [f for f in fields if f.field_name == "vault_header"]
    assert headers
    assert "prod" in headers[0].context  # vault_id


def test_ansible_vault_extracts_ciphertext():
    fields = parse_file("secrets.vault", VAULT_FIXTURE)
    ct = [f for f in fields if f.field_name == "vault_ciphertext"]
    assert ct


def test_ansible_vault_plain_yaml_does_not_fire():
    fields = parse_file("group_vars/prod.yml", "vars:\n  foo: bar\n")
    assert all(f.parser != "ansible_vault" for f in fields)
