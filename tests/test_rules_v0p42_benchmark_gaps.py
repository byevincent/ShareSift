"""v0.42 — benchmark-gap rules closing the 11 both-missed MSF2 paths.

After the 2026-06 head-to-head benchmark against Snaffler, MSF2
left 11 credential files neither tool caught. v0.42 adds 6 rules
targeting those paths. Re-run validation: 11 both-missed →  1
(only ``/root/reset_logs.sh`` remains, intentionally hard to rule).
"""

from __future__ import annotations

from sharesift.content_rules import get_default_engine


def _fires(path: str, expected_substring: str) -> bool:
    engine = get_default_engine()
    verdict = engine.evaluate(path, content=None)
    return any(expected_substring in m.rule_name for m in verdict.matches)


def _matches_named(path: str, name: str) -> list:
    engine = get_default_engine()
    verdict = engine.evaluate(path, content=None)
    return [m for m in verdict.matches if name in m.rule_name]


# --- Shadow / gshadow backups ---------------------------------------


def test_shadow_dash_backup_fires():
    """``/etc/shadow-`` is the backup written before passwd updates."""
    assert _fires("/etc/shadow-", "ShadowBackup")


def test_gshadow_backup_fires():
    assert _fires("/etc/gshadow-", "ShadowBackup")


def test_gshadow_base_fires():
    """Some Linux distros use ``/etc/gshadow`` without the trailing
    dash for the live file too."""
    assert _fires("/etc/gshadow", "ShadowBackup")


def test_shadow_backup_does_not_fire_on_user_paths():
    """Operator's home dir shadow-shaped files (someone named their
    file ``shadow-something``) shouldn't trip the rule."""
    assert _matches_named("/home/alice/shadow-config.txt", "ShadowBackup") == []


# --- NFS exports ---------------------------------------------------


def test_nfs_exports_fires():
    assert _fires("/etc/exports", "NfsExports")


def test_nfs_exports_does_not_fire_on_other_exports_files():
    """Lots of files are called ``exports``; the rule is path-
    anchored to ``/etc/exports`` specifically."""
    assert _matches_named("/home/alice/my-exports.csv", "NfsExports") == []


# --- Postfix mail server config ------------------------------------


def test_postfix_main_cf_fires():
    assert _fires("/etc/postfix/main.cf", "PostfixConfig")


def test_postfix_sasl_passwd_fires():
    """sasl_passwd is the smoking gun — plaintext relay credentials."""
    assert _fires("/etc/postfix/sasl_passwd", "PostfixConfig")


def test_postfix_does_not_fire_on_other_main_cf():
    """Other apps have main.cf too (Pacman, etc.). Path-anchored."""
    assert _matches_named("/etc/pacman/main.cf", "PostfixConfig") == []


# --- MySQL data directory ------------------------------------------


def test_mysql_user_myd_fires():
    assert _fires("/var/lib/mysql/mysql/user.MYD", "MysqlDataDir")


def test_mysql_user_myi_fires():
    assert _fires("/var/lib/mysql/mysql/user.MYI", "MysqlDataDir")


def test_mysql_user_frm_fires():
    assert _fires("/var/lib/mysql/mysql/user.frm", "MysqlDataDir")


def test_mysql_db_table_fires():
    assert _fires("/var/lib/mysql/mysql/db.MYD", "MysqlDataDir")


def test_mysql_does_not_fire_on_app_database():
    """An application's own database tables shouldn't trigger; only
    the MySQL system table (``mysql.user``)."""
    assert _matches_named(
        "/var/lib/mysql/myapp/customers.MYD", "MysqlDataDir"
    ) == []


# --- Editor backup of credential-shaped config ---------------------


def test_php_config_swap_fires():
    """vim swap file of a PHP config — original may be redacted,
    .swp often isn't."""
    assert _fires("/var/www/dvwa/config/config.inc.php.swp", "EditorBackupConfig")


def test_php_config_tilde_fires():
    """Editor backup with ``~`` suffix (nano/gedit default)."""
    assert _fires("/var/www/dvwa/config/config.inc.php~", "EditorBackupConfig")


def test_env_bak_fires():
    """``.env.bak`` is the canonical leaked-credential pattern."""
    assert _fires("/srv/app/.env.bak", "EditorBackupConfig")


def test_yaml_orig_fires():
    """Conflict-resolution leftover."""
    assert _fires("/srv/app/config.yml.orig", "EditorBackupConfig")


def test_editor_backup_does_not_fire_on_normal_config():
    """The plain config itself isn't matched by this rule (other
    rules handle that)."""
    assert _matches_named(
        "/var/www/dvwa/config/config.inc.php", "EditorBackupConfig"
    ) == []


def test_editor_backup_does_not_fire_on_non_config_swap():
    """A random ``.swp`` (e.g. text doc backup) shouldn't fire — the
    extension whitelist is config-shaped only."""
    assert _matches_named(
        "/home/alice/notes.txt.swp", "EditorBackupConfig"
    ) == []


# --- SSH host public keys ------------------------------------------


def test_ssh_host_rsa_pub_fires():
    assert _fires("/etc/ssh/ssh_host_rsa_key.pub", "SshHostPubKeys")


def test_ssh_host_ed25519_pub_fires():
    assert _fires("/etc/ssh/ssh_host_ed25519_key.pub", "SshHostPubKeys")


def test_ssh_user_pub_does_not_fire_on_host_rule():
    """User pub keys (id_rsa.pub) shouldn't match the HOST key rule —
    different rule handles user keys."""
    assert _matches_named(
        "/home/alice/.ssh/id_rsa.pub", "SshHostPubKeys"
    ) == []
