r"""Build the v0.27 Metasploitable 2 held-out benchmark.

Reads a filtered file list from MSF2's filesystem and emits a
labeled benchmark matching the v0.14 MSF3 shape:

* ``data/external/metasploitable2/file_list.txt`` — paths
* ``data/external/metasploitable2/ground_truth.jsonl`` — labels

Labels come from public Metasploitable 2 walkthroughs. The standard
credential-bearing locations are well-documented; we hard-code them
here so the labels are reproducible from the public knowledge base,
not from running ShareSift against the share (which would be
overfitting).

Each ground truth entry mirrors the MSF3 schema:
    {"path": "...", "has_credential": true/false, "credential_type": "..."}
"""

from __future__ import annotations

import argparse
import json
import random
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

# Known credential-bearing paths from public Metasploitable 2 walkthroughs.
# Each entry is (path_substring_or_regex, credential_type).
# Match is case-sensitive path-suffix substring; if any of these is
# contained in a file path, the file is labeled has_credential=True.
_POSITIVE_PATTERNS: list[tuple[str, str]] = [
    # Unix shadow / password files
    ("/etc/shadow", "hash"),
    ("/etc/passwd", "user_list"),
    ("/etc/gshadow", "group_hash"),
    # Host SSH keys
    ("/etc/ssh/ssh_host_dsa_key", "ssh_private_key"),
    ("/etc/ssh/ssh_host_rsa_key", "ssh_private_key"),
    # User SSH
    ("/root/.ssh/authorized_keys", "ssh_authorized_keys"),
    ("/root/.ssh/known_hosts", "ssh_known_hosts"),
    ("/home/msfadmin/.ssh", "ssh_user_artifact"),
    ("/home/user/.ssh", "ssh_user_artifact"),
    # MySQL / DB
    ("/etc/mysql/my.cnf", "db_config"),
    ("/opt/lampp/etc/my.cnf", "db_config"),
    ("/var/lib/mysql/mysql/user.MYD", "mysql_user_table"),
    ("/var/lib/mysql/mysql/user.MYI", "mysql_user_index"),
    # PostgreSQL
    ("/etc/postgresql/8.3/main/pg_hba.conf", "pg_auth_config"),
    ("/etc/postgresql/8.3/main/pg_ident.conf", "pg_auth_config"),
    # Web apps (DVWA, TikiWiki, phpMyAdmin)
    ("/usr/share/dvwa/config/config.inc.php", "dvwa_db_config"),
    ("/var/www/dvwa/config/config.inc.php", "dvwa_db_config"),
    ("/var/www/tikiwiki/db/local.php", "tiki_db_config"),
    ("/usr/share/tikiwiki/db/local.php", "tiki_db_config"),
    ("/var/www/phpmyadmin/config.inc.php", "phpmyadmin_config"),
    ("/etc/phpmyadmin/config.inc.php", "phpmyadmin_config"),
    ("/opt/lampp/phpmyadmin/config.inc.php", "phpmyadmin_config"),
    # SquirrelMail
    ("/etc/squirrelmail/config.php", "squirrelmail_config"),
    ("/usr/share/squirrelmail/config/config.php", "squirrelmail_config"),
    # Samba
    ("/etc/samba/smb.conf", "smb_config"),
    ("/etc/samba/smbusers", "smb_users"),
    # FTP servers
    ("/etc/proftpd/proftpd.conf", "ftp_config"),
    ("/etc/vsftpd.conf", "ftp_config"),
    # IAX / Asterisk
    ("/etc/iaxmodem/iaxmodem.conf", "iax_creds"),
    ("/etc/asterisk/iax.conf", "asterisk_creds"),
    ("/etc/asterisk/sip.conf", "asterisk_creds"),
    # LDAP
    ("/etc/ldap/slapd.conf", "ldap_config"),
    ("/etc/openldap/slapd.conf", "ldap_config"),
    # Apache + auth
    ("/etc/apache2/.htpasswd", "htpasswd"),
    ("/var/www/.htpasswd", "htpasswd"),
    # TWiki
    ("/var/www/twiki/data/.htpasswd", "twiki_passwd"),
    # IRC backdoor binary path (UnrealIRCd 3.2.8.1)
    ("/etc/unrealircd", "irc_config"),
    # Tomcat manager creds
    ("/var/lib/tomcat5.5/conf/tomcat-users.xml", "tomcat_users"),
    ("/etc/tomcat5.5/tomcat-users.xml", "tomcat_users"),
    # Cups
    ("/etc/cups/printers.conf", "cups_config"),
    # NFS exports
    ("/etc/exports", "nfs_config"),
    # Cron + at allow files
    ("/etc/sudoers", "sudoers"),
    # MetaSploitable-specific (msfadmin user)
    ("/root/reset_logs.sh", "shell_secret"),
    # Postfix / Sendmail
    ("/etc/postfix/main.cf", "postfix_config"),
    ("/etc/postfix/sasl_passwd", "smtp_relay_creds"),
    # WebDAV (DAV test page noted in walkthroughs)
    ("/var/www/dav/davtest.html", "webdav_test"),
]


def _label_path(p: str) -> tuple[bool, str | None]:
    """Apply the public-walkthrough pattern set to a single path."""
    for sub, cred_type in _POSITIVE_PATTERNS:
        if sub in p:
            return True, cred_type
    return False, None


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--source", type=Path, required=True,
                   help="Filtered MSF2 file list (one path per line).")
    p.add_argument("--output-dir", type=Path,
                   default=REPO_ROOT / "data" / "external" / "metasploitable2")
    p.add_argument("--sample-size", type=int, default=1500)
    p.add_argument("--seed", type=int, default=2027)
    args = p.parse_args(argv)

    all_paths = [
        line.strip() for line in args.source.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]

    # Find every known positive in the full file list (no sampling on positives).
    positives = []
    negatives_pool = []
    for path in all_paths:
        is_pos, cred_type = _label_path(path)
        if is_pos:
            positives.append((path, cred_type))
        else:
            negatives_pool.append(path)

    # Sample negatives.
    rng = random.Random(args.seed)
    n_neg = max(0, args.sample_size - len(positives))
    negatives = rng.sample(negatives_pool, min(n_neg, len(negatives_pool)))

    args.output_dir.mkdir(parents=True, exist_ok=True)

    all_records: list[dict] = []
    for path, cred_type in positives:
        all_records.append({
            "path": path,
            "has_credential": True,
            "credential_type": cred_type,
            "verified": True,
            "source": "public_msf2_walkthrough",
        })
    for path in negatives:
        all_records.append({
            "path": path,
            "has_credential": False,
            "credential_type": None,
            "verified": True,
            "source": "negative_sample",
        })

    # Stable sort for reproducibility.
    all_records.sort(key=lambda r: r["path"])

    (args.output_dir / "file_list.txt").write_text(
        "\n".join(r["path"] for r in all_records) + "\n",
        encoding="utf-8",
    )
    with (args.output_dir / "ground_truth.jsonl").open("w", encoding="utf-8") as f:
        for r in all_records:
            f.write(json.dumps(r) + "\n")

    print(f"wrote {len(all_records)} records to {args.output_dir}")
    print(f"  positives: {len(positives)}")
    print(f"  negatives: {len(negatives)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
