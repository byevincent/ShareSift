#!/usr/bin/env python3
"""diskforge_winshare_v1 — synthetic positive + noise file generator.

Deterministic (seeded). Produces ~80 positive files + ~2400 noise
files under tools/diskforge_winshare/files/{positives,noise}/.
Also emits positives_map.json (file → target Windows path) which
the manifest builder consumes.

All synthetic content is fictional — see files/positives/README.md
for the no-real-credentials guarantee.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import random
from pathlib import Path

ROOT = Path(__file__).resolve().parent
FILES = ROOT / "files"
POSITIVES = FILES / "positives"
NOISE = FILES / "noise"

# Stable seed for reproducibility — same seed = same file list.
SEED = 20260610


def write(path: Path, content: str | bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(content, str):
        path.write_text(content, encoding="utf-8")
    else:
        path.write_bytes(content)


def record_positive(category: str, idx: int, target: str,
                    content: str | bytes) -> tuple[str, str]:
    """Write a positive file to POSITIVES/<category>/<idx>/<basename(target)>
    so its source basename matches its target basename. DiskForge appends
    source basename to target dir, so this guarantees the final path
    equals `target`.
    """
    basename = target.rsplit("/", 1)[-1]
    src_rel = f"{category}/{idx}/{basename}"
    write(POSITIVES / src_rel, content)
    return (src_rel, target)


# ---------------------------------------------------------------------------
# POSITIVES — one section per category, indexed to match LAYOUT.md
# Each function returns a list of (source_relative_path, target_windows_path)
# tuples so the manifest builder can map them onto the disk image.
# ---------------------------------------------------------------------------

def _fake_cpassword(seed_byte: str) -> str:
    """Format-shaped GPP cpassword — 64 chars of [A-Za-z0-9+/=]."""
    return f"FAKE-cpassword-{seed_byte * 50}"[:64]


def cat_01_gpp() -> list[tuple[str, str]]:
    """GPP cpassword Groups.xml in SYSVOL paths (5 files)."""
    out = []
    accounts = [
        ("A", "local_admin", "Local Admin"),
        ("B", "srv_backup", "Backup Service"),
        ("C", "helpdesk_admin", "Helpdesk Local Admin"),
        ("D", "svc_iis", "IIS Service Account"),
        ("E", "svc_sql", "SQL Server Service"),
    ]
    for i, (seed, user, full) in enumerate(accounts):
        guid = f"{seed*8}-{seed*4}-{seed*4}-{seed*4}-{seed*12}"
        target = f"/SYSVOL/corp.local/Policies/{{{guid}}}/Machine/Preferences/Groups/Groups.xml"
        content = f"""<?xml version="1.0" encoding="utf-8"?>
<Groups clsid="{{3125E937-EB16-4b4c-9934-544FC6D24D26}}">
  <User clsid="{{DF5F1855-51E5-4d24-8B1A-D9BDE98BA1D1}}" name="{user}" image="2" changed="2024-03-15 14:22:08" uid="{{D5DE5D0E-DC2F-4D24-BCFF-AE92AFB13F00}}">
    <Properties action="U" newName="" fullName="{full}" description="" cpassword="{_fake_cpassword(seed)}" changeLogon="0" noChange="0" neverExpires="1" acctDisabled="0" userName="{user}"/>
  </User>
</Groups>
"""
        out.append(record_positive("01_gpp", i, target, content))
    return out


def cat_02_unattend() -> list[tuple[str, str]]:
    """Unattend / autounattend XML + autounattend.txt (5 files)."""
    out = []
    bodies = [
        ("unattend_server2019.xml",
         "/IT-Admin/imaging/server2019/unattend.xml",
         """<?xml version="1.0" encoding="utf-8"?>
<unattend xmlns="urn:schemas-microsoft-com:unattend">
  <settings pass="oobeSystem">
    <component name="Microsoft-Windows-Shell-Setup">
      <AutoLogon>
        <Password><Value>FAKE-Sup3rS3cret-2024!</Value><PlainText>true</PlainText></Password>
        <Username>Administrator</Username>
        <Enabled>true</Enabled>
      </AutoLogon>
    </component>
  </settings>
</unattend>
"""),
        ("autounattend_win10.xml",
         "/IT-Admin/imaging/win10/autounattend.xml",
         """<?xml version="1.0" encoding="utf-8"?>
<unattend xmlns="urn:schemas-microsoft-com:unattend">
  <settings pass="specialize">
    <component name="Microsoft-Windows-Shell-Setup">
      <AdministratorPassword><Value>FAKE-RootPass-2024!</Value><PlainText>true</PlainText></AdministratorPassword>
    </component>
  </settings>
</unattend>
"""),
        ("sysprep_corp.xml",
         "/IT-Admin/imaging/sysprep/sysprep_corp.xml",
         """<?xml version="1.0" encoding="utf-8"?>
<unattend xmlns="urn:schemas-microsoft-com:unattend">
  <settings pass="oobeSystem">
    <component name="Microsoft-Windows-Shell-Setup">
      <UserAccounts>
        <LocalAccounts>
          <LocalAccount wcm:action="add">
            <Password><Value>FAKE-LocalSetupPw-2024!</Value><PlainText>true</PlainText></Password>
            <Name>setupadmin</Name>
          </LocalAccount>
        </LocalAccounts>
      </UserAccounts>
    </component>
  </settings>
</unattend>
"""),
        ("install-server.txt",
         "/Public/IT-Templates/install-server.txt",
         """[OOBESystem]
ProductKey=FAKE-PROD-KEY-12345-67890-XXXXX
AutoLogon=Yes
AdminPassword=FAKE-DeployBootstrap-2024!
JoinDomain=corp.local
DomainAdmin=svc_join
DomainAdminPassword=FAKE-DomainJoinPw-2024!
"""),
        ("answer.xml",
         "/IT-Admin/imaging/legacy/answer.xml",
         """<?xml version="1.0" encoding="utf-8"?>
<unattend xmlns="urn:schemas-microsoft-com:unattend">
  <settings pass="oobeSystem">
    <component name="Microsoft-Windows-Shell-Setup">
      <AutoLogon>
        <Password><Value>FAKE-LegacyAnswerPw-2024!</Value><PlainText>true</PlainText></Password>
      </AutoLogon>
    </component>
  </settings>
</unattend>
"""),
    ]
    for i, (_, target, body) in enumerate(bodies):
        out.append(record_positive("02_unattend", i, target, body))
    return out


def cat_03_cloud_creds() -> list[tuple[str, str]]:
    """AWS / GCP / Azure CLI creds (6 files)."""
    out = []
    files = [
        ("aws_credentials",
         "/Departments/IT/svc-accounts/svc_backup/.aws/credentials",
         """[default]
aws_access_key_id = AKIAIOSFODNN7EXAMPLE
aws_secret_access_key = wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY
region = us-east-1

[prod-readonly]
aws_access_key_id = AKIAI44QH8DHBEXAMPLE
aws_secret_access_key = je7MtGbClwBF/2Zp9Utk/h3yCo8nvbEXAMPLEKEY
"""),
        ("aws_config",
         "/Departments/IT/svc-accounts/svc_deploy/.aws/credentials",
         """[default]
aws_access_key_id = AKIAEXAMPLE000000003
aws_secret_access_key = FAKEbenchmarkSecretEXAMPLEKEYxxxxxxxxxxx
output = json
"""),
        ("gcp_service_account.json",
         "/Departments/IT/svc-accounts/svc_gke/gcp_service_account.json",
         """{
  "type": "service_account",
  "project_id": "corp-prod-12345",
  "private_key_id": "FAKE-pkid-1111111111111111111111111111111111111111",
  "private_key": "-----BEGIN PRIVATE KEY-----\\nMIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQDFAKE-NOT-REAL-KEY-MATERIAL-FOR-BENCHMARK-PURPOSES-ONLY-AAAAAAAA\\n-----END PRIVATE KEY-----\\n",
  "client_email": "svc-gke@corp-prod-12345.iam.gserviceaccount.com",
  "client_id": "111111111111111111111"
}
"""),
        ("azure_credentials",
         "/Departments/IT/svc-accounts/svc_az/.azure/credentials",
         """[default]
tenant_id = aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee
client_id = ffffffff-1111-2222-3333-444444444444
client_secret = FAKE-AzureClientSecret-2024-DO-NOT-USE
subscription_id = 99999999-8888-7777-6666-555555555555
"""),
        ("azure_powershell.json",
         "/Departments/IT/svc-accounts/svc_az/azure_powershell_settings.json",
         """{
  "Subscriptions": [
    {"Id": "99999999-8888-7777-6666-555555555555", "Name": "corp-prod"}
  ],
  "Accounts": [
    {"Id": "svc_az@corp.onmicrosoft.com", "Credential": "FAKE-AzPSCred-2024-base64placeholder=="}
  ]
}
"""),
        ("rclone.conf",
         "/Departments/IT/svc-accounts/svc_storage/rclone.conf",
         """[corp-s3]
type = s3
provider = AWS
access_key_id = AKIAIOSFODNN7EXAMPLE
secret_access_key = wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY
region = us-east-1

[corp-azure]
type = azureblob
account = corpstorage
key = FAKE-AzBlobKey-2024-base64-placeholder/AAAAA==
"""),
    ]
    for i, (_, target, body) in enumerate(files):
        out.append(record_positive("03_cloud_creds", i, target, body))
    return out


def cat_04_ssh_keys() -> list[tuple[str, str]]:
    """SSH private keys + PPK files (6 files)."""
    out = []
    fake_rsa_key = """-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA1AKE-FAKE-NOT-REAL-RSA-KEY-MATERIAL-FOR-BENCHMARK-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB
CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC
-----END RSA PRIVATE KEY-----
"""
    fake_ed25519_key = """-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAACmFlczI1Ni1jdHIAAAAGYmNyeXB0AAAAGAAAABCFAKE-NOT-REAL-OPENSSH-KEY-MATERIAL-FOR-BENCHMARK-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
-----END OPENSSH PRIVATE KEY-----
"""
    fake_ppk_unencrypted = """PuTTY-User-Key-File-3: ssh-ed25519
Encryption: none
Comment: imported-openssh-key-2024
Public-Lines: 2
AAAAC3NzaC1lZDI1NTE5AAAAII6FAKE-NOT-REAL-PUBLIC-KEY-MATERIAL-AAAAA
Private-Lines: 1
FAKE-NOT-REAL-PRIVATE-KEY-MATERIAL-FOR-BENCHMARK-PURPOSES-AAAAAA==
Private-MAC: 0000000000000000000000000000000000000000000000000000000000000000
"""
    fake_ppk_encrypted = """PuTTY-User-Key-File-3: ssh-rsa
Encryption: aes256-cbc
Comment: encrypted-key-2024
Public-Lines: 6
AAAAB3NzaC1yc2EAAAADAQABAAABAQDFAKE-NOT-REAL-RSA-PUBLIC-AAAAAAA
Private-Lines: 14
FAKE-ENCRYPTED-NOT-REAL-PRIVATE-KEY-MATERIAL-FOR-BENCHMARK-AAA==
Private-MAC: ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
"""
    files = [
        ("id_rsa", "/IT-Admin/admin-home/.ssh/id_rsa", fake_rsa_key),
        ("id_ed25519", "/IT-Admin/admin-home/.ssh/id_ed25519", fake_ed25519_key),
        ("id_rsa_svcdeploy", "/Departments/IT/svc-accounts/svc_deploy/.ssh/id_rsa", fake_rsa_key),
        ("bastion_unencrypted.ppk", "/IT-Admin/admin-home/Documents/bastion.ppk", fake_ppk_unencrypted),
        ("bastion_encrypted.ppk", "/IT-Admin/admin-home/Documents/bastion_enc.ppk", fake_ppk_encrypted),
        ("jenkins_id_rsa", "/Departments/IT/svc-accounts/svc_jenkins/.ssh/id_rsa", fake_rsa_key),
    ]
    for i, (_, target, body) in enumerate(files):
        out.append(record_positive("04_ssh_keys", i, target, body))
    return out


def cat_05_keepass() -> list[tuple[str, str]]:
    """KeePass .kdbx databases (3 files, header-only stubs)."""
    out = []
    # KeePass2 .kdbx file signature: 03 D9 A2 9A 67 FB 4B B5
    # We write the signature + 256 bytes of random-shaped placeholder
    # so the file parses as a kdbx but contains no entries.
    sig = bytes([0x03, 0xD9, 0xA2, 0x9A, 0x67, 0xFB, 0x4B, 0xB5])
    rng = random.Random(SEED)
    bodies = [
        ("it_team_passwords.kdbx", "/IT-Admin/password-vault/passwords.kdbx"),
        ("network_credentials.kdbx", "/Departments/IT/network-creds/network_credentials.kdbx"),
        ("personal_kdbx.kdbx", "/Departments/IT/svc-accounts/svc_helpdesk/Documents/personal.kdbx"),
    ]
    for i, (_, target) in enumerate(bodies):
        body = sig + bytes(rng.randint(0, 255) for _ in range(248))
        out.append(record_positive("05_keepass", i, target, body))
    return out


def cat_06_pshistory() -> list[tuple[str, str]]:
    """PowerShell history files (4 files)."""
    out = []
    bodies = [
        ("admin_ConsoleHost_history.txt",
         "/IT-Admin/admin-home/AppData/Roaming/Microsoft/Windows/PowerShell/PSReadLine/ConsoleHost_history.txt",
         """Connect-VIServer -Server vcenter.corp.local -User administrator@vsphere.local -Password 'FAKE-VSphereAdmin-2024!'
Enter-PSSession -ComputerName dc01.corp.local -Credential (New-Object PSCredential -ArgumentList 'corp\\Administrator', (ConvertTo-SecureString 'FAKE-DomainAdmin-2024!' -AsPlainText -Force))
Invoke-Sqlcmd -ServerInstance sql01.corp.local -Username sa -Password 'FAKE-SaPassword-2024!' -Query 'SELECT @@VERSION'
$cred = Get-Credential -UserName 'corp\\svc_backup' -Message 'Backup creds'
"""),
        ("svc_deploy_history.txt",
         "/Departments/IT/svc-accounts/svc_deploy/AppData/Roaming/Microsoft/Windows/PowerShell/PSReadLine/ConsoleHost_history.txt",
         """az login --username svc-deploy@corp.onmicrosoft.com --password 'FAKE-AzDeploy-2024!'
gh auth login --with-token <<< 'ghp_FAKEGitHubPATFOR2024BenchmarkOnlyAAAAAAAAAA'
docker login registry.corp.local -u svc_deploy -p 'FAKE-RegistryPw-2024!'
"""),
        ("svc_sql_history.txt",
         "/Departments/IT/svc-accounts/svc_sql/AppData/Roaming/Microsoft/Windows/PowerShell/PSReadLine/ConsoleHost_history.txt",
         """sqlcmd -S sql01.corp.local -U sa -P 'FAKE-SaPassword-2024!' -Q 'BACKUP DATABASE master TO DISK = ''C:\\backups\\master.bak'''
Invoke-WebRequest -Uri https://api.internal/v1/keys -Headers @{Authorization='Bearer FAKE-bearer-token-2024-aaaaaaaaa'}
"""),
        ("helpdesk_history.txt",
         "/Departments/IT/helpdesk/AppData/Roaming/Microsoft/Windows/PowerShell/PSReadLine/ConsoleHost_history.txt",
         """New-LocalUser -Name 'temp_helper' -Password (ConvertTo-SecureString 'FAKE-TempHelper-2024!' -AsPlainText -Force)
Reset-ADAccountPassword -Identity contractor01 -NewPassword (ConvertTo-SecureString 'FAKE-Contractor-2024!' -AsPlainText -Force)
"""),
    ]
    for i, (_, target, body) in enumerate(bodies):
        out.append(record_positive("06_pshistory", i, target, body))
    return out


def cat_07_browser() -> list[tuple[str, str]]:
    """Browser saved-creds DBs (Chrome / Edge / Firefox + Brave + Opera + Chromium, 6 files).

    We emit empty SQLite-shaped placeholders for Chromium-base Login
    Data and a logins.json stub for Firefox.
    """
    out = []
    sqlite_header = b"SQLite format 3\x00" + bytes(496)  # header + zeroed db page
    firefox_logins = """{
  "nextId": 1,
  "logins": [],
  "potentiallyVulnerablePasswords": [],
  "dismissedBreachAlertsByLoginGUID": {},
  "version": 3
}
"""
    files_bin = [
        ("chrome_Login_Data",
         "/Departments/IT/profile-backups/svc_helpdesk/Chrome/User Data/Default/Login Data"),
        ("edge_Login_Data",
         "/Departments/IT/profile-backups/svc_helpdesk/Microsoft/Edge/User Data/Default/Login Data"),
        ("brave_Login_Data",
         "/Departments/IT/profile-backups/svc_helpdesk/BraveSoftware/Brave-Browser/User Data/Default/Login Data"),
        ("opera_Login_Data",
         "/Departments/IT/profile-backups/svc_helpdesk/Opera Software/Opera/User Data/Default/Login Data"),
    ]
    for i, (_, target) in enumerate(files_bin):
        out.append(record_positive("07_browser", i, target, sqlite_header))
    files_txt = [
        ("firefox_logins.json",
         "/Departments/IT/profile-backups/svc_helpdesk/Mozilla/Firefox/Profiles/abc123.default/logins.json",
         firefox_logins),
        ("firefox_key4_db",
         "/Departments/IT/profile-backups/svc_helpdesk/Mozilla/Firefox/Profiles/abc123.default/key4.db",
         ""),
    ]
    for j, (_, target, body) in enumerate(files_txt):
        out.append(record_positive("07_browser", 100 + j, target, body))
    return out


def cat_08_appsettings() -> list[tuple[str, str]]:
    """web.config / appsettings.json with embedded DB passwords (5 files)."""
    out = []
    files = [
        ("web.config_internal",
         "/Departments/Eng/webapps/internal/web.config",
         """<?xml version="1.0"?>
<configuration>
  <connectionStrings>
    <add name="DefaultConnection" providerName="System.Data.SqlClient"
         connectionString="Data Source=sql01.corp.local;Initial Catalog=Internal;User ID=sa;Password=FAKE-SaWebPw-2024!"/>
  </connectionStrings>
</configuration>
"""),
        ("web.config_reporting",
         "/Departments/Eng/webapps/reporting/web.config",
         """<?xml version="1.0"?>
<configuration>
  <connectionStrings>
    <add name="ReportDB" connectionString="Server=sql02;Database=Reporting;UID=reportreader;Password=FAKE-ReportPw-2024!"/>
  </connectionStrings>
</configuration>
"""),
        ("appsettings.json_api",
         "/Departments/Eng/webapps/api-gateway/appsettings.json",
         """{
  "ConnectionStrings": {
    "DefaultConnection": "Server=sql01.corp.local;Database=ApiGateway;User Id=svc_api;Password=FAKE-ApiDb-2024!;TrustServerCertificate=true"
  },
  "Logging": {"LogLevel": {"Default": "Information"}}
}
"""),
        ("appsettings.Production.json_orders",
         "/Departments/Eng/webapps/orders/appsettings.Production.json",
         """{
  "ConnectionStrings": {
    "OrdersDB": "Data Source=sql-prod.corp.local;Initial Catalog=Orders;User ID=svc_orders;Password=FAKE-OrdersDb-2024!"
  }
}
"""),
        ("web.config_legacy",
         "/Departments/Eng/webapps/legacy/web.config",
         """<?xml version="1.0"?>
<configuration>
  <connectionStrings>
    <add name="LegacyDB" connectionString="Provider=MSDAORA;Data Source=ora01;User Id=app_legacy;Password=FAKE-LegacyOra-2024!"/>
  </connectionStrings>
</configuration>
"""),
    ]
    for i, (_, target, body) in enumerate(files):
        out.append(record_positive("08_appsettings", i, target, body))
    return out


def cat_09_wpconfig() -> list[tuple[str, str]]:
    """wp-config.php with DB creds (3 files)."""
    out = []
    files = [
        ("wp-config_main",
         "/Departments/Marketing/blog-backups/main/wp-config.php",
         """<?php
define('DB_NAME', 'corp_blog');
define('DB_USER', 'wp_blog');
define('DB_PASSWORD', 'FAKE-WpMainBlog-2024!');
define('DB_HOST', 'mysql01.corp.local');
define('AUTH_KEY', 'FAKE-auth-key-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa');
?>
"""),
        ("wp-config_dev",
         "/Departments/Marketing/blog-backups/dev/wp-config.php",
         """<?php
define('DB_NAME', 'corp_blog_dev');
define('DB_USER', 'wp_dev');
define('DB_PASSWORD', 'FAKE-WpDevBlog-2024!');
define('DB_HOST', 'mysql-dev.corp.local');
?>
"""),
        ("wp-config_bak",
         "/Departments/Marketing/blog-backups/main/wp-config.php.bak",
         """<?php
define('DB_NAME', 'corp_blog');
define('DB_USER', 'wp_blog_old');
define('DB_PASSWORD', 'FAKE-WpMainOld-2023!');
define('DB_HOST', 'mysql01.corp.local');
?>
"""),
    ]
    for i, (_, target, body) in enumerate(files):
        out.append(record_positive("09_wpconfig", i, target, body))
    return out


def cat_10_cisco() -> list[tuple[str, str]]:
    """Cisco IOS config files (5 files)."""
    out = []
    files = [
        ("corp-rtr01.config", "/Departments/IT/network-backups/corp-rtr01.config",
         """hostname corp-rtr01
!
enable secret 5 $1$FAKEsalt$FAKEhashedSecretXXXXXX/
enable password 7 110A1016141D
!
username svc_netadmin privilege 15 secret 5 $1$FAKEsalt2$FAKEhashedSecret2XXXX/
username monitor privilege 1 password 7 02050D480809
!
snmp-server community FAKE-snmpReadOnly RO
snmp-server community FAKE-snmpReadWrite RW
"""),
        ("corp-sw02.config", "/Departments/IT/network-backups/corp-sw02.config",
         """hostname corp-sw02
!
enable secret 8 $8$FAKEsalt$FAKEpbkdf2hashXXXX/
username admin privilege 15 password 7 030752180500
!
snmp-server community FAKE-snmpCorpRO RO
"""),
        ("branch-rtr03.config", "/Departments/IT/network-backups/branch-rtr03.config",
         """hostname branch-rtr03
!
enable secret 5 $1$FAKEsalt3$FAKEhashedSecret3XXXX/
username branch_op privilege 5 password 7 045802150C2E
!
snmp-server community FAKE-snmpBranchRW RW
"""),
        ("corp-asa01-running.config", "/Departments/IT/network-backups/corp-asa01-running.config",
         """hostname corp-asa01
!
enable password FAKE-ASA-EnablePw-2024! encrypted
username asaadmin password FAKE-ASA-Admin-2024! privilege 15
!
"""),
        ("corp-fw02.config", "/Departments/IT/network-backups/corp-fw02.config",
         """hostname corp-fw02
!
enable secret 5 $1$FAKEsalt4$FAKEhashedSecret4XXXX/
snmp-server community FAKE-snmpFwRO RO
snmp-server community FAKE-snmpFwRW RW
"""),
    ]
    for i, (_, target, body) in enumerate(files):
        out.append(record_positive("10_cisco", i, target, body))
    return out


def cat_11_sccm() -> list[tuple[str, str]]:
    """SCCM artifacts — boot var, Variables.dat, Policy.xml, ContentLib (6 files)."""
    out = []
    files = [
        ("PKG00001.var", "/Departments/IT/sccm-mirror/REMINST/SMSTemp/PKG00001.var",
         "FAKE-SCCM-BootVar-PKG00001-NetworkAccessAccount=svc_naa-Password=FAKE-NaaPw-2024!\n"),
        ("PKG00007.var", "/Departments/IT/sccm-mirror/REMINST/SMSTemp/PKG00007.var",
         "FAKE-SCCM-BootVar-PKG00007-NetworkAccessAccount=svc_naa-Password=FAKE-NaaPw-2024!\n"),
        ("Variables.dat", "/Departments/IT/sccm-mirror/SMS/data/Variables.dat",
         "FAKE-SCCM-Variables-TaskSequence-creds-blob\n"),
        ("Policy.xml", "/Departments/IT/sccm-mirror/SMS/data/Policy.xml",
         """<?xml version="1.0"?>
<Policy>
  <NAA Username="svc_naa" Password="FAKE-NaaPolicyPw-2024!"/>
</Policy>
"""),
        ("contentlib_some.ini", "/Departments/IT/sccm-mirror/SCCMContentLib$/DataLib/PKG00001.1/some.ini",
         "[Settings]\nAdminPw=FAKE-ContentLibPw-2024!\n"),
        ("contentlib_settings.reg", "/Departments/IT/sccm-mirror/SCCMContentLib$/PkgLib/PKG00100/settings.reg",
         """Windows Registry Editor Version 5.00
[HKEY_LOCAL_MACHINE\\SOFTWARE\\CorpApp]
"AdminPassword"="FAKE-RegPw-2024!"
"""),
    ]
    for i, (_, target, body) in enumerate(files):
        out.append(record_positive("11_sccm", i, target, body))
    return out


def cat_12_kerberos() -> list[tuple[str, str]]:
    """Kerberos keytab + ccache files (4 files)."""
    out = []
    # Kerberos keytab v2 magic: 0x05 0x02
    keytab_stub = bytes([0x05, 0x02, 0x00, 0x00, 0x00, 0x40]) + bytes(58)
    ccache_stub = bytes([0x05, 0x04, 0x00, 0x0c]) + bytes(60)
    files = [
        ("app01_etc_krb5.keytab",
         "/Departments/IT/linux-backups/app01/etc/krb5.keytab", keytab_stub),
        ("dev02_admin.CCACHE",
         "/Departments/IT/linux-backups/dev02/tmp/admin.CCACHE", ccache_stub),
        ("bastion_krb5cc",
         "/Departments/IT/linux-backups/bastion/tmp/krb5cc_1000", ccache_stub),
        ("svc_http_keytab",
         "/Departments/IT/linux-backups/web01/etc/http.keytab", keytab_stub),
    ]
    for i, (_, target, body) in enumerate(files):
        out.append(record_positive("12_kerberos", i, target, body))
    return out


def cat_13_filezilla() -> list[tuple[str, str]]:
    """FileZilla saved sites + recent servers (3 files)."""
    out = []
    sitemanager_xml = """<?xml version="1.0"?>
<FileZilla3>
  <Servers>
    <Server>
      <Host>backup.corp.local</Host><Port>22</Port><Protocol>1</Protocol>
      <Type>0</Type><User>svc_backup</User>
      <Pass encoding="base64">RkFLRS1GekJhY2t1cFB3LTIwMjQh</Pass>
      <Name>Corp Backup Server</Name>
    </Server>
  </Servers>
</FileZilla3>
"""
    files = [
        ("sitemanager.xml",
         "/Departments/IT/profile-backups/svc_helpdesk/FileZilla/sitemanager.xml",
         sitemanager_xml),
        ("recentservers.xml",
         "/Departments/IT/profile-backups/svc_helpdesk/FileZilla/recentservers.xml",
         """<?xml version="1.0"?>
<FileZilla3>
  <RecentServers>
    <Server><Host>backup.corp.local</Host><User>svc_backup</User></Server>
    <Server><Host>vendor-sftp.example.com</Host><User>corp_vendor</User></Server>
  </RecentServers>
</FileZilla3>
"""),
        ("sitemanager_svc_jenkins.xml",
         "/Departments/IT/profile-backups/svc_jenkins/FileZilla/sitemanager.xml",
         sitemanager_xml),
    ]
    for i, (_, target, body) in enumerate(files):
        out.append(record_positive("13_filezilla", i, target, body))
    return out


def cat_14_german() -> list[tuple[str, str]]:
    """German credential filename keywords (4 files)."""
    out = []
    body = "FAKE - synthetic placeholder for German credential filename keyword test\n"
    files = [
        ("zugaenge_2024.xlsx",
         "/Departments/HR/Abteilungen-IT/Passwoerter/zugaenge_2024.xlsx"),
        ("kennwoerter_aktuell.xlsx",
         "/Departments/HR/Abteilungen-IT/kennwoerter_aktuell.xlsx"),
        ("anmeldedaten_export.csv",
         "/Departments/HR/exporte/anmeldedaten_export.csv"),
        ("logindaten_archiv.xlsx",
         "/Departments/IT/archive/logindaten_archiv.xlsx"),
    ]
    for i, (_, target) in enumerate(files):
        out.append(record_positive("14_german", i, target, body))
    return out


def cat_15_credname() -> list[tuple[str, str]]:
    """Credential-keyword filenames on data/export extensions (5 files)."""
    out = []
    body = "FAKE - synthetic placeholder for credential filename keyword test\n"
    files = [
        ("employee_credentials_2024.xlsx",
         "/Departments/HR/export/employee_credentials_2024.xlsx"),
        ("CustomerCredentialsExport.csv",
         "/Departments/Marketing/data-exports/CustomerCredentialsExport.csv"),
        ("partner_credentials_q3.csv",
         "/Departments/HR/export/partner_credentials_q3.csv"),
        ("svc_credentials_backup.json",
         "/Departments/IT/sccm-mirror/svc_credentials_backup.json"),
        ("CredentialsArchive2023.zip",
         "/Departments/HR/archive/CredentialsArchive2023.zip"),
    ]
    for i, (_, target) in enumerate(files):
        out.append(record_positive("15_credname", i, target, body))
    return out


def cat_16_cmdset() -> list[tuple[str, str]]:
    """CMD batch with set "VAR=val" credential assignments (5 files)."""
    out = []
    files = [
        ("restore_db.bat",
         "/Public/IT-Templates/setup/restore_db.bat",
         """@echo off
set PASSWORD=FAKE-Sup3rS3cret2024!
set DB_HOST=dbprod.corp.local
mysql -uroot -p%PASSWORD% -h %DB_HOST% -e "SELECT NOW()"
"""),
        ("export_pg.cmd",
         "/Public/IT-Templates/setup/export_pg.cmd",
         """@echo off
set "PGPASSWORD=FAKE-W3lc0m3-2024!"
set "PGUSER=postgres"
pg_dump -h db.corp.local -U postgres mydb > backup.sql
"""),
        ("jenkins_deploy.bat",
         "/Departments/IT/jenkins-scripts/deploy.bat",
         """@echo off
set CLIENT_SECRET=FAKE-aBcDeFgHiJkLmNoPqRsTuVwXyZ012345
set CLIENT_ID=00000000-0000-0000-0000-000000000000
echo %CLIENT_SECRET% > .env
"""),
        ("api_invoke.cmd",
         "/Departments/IT/automation/api_invoke.cmd",
         """@echo off
rem corp API daily pull
set "API_KEY=FAKE-ApiKey-2024-aBcDeF123456"
curl -H "Authorization: Bearer %API_KEY%" https://api.corp.local/v1/data
"""),
        ("svc_restart.bat",
         "/Departments/IT/automation/svc_restart.bat",
         """@echo off
set SVCPASS=FAKE-SvcRestart-2024!
sc.exe \\\\srv01 stop CorpService
sc.exe \\\\srv01 start CorpService obj= corp\\svc_runner password= %SVCPASS%
"""),
    ]
    for i, (_, target, body) in enumerate(files):
        out.append(record_positive("16_cmdset", i, target, body))
    return out


# ---------------------------------------------------------------------------
# NOISE — 8 classes, generated by stable seed
# ---------------------------------------------------------------------------

def gen_noise(rng: random.Random, count: int, dir_prefix: str,
              templates: list[tuple[str, str]]) -> list[tuple[str, str]]:
    """Generate `count` zero-byte noise files distributed across template
    target paths.

    Each file lives in its own numbered subdir so source basename ==
    target basename (DiskForge appends source basename to target dir).
    Returns (source_relative, target_full_path) tuples.
    """
    out = []
    for i in range(count):
        tmpl_name, tmpl_dir = rng.choice(templates)
        fname = tmpl_name.format(n=i)
        target_dir = tmpl_dir.format(n=i)
        # Each noise file in its own indexed subdir → source basename
        # matches target basename, no source-path collisions.
        src = f"{dir_prefix}/{i:05d}/{fname}"
        target = f"{target_dir}/{fname}"
        write(NOISE / src, "")
        out.append((src, target))
    return out


def class_hr_policy(rng: random.Random) -> list[tuple[str, str]]:
    templates = [
        ("handbook_v3_{n}.docx", "/Departments/HR/policies"),
        ("code_of_conduct_2024_{n}.pdf", "/Departments/HR/policies"),
        ("onboarding_checklist_{n}.docx", "/Departments/HR/onboarding"),
        ("offboarding_form_{n}.docx", "/Departments/HR/offboarding"),
        ("benefits_summary_{n}.pdf", "/Departments/HR/policies"),
        ("training_module_{n}.pptx", "/Departments/HR/training"),
        ("travel_policy_v{n}.pdf", "/Departments/HR/policies"),
        ("dress_code_v{n}.docx", "/Departments/HR/policies"),
    ]
    return gen_noise(rng, 300, "hr_policy", templates)


def class_finance_reports(rng: random.Random) -> list[tuple[str, str]]:
    templates = [
        ("Q{n}_2024_close.xlsx", "/Departments/Finance/quarterly"),
        ("forecast_FY{n}.xlsx", "/Departments/Finance/forecasts"),
        ("annual_report_20{n}.pdf", "/Departments/Finance/annual"),
        ("balance_sheet_{n}.xlsx", "/Departments/Finance/statements"),
        ("cashflow_{n}.xlsx", "/Departments/Finance/statements"),
        ("budget_proposal_{n}.docx", "/Departments/Finance/budgets"),
        ("expense_report_{n}.xlsx", "/Departments/Finance/expenses"),
        ("audit_notes_{n}.docx", "/Departments/Finance/audit"),
    ]
    return gen_noise(rng, 300, "finance_reports", templates)


def class_marketing_assets(rng: random.Random) -> list[tuple[str, str]]:
    templates = [
        ("logo_v{n}.psd", "/Departments/Marketing/assets/logos"),
        ("campaign_brief_summer{n}.docx", "/Departments/Marketing/campaigns"),
        ("rebrand_2025_v{n}.pdf", "/Departments/Marketing/rebrand"),
        ("collateral_pack_{n}.zip", "/Departments/Marketing/collateral"),
        ("photoshoot_{n}.jpg", "/Departments/Marketing/assets/photos"),
        ("press_release_{n}.docx", "/Departments/Marketing/press"),
        ("social_media_calendar_{n}.xlsx", "/Departments/Marketing/social"),
        ("email_template_{n}.html", "/Departments/Marketing/email-templates"),
    ]
    return gen_noise(rng, 300, "marketing_assets", templates)


def class_software_install(rng: random.Random) -> list[tuple[str, str]]:
    templates = [
        ("Office_2021_x64_{n}.msi", "/Public/Software/Office"),
        ("Adobe_Acrobat_{n}.exe", "/Public/Software/Adobe"),
        ("Visio_2019_{n}.msi", "/Public/Software/Visio"),
        ("SQLServer2019_Standard_{n}.iso", "/Public/Software/SQL"),
        ("VSCode_{n}.exe", "/Public/Software/DevTools"),
        ("Git_for_Windows_{n}.exe", "/Public/Software/DevTools"),
        ("7zip_install_{n}.exe", "/Public/Software/Utilities"),
        ("Notepad++_{n}.exe", "/Public/Software/Utilities"),
    ]
    return gen_noise(rng, 300, "software_install", templates)


def class_log_archives(rng: random.Random) -> list[tuple[str, str]]:
    templates = [
        ("app_2024-{n:02d}.log.gz", "/Departments/IT/logs/app"),
        ("iis_2024-{n:02d}.zip", "/Departments/IT/logs/system"),
        ("security_evt_2024-{n:02d}.evtx", "/Departments/IT/logs/security"),
        ("access_2024-{n:02d}.log", "/Departments/IT/logs/access"),
        ("system_2024-{n:02d}.log.gz", "/Departments/IT/logs/system"),
        ("audit_2024-{n:02d}.log", "/Departments/IT/logs/audit"),
        ("dns_2024-{n:02d}.log.gz", "/Departments/IT/logs/dns"),
        ("dhcp_2024-{n:02d}.log", "/Departments/IT/logs/dhcp"),
    ]
    return gen_noise(rng, 300, "log_archives", templates)


def class_vendor_pdfs(rng: random.Random) -> list[tuple[str, str]]:
    templates = [
        ("Dell_R740_install_guide_{n}.pdf", "/Public/Vendor-Docs/Dell"),
        ("Cisco_2960_config_guide_{n}.pdf", "/Public/Vendor-Docs/Cisco"),
        ("VMware_vSphere_admin_{n}.pdf", "/Public/Vendor-Docs/VMware"),
        ("Microsoft_AD_Admin_{n}.pdf", "/Public/Vendor-Docs/Microsoft"),
        ("Veeam_backup_guide_{n}.pdf", "/Public/Vendor-Docs/Veeam"),
        ("HP_ProLiant_manual_{n}.pdf", "/Public/Vendor-Docs/HP"),
        ("Fortinet_FortiGate_{n}.pdf", "/Public/Vendor-Docs/Fortinet"),
        ("NetApp_FAS_guide_{n}.pdf", "/Public/Vendor-Docs/NetApp"),
    ]
    return gen_noise(rng, 300, "vendor_pdfs", templates)


def class_project_files(rng: random.Random) -> list[tuple[str, str]]:
    templates = [
        ("OrderService_{n}.cs", "/Departments/Eng/proj-x/src"),
        ("controller_{n}.py", "/Departments/Eng/proj-y/src"),
        ("repository_{n}.cs", "/Departments/Eng/proj-x/src"),
        ("middleware_{n}.py", "/Departments/Eng/proj-y/src"),
        ("Program_{n}.cs", "/Departments/Eng/sandbox/src"),
        ("test_helper_{n}.py", "/Departments/Eng/proj-y/tests"),
        ("README_{n}.md", "/Departments/Eng/proj-x"),
        ("CHANGELOG_{n}.md", "/Departments/Eng/proj-y"),
    ]
    return gen_noise(rng, 300, "project_files", templates)


def class_public_templates(rng: random.Random) -> list[tuple[str, str]]:
    templates = [
        ("meeting_agenda_template_v{n}.docx", "/Public/Templates/office"),
        ("project_charter_v{n}.docx", "/Public/Templates/project"),
        ("status_report_template_v{n}.docx", "/Public/Templates/reports"),
        ("expense_template_v{n}.xlsx", "/Public/Templates/office"),
        ("invoice_template_v{n}.docx", "/Public/Templates/office"),
        ("contract_template_v{n}.docx", "/Public/Templates/legal"),
        ("nda_template_v{n}.docx", "/Public/Templates/legal"),
        ("presentation_template_v{n}.pptx", "/Public/Templates/office"),
    ]
    return gen_noise(rng, 300, "public_templates", templates)


# ---------------------------------------------------------------------------
# PRECISION-STRESS NOISE — credential-keyword names in benign context
# ---------------------------------------------------------------------------

def stress_noise() -> list[tuple[str, str]]:
    """~20 negative-label files with credential-shaped names. Test that
    rules don't over-fire on policy / training / test files."""
    items = [
        ("password_policy.docx", "/Departments/HR/policies"),
        ("credential_request_template.docx", "/Departments/HR/onboarding"),
        ("account_setup_checklist.xlsx", "/Departments/HR/onboarding"),
        ("secrets_management_guidelines.pdf", "/Departments/HR/policies"),
        ("key_management_template.xlsx", "/Public/Templates/office"),
        ("secret_santa_2024.xlsx", "/Departments/IT/projects"),
        ("Q3_credentials_review_meeting.docx", "/Departments/Marketing/rebrand_2024"),
        ("AuthCredentialsTest.cs", "/Departments/Eng/proj-x/src"),
        ("password_complexity_policy_v3.docx", "/Departments/HR/policies"),
        ("ApiKeyHelperTests.py", "/Departments/Eng/proj-y/tests"),
        ("how_to_rotate_credentials.pdf", "/Public/Vendor-Docs/Microsoft"),
        ("OAuthTokenValidatorTests.cs", "/Departments/Eng/proj-x/tests"),
        ("password_reset_workflow.docx", "/Departments/HR/policies"),
        ("Apikey_training_module_2024.pptx", "/Departments/HR/training"),
        ("incident_response_credentials_guide.pdf", "/Departments/HR/policies"),
        ("CredentialHelperFactory.cs", "/Departments/Eng/proj-x/src"),
        ("secrets_rotation_runbook.docx", "/Public/Templates/project"),
        ("password_audit_template.xlsx", "/Public/Templates/reports"),
        ("AuthSecretsValidatorTests.py", "/Departments/Eng/proj-y/tests"),
        ("credentials_management_handbook.pdf", "/Departments/HR/policies"),
    ]
    out = []
    for i, (fname, target_dir) in enumerate(items):
        src = f"stress/{i:05d}/{fname}"
        target = f"{target_dir}/{fname}"
        write(NOISE / src, "")
        out.append((src, target))
    return out


# ---------------------------------------------------------------------------
# DRIVER
# ---------------------------------------------------------------------------

def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--clean", action="store_true",
                        help="Wipe files/ before generation")
    args = parser.parse_args()

    if args.clean:
        import shutil
        for d in (POSITIVES, NOISE):
            if d.exists():
                shutil.rmtree(d)

    rng = random.Random(SEED)

    positive_mappings: list[tuple[str, str, str]] = []  # (source, target, category)
    for n, fn in enumerate([
        cat_01_gpp, cat_02_unattend, cat_03_cloud_creds, cat_04_ssh_keys,
        cat_05_keepass, cat_06_pshistory, cat_07_browser, cat_08_appsettings,
        cat_09_wpconfig, cat_10_cisco, cat_11_sccm, cat_12_kerberos,
        cat_13_filezilla, cat_14_german, cat_15_credname, cat_16_cmdset,
    ], 1):
        category = fn.__name__.replace("cat_", "")
        for src, target in fn():
            positive_mappings.append((src, target, category))

    print(f"[positives] {len(positive_mappings)} files written under {POSITIVES}")

    noise_mappings: list[tuple[str, str, str]] = []  # (source, target, class)
    for cls_name, fn in [
        ("hr_policy", class_hr_policy),
        ("finance_reports", class_finance_reports),
        ("marketing_assets", class_marketing_assets),
        ("software_install", class_software_install),
        ("log_archives", class_log_archives),
        ("vendor_pdfs", class_vendor_pdfs),
        ("project_files", class_project_files),
        ("public_templates", class_public_templates),
    ]:
        for src, target in fn(rng):
            noise_mappings.append((src, target, cls_name))
    for src, target in stress_noise():
        noise_mappings.append((src, target, "stress"))

    print(f"[noise] {len(noise_mappings)} files written under {NOISE}")

    # Emit the manifest mapping file the docker manifest builder consumes
    mapping = {
        "schema": "diskforge_winshare_v1",
        "seed": SEED,
        "positives": [
            {"source": f"positives/{s}", "target": t, "category": c}
            for s, t, c in positive_mappings
        ],
        "noise": [
            {"source": f"noise/{s}", "target": t, "class": c}
            for s, t, c in noise_mappings
        ],
    }
    out_path = ROOT / "positives_map.json"
    out_path.write_text(json.dumps(mapping, indent=2))
    print(f"[mapping] wrote {out_path}")

    # Checksum the file tree so anyone can verify they got identical output
    h = hashlib.sha256()
    for p in sorted(POSITIVES.rglob("*")):
        if p.is_file():
            h.update(p.relative_to(POSITIVES).as_posix().encode())
            h.update(p.read_bytes())
    for p in sorted(NOISE.rglob("*")):
        if p.is_file():
            h.update(p.relative_to(NOISE).as_posix().encode())
            h.update(p.read_bytes())
    print(f"[checksum] sha256 = {h.hexdigest()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
