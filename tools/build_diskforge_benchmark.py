r"""v0.29: build the DiskForge synthetic Windows 10 share benchmark.

Reads a DiskForge manifest + the file list extracted from the
generated disk image, and emits a labeled benchmark in the v0.14
MSF3 schema. Positives are exactly the manifest's ``add_files``
target paths (planted at documented Windows credential locations
sourced from MITRE ATT&CK T1552 + Snaffler default rules); negatives
are every other path in Stauffer's windows10 template.

The ground truth is by construction — the manifest IS the answer key.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

# Credential-type label per planted path. DiskForge's populate
# behavior is inconsistent: when a target directory is shared with
# other add_files entries (v0.31's bigger image), the source file
# lands at ``<target>/<source_basename>``; when the target is unique
# to one entry (v0.29), the target itself becomes a directory and
# the file is nested inside. We label BOTH path shapes so the
# benchmark builder works regardless of how DiskForge resolved each
# entry.
_PLANT_LABELS: dict[str, str] = {
    # v0.31 bare paths
    "/Windows/Panther/unattend.xml": "windows_install_password",
    "/inetpub/wwwroot/web.config": "iis_connection_string",
    "/ProgramData/Microsoft/Group Policy/History/Preferences/Groups/Groups.xml": "gpp_cpassword",
    "/Users/Administrator/Documents/passwords.kdbx": "keepass_database",
    "/Users/Administrator/.aws/credentials": "aws_cli_credentials",
    "/Users/Administrator/.ssh/id_rsa": "ssh_private_key",
    "/Users/Administrator/.pypirc/pypirc": "pypi_upload_token",
    "/Users/Administrator/AppData/Roaming/Microsoft/Windows/PowerShell/PSReadLine/ConsoleHost_history.txt": "powershell_history",
    "/inetpub/wordpress/wp-config.php": "wp_config_db_password",
    "/inetpub/wordpress/wp-config.php.bak": "wp_config_db_password",
    "/Users/Administrator/Documents/server.ppk": "putty_ppk_unencrypted",
    "/Users/Administrator/.config/gh/hosts.yml": "gh_cli_oauth_token",
    # v0.34 GCP SA JSON plant — end-to-end smoke for v0.32 extractor +
    # v0.33 live verifier on a planted disk.
    "/Users/Administrator/Documents/gcp_service_account.json": "gcp_service_account_json",
    # v0.29 nested-fallback variants (kept so the v0.29 build still labels)
    "/Windows/Panther/Unattend.xml/unattend.xml": "windows_install_password",
    "/inetpub/wwwroot/web.config/web.config": "iis_connection_string",
    "/ProgramData/Microsoft/Group Policy/History/Preferences/Groups/Groups.xml/Groups.xml": "gpp_cpassword",
    "/Users/Administrator/Documents/passwords.kdbx/passwords.kdbx": "keepass_database",
    "/Users/Administrator/.aws/credentials/credentials": "aws_cli_credentials",
    "/Users/Administrator/.ssh/id_rsa/id_rsa": "ssh_private_key",
    "/Users/Administrator/AppData/Roaming/Microsoft/Windows/PowerShell/PSReadLine/ConsoleHost_history.txt/ConsoleHost_history.txt": "powershell_history",
    "/inetpub/wordpress/wp-config.php/wp-config.php": "wp_config_db_password",
    "/inetpub/wordpress/wp-config.php.bak/wp-config.php.bak": "wp_config_db_password",
    "/Users/Administrator/Documents/server.ppk/server.ppk": "putty_ppk_unencrypted",
    "/Users/Administrator/.config/gh/hosts.yml/hosts.yml": "gh_cli_oauth_token",
}


def _read_manifest_targets(manifest_path: Path) -> list[str]:
    """Returns the post-build paths the manifest produced — i.e.,
    ``<target>/<source_basename>`` per add_files entry."""
    data = json.loads(manifest_path.read_text(encoding="utf-8"))
    targets: list[str] = []
    for disk in data.get("disks", []):
        for part in disk.get("partitions", []):
            for entry in part.get("populate", {}).get("add_files", []):
                t = entry.get("target", "")
                src = entry.get("source", "")
                if t and src:
                    src_basename = src.rsplit("/", 1)[-1]
                    targets.append(f"{t}/{src_basename}")
    return targets


def _normalize_path(p: str) -> str:
    """Normalize a path from the disk-image listing to compare to the
    manifest targets. DiskForge writes NT-style paths in the image;
    the listing comes back as POSIX-style relative paths."""
    p = p.strip().replace("\\", "/")
    if not p.startswith("/"):
        p = "/" + p
    return p


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument(
        "--manifest",
        type=Path,
        required=True,
        help="DiskForge manifest.json that drove the disk image build.",
    )
    p.add_argument(
        "--file-list",
        type=Path,
        required=True,
        help="Plain text file with one path per line, extracted from the generated disk image.",
    )
    p.add_argument(
        "--output-dir",
        type=Path,
        default=REPO_ROOT / "data" / "external" / "diskforge_win10",
    )
    args = p.parse_args(argv)

    # ``_PLANT_LABELS`` is the SOURCE OF TRUTH for positives. The manifest
    # may also contain decoy entries (added to dilute positive density to
    # realistic levels); those are NEGATIVE by construction even though
    # they appear in ``add_files``. Only paths that show up in
    # ``_PLANT_LABELS`` get the has_credential=True label.
    positive_paths = set(_PLANT_LABELS.keys())

    all_paths = [
        _normalize_path(line)
        for line in args.file_list.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    # De-dupe + stable sort for reproducibility.
    all_paths = sorted(set(all_paths))

    args.output_dir.mkdir(parents=True, exist_ok=True)
    records: list[dict] = []
    for path in all_paths:
        is_positive = path in positive_paths
        cred_type = _PLANT_LABELS.get(path)
        records.append({
            "path": path,
            "has_credential": is_positive,
            "credential_type": cred_type if is_positive else None,
            "verified": True,
            "source": "diskforge_manifest_positive" if is_positive
                      else "diskforge_template_or_decoy",
        })

    (args.output_dir / "file_list.txt").write_text(
        "\n".join(r["path"] for r in records) + "\n", encoding="utf-8"
    )
    with (args.output_dir / "ground_truth.jsonl").open("w", encoding="utf-8") as f:
        for r in records:
            f.write(json.dumps(r) + "\n")

    n_pos = sum(1 for r in records if r["has_credential"])
    print(
        f"wrote {len(records)} records to {args.output_dir}; "
        f"positives = {n_pos}, _PLANT_LABELS expected = {len(positive_paths) // 2}"
    )
    if n_pos != len(positive_paths):
        missing = sorted(positive_paths - {_normalize_path(p) for p in all_paths})
        print(f"  WARN: {len(missing)} planted target(s) not found in file list:")
        for m in missing[:5]:
            print(f"    {m}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
