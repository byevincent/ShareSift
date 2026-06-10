#!/usr/bin/env python3
"""Walk a built diskforge .img and emit file_list.txt + ground_truth.jsonl.

Uses 7z to list NTFS partition contents — avoids needing root mount.
Cross-references against positives_map.json so each path gets a
verified has_credential label + credential_type + category.

Paths are emitted in UNC backslash form (\\\\corp-fs01\\<rest>) — that's
what real ShareSift sees when scanning a real SMB share, and what
the rule regexes are tuned for. The positives_map.json uses POSIX
form internally (forward slashes); both the lookup key and the
final emitted path are converted to UNC.

Output schema (one record per line in ground_truth.jsonl):

    {
      "path": "\\\\\\\\corp-fs01\\\\Departments\\\\IT\\\\...",
      "has_credential": bool,
      "credential_type": "gpp_cpassword" | ... | null,
      "category": "01_gpp" | "noise:hr_policy" | "noise:stress" | "template_stub",
      "verified": true,
      "source": "diskforge_winshare_v1"
    }
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
from pathlib import Path


# Map category → credential_type for positives. Aligned with the existing
# diskforge_win10 ground_truth schema for sweep compatibility.
# Simulated UNC server prefix prepended to every path. Real share
# scanning hits paths like \\corp-fs01\Departments\HR\..., which is
# the regex form the rule engine is tuned for.
UNC_PREFIX = r"\\corp-fs01"


def to_unc(posix_path: str) -> str:
    """Convert a POSIX-form path from 7z output to UNC backslash form."""
    # Drop leading '/', replace '/' with '\', prepend the UNC prefix.
    rel = posix_path.lstrip("/").replace("/", "\\")
    return f"{UNC_PREFIX}\\{rel}"


CRED_TYPE = {
    "01_gpp": "gpp_cpassword",
    "02_unattend": "windows_install_password",
    "03_cloud_creds": "cloud_cli_credentials",
    "04_ssh_keys": "ssh_private_key",
    "05_keepass": "keepass_database",
    "06_pshistory": "powershell_history",
    "07_browser": "browser_saved_creds",
    "08_appsettings": "db_connection_string",
    "09_wpconfig": "wp_config_db_password",
    "10_cisco": "cisco_config",
    "11_sccm": "sccm_credentials",
    "12_kerberos": "kerberos_keytab",
    "13_filezilla": "filezilla_saved_sites",
    "14_german": "german_credential_filename",
    "15_credname": "credential_filename_keyword",
    "16_cmdset": "cmd_set_credential",
}


def list_image_paths(image: Path) -> list[str]:
    """Run `7z l` on the image and pull out file paths only.

    7z lists files with absolute paths (relative to the partition
    root). We prepend '/' and normalize Windows backslashes — but
    7z already emits forward slashes for NTFS contents on this
    Linux host, so the normalization is mostly defensive.
    """
    out = subprocess.run(
        ["7z", "l", "-slt", str(image)],
        capture_output=True, text=True, check=True,
    )
    paths: list[str] = []
    current_path: str | None = None
    is_dir = False
    for line in out.stdout.splitlines():
        if line.startswith("Path = "):
            current_path = line[len("Path = "):]
            is_dir = False
        elif line.startswith("Attributes = ") and "D" in line.split("=", 1)[1]:
            is_dir = True
        elif line == "" and current_path is not None:
            if not is_dir:
                p = current_path.replace("\\", "/")
                if not p.startswith("/"):
                    p = "/" + p
                paths.append(p)
            current_path = None
            is_dir = False
    return paths


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", type=Path, required=True)
    parser.add_argument("--mapping", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    mapping = json.loads(args.mapping.read_text())
    # Lookup keys are UNC-form so they match the converted emitted paths.
    positive_lookup = {
        to_unc(e["target"]): (True, CRED_TYPE.get(e["category"], "unknown"), e["category"])
        for e in mapping["positives"]
    }
    noise_lookup = {
        to_unc(e["target"]): (False, None, f"noise:{e['class']}")
        for e in mapping["noise"]
    }

    raw_paths = list_image_paths(args.image)
    paths = sorted(set(to_unc(p) for p in raw_paths))

    args.output.mkdir(parents=True, exist_ok=True)
    file_list = args.output / "file_list.txt"
    gt_path = args.output / "ground_truth.jsonl"

    file_list.write_text("\n".join(paths) + "\n")

    written = 0
    with gt_path.open("w") as fh:
        for p in paths:
            if p in positive_lookup:
                has_cred, ctype, cat = positive_lookup[p]
            elif p in noise_lookup:
                has_cred, ctype, cat = noise_lookup[p]
            else:
                # Path came from the windows10 OS template (System32,
                # NTUSER.DAT, etc) — neither in positives nor noise map.
                has_cred, ctype, cat = False, None, "template_stub"
            rec = {
                "path": p,
                "has_credential": has_cred,
                "credential_type": ctype,
                "category": cat,
                "verified": True,
                "source": "diskforge_winshare_v1",
            }
            fh.write(json.dumps(rec) + "\n")
            written += 1

    print(f"[file_list]   {len(paths)} paths → {file_list}")
    print(f"[ground_truth] {written} records → {gt_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
