#!/usr/bin/env python3
"""
tools/build_msf3_ground_truth.py

Scaffolds the ground-truth JSONL for Metasploitable 3 evaluation.

Three data sources are merged:
  1. Hardcoded known-credential paths from Metasploitable 3 documentation
     (these are the intentional vuln files Rapid7 ships with the box)
  2. Paths flagged by Truffler or Snaffler that aren't yet in GT
     (these get stubbed with has_credential=null — manual verification required)
  3. Optional: a manually edited supplement file

Usage:
    # Bootstrap from docs only
    uv run python tools/build_msf3_ground_truth.py \
        --vm-ip 192.168.56.101 \
        --output data/external/metasploitable3/ground_truth.jsonl

    # Also add stubs for all Truffler/Snaffler-flagged paths
    uv run python tools/build_msf3_ground_truth.py \
        --vm-ip 192.168.56.101 \
        --truffler-stage1 reports/metasploitable3_path_predictions.jsonl \
        --snaffler-output /tmp/snaffler_msf3.tsv \
        --output data/external/metasploitable3/ground_truth.jsonl

    # Merge in a supplement you edited manually
    uv run python tools/build_msf3_ground_truth.py \
        --vm-ip 192.168.56.101 \
        --supplement data/external/metasploitable3/ground_truth_manual.jsonl \
        --output data/external/metasploitable3/ground_truth.jsonl

Output format (one JSON per line):
    {
        "path": "\\\\<VM_IP>\\C$\\...",
        "has_credential": true | false | null,
        "verified": true | false,
        "credential_type": "plaintext_password" | "hash" | "config_secret" | ... | null,
        "source": "metasploitable3_docs" | "truffler_flag" | "snaffler_flag" | "manual",
        "notes": "..."
    }

    has_credential=null means the stub hasn't been verified yet.
    Run the output through `jq 'select(.has_credential == null)'` to see the
    manual-verification queue.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path
from typing import Any


# ---------------------------------------------------------------------------
# Known credential-bearing files from Metasploitable 3 documentation
# https://github.com/rapid7/metasploitable3/wiki
#
# IMPORTANT: These are TEMPLATES — the <VM_IP> placeholder is replaced at
# runtime with the actual --vm-ip argument.
#
# Sources:
#   - metasploitable3 wiki / README
#   - Services: ManageEngine, ElasticSearch, Jenkins, phpMyAdmin, WampServer,
#     FileZilla FTP, Tomcat, MySQL, UnrealIRCd, Backdoors
#   - Intentional files left on disk for pen-testing exercises
# ---------------------------------------------------------------------------

_KNOWN_CRED_TEMPLATE: list[dict] = [
    # --- Windows credential stores ---
    {
        "path_template": "\\\\{ip}\\C$\\Windows\\System32\\config\\SAM",
        "has_credential": True,
        "credential_type": "hash",
        "source": "metasploitable3_docs",
        "notes": "Windows SAM hive — NTLM hashes for local accounts",
    },
    {
        "path_template": "\\\\{ip}\\C$\\Windows\\System32\\config\\SYSTEM",
        "has_credential": True,
        "credential_type": "hash",
        "source": "metasploitable3_docs",
        "notes": "SYSTEM hive needed to decrypt SAM (syskey/bootkey)",
    },
    {
        "path_template": "\\\\{ip}\\C$\\Windows\\NTDS\\ntds.dit",
        "has_credential": True,
        "credential_type": "hash",
        "source": "metasploitable3_docs",
        "notes": "AD DS database — present if DC role installed",
    },
    # --- Intentional plaintext cred files (pedagogical) ---
    {
        "path_template": "\\\\{ip}\\C$\\Users\\Administrator\\Desktop\\credentials.txt",
        "has_credential": True,
        "credential_type": "plaintext_password",
        "source": "metasploitable3_docs",
        "notes": "Intentional credential file left on Administrator desktop",
    },
    {
        "path_template": "\\\\{ip}\\C$\\Users\\vagrant\\Desktop\\credentials.txt",
        "has_credential": True,
        "credential_type": "plaintext_password",
        "source": "metasploitable3_docs",
        "notes": "Credential file on vagrant user desktop",
    },
    # --- WampServer / Apache config ---
    {
        "path_template": "\\\\{ip}\\C$\\wamp\\apps\\phpmyadmin3.4.10.1\\config.inc.php",
        "has_credential": True,
        "credential_type": "config_secret",
        "source": "metasploitable3_docs",
        "notes": "phpMyAdmin config with MySQL root password",
    },
    {
        "path_template": "\\\\{ip}\\C$\\wamp\\bin\\mysql\\mysql5.5.24\\my.ini",
        "has_credential": True,
        "credential_type": "config_secret",
        "source": "metasploitable3_docs",
        "notes": "MySQL config file — may contain auth details",
    },
    {
        "path_template": "\\\\{ip}\\C$\\wamp\\www\\wordpress\\wp-config.php",
        "has_credential": True,
        "credential_type": "config_secret",
        "source": "metasploitable3_docs",
        "notes": "WordPress wp-config.php with DB_PASSWORD",
    },
    # --- Jenkins ---
    {
        "path_template": "\\\\{ip}\\C$\\Program Files (x86)\\Jenkins\\secrets\\master.key",
        "has_credential": True,
        "credential_type": "key_material",
        "source": "metasploitable3_docs",
        "notes": "Jenkins master.key — used to decrypt stored credentials",
    },
    {
        "path_template": "\\\\{ip}\\C$\\Program Files (x86)\\Jenkins\\secrets\\hudson.util.Secret",
        "has_credential": True,
        "credential_type": "key_material",
        "source": "metasploitable3_docs",
        "notes": "Jenkins Hudson secret — credential encryption key",
    },
    {
        "path_template": "\\\\{ip}\\C$\\Program Files (x86)\\Jenkins\\credentials.xml",
        "has_credential": True,
        "credential_type": "encrypted_credential",
        "source": "metasploitable3_docs",
        "notes": "Jenkins stored credentials (encrypted with master.key)",
    },
    {
        "path_template": "\\\\{ip}\\C$\\Program Files (x86)\\Jenkins\\users\\admin\\config.xml",
        "has_credential": True,
        "credential_type": "hash",
        "source": "metasploitable3_docs",
        "notes": "Jenkins admin user config — bcrypt or SHA-256 hash",
    },
    # --- FileZilla FTP ---
    {
        "path_template": "\\\\{ip}\\C$\\Program Files (x86)\\FileZilla Server\\FileZilla Server.xml",
        "has_credential": True,
        "credential_type": "plaintext_password",
        "source": "metasploitable3_docs",
        "notes": "FileZilla FTP server config — user accounts with passwords",
    },
    # --- ManageEngine ---
    {
        "path_template": "\\\\{ip}\\C$\\ManageEngine\\AppManager12\\working\\conf\\AMserver.properties",
        "has_credential": True,
        "credential_type": "config_secret",
        "source": "metasploitable3_docs",
        "notes": "ManageEngine AppManager DB credentials",
    },
    # --- Tomcat ---
    {
        "path_template": "\\\\{ip}\\C$\\Program Files\\Apache Software Foundation\\Tomcat 8.0\\conf\\tomcat-users.xml",
        "has_credential": True,
        "credential_type": "plaintext_password",
        "source": "metasploitable3_docs",
        "notes": "Tomcat manager credentials in tomcat-users.xml",
    },
    # --- SSH keys ---
    {
        "path_template": "\\\\{ip}\\C$\\Users\\vagrant\\.ssh\\id_rsa",
        "has_credential": True,
        "credential_type": "private_key",
        "source": "metasploitable3_docs",
        "notes": "Vagrant default SSH private key",
    },
    {
        "path_template": "\\\\{ip}\\C$\\Users\\Administrator\\.ssh\\id_rsa",
        "has_credential": True,
        "credential_type": "private_key",
        "source": "metasploitable3_docs",
        "notes": "Administrator SSH private key (if present)",
    },
    # --- IIS config ---
    {
        "path_template": "\\\\{ip}\\C$\\Windows\\System32\\inetsrv\\config\\applicationHost.config",
        "has_credential": True,
        "credential_type": "config_secret",
        "source": "metasploitable3_docs",
        "notes": "IIS applicationHost.config — may contain basic auth credentials",
    },
    # --- Scheduled tasks / scripts with embedded creds ---
    {
        "path_template": "\\\\{ip}\\C$\\Users\\Administrator\\Documents\\passwords.txt",
        "has_credential": True,
        "credential_type": "plaintext_password",
        "source": "metasploitable3_docs",
        "notes": "Intentional password file in Administrator Documents",
    },
]

# Files that are definitively NOT credential-bearing (helps bound FP evaluation)
_KNOWN_CLEAN_TEMPLATE: list[dict] = [
    {
        "path_template": "\\\\{ip}\\C$\\Windows\\System32\\drivers\\etc\\hosts",
        "has_credential": False,
        "credential_type": None,
        "source": "metasploitable3_docs",
        "notes": "hosts file — no credentials",
    },
    {
        "path_template": "\\\\{ip}\\C$\\Windows\\win.ini",
        "has_credential": False,
        "credential_type": None,
        "source": "metasploitable3_docs",
        "notes": "Windows win.ini — no credentials",
    },
    {
        "path_template": "\\\\{ip}\\vagrant\\readme.md",
        "has_credential": False,
        "credential_type": None,
        "source": "metasploitable3_docs",
        "notes": "Vagrant readme — no credentials",
    },
]


# ---------------------------------------------------------------------------
# Snaffler output format parser
#
# Snaffler emits one line per hit in the following bracket-delimited shape
# (NOT tab-separated — the .tsv extension on the output file is misleading):
#
#   [HOST\user@machine] YYYY-MM-DD HH:MM:SSZ [File] {Tier}<Rule|R|Pattern|Size|Mtime>(Path) match_context
#
# Example:
#   [METASPLOITABLE3\vagrant@machine] 2026-06-03 17:27:59Z [File]
#   {Red}<KeepPassOrKeyInCode|R|passw?o?r?d\s*=\s*[\'\"][^\'\"]....|2.4kB|2015-10-07 13:32:38Z>
#   (C:\ManageEngine\DesktopCentral_Server\bin\resetPWD.xml) ...match...
#
# Paths are local (C:\...) when Snaffler ran on the VM. We convert them to
# the share-style \\<vm_ip>\C$\... so they match Truffler-flagged paths in
# the same ground_truth file.
# ---------------------------------------------------------------------------

_SNAFFLER_LINE_RE = re.compile(
    r'^\[[^\]]+\] \S+ \S+ \[File\] '
    r'\{(?P<tier>\w+)\}'
    r'<(?P<rule>[^|]+)\|R\|(?P<pattern>.*?)\|(?P<size>[^|]+)\|(?P<mtime>[^>]+)>'
    r'\((?P<path>[^)]+)\)'
    r'(?: (?P<match>.*))?$'
)

_DRIVE_RE = re.compile(r'^([A-Za-z]):\\')


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _norm(path: str) -> str:
    return path.replace("/", "\\").strip().lower()


def _render_template(template: str, vm_ip: str) -> str:
    return template.replace("{ip}", vm_ip)


def _local_to_share(path: str, vm_ip: str) -> str:
    """Convert local Windows path (C:\\...) to share-style (\\\\<vm_ip>\\C$\\...).

    Leaves UNC paths (\\\\...) untouched.
    """
    if path.startswith("\\\\"):
        return path
    m = _DRIVE_RE.match(path)
    if m:
        drive = m.group(1).upper()
        return f"\\\\{vm_ip}\\{drive}$\\" + path[3:]
    return path


def _load_jsonl(path: str) -> list[dict]:
    if not os.path.exists(path):
        return []
    records = []
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError:
                pass
    return records


def _load_snaffler_hits(tsv_path: str, vm_ip: str) -> list[dict]:
    """Parse Snaffler's bracket-delimited output into structured hit records.

    Returns one dict per hit with: path (share-style), tier, rule, match,
    size, mtime. Skips lines that don't match the expected format.
    """
    hits: list[dict] = []
    if not os.path.exists(tsv_path) or tsv_path in ("/dev/null", "nul"):
        return hits
    n_parsed = 0
    n_skipped = 0
    with open(tsv_path, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.rstrip("\n").rstrip("\r")
            if not line or not line.startswith("["):
                continue
            m = _SNAFFLER_LINE_RE.match(line)
            if not m:
                n_skipped += 1
                continue
            n_parsed += 1
            hits.append({
                "path": _local_to_share(m["path"], vm_ip),
                "tier": m["tier"],
                "rule": m["rule"],
                "match": (m["match"] or "").strip(),
                "size": m["size"],
                "mtime": m["mtime"],
            })
    if n_skipped:
        print(
            f"[warn] Snaffler parser: {n_parsed} parsed, {n_skipped} skipped "
            f"(unrecognized lines — check format)",
            file=sys.stderr,
        )
    return hits


# ---------------------------------------------------------------------------
# Core build
# ---------------------------------------------------------------------------

def build(
    vm_ip: str,
    output_path: str,
    truffler_stage1: str | None = None,
    snaffler_tsv: str | None = None,
    supplement: str | None = None,
    overwrite_verified: bool = False,
) -> None:
    # Start with a dict keyed by normalised path so merges deduplicate
    gt: dict[str, dict] = {}

    # 1. Known credential-bearing files from docs
    for tmpl in _KNOWN_CRED_TEMPLATE:
        path = _render_template(tmpl["path_template"], vm_ip)
        rec = {
            "path": path,
            "has_credential": tmpl["has_credential"],
            "verified": False,  # start unverified — set to true after manual check
            "credential_type": tmpl.get("credential_type"),
            "source": tmpl["source"],
            "notes": tmpl.get("notes", ""),
        }
        gt[_norm(path)] = rec

    # 2. Known clean files from docs
    for tmpl in _KNOWN_CLEAN_TEMPLATE:
        path = _render_template(tmpl["path_template"], vm_ip)
        rec = {
            "path": path,
            "has_credential": False,
            "verified": False,
            "credential_type": None,
            "source": tmpl["source"],
            "notes": tmpl.get("notes", ""),
        }
        gt[_norm(path)] = rec

    print(f"[info] {len(gt)} records from documentation templates", file=sys.stderr)

    # 3. Stubs for Truffler-flagged paths not yet in GT
    if truffler_stage1:
        stage1_records = _load_jsonl(truffler_stage1)
        added = 0
        for rec in stage1_records:
            path = rec.get("path", "")
            if not path:
                continue
            norm_p = _norm(path)
            if norm_p not in gt:
                gt[norm_p] = {
                    "path": path,
                    "has_credential": None,   # <-- requires manual verification
                    "verified": False,
                    "credential_type": None,
                    "source": "truffler_flag",
                    "path_tier": rec.get("path_tier"),
                    "notes": "stub — manual verification required",
                }
                added += 1
        print(f"[info] +{added} stubs from Truffler stage1 flags", file=sys.stderr)

    # 4. Stubs for Snaffler-flagged paths not yet in GT
    if snaffler_tsv:
        snaffler_hits = _load_snaffler_hits(snaffler_tsv, vm_ip)
        added = 0
        enriched = 0
        for hit in snaffler_hits:
            norm_p = _norm(hit["path"])
            if norm_p not in gt:
                gt[norm_p] = {
                    "path": hit["path"],
                    "has_credential": None,
                    "verified": False,
                    "credential_type": None,
                    "source": "snaffler_flag",
                    "snaffler_tier": hit["tier"],
                    "snaffler_rule": hit["rule"],
                    "snaffler_match": hit["match"][:500],  # cap snippet for JSONL sanity
                    "notes": "stub — manual verification required",
                }
                added += 1
            else:
                # Enrich existing record with Snaffler signal (useful when a doc
                # template OR a Truffler flag also got a Snaffler hit)
                existing = gt[norm_p]
                if "snaffler_tier" not in existing:
                    existing["snaffler_tier"] = hit["tier"]
                    existing["snaffler_rule"] = hit["rule"]
                    existing["snaffler_match"] = hit["match"][:500]
                    enriched += 1
        msg = f"[info] +{added} stubs from Snaffler flags"
        if enriched:
            msg += f" ({enriched} enriched existing records)"
        print(msg, file=sys.stderr)

    # 5. Merge supplement (manual edits take priority)
    if supplement:
        supplement_records = _load_jsonl(supplement)
        for rec in supplement_records:
            path = rec.get("path", "")
            if not path:
                continue
            norm_p = _norm(path)
            existing = gt.get(norm_p, {})
            if overwrite_verified or not existing.get("verified"):
                gt[norm_p] = rec
                gt[norm_p]["source"] = "manual"
        print(f"[info] merged {len(supplement_records)} records from supplement", file=sys.stderr)

    # Write output
    os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
    records = sorted(gt.values(), key=lambda r: r["path"])
    unverified = sum(1 for r in records if not r.get("verified"))
    null_cred = sum(1 for r in records if r.get("has_credential") is None)
    positives = sum(1 for r in records if r.get("has_credential") is True)

    with open(output_path, "w", encoding="utf-8") as fh:
        for rec in records:
            fh.write(json.dumps(rec) + "\n")

    print(
        f"[done] wrote {len(records)} records → {output_path}\n"
        f"       positives={positives}  "
        f"unverified={unverified}  "
        f"needs-manual={null_cred}",
        file=sys.stderr,
    )

    if null_cred > 0:
        print(
            f"\n[action] {null_cred} paths need manual verification.\n"
            f"  Filter them with:\n"
            f"    jq 'select(.has_credential == null)' {output_path}\n"
            f"  After inspecting, edit has_credential and set verified=true,\n"
            f"  then re-run with --supplement to merge your edits.",
            file=sys.stderr,
        )


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Build Metasploitable 3 ground-truth JSONL from documentation + tool outputs.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument(
        "--vm-ip", required=True,
        help="Metasploitable 3 VM IP (e.g. 192.168.56.101)",
    )
    p.add_argument(
        "--output", required=True,
        help="Output JSONL path for ground truth",
    )
    p.add_argument(
        "--truffler-stage1",
        help="JSONL from `truffler score-paths` — adds stubs for flagged paths",
    )
    p.add_argument(
        "--snaffler-output",
        help="Snaffler TSV — adds stubs for flagged paths",
    )
    p.add_argument(
        "--supplement",
        help="Manual JSONL supplement to merge (has_credential values here override stubs)",
    )
    p.add_argument(
        "--overwrite-verified", action="store_true",
        help="Let supplement overwrite already-verified records (default: skip verified)",
    )
    return p


def main() -> None:
    args = _build_parser().parse_args()
    build(
        vm_ip=args.vm_ip,
        output_path=args.output,
        truffler_stage1=args.truffler_stage1,
        snaffler_tsv=args.snaffler_output,
        supplement=args.supplement,
        overwrite_verified=args.overwrite_verified,
    )


if __name__ == "__main__":
    main()
