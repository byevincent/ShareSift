"""Linux-shaped rule pack baseline (Snaffler-discipline analog for Linux).

Tier-1 audit item from the 2026-05-31 v0.5 research pass. The Windows
side has a Snaffler-blind benchmark and a clear "Snaffler catches 41.5%"
baseline; the Linux side has neither. This module is a hand-curated
high-confidence regex rule pack mimicking Snaffler's TOML discipline
but for Linux/Unix paths — it generates the analog of "what fraction
of Linux juicy paths would a rule-based system catch?" so the Linux
model's 0.97 PR-AUC has a meaningful baseline.

Rules are intentionally high-precision (Snaffler's posture). Wider
"contains /etc/" style patterns are deliberately omitted — they have
high recall but low precision, and the Snaffler equivalent doesn't
do that either.

Output:
* For each rule: how many juicy paths it catches in the labeled Linux
  corpus (recall contribution).
* Overall: rule-pack precision, recall, F1 on the Linux corpus.
* A "Linux-rule-blind benchmark" — records the rule pack doesn't
  match — analogous to the Snaffler-blind set.

The shipped Linux rule pack here is NOT meant to be used as Truffler's
production triage layer; the ML model strictly dominates it. It's
purely for headline-comparison rigor.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent


# Format: (regex, tier, category, description)
# Each pattern uses re.IGNORECASE.
_LINUX_RULES: list[tuple[str, str, str, str]] = [
    # /etc/shadow family
    (r"^/etc/(g)?shadow(-|\.bak|\.backup)?$", "Black", "ssh_credentials", "Linux password hash file"),
    # /etc/sudoers family
    (r"^/etc/sudoers(\.d/.*|\.bak|\.dpkg-old)?$", "Red", "ssh_credentials", "sudoers privilege config"),
    # /etc/passwd family (lower tier — no hashes since shadow split)
    (r"^/etc/(passwd|group)(-|\.bak)?$", "Yellow", "ssh_credentials", "Unix account enumeration"),
    # SSH private keys (user-level)
    (r"/\.ssh/(id_rsa|id_ed25519|id_ecdsa|id_dsa|id_xmss)$", "Black", "ssh_credentials", "User SSH private key"),
    # SSH authorized_keys / known_hosts
    (r"/\.ssh/authorized_keys2?$", "Red", "ssh_credentials", "Authorized SSH keys"),
    (r"/\.ssh/known_hosts2?$", "Red", "ssh_credentials", "Known SSH hosts (internal network intel)"),
    (r"/\.ssh/config$", "Yellow", "ssh_credentials", "User SSH client config"),
    # SSH host keys
    (r"^/etc/ssh/ssh_host_[a-z0-9_]+_key$", "Black", "ssh_credentials", "Host SSH private key"),
    (r"^/etc/ssh/ssh_host_[a-z0-9_]+_key\.pub$", "Yellow", "ssh_credentials", "Host SSH public key"),
    (r"^/etc/ssh/sshd_config$", "Yellow", "ssh_credentials", "SSH daemon config"),
    # AWS credentials
    (r"/\.aws/credentials$", "Black", "cloud_credentials", "AWS credentials file"),
    (r"/\.aws/config$", "Yellow", "cloud_credentials", "AWS config"),
    # GCP / Kubernetes
    (r"/\.kube/config$", "Black", "cloud_credentials", "Kubernetes credentials"),
    (r"^/etc/kubernetes/admin\.conf$", "Black", "cloud_credentials", "Kubernetes admin config"),
    (r"/\.config/gcloud/.*credentials.*\.(json|db)$", "Black", "cloud_credentials", "GCP credentials"),
    (r"/\.azure/(credentials|accessTokens\.json)$", "Black", "cloud_credentials", "Azure credentials"),
    # Docker config
    (r"/\.docker/config\.json$", "Red", "scm_cicd_tokens", "Docker registry credentials"),
    # netrc
    (r"/\.netrc$", "Red", "embedded_secrets", "netrc plaintext FTP/HTTP credentials"),
    # Shell histories
    (r"/\.(bash|zsh|sh|fish|ksh)_history$", "Red", "embedded_secrets", "Shell history with potential creds"),
    # NetworkManager + WireGuard
    (r"^/etc/NetworkManager/system-connections/.+\.nmconnection$", "Red", "embedded_secrets", "WiFi/VPN credentials"),
    (r"^/etc/wireguard/.+\.conf$", "Red", "embedded_secrets", "WireGuard private key config"),
    # OpenVPN
    (r"^/etc/openvpn/.+\.key$", "Black", "private_keys_x509", "OpenVPN private key"),
    # SSL private keys + certs
    (r"^/etc/(letsencrypt/live|ssl/private)/.+/privkey\.pem$", "Black", "private_keys_x509", "Let's Encrypt private key"),
    (r"^/etc/ssl/private/.+\.key$", "Black", "private_keys_x509", "TLS private key in private dir"),
    (r"^/etc/(nginx|apache2|httpd)/.+\.(key|priv\.pem)$", "Black", "private_keys_x509", "Web server private key"),
    # Database files
    (r"^/var/lib/(mysql|postgresql|mongo|redis|cassandra)/", "Red", "db_files", "Database data directory"),
    # Application secrets
    (r"^/opt/.+/\.env(\..+)?$", "Red", "embedded_secrets", "Application env file with secrets"),
    (r"^/srv/.+/\.env(\..+)?$", "Red", "embedded_secrets", "Application env file with secrets"),
    # Jenkins
    (r"^/var/lib/jenkins/secrets(/.+)?$", "Red", "embedded_secrets", "Jenkins secrets directory"),
    (r"^/var/lib/jenkins/secrets/master\.key$", "Black", "embedded_secrets", "Jenkins master encryption key"),
    # Postfix / mail credentials
    (r"^/etc/postfix/(sasl/)?sasl_passwd$", "Red", "embedded_secrets", "Postfix SMTP relay credentials"),
    # /var/log auth
    (r"^/var/log/(auth\.log|secure)(\.\d+(\.gz)?)?$", "Yellow", "embedded_secrets", "Auth log (may contain creds)"),
    # RANCID / network device
    (r"^/usr/local/etc/clogin\.conf$", "Red", "network_device", "RANCID clogin credentials"),
    (r"/\.cloginrc$", "Red", "network_device", "RANCID cloginrc credentials"),
    # KeePass / 1Password
    (r"\.kdbx?$", "Black", "credential_containers", "KeePass database"),
    (r"\.opvault$", "Black", "credential_containers", "1Password vault"),
    # Generic .pem private keys (not pub, not crt)
    (r"\.(key|priv\.pem)$", "Black", "private_keys_x509", "Private key file by extension"),
    # PKCS12
    (r"\.(p12|pfx)$", "Black", "private_keys_x509", "PKCS#12 cert+key bundle"),
]


def _build_compiled() -> list[dict]:
    """Compile rules once for reuse across many path scans."""
    out = []
    for pattern, tier, category, desc in _LINUX_RULES:
        out.append(
            {
                "pattern": pattern,
                "compiled": re.compile(pattern, re.IGNORECASE),
                "tier": tier,
                "category": category,
                "description": desc,
            }
        )
    return out


def classify_path(path: str, rules: list[dict] | None = None) -> dict | None:
    """Return the first matching rule's verdict, or None if no match."""
    if rules is None:
        rules = _build_compiled()
    for rule in rules:
        if rule["compiled"].search(path):
            return {
                "matched_pattern": rule["pattern"],
                "tier": rule["tier"],
                "category": rule["category"],
                "description": rule["description"],
            }
    return None


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--linux-corpus",
        type=Path,
        default=REPO_ROOT / "data" / "eval" / "eval_set_claude_linux_with_seed.jsonl",
    )
    parser.add_argument(
        "--blind-output",
        type=Path,
        default=REPO_ROOT / "data" / "eval" / "linux_rule_blind_benchmark.jsonl",
        help="Write a Linux-rule-blind benchmark (records the rule pack didn't match).",
    )
    parser.add_argument(
        "--report-output",
        type=Path,
        default=REPO_ROOT / "reports" / "linux_rules_baseline.json",
    )
    parser.add_argument(
        "--blind-sample",
        type=int,
        default=500,
        help="Sample size for the blind benchmark, stratified by label.",
    )
    parser.add_argument("--seed", type=int, default=2026)
    args = parser.parse_args()

    records = [
        json.loads(line)
        for line in args.linux_corpus.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    print(f"Linux corpus: {len(records)} records", file=sys.stderr)

    rules = _build_compiled()

    matched: list[dict] = []
    unmatched: list[dict] = []
    per_rule_hits: dict[str, dict] = {
        rule["pattern"]: {
            "pattern": rule["pattern"],
            "description": rule["description"],
            "tier": rule["tier"],
            "category": rule["category"],
            "n_matched": 0,
            "n_juicy_matched": 0,
            "sample_juicy_paths": [],
            "sample_non_juicy_paths": [],
        }
        for rule in rules
    }

    for rec in records:
        verdict = classify_path(rec["path"], rules)
        if verdict is None:
            unmatched.append(rec)
            continue
        matched.append({**rec, "rule_verdict": verdict})
        slot = per_rule_hits[verdict["matched_pattern"]]
        slot["n_matched"] += 1
        if rec["label"] == "juicy":
            slot["n_juicy_matched"] += 1
            if len(slot["sample_juicy_paths"]) < 5:
                slot["sample_juicy_paths"].append(rec["path"])
        else:
            if len(slot["sample_non_juicy_paths"]) < 5:
                slot["sample_non_juicy_paths"].append(rec["path"])

    n_total = len(records)
    n_juicy = sum(1 for r in records if r["label"] == "juicy")
    n_not_juicy = n_total - n_juicy

    # Rule-pack precision/recall (treat matched as "predicted juicy",
    # comparing against the "label == juicy" ground truth).
    n_matched_juicy = sum(1 for r in matched if r["label"] == "juicy")
    n_matched_not_juicy = sum(1 for r in matched if r["label"] != "juicy")
    rule_precision = n_matched_juicy / len(matched) if matched else 0.0
    rule_recall = n_matched_juicy / n_juicy if n_juicy else 0.0
    rule_f1 = (
        2 * rule_precision * rule_recall / (rule_precision + rule_recall + 1e-12)
    )

    # Linux-rule-blind benchmark: 500 records stratified by label from the unmatched set.
    import random as _random

    rng = _random.Random(args.seed)
    blind_juicy = [r for r in unmatched if r["label"] == "juicy"]
    blind_not_juicy = [r for r in unmatched if r["label"] != "juicy"]
    print(
        f"Unmatched (Linux-rule-blind): {len(blind_juicy)} juicy / "
        f"{len(blind_not_juicy)} not_juicy",
        file=sys.stderr,
    )
    n_blind_each = min(args.blind_sample // 2, len(blind_juicy), len(blind_not_juicy))
    blind_sample = (
        rng.sample(blind_juicy, n_blind_each) + rng.sample(blind_not_juicy, n_blind_each)
    )
    rng.shuffle(blind_sample)

    args.blind_output.parent.mkdir(parents=True, exist_ok=True)
    with args.blind_output.open("w", encoding="utf-8") as f:
        for rec in blind_sample:
            f.write(json.dumps(rec) + "\n")
    print(
        f"Wrote {len(blind_sample)} blind-benchmark records to "
        f"{args.blind_output.relative_to(REPO_ROOT)}",
        file=sys.stderr,
    )

    report = {
        "version": "v0.5",
        "generated": "2026-05-31",
        "linux_corpus": str(args.linux_corpus.relative_to(REPO_ROOT)),
        "n_records": n_total,
        "n_juicy": n_juicy,
        "n_not_juicy": n_not_juicy,
        "n_rules": len(rules),
        "summary": {
            "n_matched": len(matched),
            "n_matched_juicy": n_matched_juicy,
            "n_matched_not_juicy": n_matched_not_juicy,
            "rule_pack_precision": rule_precision,
            "rule_pack_recall": rule_recall,
            "rule_pack_f1": rule_f1,
            "n_blind_juicy": len(blind_juicy),
            "n_blind_not_juicy": len(blind_not_juicy),
        },
        "per_rule": list(per_rule_hits.values()),
    }
    args.report_output.parent.mkdir(parents=True, exist_ok=True)
    args.report_output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(
        f"\nWrote {args.report_output.relative_to(REPO_ROOT)}", file=sys.stderr
    )

    print("\n=== LINUX RULE-PACK HEADLINE ===", file=sys.stderr)
    print(
        f"  Records: {n_total} ({n_juicy} juicy / {n_not_juicy} not_juicy)",
        file=sys.stderr,
    )
    print(
        f"  Rule pack: {len(rules)} rules → matched {len(matched)} records",
        file=sys.stderr,
    )
    print(
        f"  Precision: {rule_precision:.3f}   Recall: {rule_recall:.3f}   F1: {rule_f1:.3f}",
        file=sys.stderr,
    )
    print(
        f"  vs ML headline (Linux test PR-AUC 0.97, F1@0.5=0.93): "
        f"rule recall {100 * rule_recall:.1f}% — ML gain over rules = "
        f"+{100 * (0.93 - rule_recall):.1f}pp F1",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
