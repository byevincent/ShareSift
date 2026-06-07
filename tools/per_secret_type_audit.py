"""Per-secret-type breakdown of the content classifier.

Tier-1 audit item from the 2026-05-31 v0.5 research pass. The content
classifier reports overall P=0.984 / R=0.958 / F1=0.971 but the test
set has no secret-type metadata, so it's unknown whether all secret
classes are equally easy. Both research agents flagged this as the
biggest single eval gap.

Approach: regex-based type inference over each snippet, then per-type
confusion-matrix + P/R/F1 from the per-record predictions captured by
``tools/eval_content_classifier.py --predictions-out``.

The type inference is intentionally hierarchical / first-match-wins
with high-confidence patterns first — same posture as the Linux rule
pack. Snippets matching no specific type fall into ``other``.

Output: ``reports/per_secret_type_audit.json``.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import defaultdict
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent


# Each entry: (type_name, regex_or_callable)
_TYPE_PATTERNS: list[tuple[str, re.Pattern]] = [
    # High-confidence specific patterns first.
    ("aws_access_key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("aws_secret_key", re.compile(r"aws[_-]?secret[_-]?access[_-]?key", re.I)),
    (
        "gcp_service_account_json",
        re.compile(
            r'"type"\s*:\s*"service_account"|"private_key_id"|"client_email".*\.iam\.gserviceaccount\.com',
            re.I | re.S,
        ),
    ),
    (
        "azure_storage_connstring",
        re.compile(
            r"DefaultEndpointsProtocol=https?;AccountName=|AccountKey=", re.I
        ),
    ),
    (
        "ssh_private_key_pem",
        re.compile(
            r"-----BEGIN\s+(RSA|EC|DSA|OPENSSH|ED25519)\s+PRIVATE\s+KEY-----", re.I
        ),
    ),
    (
        "tls_private_key_pem",
        re.compile(r"-----BEGIN\s+(PRIVATE|ENCRYPTED PRIVATE)\s+KEY-----", re.I),
    ),
    ("tls_certificate_pem", re.compile(r"-----BEGIN\s+CERTIFICATE-----", re.I)),
    ("pgp_private_key", re.compile(r"-----BEGIN\s+PGP\s+PRIVATE\s+KEY", re.I)),
    (
        "jwt_token",
        re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]+"),
    ),
    (
        "stripe_key",
        re.compile(r"\bsk_(live|test)_[A-Za-z0-9]{24,}\b|\brk_(live|test)_[A-Za-z0-9]{24,}\b"),
    ),
    ("github_token", re.compile(r"\bgh[opsu]_[A-Za-z0-9]{30,}\b")),
    ("github_pat_old", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{30,}\b")),
    ("slack_webhook", re.compile(r"hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+")),
    ("slack_token", re.compile(r"\bxox[bopars]-[A-Za-z0-9-]{10,}", re.I)),
    ("discord_webhook", re.compile(r"discord(?:app)?\.com/api/webhooks/\d+/[\w-]+", re.I)),
    ("discord_bot_token", re.compile(r"\b[A-Za-z0-9._-]{59,68}\b(?=.*discord)", re.I)),
    ("twilio", re.compile(r"\bSK[a-f0-9]{32}\b|\bAC[a-f0-9]{32}\b")),
    (
        "db_connection_string",
        re.compile(
            r"(postgres|postgresql|mysql|mongodb|mariadb|redis)://[^\s\"']+:[^\s\"']+@",
            re.I,
        ),
    ),
    (
        "env_file_assignment",
        re.compile(
            r"^[ \t]*(?:export\s+)?[A-Z][A-Z0-9_]{2,}\s*=\s*['\"]?[^\s'\"]{6,}['\"]?",
            re.M,
        ),
    ),
    (
        "hardcoded_password_assignment",
        re.compile(
            r"\b(passw(or)?d|pwd|secret|api[_-]?key|api[_-]?token|access[_-]?token|auth[_-]?token)\s*[:=]\s*['\"][^'\"]{4,}['\"]",
            re.I,
        ),
    ),
    (
        "basic_auth_header",
        re.compile(r"\bauthorization\s*:\s*basic\s+[A-Za-z0-9+/=]{12,}", re.I),
    ),
    (
        "bearer_token_header",
        re.compile(r"\bauthorization\s*:\s*bearer\s+[A-Za-z0-9._-]{12,}", re.I),
    ),
    (
        "oauth_client_secret",
        re.compile(r"\bclient[_-]?secret\b", re.I),
    ),
    # Catch-all for generic "key/secret/password" mentions (low precision).
    (
        "generic_credential_mention",
        re.compile(
            r"\b(password|secret|api[_-]?key|access[_-]?key|auth[_-]?token|credential)\b",
            re.I,
        ),
    ),
]


def classify(snippet: str) -> str:
    for type_name, regex in _TYPE_PATTERNS:
        if regex.search(snippet):
            return type_name
    return "other"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--predictions",
        type=Path,
        default=REPO_ROOT / "reports" / "content_predictions_v0p3.jsonl",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=REPO_ROOT / "reports" / "per_secret_type_audit.json",
    )
    args = parser.parse_args()

    records = []
    for line in args.predictions.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        records.append(json.loads(line))
    print(f"Loaded {len(records)} predictions", file=sys.stderr)

    # Per-type confusion matrices.
    per_type_tp: dict[str, int] = defaultdict(int)
    per_type_fp: dict[str, int] = defaultdict(int)
    per_type_fn: dict[str, int] = defaultdict(int)
    per_type_tn: dict[str, int] = defaultdict(int)
    per_type_total: dict[str, int] = defaultdict(int)
    per_type_pos: dict[str, int] = defaultdict(int)

    sample_errors: dict[str, list[dict]] = defaultdict(list)

    for rec in records:
        secret_type = classify(rec["snippet"])
        true = rec["true_label"]  # "yes" / "no"
        pred = rec["predicted_label"]  # "yes" / "no" / None
        per_type_total[secret_type] += 1
        if true == "yes":
            per_type_pos[secret_type] += 1
        if pred == "yes" and true == "yes":
            per_type_tp[secret_type] += 1
        elif pred == "yes" and true == "no":
            per_type_fp[secret_type] += 1
            if len(sample_errors[secret_type]) < 3:
                sample_errors[secret_type].append(
                    {
                        "kind": "FP",
                        "snippet_preview": rec["snippet"][:180].replace("\n", " "),
                        "true_label": true,
                        "predicted_label": pred,
                    }
                )
        elif pred == "no" and true == "yes":
            per_type_fn[secret_type] += 1
            if len(sample_errors[secret_type]) < 3:
                sample_errors[secret_type].append(
                    {
                        "kind": "FN",
                        "snippet_preview": rec["snippet"][:180].replace("\n", " "),
                        "true_label": true,
                        "predicted_label": pred,
                    }
                )
        elif pred == "no" and true == "no":
            per_type_tn[secret_type] += 1

    # Compute P/R/F1 per type.
    per_type_rows = []
    all_types = sorted(per_type_total)
    for t in all_types:
        tp = per_type_tp[t]
        fp = per_type_fp[t]
        fn = per_type_fn[t]
        tn = per_type_tn[t]
        precision = tp / (tp + fp) if (tp + fp) else None
        recall = tp / (tp + fn) if (tp + fn) else None
        if precision is None or recall is None:
            f1 = None
        elif precision + recall == 0:
            f1 = 0.0
        else:
            f1 = 2 * precision * recall / (precision + recall)
        per_type_rows.append(
            {
                "secret_type": t,
                "n_total": per_type_total[t],
                "n_positive": per_type_pos[t],
                "tp": tp,
                "fp": fp,
                "fn": fn,
                "tn": tn,
                "precision": precision,
                "recall": recall,
                "f1": f1,
                "sample_errors": sample_errors[t],
            }
        )

    report = {
        "version": "v0.5",
        "generated": "2026-05-31",
        "predictions_source": str(args.predictions.relative_to(REPO_ROOT)),
        "n_records": len(records),
        "per_type": per_type_rows,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(f"Wrote {args.output.relative_to(REPO_ROOT)}", file=sys.stderr)

    # Headline table.
    print("\n=== PER-SECRET-TYPE BREAKDOWN ===", file=sys.stderr)
    print(
        f"{'type':32s}  {'n':>4s}  {'pos':>4s}  {'P':>6s}  {'R':>6s}  {'F1':>6s}",
        file=sys.stderr,
    )
    for row in sorted(per_type_rows, key=lambda x: -x["n_total"]):
        p = f"{row['precision']:.3f}" if row["precision"] is not None else "n/a"
        r = f"{row['recall']:.3f}" if row["recall"] is not None else "n/a"
        f = f"{row['f1']:.3f}" if row["f1"] is not None else "n/a"
        print(
            f"{row['secret_type']:32s}  {row['n_total']:4d}  "
            f"{row['n_positive']:4d}  {p:>6s}  {r:>6s}  {f:>6s}",
            file=sys.stderr,
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
