"""GOAD head-to-head benchmark harness for ShareSift vs Snaffler.

Runs ``sharesift hunt`` against a GOAD-class Active Directory lab,
ingests an operator-provided Snaffler TSV (Snaffler.exe must be
run from a Windows host inside the lab — see the methodology doc),
diffs the two find sets, and emits a per-category scorecard.

Usage::

    # On the attacker box (Kali / Linux):
    python tools/goad_benchmark.py \\
        --ad-domain sevenkingdoms.local --dc 192.168.56.10 \\
        -u khal.drogo -p horse \\
        --snaffler-tsv ./snaffler_run.tsv \\
        --output-dir ./goad_bench_2026-06-11

The harness does not run Snaffler itself — the operator runs
``Snaffler.exe -s -d <domain> -o snaffler.log -y tsv`` from a
Windows host with the same credentials, copies the TSV back, and
passes it via ``--snaffler-tsv``. See ``docs/goad_benchmark_methodology.md``
for the full lab setup recipe.

Output:

- ``<output-dir>/sharesift/`` — full hunt output (per-share subdirs)
- ``<output-dir>/sharesift_hits.jsonl`` — combined hits across shares
- ``<output-dir>/snaffler_hits.tsv`` — copy of operator TSV (for reproducibility)
- ``<output-dir>/scorecard.md`` — per-category recall + unique finds
- ``<output-dir>/scorecard.json`` — same data, machine-readable
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import re
import subprocess
import sys
import time
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable


# Snaffler severity values. Tier ordering reflects Snaffler's own
# conventions (Black highest, Green lowest).
SNAFFLER_TIERS = ("Black", "Red", "Yellow", "Green")

# Bucket category labels — coarse enough to compare across rule sets
# (Snaffler's regex labels vs ShareSift's rule IDs use different
# names but cluster around the same underlying credential shapes).
CATEGORY_LABELS = (
    "gpp_cpassword",
    "keepass_db",
    "ssh_private_key",
    "putty_ppk",
    "aws_credentials",
    "gcp_service_account",
    "azure_credentials",
    "browser_password_store",
    "windows_credential_file",
    "powershell_credential",
    "sql_connection_string",
    "registry_hive",
    "iis_webconfig_secret",
    "wifi_psk",
    "sccm_naa",
    "generic_password_file",
    "credentials_filename",
    "backup_archive",
    "unsorted_other",
)


@dataclass
class Hit:
    """One credential finding from either tool, normalized."""

    unc_path: str
    tier: str  # Black / Red / Yellow / Green
    rule_id: str  # Snaffler rule name or ShareSift rule ID
    category: str  # One of CATEGORY_LABELS, or unsorted_other
    raw_source: str = "sharesift"  # "sharesift" or "snaffler"
    snippet: str = ""


@dataclass
class Scorecard:
    """Comparison summary between two find sets."""

    sharesift_total: int = 0
    snaffler_total: int = 0
    overlap: int = 0
    sharesift_only: int = 0
    snaffler_only: int = 0
    by_category: dict = field(default_factory=lambda: defaultdict(dict))
    sharesift_elapsed_s: float | None = None
    snaffler_note: str = ""


# --- Path normalization ------------------------------------------


def normalize_unc(path: str) -> str:
    """Normalize a UNC for path-equality comparison across tools.

    Both tools emit UNCs but with subtle differences:

    - ShareSift: ``\\\\host\\share\\dir\\file.ext``
    - Snaffler: ``\\\\host\\share\\dir\\file.ext`` (usually same)
    - Older Snaffler / Snafflepy: mixed backslash/forward-slash

    Normalize to: lowercase host + share, backslash separators,
    no trailing whitespace.
    """
    p = path.strip().replace("/", "\\")
    # Lowercase first three components (host + share)
    m = re.match(r"^(\\\\[^\\]+\\[^\\]+)(.*)$", p)
    if m:
        head = m.group(1).lower()
        tail = m.group(2)
        return head + tail
    return p.lower()


def categorize(rule_id: str, snippet: str = "") -> str:
    """Map a tool's rule label into a coarse category for scoring.

    The rule_id strings from Snaffler and ShareSift don't align —
    Snaffler uses names like ``KeepGppPassword``, ShareSift uses
    things like ``ShareSiftKeepGroupsXmlCpassword``. Categorize
    both into a shared bucket so we can compute per-category
    recall.
    """
    rid = rule_id.lower()
    snip = snippet.lower() if snippet else ""

    if "gpp" in rid or "cpassword" in rid or "groups.xml" in snip:
        return "gpp_cpassword"
    if "keepass" in rid or ".kdbx" in rid or ".kdbx" in snip:
        return "keepass_db"
    if "putty" in rid or ".ppk" in rid or ".ppk" in snip:
        return "putty_ppk"
    if "ssh" in rid and ("private" in rid or "id_rsa" in rid or "openssh" in rid):
        return "ssh_private_key"
    if "aws" in rid or "akia" in snip:
        return "aws_credentials"
    if "gcp" in rid or "google" in rid or "service_account" in rid:
        return "gcp_service_account"
    if "azure" in rid or "msft_azure" in rid:
        return "azure_credentials"
    if "browser" in rid or "chrome" in rid or "firefox" in rid or "edge" in rid:
        return "browser_password_store"
    if "credentialfile" in rid or "wcm" in rid:
        return "windows_credential_file"
    if "powershell" in rid and ("credential" in rid or "psd1" in rid):
        return "powershell_credential"
    if "sql" in rid and ("conn" in rid or "string" in rid):
        return "sql_connection_string"
    if "ntds" in rid or "registry" in rid or ".reg" in rid or "sam" in rid:
        return "registry_hive"
    if "iis" in rid or "web.config" in rid or "webconfig" in rid:
        return "iis_webconfig_secret"
    if "wifi" in rid or "wlan" in rid or "psk" in rid:
        return "wifi_psk"
    if "sccm" in rid or "naa" in rid or "ccmcache" in rid:
        return "sccm_naa"
    if "credentials_filename" in rid or "credentialfilename" in rid:
        return "credentials_filename"
    if (".bak" in rid or "backup" in rid or "archive" in rid
            or ".zip" in rid or ".7z" in rid):
        return "backup_archive"
    if "password" in rid:
        return "generic_password_file"
    return "unsorted_other"


# --- Snaffler TSV ingest ----------------------------------------


def parse_snaffler_tsv(tsv_path: Path) -> list[Hit]:
    """Parse a Snaffler TSV emitted by ``Snaffler.exe -y tsv``.

    Snaffler's TSV columns (empirically, from v1.x):
    severity, rule_id, share_unc, modified_date, size, snippet.
    Tolerant of column reordering — looks up by header when
    present.
    """
    hits: list[Hit] = []
    text = tsv_path.read_text(encoding="utf-8", errors="replace")
    lines = [ln for ln in text.splitlines() if ln.strip()]
    if not lines:
        return []

    # Detect header
    first = lines[0].split("\t")
    has_header = any(
        h.lower() in ("severity", "tier", "rule", "rule_id", "unc", "path")
        for h in first
    )
    if has_header:
        reader = csv.DictReader(lines, delimiter="\t")
        for row in reader:
            tier = (row.get("severity") or row.get("tier") or "").strip()
            rule = (row.get("rule") or row.get("rule_id") or "").strip()
            unc = (
                row.get("unc") or row.get("path") or row.get("share")
                or ""
            ).strip()
            snippet = (row.get("snippet") or row.get("preview") or "").strip()
            if not unc:
                continue
            hits.append(Hit(
                unc_path=normalize_unc(unc),
                tier=tier or "Yellow",
                rule_id=rule or "unknown",
                category=categorize(rule, snippet),
                raw_source="snaffler",
                snippet=snippet[:200],
            ))
    else:
        # Positional: severity \t rule \t unc \t (extras)
        for line in lines:
            parts = line.split("\t")
            if len(parts) < 3:
                continue
            tier, rule, unc = parts[0], parts[1], parts[2]
            snippet = parts[-1] if len(parts) >= 6 else ""
            hits.append(Hit(
                unc_path=normalize_unc(unc),
                tier=tier.strip(),
                rule_id=rule.strip(),
                category=categorize(rule, snippet),
                raw_source="snaffler",
                snippet=snippet[:200].strip(),
            ))
    return hits


# --- ShareSift JSONL ingest -------------------------------------


def parse_sharesift_jsonl(jsonl_path: Path) -> list[Hit]:
    """Parse a ``hits.jsonl`` file from a ``sharesift hunt`` run."""
    hits: list[Hit] = []
    for line in jsonl_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            continue
        unc = rec.get("path") or rec.get("unc") or rec.get("file") or ""
        if not unc:
            continue
        tier = rec.get("tier") or rec.get("severity") or "Yellow"
        rule = (
            rec.get("rule_id") or rec.get("rule") or rec.get("matched_rule")
            or "sharesift"
        )
        snippet = rec.get("snippet") or rec.get("preview") or ""
        hits.append(Hit(
            unc_path=normalize_unc(unc),
            tier=str(tier).capitalize(),
            rule_id=str(rule),
            category=categorize(str(rule), snippet),
            raw_source="sharesift",
            snippet=snippet[:200] if snippet else "",
        ))
    return hits


def collect_sharesift_hits(hunt_output_dir: Path) -> list[Hit]:
    """Walk a hunt --output-dir tree and gather all hits.jsonl files
    from per-share subdirectories."""
    out: list[Hit] = []
    for hits_file in hunt_output_dir.rglob("hits.jsonl"):
        out.extend(parse_sharesift_jsonl(hits_file))
    return out


# --- ShareSift invocation ----------------------------------------


def run_sharesift_hunt(
    ad_domain: str,
    dc: str | None,
    user: str | None,
    password: str | None,
    use_kcache: bool,
    output_dir: Path,
    extra_args: list[str] | None = None,
) -> tuple[int, float]:
    """Invoke ``sharesift hunt --ad-domain ...`` as a subprocess.

    Returns ``(exit_code, elapsed_s)``. Captures stderr to
    ``<output-dir>/sharesift.stderr.log`` for debugging.
    """
    cmd = [
        "sharesift", "hunt",
        "--ad-domain", ad_domain,
        "--output-dir", str(output_dir),
    ]
    if dc:
        cmd += ["--dc", dc]
    if use_kcache:
        cmd += ["--use-kcache"]
    elif user and password:
        cmd += ["-u", user, "-p", password]
    if extra_args:
        cmd += extra_args

    output_dir.mkdir(parents=True, exist_ok=True)
    stderr_log = output_dir / "sharesift.stderr.log"

    t0 = time.monotonic()
    with stderr_log.open("w", encoding="utf-8") as logf:
        proc = subprocess.run(
            cmd, stdout=subprocess.PIPE, stderr=logf, text=True,
            env={**os.environ, "PYTHONUNBUFFERED": "1"},
        )
    elapsed = time.monotonic() - t0
    return proc.returncode, elapsed


# --- Scorecard generation ----------------------------------------


def compute_scorecard(
    sharesift_hits: Iterable[Hit],
    snaffler_hits: Iterable[Hit],
    *,
    sharesift_elapsed_s: float | None = None,
    snaffler_note: str = "",
) -> Scorecard:
    """Diff the two find sets by normalized UNC + categorize."""
    ss_set = list(sharesift_hits)
    sn_set = list(snaffler_hits)

    ss_paths = {h.unc_path for h in ss_set}
    sn_paths = {h.unc_path for h in sn_set}

    overlap = ss_paths & sn_paths
    ss_only = ss_paths - sn_paths
    sn_only = sn_paths - ss_paths

    by_cat: dict = defaultdict(
        lambda: {"sharesift": 0, "snaffler": 0, "overlap": 0,
                 "sharesift_only": 0, "snaffler_only": 0}
    )
    for h in ss_set:
        by_cat[h.category]["sharesift"] += 1
        if h.unc_path in overlap:
            by_cat[h.category]["overlap"] += 1
        else:
            by_cat[h.category]["sharesift_only"] += 1
    for h in sn_set:
        by_cat[h.category]["snaffler"] += 1
        if h.unc_path not in overlap:
            by_cat[h.category]["snaffler_only"] += 1

    return Scorecard(
        sharesift_total=len(ss_paths),
        snaffler_total=len(sn_paths),
        overlap=len(overlap),
        sharesift_only=len(ss_only),
        snaffler_only=len(sn_only),
        by_category=dict(by_cat),
        sharesift_elapsed_s=sharesift_elapsed_s,
        snaffler_note=snaffler_note,
    )


def render_scorecard_md(
    scorecard: Scorecard,
    sharesift_hits: list[Hit],
    snaffler_hits: list[Hit],
) -> str:
    """Render a markdown scorecard for human review."""
    lines: list[str] = []
    lines.append("# GOAD head-to-head — ShareSift vs Snaffler\n")

    if scorecard.sharesift_elapsed_s is not None:
        lines.append(
            f"**ShareSift hunt elapsed:** "
            f"{scorecard.sharesift_elapsed_s:.1f}s\n"
        )
    if scorecard.snaffler_note:
        lines.append(f"**Snaffler note:** {scorecard.snaffler_note}\n")

    lines.append("## Overall\n")
    lines.append("| | ShareSift | Snaffler |")
    lines.append("|---|---:|---:|")
    lines.append(
        f"| Total unique finds | {scorecard.sharesift_total} | "
        f"{scorecard.snaffler_total} |"
    )
    lines.append(f"| Caught by both | {scorecard.overlap} | {scorecard.overlap} |")
    lines.append(
        f"| Unique to tool | {scorecard.sharesift_only} | "
        f"{scorecard.snaffler_only} |"
    )

    lines.append("\n## Per-category breakdown\n")
    lines.append(
        "| Category | ShareSift | Snaffler | Overlap | "
        "ShareSift-only | Snaffler-only |"
    )
    lines.append("|---|---:|---:|---:|---:|---:|")
    cat_order = list(CATEGORY_LABELS)
    seen_cats = set(scorecard.by_category.keys())
    for cat in cat_order:
        if cat not in seen_cats:
            continue
        row = scorecard.by_category[cat]
        lines.append(
            f"| {cat} | {row['sharesift']} | {row['snaffler']} | "
            f"{row['overlap']} | {row['sharesift_only']} | "
            f"{row['snaffler_only']} |"
        )
    # Any categories not in CATEGORY_LABELS (shouldn't happen but
    # be safe)
    for cat in sorted(seen_cats - set(cat_order)):
        row = scorecard.by_category[cat]
        lines.append(
            f"| {cat} | {row['sharesift']} | {row['snaffler']} | "
            f"{row['overlap']} | {row['sharesift_only']} | "
            f"{row['snaffler_only']} |"
        )

    # Sample of unique finds from each side
    lines.append("\n## ShareSift-only finds (sample)\n")
    ss_only = [
        h for h in sharesift_hits
        if h.unc_path not in {h2.unc_path for h2 in snaffler_hits}
    ]
    for h in ss_only[:20]:
        lines.append(f"- `{h.unc_path}` ({h.category}, {h.tier}, {h.rule_id})")
    if len(ss_only) > 20:
        lines.append(f"  ... and {len(ss_only) - 20} more")

    lines.append("\n## Snaffler-only finds (sample)\n")
    sn_only = [
        h for h in snaffler_hits
        if h.unc_path not in {h2.unc_path for h2 in sharesift_hits}
    ]
    for h in sn_only[:20]:
        lines.append(f"- `{h.unc_path}` ({h.category}, {h.tier}, {h.rule_id})")
    if len(sn_only) > 20:
        lines.append(f"  ... and {len(sn_only) - 20} more")

    return "\n".join(lines) + "\n"


def render_scorecard_json(scorecard: Scorecard) -> str:
    """Machine-readable scorecard."""
    return json.dumps({
        "sharesift_total": scorecard.sharesift_total,
        "snaffler_total": scorecard.snaffler_total,
        "overlap": scorecard.overlap,
        "sharesift_only": scorecard.sharesift_only,
        "snaffler_only": scorecard.snaffler_only,
        "by_category": dict(scorecard.by_category),
        "sharesift_elapsed_s": scorecard.sharesift_elapsed_s,
        "snaffler_note": scorecard.snaffler_note,
    }, indent=2)


# --- CLI -----------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="GOAD head-to-head benchmark — ShareSift vs Snaffler.",
    )
    p.add_argument(
        "--ad-domain", required=True,
        help="AD domain (e.g. sevenkingdoms.local for GOAD).",
    )
    p.add_argument(
        "--dc", default=None,
        help="DC hostname/IP. Defaults to --ad-domain.",
    )
    p.add_argument("-u", "--user", default=None, help="Username.")
    p.add_argument("-p", "--password", default=None, help="Password.")
    p.add_argument(
        "--use-kcache", action="store_true",
        help="Kerberos via KRB5CCNAME (run kinit first).",
    )
    p.add_argument(
        "--output-dir", type=Path, required=True,
        help="Output directory; harness writes sharesift/ + scorecard.* here.",
    )
    p.add_argument(
        "--snaffler-tsv", type=Path, default=None,
        help=(
            "Path to Snaffler.exe TSV output (operator runs Snaffler "
            "separately — see docs/goad_benchmark_methodology.md)."
        ),
    )
    p.add_argument(
        "--skip-sharesift", action="store_true",
        help=(
            "Don't run sharesift hunt; expect a previous run's output in "
            "<output-dir>/sharesift/ (useful for re-scoring after Snaffler TSV updates)."
        ),
    )
    p.add_argument(
        "--sharesift-arg", action="append", default=[],
        help=(
            "Pass an extra arg through to sharesift hunt. Repeatable. "
            "Example: --sharesift-arg --writable-only"
        ),
    )
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    out: Path = args.output_dir
    out.mkdir(parents=True, exist_ok=True)
    sharesift_dir = out / "sharesift"

    elapsed: float | None = None
    if not args.skip_sharesift:
        if not (args.use_kcache or (args.user and args.password)):
            print(
                "error: pass either --use-kcache or -u/-p (or --skip-sharesift "
                "to re-score a previous run).",
                file=sys.stderr,
            )
            return 2
        print(
            f"[1/3] running sharesift hunt against {args.ad_domain}",
            file=sys.stderr,
        )
        rc, elapsed = run_sharesift_hunt(
            ad_domain=args.ad_domain, dc=args.dc,
            user=args.user, password=args.password,
            use_kcache=args.use_kcache,
            output_dir=sharesift_dir,
            extra_args=args.sharesift_arg,
        )
        print(f"   sharesift exited {rc} after {elapsed:.1f}s", file=sys.stderr)
        if rc != 0:
            print(
                f"   sharesift stderr in {sharesift_dir}/sharesift.stderr.log",
                file=sys.stderr,
            )

    print("[2/3] parsing find sets", file=sys.stderr)
    sharesift_hits = collect_sharesift_hits(sharesift_dir)
    print(
        f"   sharesift: {len(sharesift_hits)} hits across "
        f"{len(set(h.unc_path for h in sharesift_hits))} unique paths",
        file=sys.stderr,
    )

    snaffler_hits: list[Hit] = []
    snaffler_note = ""
    if args.snaffler_tsv and args.snaffler_tsv.exists():
        snaffler_hits = parse_snaffler_tsv(args.snaffler_tsv)
        print(f"   snaffler: {len(snaffler_hits)} hits", file=sys.stderr)
        # Copy the TSV for reproducibility
        (out / "snaffler_hits.tsv").write_text(
            args.snaffler_tsv.read_text(encoding="utf-8", errors="replace"),
            encoding="utf-8",
        )
    else:
        snaffler_note = (
            "no Snaffler TSV provided — pass --snaffler-tsv to populate "
            "the head-to-head column"
        )
        print(f"   snaffler: skipped ({snaffler_note})", file=sys.stderr)

    print("[3/3] writing scorecard", file=sys.stderr)
    scorecard = compute_scorecard(
        sharesift_hits, snaffler_hits,
        sharesift_elapsed_s=elapsed,
        snaffler_note=snaffler_note,
    )
    (out / "scorecard.md").write_text(
        render_scorecard_md(scorecard, sharesift_hits, snaffler_hits),
        encoding="utf-8",
    )
    (out / "scorecard.json").write_text(
        render_scorecard_json(scorecard), encoding="utf-8",
    )
    (out / "sharesift_hits.jsonl").write_text(
        "\n".join(
            json.dumps({
                "unc_path": h.unc_path, "tier": h.tier,
                "rule_id": h.rule_id, "category": h.category,
            })
            for h in sharesift_hits
        ) + ("\n" if sharesift_hits else ""),
        encoding="utf-8",
    )
    print(f"   wrote {out / 'scorecard.md'}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
