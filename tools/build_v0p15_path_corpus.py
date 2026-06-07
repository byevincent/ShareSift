"""v0.15 — assemble the path classifier retrain corpus.

Merges three streams into a single JSONL ready for
``tools/train_path_classifier.py`` to consume via ``--train-data``:

1. Existing v0p2 labeled data (``data/eval/train_split.jsonl``) — the
   baseline corpus the current path classifier was trained on. Kept
   as-is so v0.15 doesn't lose any signal v0p2 already had.
2. Engagement-extracted real paths
   (``data/external/engagement_corpus/extracted_paths_clean.jsonl``)
   — high-quality seeds from DFIR Report / red team writeups.
3. Engagement-synthetic paths
   (``data/external/engagement_corpus/synthetic_paths.jsonl``) —
   combinatorial expansion of (2) for install-path generalization.

Schema is the v0p2 ``train_split.jsonl`` shape (path, label, tier,
category, sub_type, source, added_date, added_by, pre_category,
validator_warnings) so the trainer doesn't need code changes.

Deduplication: any (normalized path) collision across the three
streams keeps the first-seen record. Existing labeled data wins over
new engagement data when the path is identical — operator labels are
ground truth.

Provenance: every record carries a ``v0p15_origin`` field so we can
ablate (train on existing only / +extracted / +synthetic) and measure
each stream's contribution to PR-AUC.

Usage::

    uv run python tools/build_v0p15_path_corpus.py \\
        --output data/synthetic/training_v0p15.jsonl

    # Then retrain:
    uv run python tools/train_path_classifier.py \\
        --train-data data/synthetic/training_v0p15.jsonl
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter
from datetime import date
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

DEFAULT_EXISTING_TRAIN = REPO_ROOT / "data" / "eval" / "train_split.jsonl"
DEFAULT_EXTRACTED = REPO_ROOT / "data" / "external" / "engagement_corpus" / "extracted_paths_clean.jsonl"
DEFAULT_SYNTHETIC = REPO_ROOT / "data" / "external" / "engagement_corpus" / "synthetic_paths.jsonl"
DEFAULT_OUTPUT = REPO_ROOT / "data" / "synthetic" / "training_v0p15.jsonl"

# Additional extraction sources (Tier-1 structured sources from Vincent's
# 2026-06-04 question about more internet data).
DEFAULT_PEAS = REPO_ROOT / "data" / "external" / "peas" / "extracted_paths.jsonl"
DEFAULT_KAPE = REPO_ROOT / "data" / "external" / "kape" / "extracted_paths.jsonl"
DEFAULT_HACKTRICKS = REPO_ROOT / "data" / "external" / "hacktricks" / "extracted_paths.jsonl"

_TODAY = date.today().isoformat()


# Sanity filters applied at merge time to drop over-broad classifications
# the regex+rules pipeline produced. These were surfaced via spot-check:
#   - KeepWinHashesByName firing on /etc/systemd/system (Linux path)
#   - heuristic_hive firing on System.evtx, /etc/systemd/system, etc.
#   - KeepNixLocalHashesByName firing on Windows paths

_WINDOWS_RULES = {
    "KeepWinHashesByName", "KeepCyberArkConfigsByName", "KeepUnattendXmlRelay",
    "TrufflerKeepWindowsUnattend", "TrufflerKeepUnattendXmlUpgrade",
    "KeepDomainJoinCredsByName", "KeepDomainJoinCredsByPath",
    "KeepSCCMBootVarCredsByPath", "KeepCSharpDbConnStrings",
    "KeepCSharpDbConnStringsRed", "KeepCSharpDbConnStringsYellow",
    "KeepCSharpViewstateKeys",
}
_LINUX_RULES = {
    "KeepNixLocalHashesByName", "KeepKerberosCredentialsByName",
    "KeepKerberosCredentialsByExtension", "KeepShellHistoryByName",
    "KeepShellRcFilesByName",
}


def _path_is_linux(path: str) -> bool:
    return path.startswith("/") or path.startswith("~/")


def _path_is_windows(path: str) -> bool:
    return path.startswith("\\\\") or (len(path) >= 2 and path[1] == ":")


def _passes_sanity(rec: dict) -> tuple[bool, str | None]:
    """Returns (kept, drop_reason). Drop reasons:
    - 'os_mismatch_win_rule_linux_path'
    - 'os_mismatch_linux_rule_win_path'
    - 'hive_over_match' (heuristic_hive fired on a non-hive file)
    """
    rule = rec.get("matched_rule") or ""
    path = rec.get("verbatim_path") or ""
    if rule in _WINDOWS_RULES and _path_is_linux(path):
        return False, "os_mismatch_win_rule_linux_path"
    if rule in _LINUX_RULES and _path_is_windows(path):
        return False, "os_mismatch_linux_rule_win_path"
    if rule == "heuristic_hive":
        # The hive heuristic should only match SAM/SYSTEM/SECURITY as the
        # actual basename (no extension, or .save/.bak/.hiv suffix only).
        # Reject when the path's basename is something like System.evtx or
        # /etc/systemd/system.
        basename = path.replace("/", "\\").rsplit("\\", 1)[-1]
        base_lower = basename.lower()
        # Pure hive names
        if base_lower in ("sam", "system", "security", "ntds.dit"):
            return True, None
        # Backup / save variants
        if re.match(r"^(sam|system|security)\.(save|bak|hiv|hive|old)$",
                    base_lower):
            return True, None
        # If the basename has any other extension, this is over-matching
        if "." in basename:
            return False, "hive_over_match"
        # Standalone "SAM"/"SYSTEM" etc. dirs are rarely actual hives
        # outside of \\config\\ context — keep them only if path explicitly
        # contains \\config\\
        if "\\config\\" in path.lower() or "/config/" in path.lower():
            return True, None
        return False, "hive_over_match"
    return True, None


def _normalize_path(path: str) -> str:
    """Case-fold + collapse separators for dedup."""
    return path.replace("/", "\\").lower()


def _convert_extracted_record(rec: dict, origin: str = "extracted_engagement",
                              category: str = "engagement_extracted",
                              source: str = "engagement_article") -> dict:
    """extracted_paths_clean.jsonl → train_split.jsonl schema."""
    tier = rec.get("tier")
    if tier in (None, "None"):
        tier = None
        label = "not_juicy"
    elif tier == "Green":
        # Relay rules: file IS interesting (config/script) but not by itself
        # credential-bearing. Treat as not_juicy for the path-classifier
        # binary objective — the content classifier handles relayed content.
        tier = None
        label = "not_juicy"
    else:
        label = "juicy"
    return {
        "path": rec.get("verbatim_path") or rec.get("path"),
        "label": label,
        "tier": tier,
        "category": category,
        "sub_type": rec.get("credential_type"),
        "source": source,
        "added_date": _TODAY,
        "added_by": "regex+snaffler_rules",
        "pre_category": rec.get("matched_rule"),
        "validator_warnings": [],
        "v0p15_origin": origin,
        "_source_url": rec.get("source_url"),
    }


def _convert_synthetic_record(rec: dict) -> dict:
    """synthetic_paths.jsonl → train_split.jsonl schema."""
    tier = rec.get("tier")
    if tier in (None, "None"):
        tier = None
    label = rec.get("label", "not_juicy")
    return {
        "path": rec["path"],
        "label": label,
        "tier": tier,
        "category": "synthetic_engagement",
        "sub_type": rec.get("credential_type"),
        "source": "synthetic",
        "added_date": _TODAY,
        "added_by": "synthetic_recombination",
        "pre_category": None,
        "validator_warnings": [],
        "v0p15_origin": "synthetic_engagement",
    }


def _convert_existing_record(rec: dict) -> dict:
    """Pass-through with v0p15_origin marker added."""
    out = dict(rec)
    out["v0p15_origin"] = "existing_v0p2"
    return out


def _load_jsonl(path: Path) -> list[dict]:
    if not path.exists():
        return []
    out: list[dict] = []
    with path.open(encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return out


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--existing-train", type=Path, default=DEFAULT_EXISTING_TRAIN)
    p.add_argument("--extracted", type=Path, default=DEFAULT_EXTRACTED)
    p.add_argument("--synthetic", type=Path, default=DEFAULT_SYNTHETIC)
    p.add_argument("--peas", type=Path, default=DEFAULT_PEAS,
                   help="PEAS-extracted paths (LinPEAS/WinPEAS source mining)")
    p.add_argument("--kape", type=Path, default=DEFAULT_KAPE,
                   help="KAPE target enumeration paths")
    p.add_argument("--hacktricks", type=Path, default=DEFAULT_HACKTRICKS,
                   help="HackTricks book scrape")
    p.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    p.add_argument("--skip-existing", action="store_true",
                   help="Don't include data/eval/train_split.jsonl in the merge "
                        "(useful for ablation: engagement-only training)")
    p.add_argument("--skip-synthetic", action="store_true",
                   help="Don't include synthetic recombinations "
                        "(ablation: real-only training)")
    p.add_argument("--skip-tier1", action="store_true",
                   help="Don't include PEAS/KAPE/HackTricks tier-1 sources")
    p.add_argument("--no-sanity-filter", action="store_true",
                   help="Disable the OS-mismatch + hive-over-match sanity filter")
    args = p.parse_args(argv)

    existing = [] if args.skip_existing else _load_jsonl(args.existing_train)
    extracted = _load_jsonl(args.extracted)
    synthetic = [] if args.skip_synthetic else _load_jsonl(args.synthetic)
    peas = [] if args.skip_tier1 else _load_jsonl(args.peas)
    kape = [] if args.skip_tier1 else _load_jsonl(args.kape)
    hacktricks = [] if args.skip_tier1 else _load_jsonl(args.hacktricks)

    print(f"[load] existing v0p2 labeled: {len(existing)}", file=sys.stderr)
    print(f"[load] engagement-extracted: {len(extracted)}", file=sys.stderr)
    print(f"[load] engagement-synthetic: {len(synthetic)}", file=sys.stderr)
    print(f"[load] PEAS source mining:   {len(peas)}", file=sys.stderr)
    print(f"[load] KAPE target enum:     {len(kape)}", file=sys.stderr)
    print(f"[load] HackTricks book:      {len(hacktricks)}", file=sys.stderr)

    seen_paths: set[str] = set()
    merged: list[dict] = []
    dup_existing = dup_extracted = dup_synthetic = 0

    # Order matters: existing data wins on collisions (operator labels = truth).
    for rec in existing:
        path = rec.get("path", "")
        if not path:
            continue
        key = _normalize_path(path)
        if key in seen_paths:
            dup_existing += 1
            continue
        seen_paths.add(key)
        merged.append(_convert_existing_record(rec))

    sanity_drops: Counter = Counter()

    def _process_extracted_stream(records, origin, category, source):
        nonlocal dup_extracted
        n_kept = 0
        for rec in records:
            path = rec.get("verbatim_path", "")
            if not path:
                continue
            if not args.no_sanity_filter:
                ok, reason = _passes_sanity(rec)
                if not ok:
                    sanity_drops[reason] += 1
                    continue
            key = _normalize_path(path)
            if key in seen_paths:
                dup_extracted += 1
                continue
            seen_paths.add(key)
            merged.append(_convert_extracted_record(rec, origin, category, source))
            n_kept += 1
        return n_kept

    n_eng_kept = _process_extracted_stream(
        extracted, "extracted_engagement", "engagement_extracted",
        "engagement_article")
    n_peas_kept = _process_extracted_stream(
        peas, "tier1_peas", "tier1_extracted", "peas_source_mining")
    n_kape_kept = _process_extracted_stream(
        kape, "tier1_kape", "tier1_extracted", "kape_target")
    n_hacktricks_kept = _process_extracted_stream(
        hacktricks, "tier1_hacktricks", "tier1_extracted", "hacktricks_book")

    print(f"[tier1] kept after sanity filter: engagement={n_eng_kept}, "
          f"peas={n_peas_kept}, kape={n_kape_kept}, "
          f"hacktricks={n_hacktricks_kept}", file=sys.stderr)
    if sanity_drops:
        print(f"[sanity] dropped:", file=sys.stderr)
        for reason, n in sanity_drops.most_common():
            print(f"    {reason:35s} {n}", file=sys.stderr)

    for rec in synthetic:
        path = rec.get("path", "")
        if not path:
            continue
        key = _normalize_path(path)
        if key in seen_paths:
            dup_synthetic += 1
            continue
        seen_paths.add(key)
        merged.append(_convert_synthetic_record(rec))

    print(f"\n[merge] {len(merged)} unique records "
          f"(existing {len(existing) - dup_existing}, "
          f"+extracted {len(extracted) - dup_extracted}, "
          f"+synthetic {len(synthetic) - dup_synthetic})",
          file=sys.stderr)
    print(f"[merge] dropped duplicates: existing×extracted/synthetic={dup_extracted}, "
          f"existing×synthetic={dup_synthetic}", file=sys.stderr)

    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", encoding="utf-8") as fh:
        for rec in merged:
            fh.write(json.dumps(rec) + "\n")

    label_counts = Counter(r["label"] for r in merged)
    tier_counts = Counter(r.get("tier") for r in merged)
    origin_counts = Counter(r["v0p15_origin"] for r in merged)
    source_counts = Counter(r.get("source") for r in merged)

    print(f"\n[write] {len(merged)} records → {args.output}", file=sys.stderr)
    print(f"\n  Labels:", file=sys.stderr)
    for label, n in label_counts.most_common():
        print(f"    {label:12s} {n}", file=sys.stderr)
    print(f"\n  Tiers:", file=sys.stderr)
    for tier, n in tier_counts.most_common():
        print(f"    {str(tier):8s} {n}", file=sys.stderr)
    print(f"\n  v0p15 origin breakdown:", file=sys.stderr)
    for origin, n in origin_counts.most_common():
        print(f"    {origin:28s} {n}", file=sys.stderr)
    print(f"\n  Source breakdown (top 10):", file=sys.stderr)
    for source, n in source_counts.most_common(10):
        print(f"    {str(source):25s} {n}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
