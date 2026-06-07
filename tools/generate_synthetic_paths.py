"""v0.15 Phase D — synthetic path generator for the path-classifier retrain.

Takes the extracted real paths from
``tools/extract_paths_from_articles.py`` and recombines their
components (share roots, intermediate dirs, credential filenames) to
generate a 10–50× larger training corpus that covers the install-path
variation v0.12's path classifier failed to generalize across.

Why this matters: v0.12 confirmed Truffler missed ``wp-config.php`` at
``\\\\host\\share\\wamp\\apps\\phpmyadmin3.4.10.1\\config.inc.php`` —
the filename was in training but at HTB-shallow depths; the versioned
install directory and depth-5 nesting broke generalization. Synthetic
recombination puts known credential filenames at varied depths inside
varied install paths so the classifier learns the filename signal
robustly to intermediate noise.

**Critical leakage control:** the held-out evaluation set (your
HTB/VulnLab notes, when you mine them) must NEVER appear in either the
component pools OR the generated synthetic paths. The generator
respects an exclusion list via ``--exclude-source``.

Generation strategy (composable via flags):

- **recombination** (default): swap share roots + intermediate sequences
  while keeping credential filenames as the positive-class anchor
- **versioning**: replace version stamps in intermediate dirs with
  alternative versions (e.g., ``phpmyadmin3.4.10.1`` → ``phpmyadmin5.2.0``)
- **case_variation**: case-fold intermediate dir names with realistic
  variations (``Program Files`` ↔ ``program files`` ↔ ``ProgramFiles``)
- **depth_variation**: insert/remove intermediate dirs to vary path
  depth around the credential filename
- **drive_drift**: vary admin-share drive letter (C$/D$/E$)

Output schema (compatible with the existing path-classifier training
pipeline; ``source=synthetic`` lets the trainer filter for ablations)::

    {
        "path": "\\\\\\\\fileserver\\\\IT\\\\webapps\\\\prod\\\\wp-config.php",
        "label": "juicy" | "not_juicy",
        "tier": "Black" | "Red" | "Yellow" | "None",
        "credential_type": "config_secret" | ... | null,
        "source": "synthetic",
        "components": {
            "share_root": "\\\\\\\\fileserver\\\\IT",
            "intermediate": ["webapps", "prod"],
            "filename": "wp-config.php"
        },
        "provenance": {
            "filename_source_url": "https://...",
            "share_root_source_url": "https://...",
            "generation_modes": ["recombination", "versioning"]
        }
    }

Usage::

    uv run python tools/generate_synthetic_paths.py \\
        --input data/external/engagement_corpus/extracted_paths.jsonl \\
        --output data/external/engagement_corpus/synthetic_paths.jsonl \\
        --target-count 50000 \\
        --positive-fraction 0.30 \\
        --seed 2026
"""

from __future__ import annotations

import argparse
import json
import random
import re
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_INPUT = REPO_ROOT / "data" / "external" / "engagement_corpus" / "extracted_paths.jsonl"
DEFAULT_OUTPUT = REPO_ROOT / "data" / "external" / "engagement_corpus" / "synthetic_paths.jsonl"


# ---------------------------------------------------------------------------
# Path decomposition
# ---------------------------------------------------------------------------

@dataclass
class PathComponents:
    share_root: str          # \\host\share OR just / (linux)
    intermediate: list[str]  # ['Program Files', 'Rails_Server', 'config']
    filename: str            # 'database.yml'
    is_windows: bool


_UNC_RE = re.compile(r"^(\\\\[^\\]+\\[^\\]+)\\(.*)$")
_DRIVE_RE = re.compile(r"^([A-Za-z]:\\)(.*)$")


def _decompose_path(path: str) -> PathComponents | None:
    """Split a path into (share_root, intermediate_dirs, filename).

    Returns None for paths that look malformed (no separators, URLs, etc.)."""
    if not path or path.startswith(("http://", "https://", "ftp://")):
        return None
    p = path.strip()
    # UNC: \\host\share\path
    m = _UNC_RE.match(p)
    if m:
        share_root, tail = m.group(1), m.group(2)
        if "\\" not in tail:
            # Just \\host\share\file with no intermediate dirs
            return PathComponents(share_root, [], tail, is_windows=True)
        parts = tail.split("\\")
        return PathComponents(share_root, parts[:-1], parts[-1], is_windows=True)
    # Drive-letter: C:\path
    m = _DRIVE_RE.match(p)
    if m:
        share_root, tail = m.group(1).rstrip("\\"), m.group(2)
        if "\\" not in tail:
            return PathComponents(share_root, [], tail, is_windows=True)
        parts = tail.split("\\")
        return PathComponents(share_root, parts[:-1], parts[-1], is_windows=True)
    # Linux: /path/to/file
    if p.startswith("/"):
        parts = p.split("/")
        # parts[0] is empty (leading /)
        if len(parts) <= 1:
            return None
        return PathComponents("/", parts[1:-1], parts[-1], is_windows=False)
    return None


def _compose_path(parts: PathComponents) -> str:
    sep = "\\" if parts.is_windows else "/"
    inter = sep.join(parts.intermediate) if parts.intermediate else ""
    if parts.is_windows:
        prefix = parts.share_root + sep
        return prefix + (inter + sep if inter else "") + parts.filename
    else:
        if parts.share_root == "/":
            return "/" + (inter + "/" if inter else "") + parts.filename
        return parts.share_root + "/" + (inter + "/" if inter else "") + parts.filename


# ---------------------------------------------------------------------------
# Component pools
# ---------------------------------------------------------------------------

@dataclass
class ExtractedRecord:
    path: str
    tier: str | None
    credential_type: str | None
    source_url: str
    components: PathComponents


def _load_extracted(path: Path) -> list[ExtractedRecord]:
    records: list[ExtractedRecord] = []
    with path.open(encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                r = json.loads(line)
            except json.JSONDecodeError:
                continue
            vpath = r.get("verbatim_path", "")
            comps = _decompose_path(vpath)
            if comps is None:
                continue
            records.append(ExtractedRecord(
                path=vpath,
                tier=r.get("tier"),
                credential_type=r.get("credential_type"),
                source_url=r.get("source_url", ""),
                components=comps,
            ))
    return records


# ---------------------------------------------------------------------------
# Noise modes
# ---------------------------------------------------------------------------

_VERSION_RE = re.compile(r"(\d+(?:\.\d+){1,3})")
_ALT_VERSIONS = [
    "1.0", "1.2.3", "2.0", "2.5.1", "3.4.10.1", "5.2.0", "5.6.40",
    "7.0.0", "8.0.30", "10.4.24", "11.0.20", "12.0.5",
]


def _apply_versioning(intermediate: list[str], rng: random.Random) -> list[str]:
    out = []
    for seg in intermediate:
        m = _VERSION_RE.search(seg)
        if m and rng.random() < 0.6:
            new_ver = rng.choice(_ALT_VERSIONS)
            seg = seg[: m.start()] + new_ver + seg[m.end():]
        out.append(seg)
    return out


def _apply_case_variation(intermediate: list[str], rng: random.Random) -> list[str]:
    """Vary case across intermediate dirs. Real shares have ProgramFiles,
    Program Files, program files, programfiles — the classifier needs
    robustness to all."""
    out = []
    for seg in intermediate:
        r = rng.random()
        if r < 0.25:
            out.append(seg.lower())
        elif r < 0.40:
            out.append(seg.upper())
        elif r < 0.55:
            out.append(seg.replace(" ", ""))  # ProgramFiles
        else:
            out.append(seg)
    return out


_PLAUSIBLE_INSERTS = [
    "production", "prod", "dev", "test", "staging",
    "v1", "v2", "current", "latest",
    "internal", "external", "public",
    "backup", "live",
]


def _apply_depth_variation(intermediate: list[str], rng: random.Random) -> list[str]:
    if rng.random() < 0.3 and len(intermediate) >= 2:
        # Remove a random middle component
        idx = rng.randint(1, len(intermediate) - 1)
        return intermediate[:idx] + intermediate[idx+1:]
    if rng.random() < 0.4:
        # Insert a plausible component
        idx = rng.randint(0, len(intermediate))
        inserted = rng.choice(_PLAUSIBLE_INSERTS)
        return intermediate[:idx] + [inserted] + intermediate[idx:]
    return list(intermediate)


_ALT_DRIVES = ["C$", "D$", "E$", "F$"]


def _apply_drive_drift(share_root: str, rng: random.Random) -> str:
    # Match \\host\C$ → \\host\D$ etc.
    m = re.match(r"^(\\\\[^\\]+\\)([A-Za-z])\$$", share_root)
    if m and rng.random() < 0.4:
        new_drive = rng.choice(_ALT_DRIVES)
        return m.group(1) + new_drive
    # Match drive-letter C: → D:
    m = re.match(r"^([A-Za-z]):$", share_root)
    if m and rng.random() < 0.4:
        return rng.choice(["C:", "D:", "E:"])
    return share_root


# ---------------------------------------------------------------------------
# Generation
# ---------------------------------------------------------------------------

def _is_credential_filename(record: ExtractedRecord) -> bool:
    """Treat a filename as 'credential-bearing' iff it has a non-None tier
    and a credential_type. These are the positive-class anchors."""
    return (
        record.tier in ("Black", "Red", "Yellow")
        and record.credential_type is not None
    )


_KNOWN_NOT_JUICY_FILENAMES = [
    "index.html", "index.php", "favicon.ico", "style.css", "main.js",
    "robots.txt", "sitemap.xml", "README.md", "LICENSE",
    "thumbs.db", "desktop.ini",
    "httpd.exe", "nginx.exe", "library.dll", "user32.dll",
    "kernel32.dll", "msvcrt.dll", "vcruntime140.dll",
    "icon.png", "logo.svg", "banner.jpg", "header.png",
    "package.json", "yarn.lock", "package-lock.json",  # could be juicy, treated as edge
    "Dockerfile",  # could be juicy via secrets; tier=None default
]


def _make_negative(
    record: ExtractedRecord,
    share_pool: list[tuple[str, str]],
    intermediate_pool: list[tuple[list[str], str]],
    rng: random.Random,
    modes: list[str],
) -> dict:
    """Generate a not_juicy synthetic path by combining a real share root
    with intermediates from a different article + a known non-juicy filename."""
    share_root, share_src = rng.choice(share_pool) if share_pool else (record.components.share_root, record.source_url)
    intermediate, inter_src = rng.choice(intermediate_pool) if intermediate_pool else (record.components.intermediate, record.source_url)
    intermediate = list(intermediate)
    filename = rng.choice(_KNOWN_NOT_JUICY_FILENAMES)
    if "versioning" in modes:
        intermediate = _apply_versioning(intermediate, rng)
    if "case_variation" in modes:
        intermediate = _apply_case_variation(intermediate, rng)
    if "depth_variation" in modes:
        intermediate = _apply_depth_variation(intermediate, rng)
    if "drive_drift" in modes:
        share_root = _apply_drive_drift(share_root, rng)
    is_win = "\\" in share_root or share_root.endswith(":")
    comps = PathComponents(share_root, intermediate, filename, is_windows=is_win)
    return {
        "path": _compose_path(comps),
        "label": "not_juicy",
        "tier": "None",
        "credential_type": None,
        "source": "synthetic",
        "components": {
            "share_root": share_root,
            "intermediate": intermediate,
            "filename": filename,
        },
        "provenance": {
            "filename_source_url": None,
            "share_root_source_url": share_src,
            "generation_modes": modes,
        },
    }


def _make_positive(
    record: ExtractedRecord,
    share_pool: list[tuple[str, str]],
    intermediate_pool: list[tuple[list[str], str]],
    rng: random.Random,
    modes: list[str],
) -> dict:
    """Generate a juicy synthetic path: keep credential filename + tier
    from the seed record, swap share root and intermediate from random
    other articles."""
    share_root, share_src = rng.choice(share_pool) if share_pool else (record.components.share_root, record.source_url)
    intermediate, inter_src = rng.choice(intermediate_pool) if intermediate_pool else (record.components.intermediate, record.source_url)
    intermediate = list(intermediate)
    if "versioning" in modes:
        intermediate = _apply_versioning(intermediate, rng)
    if "case_variation" in modes:
        intermediate = _apply_case_variation(intermediate, rng)
    if "depth_variation" in modes:
        intermediate = _apply_depth_variation(intermediate, rng)
    if "drive_drift" in modes:
        share_root = _apply_drive_drift(share_root, rng)
    is_win = "\\" in share_root or share_root.endswith(":")
    comps = PathComponents(share_root, intermediate, record.components.filename, is_windows=is_win)
    return {
        "path": _compose_path(comps),
        "label": "juicy",
        "tier": record.tier or "Red",
        "credential_type": record.credential_type,
        "source": "synthetic",
        "components": {
            "share_root": share_root,
            "intermediate": intermediate,
            "filename": record.components.filename,
        },
        "provenance": {
            "filename_source_url": record.source_url,
            "share_root_source_url": share_src,
            "generation_modes": modes,
        },
    }


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--input", type=Path, default=DEFAULT_INPUT,
                   help="extracted_paths.jsonl from extract_paths_from_articles.py")
    p.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    p.add_argument("--target-count", type=int, default=50000,
                   help="Total synthetic paths to generate")
    p.add_argument("--positive-fraction", type=float, default=0.30,
                   help="Fraction of output that should be juicy/positive")
    p.add_argument("--modes", default="recombination,versioning,case_variation,depth_variation,drive_drift",
                   help="Comma-separated noise modes to apply")
    p.add_argument("--exclude-source", action="append", default=None,
                   help="Source URL substring to exclude from component pools "
                        "(repeatable). Use for held-out eval data leak prevention.")
    p.add_argument("--seed", type=int, default=2026)
    p.add_argument("--min-share-pool", type=int, default=20,
                   help="Refuse to run if fewer than this many distinct share roots "
                        "are available — too small a pool produces unrealistic noise.")
    args = p.parse_args(argv)

    if not args.input.exists():
        print(f"ERROR: --input missing: {args.input}", file=sys.stderr)
        return 2

    modes = [m.strip() for m in args.modes.split(",") if m.strip()]
    rng = random.Random(args.seed)

    records = _load_extracted(args.input)
    print(f"[load] {len(records)} extracted path records", file=sys.stderr)
    if args.exclude_source:
        before = len(records)
        records = [
            r for r in records
            if not any(excl in r.source_url for excl in args.exclude_source)
        ]
        print(f"[exclude] dropped {before - len(records)} records "
              f"from {len(args.exclude_source)} excluded sources", file=sys.stderr)

    if not records:
        print("ERROR: no extracted records after filtering", file=sys.stderr)
        return 2

    # Build component pools
    share_pool: list[tuple[str, str]] = []
    intermediate_pool: list[tuple[list[str], str]] = []
    seen_shares: set[str] = set()
    seen_inters: set[tuple] = set()
    for r in records:
        if r.components.share_root and r.components.share_root not in seen_shares:
            share_pool.append((r.components.share_root, r.source_url))
            seen_shares.add(r.components.share_root)
        key = tuple(r.components.intermediate)
        if r.components.intermediate and key not in seen_inters:
            intermediate_pool.append((r.components.intermediate, r.source_url))
            seen_inters.add(key)

    print(f"[pool] {len(share_pool)} distinct share roots, "
          f"{len(intermediate_pool)} distinct intermediate sequences",
          file=sys.stderr)

    if len(share_pool) < args.min_share_pool:
        print(f"WARN: share pool ({len(share_pool)}) below --min-share-pool "
              f"({args.min_share_pool}). Generated paths will be repetitive. "
              f"Continue anyway? (set --min-share-pool 0 to silence)",
              file=sys.stderr)
        if args.min_share_pool > 0:
            return 2

    # Credential-bearing records become positive-class seeds
    positive_seeds = [r for r in records if _is_credential_filename(r)]
    print(f"[seeds] {len(positive_seeds)} credential-bearing positive seeds",
          file=sys.stderr)
    if not positive_seeds:
        print("ERROR: no positive seeds with tier + credential_type. "
              "Check the extraction output.", file=sys.stderr)
        return 2

    n_positive = int(args.target_count * args.positive_fraction)
    n_negative = args.target_count - n_positive
    print(f"[plan] generating {n_positive} positives + {n_negative} negatives "
          f"= {args.target_count} total", file=sys.stderr)

    args.output.parent.mkdir(parents=True, exist_ok=True)
    out_fh = args.output.open("w", encoding="utf-8")
    n_pos_written = 0
    n_neg_written = 0
    deduper: set[str] = set()

    try:
        for _ in range(n_positive * 3):  # over-generate to absorb dup-rejection
            if n_pos_written >= n_positive:
                break
            seed = rng.choice(positive_seeds)
            rec = _make_positive(seed, share_pool, intermediate_pool, rng, modes)
            if rec["path"] in deduper:
                continue
            deduper.add(rec["path"])
            out_fh.write(json.dumps(rec) + "\n")
            n_pos_written += 1
        for _ in range(n_negative * 3):
            if n_neg_written >= n_negative:
                break
            seed = rng.choice(records)
            rec = _make_negative(seed, share_pool, intermediate_pool, rng, modes)
            if rec["path"] in deduper:
                continue
            deduper.add(rec["path"])
            out_fh.write(json.dumps(rec) + "\n")
            n_neg_written += 1
    finally:
        out_fh.close()

    print(f"\n[final] wrote {n_pos_written + n_neg_written} synthetic paths "
          f"({n_pos_written} positive, {n_neg_written} negative) → {args.output}",
          file=sys.stderr)
    print(f"[final] tier distribution among positives:", file=sys.stderr)
    # Re-read to summarize
    tier_counts: Counter = Counter()
    cred_type_counts: Counter = Counter()
    with args.output.open(encoding="utf-8") as fh:
        for line in fh:
            try:
                r = json.loads(line)
            except json.JSONDecodeError:
                continue
            if r["label"] == "juicy":
                tier_counts[r["tier"]] += 1
                if r["credential_type"]:
                    cred_type_counts[r["credential_type"]] += 1
    for tier, n in tier_counts.most_common():
        print(f"    {tier:8s} {n}", file=sys.stderr)
    print(f"[final] credential_type breakdown:", file=sys.stderr)
    for ct, n in cred_type_counts.most_common(10):
        print(f"    {ct:25s} {n}", file=sys.stderr)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
