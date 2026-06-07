"""v0.15 — extract credential paths from the HackTricks book.

HackTricks is the pentester reference manual. Its credential-discovery
pages enumerate file locations across Windows / Linux / cloud /
container stacks. Direct enumeration of where credentials live in the
wild — closer to real-engagement coverage than HTB writeups.

Source: ``https://github.com/HackTricks-wiki/hacktricks`` (markdown
source for the book.hacktricks.xyz site).

Strategy: shallow-clone, walk all ``.md`` files, run the regex
extractor + Snaffler-rules + heuristic classifier (same pipeline as
``regex_extract_paths_from_articles.py``). Optional: filter to pages
whose path or title contains credential-relevant keywords to reduce
noise, but the per-path classifier should already drop irrelevant
matches.

Output schema matches the other extractors so downstream cleanup +
corpus build pick it up uniformly.

Usage::

    uv run python tools/scrape_hacktricks.py \\
        --output data/external/hacktricks/extracted_paths.jsonl
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import tempfile
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "tools"))
sys.path.insert(0, str(REPO_ROOT / "references" / "pysnaffler"))
sys.path.insert(0, str(REPO_ROOT / "src"))

from regex_extract_paths_from_articles import (
    _extract_paths_from_text,
    _apply_heuristics,
    _build_classifier,
    _context_excerpt,
)

HACKTRICKS_REPO_URL = "https://github.com/HackTricks-wiki/hacktricks.git"
DEFAULT_OUTPUT = REPO_ROOT / "data" / "external" / "hacktricks" / "extracted_paths.jsonl"

# Subdirectories more likely to mention credential paths. Empty list
# scans everything; default skips obvious non-credential sections to
# cut noise + scrape time.
_PRIORITY_DIRS = [
    "windows-hardening",
    "linux-hardening",
    "macos-hardening",
    "pentesting-active-directory-methodology",
    "pentesting-cloud",
    "pentesting-web",
    "network-services-pentesting",
    "binary-exploitation",
    "credentials",
    "mobile-pentesting",
    "post-exploitation",
]


def _shallow_clone(target: Path) -> str:
    print(f"[clone] {HACKTRICKS_REPO_URL} → {target} (shallow)", file=sys.stderr)
    subprocess.run(
        ["git", "clone", "--depth", "1", HACKTRICKS_REPO_URL, str(target)],
        check=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
    )
    sha = subprocess.run(
        ["git", "-C", str(target), "rev-parse", "HEAD"],
        check=True, capture_output=True, text=True,
    ).stdout.strip()
    print(f"[clone] commit={sha}", file=sys.stderr)
    return sha


def _walk_markdown(repo_root: Path, priority_only: bool):
    if not priority_only:
        for f in sorted(repo_root.rglob("*.md")):
            yield f
        return
    # Priority mode: skip obvious non-credential sections to save time
    skip_dirs = {".github", "node_modules", "translations"}
    for f in sorted(repo_root.rglob("*.md")):
        rel = f.relative_to(repo_root)
        parts = rel.parts
        if any(p in skip_dirs for p in parts):
            continue
        # If --priority-only, only emit files in priority dirs OR at repo root
        if len(parts) == 1:
            yield f
            continue
        if parts[0] in _PRIORITY_DIRS:
            yield f


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    p.add_argument("--scan-all", action="store_true",
                   help="Scan all .md files. Default scans only priority "
                        "subdirs (credential-relevant ones) to cut time")
    args = p.parse_args(argv)

    args.output.parent.mkdir(parents=True, exist_ok=True)
    print(f"[load-rules] loading ported Snaffler ruleset...", file=sys.stderr)
    classify = _build_classifier()
    print(f"[load-rules] ready", file=sys.stderr)

    now = datetime.now(timezone.utc).isoformat()
    n_files = 0
    n_candidates = 0
    n_classified = 0
    n_unknown = 0
    tier_counts: Counter = Counter()
    rule_counts: Counter = Counter()
    out_fh = args.output.open("w", encoding="utf-8")

    with tempfile.TemporaryDirectory(prefix="hacktricks_") as tmpdir:
        repo_root = Path(tmpdir) / "hacktricks"
        sha = _shallow_clone(repo_root)
        for md_file in _walk_markdown(repo_root, priority_only=not args.scan_all):
            try:
                text = md_file.read_text(encoding="utf-8", errors="replace")
            except Exception:
                continue
            n_files += 1
            candidates = _extract_paths_from_text(text)
            seen: set[str] = set()
            rel_path = md_file.relative_to(repo_root)
            source_url = f"https://github.com/HackTricks-wiki/hacktricks/blob/master/{rel_path}"
            for path, start, end in candidates:
                n_candidates += 1
                if path in seen:
                    continue
                seen.add(path)
                result = classify(path)
                if result is None:
                    result = _apply_heuristics(path)
                if result is None:
                    n_unknown += 1
                    continue
                tier, cred_type, rule_name = result
                out_fh.write(json.dumps({
                    "source_url": source_url,
                    "source_title": md_file.stem,
                    "source": "hacktricks",
                    "verbatim_path": path,
                    "context_excerpt": _context_excerpt(text, start, end),
                    "discovery_type": "hacktricks_enumeration",
                    "share_context": "unknown",
                    "tier": tier,
                    "credential_type": cred_type,
                    "matched_rule": rule_name,
                    "verbatim_match_quality": "exact",
                    "model": "regex+snaffler_rules+heuristics",
                    "hacktricks_section": str(rel_path.parts[0]) if len(rel_path.parts) > 1 else "root",
                    "hacktricks_commit_sha": sha,
                    "extracted_at": now,
                }) + "\n")
                n_classified += 1
                tier_counts[tier] += 1
                rule_counts[rule_name] += 1
            if n_files % 200 == 0:
                print(f"  [progress] {n_files} markdown files, "
                      f"{n_classified} classified", file=sys.stderr)

    out_fh.close()
    print(f"\n[final] {n_files} markdown files scanned", file=sys.stderr)
    print(f"        {n_candidates} candidate paths", file=sys.stderr)
    print(f"        {n_classified} classified → {args.output}", file=sys.stderr)
    print(f"        {n_unknown} unclassified", file=sys.stderr)
    print(f"\n  Tier distribution:", file=sys.stderr)
    for tier, n in tier_counts.most_common():
        print(f"    {tier:8s} {n}", file=sys.stderr)
    print(f"\n  Top matched rules:", file=sys.stderr)
    for rule, n in rule_counts.most_common(15):
        print(f"    {rule:35s} {n}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
