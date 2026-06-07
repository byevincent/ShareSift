"""v0.15 — extract credential paths from LinPEAS + WinPEAS source.

PEAS (Privilege Escalation Awesome Scripts) is the de facto privilege
escalation toolkit. The scripts have HUNDREDS of credential-bearing
paths hardcoded — these are paths working pentesters and red teamers
deliberately check on every engagement. High-signal, high-confidence
training data for the path classifier.

Sources:
- LinPEAS: ``linPEAS/linpeas.sh`` (and any ``Checks/`` if present)
- WinPEAS: ``winPEAS/winPEASexe/winPEAS/Info/*`` (C# source with
  hardcoded path lists)

Output schema matches ``regex_extract_paths_from_articles.py`` so the
downstream cleanup / corpus build pipeline works unchanged. ``source``
is set to ``peas_linpeas`` or ``peas_winpeas`` for provenance.

Usage::

    uv run python tools/scrape_peas_paths.py \\
        --output data/external/peas/extracted_paths.jsonl
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

# Reuse the regex extraction + Snaffler-rules + heuristic classifier
from regex_extract_paths_from_articles import (
    _extract_paths_from_text,
    _apply_heuristics,
    _build_classifier,
    _context_excerpt,
)

PEASS_REPO_URL = "https://github.com/carlospolop/PEASS-ng.git"
DEFAULT_OUTPUT = REPO_ROOT / "data" / "external" / "peas" / "extracted_paths.jsonl"


def _shallow_clone(target: Path) -> str:
    """Shallow-clone PEASS-ng; return HEAD SHA."""
    print(f"[clone] {PEASS_REPO_URL} → {target}", file=sys.stderr)
    subprocess.run(
        ["git", "clone", "--depth", "1", PEASS_REPO_URL, str(target)],
        check=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
    )
    sha = subprocess.run(
        ["git", "-C", str(target), "rev-parse", "HEAD"],
        check=True, capture_output=True, text=True,
    ).stdout.strip()
    print(f"[clone] commit={sha}", file=sys.stderr)
    return sha


def _walk_peas_files(repo_root: Path):
    """Yield (file_path, source_label, source_url_template) for each PEAS
    source file we want to scrape paths from."""
    linpeas_dir = repo_root / "linPEAS"
    winpeas_dir = repo_root / "winPEAS"
    # LinPEAS main script + any builder fragments
    for f in sorted(linpeas_dir.rglob("*.sh")):
        yield f, "peas_linpeas", f"https://github.com/carlospolop/PEASS-ng/blob/master/linPEAS/{f.relative_to(linpeas_dir)}"
    for f in sorted(linpeas_dir.rglob("*.py")):
        yield f, "peas_linpeas", f"https://github.com/carlospolop/PEASS-ng/blob/master/linPEAS/{f.relative_to(linpeas_dir)}"
    # WinPEAS: pull C# source where path lists live
    for f in sorted(winpeas_dir.rglob("*.cs")):
        yield f, "peas_winpeas", f"https://github.com/carlospolop/PEASS-ng/blob/master/winPEAS/{f.relative_to(winpeas_dir)}"


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
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
    source_counts: Counter = Counter()
    out_fh = args.output.open("w", encoding="utf-8")

    with tempfile.TemporaryDirectory(prefix="peas_") as tmpdir:
        repo_root = Path(tmpdir) / "PEASS-ng"
        sha = _shallow_clone(repo_root)
        for file_path, source_label, source_url in _walk_peas_files(repo_root):
            try:
                text = file_path.read_text(encoding="utf-8", errors="replace")
            except Exception:
                continue
            n_files += 1
            candidates = _extract_paths_from_text(text)
            seen: set[str] = set()
            for path, start, end in candidates:
                n_candidates += 1
                if path in seen:
                    continue
                seen.add(path)
                result = classify(path)
                if result is None:
                    result = _apply_heuristics(path)
                base = {
                    "source_url": source_url,
                    "source_title": file_path.name,
                    "source": source_label,
                    "verbatim_path": path,
                    "context_excerpt": _context_excerpt(text, start, end),
                    "discovery_type": "peas_hardcoded_check",
                    "share_context": "unknown",
                    "verbatim_match_quality": "exact",
                    "model": "regex+snaffler_rules+heuristics",
                    "peas_commit_sha": sha,
                    "extracted_at": now,
                }
                if result is None:
                    base["tier"] = None
                    base["credential_type"] = None
                    base["matched_rule"] = None
                    n_unknown += 1
                    continue
                tier, cred_type, rule_name = result
                base["tier"] = tier
                base["credential_type"] = cred_type
                base["matched_rule"] = rule_name
                out_fh.write(json.dumps(base) + "\n")
                n_classified += 1
                tier_counts[tier] += 1
                rule_counts[rule_name] += 1
                source_counts[source_label] += 1

    out_fh.close()
    print(f"\n[final] {n_files} PEAS source files scanned", file=sys.stderr)
    print(f"        {n_candidates} candidate paths extracted", file=sys.stderr)
    print(f"        {n_classified} classified → {args.output}", file=sys.stderr)
    print(f"        {n_unknown} unclassified (dropped)", file=sys.stderr)
    print(f"\n  Tier distribution:", file=sys.stderr)
    for tier, n in tier_counts.most_common():
        print(f"    {tier:8s} {n}", file=sys.stderr)
    print(f"\n  Source breakdown:", file=sys.stderr)
    for src, n in source_counts.most_common():
        print(f"    {src:18s} {n}", file=sys.stderr)
    print(f"\n  Top matched rules:", file=sys.stderr)
    for rule, n in rule_counts.most_common(12):
        print(f"    {rule:35s} {n}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
