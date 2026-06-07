"""v0.15 — extract credential paths from Eric Zimmerman's KAPE Targets.

KAPE (Kroll Artifact Parser and Extractor) ships YAML-style ``.tkape``
target files that enumerate forensically interesting paths to collect.
Authored by Eric Zimmerman and contributors — forensic-tooling gold
standard. Each target file lists:

- Description / category
- Path patterns (with FileMask, Recursive, etc.)
- Author + date

Direct enumeration of credential-relevant paths from the forensic
side. Complements attacker-side enumeration from PEAS.

Sources:
- Repo: https://github.com/EricZimmerman/KapeFiles
- Path: ``Targets/*.tkape`` (and ``Targets/**/*.tkape``)

Output schema matches ``regex_extract_paths_from_articles.py`` so the
downstream cleanup / corpus build pipeline works unchanged.

Usage::

    uv run python tools/scrape_kape_targets.py \\
        --output data/external/kape/extracted_paths.jsonl
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
    _apply_heuristics,
    _build_classifier,
)

KAPE_REPO_URL = "https://github.com/EricZimmerman/KapeFiles.git"
DEFAULT_OUTPUT = REPO_ROOT / "data" / "external" / "kape" / "extracted_paths.jsonl"

# Categories from KAPE target file names + descriptions that signal
# credential-relevant artifacts. Used as a category-context heuristic
# to boost tier for paths whose filenames don't match Snaffler rules.
_CRED_RELEVANT_CATEGORIES = {
    "credential", "password", "secret", "token", "key", "vault",
    "winhash", "passwd", "shadow", "nthash", "kerberos", "krb",
    "lsass", "ntds", "sam", "registry", "hive", "sysvol",
    "ssh", "rdp", "vnc", "putty", "winscp", "filezilla",
    "keystore", "wallet", "browser",
    "cyberark", "lastpass", "keepass", "1password", "bitwarden",
    "mimikatz", "secretsdump", "lazagne",
}


def _shallow_clone(target: Path) -> str:
    print(f"[clone] {KAPE_REPO_URL} → {target}", file=sys.stderr)
    subprocess.run(
        ["git", "clone", "--depth", "1", KAPE_REPO_URL, str(target)],
        check=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
    )
    sha = subprocess.run(
        ["git", "-C", str(target), "rev-parse", "HEAD"],
        check=True, capture_output=True, text=True,
    ).stdout.strip()
    print(f"[clone] commit={sha}", file=sys.stderr)
    return sha


def _parse_tkape(file_path: Path) -> dict:
    """Parse a .tkape file. Format is YAML-ish but not strict YAML —
    KAPE uses ``Key: Value`` lines and a ``Targets:`` block with
    ``-`` bullet items. We do a tolerant parse rather than depending
    on PyYAML."""
    out: dict = {"meta": {}, "targets": []}
    current_target: dict | None = None
    try:
        lines = file_path.read_text(encoding="utf-8", errors="replace").splitlines()
    except Exception:
        return out
    in_targets = False
    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if stripped.startswith("Targets:"):
            in_targets = True
            continue
        if not in_targets:
            # Meta block: "Key: Value"
            m = re.match(r"^([A-Za-z]+):\s*(.*)$", stripped)
            if m:
                out["meta"][m.group(1)] = m.group(2).strip()
            continue
        # In Targets block
        if stripped.startswith("-"):
            # Start of a new target item
            if current_target is not None:
                out["targets"].append(current_target)
            current_target = {}
            rest = stripped[1:].strip()
            if rest:
                m = re.match(r"^([A-Za-z]+):\s*(.*)$", rest)
                if m:
                    current_target[m.group(1)] = m.group(2).strip()
        else:
            m = re.match(r"^([A-Za-z]+):\s*(.*)$", stripped)
            if m and current_target is not None:
                current_target[m.group(1)] = m.group(2).strip()
    if current_target is not None:
        out["targets"].append(current_target)
    return out


def _build_path_candidates(target: dict) -> list[str]:
    """KAPE target gives us Path (a directory) + FileMask (a glob/filename
    pattern). For training-data purposes we synthesize concrete-looking
    paths by combining them: ``<path>\\<filemask-with-* dropped>``.

    The classifier downstream cares about filename signal, so this
    captures the credential intent even when the wildcard isn't resolved."""
    path = target.get("Path", "").strip().strip('"').strip("'")
    file_mask = target.get("FileMask", "").strip().strip('"').strip("'")
    if not path:
        return []
    # If FileMask is present, materialize one candidate per entry
    candidates: list[str] = []
    if file_mask:
        # FileMask can be comma-separated globs like ``*.evtx,*.evt``
        for mask in [m.strip() for m in file_mask.split(",") if m.strip()]:
            concrete = mask.replace("*", "x").replace("?", "x")
            sep = "\\" if "\\" in path else "/"
            if not path.endswith(sep):
                candidates.append(f"{path}{sep}{concrete}")
            else:
                candidates.append(f"{path}{concrete}")
    else:
        candidates.append(path)
    return candidates


def _category_signals_credential(meta: dict, target: dict) -> bool:
    blob = " ".join([
        str(meta.get("Description", "")),
        str(meta.get("Category", "")),
        str(target.get("Name", "")),
        str(target.get("Description", "")),
        str(target.get("Category", "")),
    ]).lower()
    return any(token in blob for token in _CRED_RELEVANT_CATEGORIES)


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
    n_targets = 0
    n_candidates = 0
    n_classified = 0
    n_category_bonus = 0
    n_unknown = 0
    tier_counts: Counter = Counter()
    rule_counts: Counter = Counter()
    out_fh = args.output.open("w", encoding="utf-8")

    with tempfile.TemporaryDirectory(prefix="kape_") as tmpdir:
        repo_root = Path(tmpdir) / "KapeFiles"
        sha = _shallow_clone(repo_root)
        targets_dir = repo_root / "Targets"
        if not targets_dir.exists():
            print(f"ERROR: {targets_dir} not in cloned repo", file=sys.stderr)
            return 2

        for tkape_file in sorted(targets_dir.rglob("*.tkape")):
            n_files += 1
            parsed = _parse_tkape(tkape_file)
            meta = parsed.get("meta", {})
            for target in parsed.get("targets", []):
                n_targets += 1
                category_cred = _category_signals_credential(meta, target)
                for path in _build_path_candidates(target):
                    n_candidates += 1
                    result = classify(path)
                    if result is None:
                        result = _apply_heuristics(path)
                    if result is None and category_cred:
                        # KAPE target's category context says this IS
                        # credential-relevant — use the category signal
                        # to assign a conservative Yellow tier.
                        result = ("Yellow", None, "kape_category_signal")
                        n_category_bonus += 1
                    if result is None:
                        n_unknown += 1
                        continue
                    tier, cred_type, rule_name = result
                    rec = {
                        "source_url": f"https://github.com/EricZimmerman/KapeFiles/blob/master/Targets/"
                                      f"{tkape_file.relative_to(targets_dir)}",
                        "source_title": meta.get("Description", tkape_file.stem),
                        "source": "kape_target",
                        "verbatim_path": path,
                        "context_excerpt": (
                            f"KAPE target '{target.get('Name', '')}' "
                            f"(category: {meta.get('Category', '')}, "
                            f"description: {meta.get('Description', '')[:100]})"
                        ),
                        "discovery_type": "kape_target_enumeration",
                        "share_context": "unknown",
                        "tier": tier,
                        "credential_type": cred_type,
                        "matched_rule": rule_name,
                        "verbatim_match_quality": "exact",
                        "model": "kape_target+snaffler_rules+heuristics",
                        "kape_target_name": target.get("Name"),
                        "kape_target_category": meta.get("Category"),
                        "kape_commit_sha": sha,
                        "extracted_at": now,
                    }
                    out_fh.write(json.dumps(rec) + "\n")
                    n_classified += 1
                    tier_counts[tier] += 1
                    rule_counts[rule_name] += 1

    out_fh.close()
    print(f"\n[final] {n_files} .tkape files, {n_targets} targets parsed",
          file=sys.stderr)
    print(f"        {n_candidates} candidate paths", file=sys.stderr)
    print(f"        {n_classified} classified → {args.output}", file=sys.stderr)
    print(f"          (incl. {n_category_bonus} via KAPE category signal)",
          file=sys.stderr)
    print(f"        {n_unknown} unclassified", file=sys.stderr)
    print(f"\n  Tier distribution:", file=sys.stderr)
    for tier, n in tier_counts.most_common():
        print(f"    {tier:8s} {n}", file=sys.stderr)
    print(f"\n  Top matched rules:", file=sys.stderr)
    for rule, n in rule_counts.most_common(12):
        print(f"    {rule:35s} {n}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
