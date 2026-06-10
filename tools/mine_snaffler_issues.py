"""v0.47 step 1: mine SnaffCon/Snaffler issue tracker for benchmark signal.

The premise (full reasoning in docs/v0p46_results.md trailing
section): we don't have a real corporate-share benchmark, but five
years of Snaffler bug reports is the closest free proxy. Each
"Snaffler missed X" issue is a real-world false negative; each
"Snaffler false-positived Y" is a real-world false positive. Mining
both gives us a labeled benchmark that's biased toward "things that
mattered enough for an operator to file a bug" — exactly the
distribution we care about.

This script does ONE thing: fetch every issue + PR from
``SnaffCon/Snaffler`` and save raw JSON to
``benchmarks/snaffler_issues/raw/``. Classification, extraction, and
benchmark assembly are downstream steps.

Usage:

    uv run python tools/mine_snaffler_issues.py

Requires ``gh`` (already used elsewhere in this repo for release
management). No API key needed — falls through to the same auth as
``gh api``.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

REPO = "SnaffCon/Snaffler"
RAW_DIR = Path(__file__).resolve().parent.parent / "benchmarks" / "snaffler_issues" / "raw"


def _gh_api_paginate(endpoint: str) -> list[dict]:
    """Fetch a paginated REST endpoint via ``gh api --paginate``.

    Returns the merged list of records.
    """
    cmd = ["gh", "api", "--paginate", endpoint]
    proc = subprocess.run(cmd, capture_output=True, text=True, check=True)
    # gh api --paginate concatenates JSON arrays as separate JSON values
    # on the same stream. Parse them all and flatten.
    decoder = json.JSONDecoder()
    text = proc.stdout
    records: list[dict] = []
    pos = 0
    while pos < len(text):
        while pos < len(text) and text[pos] in " \n\r\t":
            pos += 1
        if pos >= len(text):
            break
        value, end = decoder.raw_decode(text, pos)
        if isinstance(value, list):
            records.extend(value)
        else:
            records.append(value)
        pos = end
    return records


def _fetch_issue_comments(issue_number: int) -> list[dict]:
    """Fetch all comments on a single issue."""
    endpoint = f"repos/{REPO}/issues/{issue_number}/comments?per_page=100"
    return _gh_api_paginate(endpoint)


def main() -> int:
    RAW_DIR.mkdir(parents=True, exist_ok=True)

    # 1. Fetch all issues (REST /issues includes PRs).
    print(f"Fetching issues from {REPO} (open + closed)...")
    issues = _gh_api_paginate(f"repos/{REPO}/issues?state=all&per_page=100")
    issues_path = RAW_DIR / "issues.json"
    issues_path.write_text(json.dumps(issues, indent=2), encoding="utf-8")
    print(f"  Wrote {len(issues)} records → {issues_path}")

    # Split issues vs PRs for downstream convenience. /issues marks PRs
    # by presence of a ``pull_request`` key.
    pure_issues = [i for i in issues if "pull_request" not in i]
    pull_requests = [i for i in issues if "pull_request" in i]
    print(f"  → {len(pure_issues)} issues, {len(pull_requests)} PRs")

    # 2. Fetch comments per issue (a lot of detail lives in followups).
    print("Fetching comments per issue...")
    comments_dir = RAW_DIR / "comments"
    comments_dir.mkdir(exist_ok=True)
    fetched = 0
    skipped = 0
    for issue in pure_issues:
        if issue.get("comments", 0) == 0:
            skipped += 1
            continue
        num = issue["number"]
        out = comments_dir / f"{num}.json"
        if out.exists():
            skipped += 1
            continue
        try:
            comments = _fetch_issue_comments(num)
        except subprocess.CalledProcessError as e:
            print(f"  WARN: issue #{num} comments fetch failed: {e}", file=sys.stderr)
            continue
        out.write_text(json.dumps(comments, indent=2), encoding="utf-8")
        fetched += 1
    print(f"  Fetched comments for {fetched} issues, skipped {skipped}")

    # 3. Print a quick summary of the data we now have.
    print()
    print("=== Summary ===")
    print(f"Total records: {len(issues)}")
    print(f"  Pure issues: {len(pure_issues)}")
    print(f"    Open: {sum(1 for i in pure_issues if i['state'] == 'open')}")
    print(f"    Closed: {sum(1 for i in pure_issues if i['state'] == 'closed')}")
    print(f"  Pull requests: {len(pull_requests)}")
    label_counts: dict[str, int] = {}
    for i in pure_issues:
        for label in i.get("labels", []):
            label_counts[label["name"]] = label_counts.get(label["name"], 0) + 1
    if label_counts:
        print("  Labels:")
        for label, count in sorted(label_counts.items(), key=lambda x: -x[1]):
            print(f"    {label}: {count}")
    else:
        print("  (no labels in use on this repo)")
    print()
    print(f"Raw data ready at: {RAW_DIR}")
    print("Next: tools/bucket_snaffler_issues.py to classify by signal type.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
