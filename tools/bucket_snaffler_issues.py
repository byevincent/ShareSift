"""v0.47 step 2: heuristic-bucket Snaffler issues for benchmark mining.

Reads ``benchmarks/snaffler_issues/raw/issues.json`` + comments, runs
each issue through a keyword classifier, and emits a TSV with one row
per issue. Output columns:

    number | state | bucket | title | url | n_comments | body_chars

Buckets:

* ``miss``   — Snaffler missed a thing it should have found (FN signal)
* ``fp``     — Snaffler flagged a thing it shouldn't (FP signal)
* ``feat``   — feature request (operator-gap signal)
* ``bug``    — output/UX/crash bug (low benchmark signal)
* ``q``      — question / clarification request
* ``unk``    — heuristic couldn't decide

The heuristic is intentionally simple — first-pass triage. A human (or
LLM follow-up) refines from there. We optimize for recall on ``miss``
and ``fp`` since those are the high-value benchmark signal.

Usage:

    uv run python tools/bucket_snaffler_issues.py > /tmp/snaffler_buckets.tsv
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

RAW_DIR = Path(__file__).resolve().parent.parent / "benchmarks" / "snaffler_issues" / "raw"

# Order matters: first matching bucket wins. ``miss`` and ``fp`` are
# checked first because those are the highest-signal categories.
_BUCKET_PATTERNS: list[tuple[str, list[str]]] = [
    (
        "miss",
        [
            r"\bnot\s+find(ing)?\b",
            r"\bnot\s+detect",
            r"\bdoesn'?t\s+(find|detect|catch|flag|see)",
            r"\bnot\s+search(ing)?\b",
            r"\bmiss(ed|es|ing)?\b",
            r"\bnot\s+reading\b",
            r"\b(should|would)\s+(find|detect|catch|flag)\b",
            r"\bsnaffle\s+up\b",
            r"\b(rules?|detect(ion)?)\s+(for|to\s+look)\b",
            r"\bshare?\s+(lister|finder)\b.*\b(not|fail|broken)\b",
        ],
    ),
    (
        "fp",
        [
            r"\bfalse\s+positives?\b",
            r"\bnoise(y|s)?\b",
            r"\bnot\s+(juicy|interesting|relevant)\b",
            r"\bover[\-\s]?triggering\b",
            r"\bshadow(ing|s)?\s+(other|another)\b",
            r"\bdiscard\s+rules?\b",
        ],
    ),
    (
        "feat",
        [
            r"\bfeature\s+(request|proposal|suggestion)\b",
            r"\b(add|support|allow|enable|implement)\s+(the\s+)?(ability|option|flag|feature|support)\b",
            r"\b(plans?\s+to|would\s+like\s+to|wish(ful)?\b)\b",
            r"\bsupport\s+for\b",
            r"\bspecify\s+(targets?|credentials?|list)\b",
            r"\bresume\s+support\b",
            r"\bcsv\s+(export|output)\b",
            r"\bjson\s+(output|nesting|structure)\b",
            r"\bhtml\s+report\b",
            r"\b(linux|macos)\s+executable\b",
            r"\bdeduplic",
            r"\binteg(ration|rate)\b",
            r"\b(rules?)\s+to\s+look\s+for\b",
        ],
    ),
    (
        "bug",
        [
            r"\bhangs?\b",
            r"\bcrash(ed|es|ing)?\b",
            r"\b(memory|cpu|resource)s?\b.*\b(consume|leak|usage|exhaust)",
            r"\bbroken?\b",
            r"\bnot\s+working\b",
            r"\b(error|exception|stacktrace)\b",
            r"\bidles?\b",
            r"\bcompil(ing|e|ation)\s+(issue|error|fail)",
            r"\b(stops?|stopped)\s+(scanning|after)\b",
            r"\bencoding\b",
            r"\bspaced\s+instead\s+of\s+tabbed\b",
            r"\bnot\s+quit",
            r"\bbreaks?\s+when\b",
            r"\bdoesn'?t\s+(write|quit|work)\b",
        ],
    ),
    (
        "q",
        [
            r"^how\s+(do|to|can)\b",
            r"^any\s+(plans|examples|way|tips)\b",
            r"\?\s*$",
            r"\bquestion\b",
            r"\bclarif(y|ication)\b",
            r"\bany\s+plans?\s+to\b",
        ],
    ),
]


def _classify(title: str, body: str) -> str:
    """First-matching bucket wins."""
    text = (title + " " + (body or "")).lower()
    for bucket, patterns in _BUCKET_PATTERNS:
        for pattern in patterns:
            if re.search(pattern, text):
                return bucket
    return "unk"


def _count_comments(num: int) -> int:
    path = RAW_DIR / "comments" / f"{num}.json"
    if not path.exists():
        return 0
    try:
        return len(json.loads(path.read_text(encoding="utf-8")))
    except json.JSONDecodeError:
        return 0


def main() -> int:
    issues_path = RAW_DIR / "issues.json"
    issues = json.loads(issues_path.read_text(encoding="utf-8"))
    pure_issues = [i for i in issues if "pull_request" not in i]

    rows = []
    bucket_counts: dict[str, int] = {}
    for issue in pure_issues:
        title = issue.get("title") or ""
        body = issue.get("body") or ""
        bucket = _classify(title, body)
        bucket_counts[bucket] = bucket_counts.get(bucket, 0) + 1
        rows.append(
            {
                "number": issue["number"],
                "state": issue["state"],
                "bucket": bucket,
                "title": title.replace("\t", " ").replace("\n", " "),
                "url": issue["html_url"],
                "n_comments": _count_comments(issue["number"]),
                "body_chars": len(body),
            }
        )

    # Sort by bucket priority then number desc (recent issues first)
    bucket_order = {"miss": 0, "fp": 1, "feat": 2, "bug": 3, "q": 4, "unk": 5}
    rows.sort(key=lambda r: (bucket_order[r["bucket"]], -r["number"]))

    # TSV out
    print("number\tstate\tbucket\ttitle\turl\tn_comments\tbody_chars")
    for row in rows:
        print(
            f"{row['number']}\t{row['state']}\t{row['bucket']}\t"
            f"{row['title']}\t{row['url']}\t{row['n_comments']}\t{row['body_chars']}"
        )

    # Summary to stderr
    print(f"\nTotal: {len(rows)} issues", file=sys.stderr)
    for bucket in ("miss", "fp", "feat", "bug", "q", "unk"):
        print(f"  {bucket}: {bucket_counts.get(bucket, 0)}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
