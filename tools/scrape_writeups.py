"""v0.9.1: scrape HTB writeups (0xdf primarily), extract candidate paths.

Hybrid approach:

1. Fetch writeup HTML via urllib (rate-limited, polite User-Agent).
2. Parse out ``<pre>`` / ``<code>`` blocks — writeup authors put shell
   sessions, smbmap output, directory listings, and enumeration there.
3. Extract file-path candidates from code-block content via regex
   (Windows UNC paths, Linux absolute paths, Windows drive paths).
4. Deduplicate per-writeup; emit one record per (path, source_writeup)
   to ``data/eval/writeups/raw_paths.jsonl``.

Legal framing (v0.8 closeout decision: route A — fair-use research
extraction):

* HTML is fetched and parsed in-memory; the original page text is
  **not stored**. Only extracted path strings + source URL +
  scrape_date are persisted.
* Paths are facts (not copyrightable individually). The benchmark
  output is a derived dataset with explicit per-record attribution.
* Source code distributes under the MIT-licensed Truffler repo terms;
  attribution to source authors is preserved in record metadata.

The labeling step (which paths the writeup author flagged as juicy
vs just-enumeration noise) happens in v0.9.2 via LLM.

This scraper currently targets 0xdf.gitlab.io. IppSec.rocks transcripts
need YouTube API + separate parsing — deferred to v0.9.1b if scope
expands.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import time
import urllib.request
from datetime import datetime, timezone
from html.parser import HTMLParser
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_URLS = REPO_ROOT / "data" / "eval" / "writeups" / "source_urls.txt"
DEFAULT_OUT = REPO_ROOT / "data" / "eval" / "writeups" / "raw_paths.jsonl"


# Path patterns. Tuned for writeup content where paths appear in
# shell sessions / smbmap output / directory listings / ls / find /
# strings output.
#
# Windows UNC: \\host\share\path. Two leading backslashes followed
# by host + at least one share segment. First segment after the
# share must start with a normal char (not \x escape).
_RE_UNC = re.compile(
    r"\\\\[A-Za-z0-9._-]+\\[A-Za-z0-9._$-]+"
    r"(?:\\(?!x[0-9a-fA-F])[A-Za-z0-9_.$-][^\s\"'<>|`*?\\]*)*"
)
# Windows drive: C:\Users\... — require the drive-letter NOT to
# follow a word char or @ (shell prompts like user@host:/path put a
# letter immediately before the colon).
_RE_WIN_DRIVE = re.compile(
    r"(?<![A-Za-z0-9@:])"
    r"[A-Za-z]:[\\/](?!x[0-9a-fA-F])[A-Za-z0-9_.$][^\s\"'<>|`*?]*"
)
# Linux absolute path: /etc/... or /home/... at least 2 segments
# deep. Disallow \x escape leadins and common false positives.
_RE_LINUX_ABS = re.compile(
    r"(?<![A-Za-z0-9\\])/(?:[A-Za-z0-9._-][A-Za-z0-9._/-]*/)+[A-Za-z0-9._-]+"
)

# Common URL-path prefixes — these are HTTP paths, not filesystem.
_URL_PATH_PREFIXES = (
    "/api/", "/cgi-bin/", "/wp-", "/admin/", "/login", "/search",
    "/index.php", "/index.html", "/static/", "/assets/", "/public/",
    "/dist/", "/users/", "/user/", "/about", "/contact",
    "/submit", "/upload", "/download", "/auth/",
)

# Filesystem-suggestive segments — at least one of these in the path
# is a strong signal it's a real filesystem path, not noise.
_FS_HINT_SEGMENTS = frozenset({
    "etc", "home", "root", "var", "usr", "tmp", "opt", "srv", "boot",
    "Users", "Windows", "Program Files", "ProgramData", "Documents",
    "Desktop", "Downloads", "AppData", "SYSVOL", "share", "share$",
    "C$", "ADMIN$", "IPC$", "shared", "scripts", "backup", "backups",
    "Policies", "GPP", "Logon", "Logs", "log",
})


# Top-level domain suffixes — if the first segment of a Linux-style
# match contains one of these, it's a URL, not a filesystem path.
_URL_DOMAIN_SUFFIXES = (
    ".com", ".org", ".net", ".io", ".gov", ".edu", ".gitlab.io",
    ".github.io", ".readthedocs.io", ".dev", ".app", ".html",
)


def _looks_like_noise(path: str) -> bool:
    """Cheap post-filter for residual regex false positives. Catches
    URL-escape sequences (\\x20), shell-prompt residue (paths ending
    in $), URL paths (start with /api/ etc), excessively-long paths,
    and obvious non-path content that slipped through."""
    if "\\x" in path or "%20" in path:
        return True
    # Shell-prompt residue: paths that END in `$` are usually the
    # trailing edge of `user@host:/path$ ` prompts.
    if path.endswith("$") and not path.endswith(("C$", "ADMIN$", "IPC$", "share$")):
        return True
    # HTTP URL paths — strong heuristic.
    if any(path.startswith(pfx) for pfx in _URL_PATH_PREFIXES):
        return True
    # First segment is an IP address (URL-ish, e.g. /10.10.14.x/...).
    segs = [s for s in re.split(r"[\\/]", path) if s]
    if segs and re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", segs[0]):
        return True
    # Any segment ends in a known URL TLD — that's a domain, not a dir.
    for s in segs:
        s_low = s.lower()
        if any(s_low.endswith(suf) for suf in _URL_DOMAIN_SUFFIXES):
            # ...except actual .html/.htm files in a dir (foo/bar.html
            # is fine; foo.com/bar is not). Heuristic: only suspicious
            # if this segment is NOT the last in the path.
            if s is not segs[-1]:
                return True
    # Service-fingerprint-style residue (lots of commas + colons).
    if path.count(",") > 1 or path.count(";") > 2:
        return True
    # Too-many-non-separator-chars in a single segment (binary data).
    if any(len(s) > 80 for s in segs):
        return True
    return False


def _looks_like_real_filesystem_path(path: str) -> bool:
    """Stronger positive heuristic: does this path look like a
    filesystem location, not a URL or random match? Requires at least
    one segment from _FS_HINT_SEGMENTS OR a file extension OR a
    UNC-prefixed form (\\\\... is always considered FS).
    """
    if path.startswith("\\\\"):
        return True
    segs = set(re.split(r"[\\/]", path))
    if segs & _FS_HINT_SEGMENTS:
        return True
    # File extension at the end.
    last = path.rsplit("/", 1)[-1].rsplit("\\", 1)[-1]
    if "." in last and not last.startswith("."):
        ext = last.rsplit(".", 1)[-1].lower()
        if 1 <= len(ext) <= 5 and ext.isalnum():
            return True
    return False


def _fetch(url: str, timeout: float = 20.0) -> str | None:
    try:
        req = urllib.request.Request(
            url,
            headers={
                "User-Agent": "truffler-research-bench/0.9 (path-extractor; "
                "no-text-storage; attribution-preserved)",
                "Accept": "text/html",
            },
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = resp.read()
        return data.decode("utf-8", errors="replace")
    except Exception as e:
        print(f"  ! fetch failed: {url} ({e})", file=sys.stderr)
        return None


class _CodeBlockExtractor(HTMLParser):
    """Pull text content from ``<pre>`` and ``<code>`` tags. Other
    text is ignored — page prose isn't where path enumerations live."""

    def __init__(self) -> None:
        super().__init__()
        self._depth = 0
        self._buf: list[str] = []
        self.blocks: list[str] = []

    def handle_starttag(self, tag: str, attrs) -> None:
        if tag in ("pre", "code"):
            self._depth += 1
            if self._depth == 1:
                self._buf = []

    def handle_endtag(self, tag: str) -> None:
        if tag in ("pre", "code") and self._depth > 0:
            self._depth -= 1
            if self._depth == 0 and self._buf:
                text = "".join(self._buf).strip()
                if text:
                    self.blocks.append(text)

    def handle_data(self, data: str) -> None:
        if self._depth > 0:
            self._buf.append(data)


def _extract_code_blocks(html: str) -> list[str]:
    parser = _CodeBlockExtractor()
    try:
        parser.feed(html)
    except Exception:
        pass
    return parser.blocks


def _extract_paths(blocks: list[str]) -> dict[str, dict]:
    """Run path regexes over each block. Return path → {kind, snippet}.

    The snippet is the surrounding code-block context (~100 chars
    either side). v0.9.2's labeler uses it to judge whether the
    writeup author was calling out this path as juicy.
    """
    paths: dict[str, dict] = {}
    for block in blocks:
        for kind, regex in (("unc", _RE_UNC), ("win_drive", _RE_WIN_DRIVE), ("linux_abs", _RE_LINUX_ABS)):
            for m in regex.finditer(block):
                p = m.group(0).rstrip(".,:;)\"'")
                # Cap absurd paths.
                if len(p) > 300 or len(p) < 4:
                    continue
                if _looks_like_noise(p):
                    continue
                if not _looks_like_real_filesystem_path(p):
                    continue
                if p in paths:
                    continue
                lo = max(0, m.start() - 100)
                hi = min(len(block), m.end() + 100)
                paths[p] = {
                    "kind": kind,
                    "context": block[lo:hi],
                }
    return paths


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--urls", type=Path, default=DEFAULT_URLS)
    p.add_argument("--output", type=Path, default=DEFAULT_OUT)
    p.add_argument(
        "--sleep",
        type=float,
        default=1.0,
        help="Seconds between fetches (polite rate limit).",
    )
    p.add_argument(
        "--max-urls",
        type=int,
        default=None,
        help="Cap on number of writeups to scrape (default: all).",
    )
    args = p.parse_args(argv)

    if not args.urls.exists():
        print(f"ERROR: {args.urls} missing — create it with the writeup URL list", file=sys.stderr)
        return 1
    urls = [u.strip() for u in args.urls.read_text().splitlines() if u.strip()]
    if args.max_urls:
        urls = urls[: args.max_urls]
    print(f"Scraping {len(urls)} writeups...", file=sys.stderr)

    args.output.parent.mkdir(parents=True, exist_ok=True)
    n_total_paths = 0
    n_written = 0
    scrape_date = datetime.now(timezone.utc).isoformat()
    with args.output.open("w", encoding="utf-8") as f:
        for i, url in enumerate(urls):
            if (i + 1) % 25 == 0:
                print(
                    f"  [{i + 1}/{len(urls)}] paths so far: {n_total_paths}",
                    file=sys.stderr,
                )
            html = _fetch(url)
            if html is None:
                continue
            box_name = url.rstrip("/").rsplit("/", 1)[-1].removesuffix(".html").removeprefix("htb-")
            blocks = _extract_code_blocks(html)
            paths = _extract_paths(blocks)
            n_total_paths += len(paths)
            for path_str, meta in paths.items():
                rec = {
                    "path": path_str,
                    "kind": meta["kind"],
                    "context": meta["context"],
                    "source_url": url,
                    "source_box": box_name,
                    "scrape_date": scrape_date,
                    # Attribution: 0xdf is the assumed author for 0xdf.gitlab.io
                    "source_author": "0xdf" if "0xdf.gitlab.io" in url else None,
                }
                f.write(json.dumps(rec) + "\n")
                n_written += 1
            # HTML discarded here; only path records persisted.
            del html
            time.sleep(args.sleep)

    print(
        f"\nWrote {n_written} path records (across {len(urls)} writeups) to "
        f"{args.output.relative_to(REPO_ROOT)}",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
