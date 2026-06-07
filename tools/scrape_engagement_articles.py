#!/usr/bin/env python3
"""v0.15 Phase B — scrape engagement-shape articles for path mining.

Stage 1 of the v0.15 engagement-shape corpus pipeline. Fetches public
incident reports + red team blog posts that mention real attacker file
paths, saves the raw text. Stage 2 (separate tool) runs LLM extraction
on the saved articles to pull structured path records.

This script does ONLY the HTTP-heavy work — discovery via RSS/sitemaps,
fetching HTML, extracting main text. Designed to run for hours in the
background without supervision. LLM extraction is split out because it
costs API money and benefits from human inspection of the corpus before
spending it.

Output schema (JSONL, one article per line):
    {
        "url":          "https://...",
        "source":       "dfir_report" | "volexity" | "specterops" | ...,
        "title":        "...",
        "published_at": "2024-01-15T00:00:00Z" | null,
        "text":         "...main article body, plain text...",
        "scraped_at":   "2026-06-03T..."
    }

Usage:
    nohup uv run python tools/scrape_engagement_articles.py \\
        --output data/external/engagement_corpus/articles.jsonl \\
        > data/external/engagement_corpus/scrape.log 2>&1 &
    disown

Sources covered (~10 high-signal feeds; configurable in SOURCES below):
    DFIR Report (incident writeups)
    Volexity (APT research)
    SpecterOps Medium (red team tradecraft)
    Mandiant blog (M-Trends / threat reports)
    Trustwave SpiderLabs
    SANS Internet Storm Center diaries (filtered)
    AdSecurity (Sean Metcalf — AD specifics)
    SpecterOps team blog (legacy posts)
    HarmJ0y archive (Will Schroeder — older posts)
    PaperTrail Research

Sources DELIBERATELY excluded:
    0xdf.gitlab.io — already in v0p2 path classifier training (writeup
    corpus). Including would leak.
    Anything HTB-related — same reason.
"""

from __future__ import annotations

import argparse
import html.parser
import json
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_OUTPUT = REPO_ROOT / "data" / "external" / "engagement_corpus" / "articles.jsonl"

USER_AGENT = "truffler-v0p15-research-bot/1.0 (security research; contact: vincent03dinh@gmail.com)"

# Polite rate limit per domain. Most public blogs are fine with 1-2/sec.
PER_DOMAIN_INTERVAL = 1.5


# ---------------------------------------------------------------------------
# Source configuration
#
# Each source declares a `discovery` method (RSS feed URL, sitemap URL,
# or `index` for sites that require crawling listing pages). Sources are
# scraped sequentially to keep the load light; one slow source doesn't
# stall others because we yield URLs incrementally.
# ---------------------------------------------------------------------------

@dataclass
class Source:
    key: str
    base_url: str
    discovery_type: str  # "rss" | "sitemap" | "index"
    discovery_url: str
    article_url_filter: str  # regex; only URLs matching count as articles
    notes: str = ""


SOURCES: list[Source] = [
    Source(
        key="dfir_report",
        base_url="https://thedfirreport.com",
        discovery_type="sitemap",
        discovery_url="https://thedfirreport.com/sitemap.xml",
        article_url_filter=r"^https://thedfirreport\.com/\d{4}/\d{2}/\d{2}/[\w-]+/$",
        notes="incident reports — highest priority",
    ),
    Source(
        key="volexity",
        base_url="https://www.volexity.com",
        discovery_type="rss",
        discovery_url="https://www.volexity.com/blog/feed/",
        article_url_filter=r"^https://www\.volexity\.com/blog/\d{4}/\d{2}/\d{2}/[\w-]+/?$",
        notes="APT research; lots of path-rich detail",
    ),
    Source(
        key="specterops_medium",
        base_url="https://posts.specterops.io",
        discovery_type="rss",
        discovery_url="https://posts.specterops.io/feed",
        article_url_filter=r"^https://posts\.specterops\.io/",
        notes="red team tradecraft; lots of path patterns",
    ),
    Source(
        key="mandiant",
        base_url="https://www.mandiant.com",
        discovery_type="rss",
        discovery_url="https://www.mandiant.com/resources/blog/rss.xml",
        article_url_filter=r"^https://(www\.)?mandiant\.com/resources/(blog|insights)/",
        notes="threat reports; mixed marketing+technical",
    ),
    Source(
        key="adsecurity",
        base_url="https://adsecurity.org",
        discovery_type="rss",
        discovery_url="https://adsecurity.org/?feed=rss2",
        article_url_filter=r"^https://adsecurity\.org/\?p=\d+",
        notes="Sean Metcalf — AD-specific path patterns",
    ),
    Source(
        key="trustwave_spiderlabs",
        base_url="https://www.trustwave.com",
        discovery_type="rss",
        discovery_url="https://www.trustwave.com/en-us/resources/blogs/spiderlabs-blog/rss/",
        article_url_filter=r"^https://www\.trustwave\.com/en-us/resources/blogs/spiderlabs-blog/",
        notes="filter heavily — lots of marketing in this feed",
    ),
    Source(
        key="sans_isc",
        base_url="https://isc.sans.edu",
        discovery_type="rss",
        discovery_url="https://isc.sans.edu/rssfeed_full.xml",
        article_url_filter=r"^https://isc\.sans\.edu/diary/",
        notes="diary entries; high volume but mostly low signal",
    ),
    Source(
        key="harmj0y",
        base_url="https://blog.harmj0y.net",
        discovery_type="rss",
        discovery_url="https://blog.harmj0y.net/feed/",
        article_url_filter=r"^https://blog\.harmj0y\.net/",
        notes="Will Schroeder — older but still relevant AD posts",
    ),
    Source(
        key="papertrail_research",
        base_url="https://research.papertrail.io",
        discovery_type="rss",
        discovery_url="https://research.papertrail.io/feed/",
        article_url_filter=r"^https://research\.papertrail\.io/",
        notes="optional — check if feed exists",
    ),
    # ---- Vendor / IR-team blogs (added 2026-06-03) ----
    Source(
        key="unit42",
        base_url="https://unit42.paloaltonetworks.com",
        discovery_type="rss",
        discovery_url="https://unit42.paloaltonetworks.com/feed/",
        article_url_filter=r"^https://unit42\.paloaltonetworks\.com/",
        notes="PaloAlto Unit42 — extensive threat research, very path-rich",
    ),
    Source(
        key="red_canary",
        base_url="https://redcanary.com",
        discovery_type="rss",
        discovery_url="https://redcanary.com/feed/",
        article_url_filter=r"^https://redcanary\.com/blog/",
        notes="threat detection writeups; high signal",
    ),
    Source(
        key="huntress",
        base_url="https://www.huntress.com",
        discovery_type="rss",
        discovery_url="https://www.huntress.com/blog/rss.xml",
        article_url_filter=r"^https://www\.huntress\.com/blog/",
        notes="SMB-focused IR; matches our deployment target",
    ),
    Source(
        key="sophos_xops",
        base_url="https://news.sophos.com",
        discovery_type="rss",
        discovery_url="https://www.sophos.com/blog/en-us/feed/",
        article_url_filter=r"^https://(news|www)\.sophos\.com/",
        notes="follow-redirect; regular threat reports",
    ),
    Source(
        key="elastic_security_labs",
        base_url="https://www.elastic.co",
        discovery_type="rss",
        discovery_url="https://www.elastic.co/security-labs/rss/feed.xml",
        article_url_filter=r"^https://www\.elastic\.co/security-labs/",
        notes="malware analysis with path detail",
    ),
    # ---- Red team / pentest blogs (added 2026-06-03) ----
    Source(
        key="pentest_partners",
        base_url="https://www.pentestpartners.com",
        discovery_type="rss",
        discovery_url="https://www.pentestpartners.com/security-blog/feed/",
        article_url_filter=r"^https://www\.pentestpartners\.com/security-blog/",
        notes="UK pentest firm; lots of share-walk detail",
    ),
    Source(
        key="trustedsec",
        base_url="https://www.trustedsec.com",
        discovery_type="rss",
        discovery_url="https://www.trustedsec.com/feed/",
        article_url_filter=r"^https://(www\.)?trustedsec\.com/blog/",
        notes="TrustedSec — strong AD/SMB content",
    ),
    Source(
        key="black_hills",
        base_url="https://www.blackhillsinfosec.com",
        discovery_type="rss",
        discovery_url="https://www.blackhillsinfosec.com/feed/",
        article_url_filter=r"^https://www\.blackhillsinfosec\.com/",
        notes="pentester tradecraft",
    ),
    Source(
        key="praetorian",
        base_url="https://www.praetorian.com",
        discovery_type="rss",
        discovery_url="https://www.praetorian.com/feed/",
        article_url_filter=r"^https://www\.praetorian\.com/blog/",
        notes="red team writeups",
    ),
    Source(
        key="rapid7",
        base_url="https://www.rapid7.com",
        discovery_type="rss",
        discovery_url="https://www.rapid7.com/blog/rss/",
        article_url_filter=r"^https://www\.rapid7\.com/blog/post/",
        notes="Metasploit team's own writeups (relevant to MSF3 baseline)",
    ),
    Source(
        key="slayer_labs",
        base_url="https://posts.slayerlabs.com",
        discovery_type="rss",
        discovery_url="https://posts.slayerlabs.com/feed.xml",
        article_url_filter=r"^https://posts\.slayerlabs\.com/",
        notes="pentest range writeups",
    ),
]


# ---------------------------------------------------------------------------
# HTML → text extractor (stdlib only; no trafilatura/readability deps)
# ---------------------------------------------------------------------------

class _ArticleTextExtractor(html.parser.HTMLParser):
    """Strip HTML tags, preserve paragraph breaks. Crude but adequate —
    LLM extraction in stage 2 reads the result and is robust to noise."""

    SKIP_TAGS = {"script", "style", "nav", "header", "footer", "aside",
                 "form", "noscript", "svg", "iframe", "head"}

    def __init__(self) -> None:
        super().__init__()
        self._chunks: list[str] = []
        self._skip_depth = 0
        self._in_title = False
        self._title = ""

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        tag = tag.lower()
        if tag in self.SKIP_TAGS:
            self._skip_depth += 1
        elif tag == "title":
            self._in_title = True
        elif tag in ("br", "hr"):
            self._chunks.append("\n")
        elif tag in ("p", "div", "li", "h1", "h2", "h3", "h4", "h5", "h6", "pre", "code"):
            self._chunks.append("\n")

    def handle_endtag(self, tag: str) -> None:
        tag = tag.lower()
        if tag in self.SKIP_TAGS and self._skip_depth > 0:
            self._skip_depth -= 1
        elif tag == "title":
            self._in_title = False
        elif tag in ("p", "div", "li", "h1", "h2", "h3", "h4", "h5", "h6", "pre", "code"):
            self._chunks.append("\n")

    def handle_data(self, data: str) -> None:
        if self._skip_depth > 0:
            return
        if self._in_title:
            self._title += data
        else:
            self._chunks.append(data)

    @property
    def text(self) -> str:
        raw = "".join(self._chunks)
        # Collapse runs of whitespace, preserve paragraph breaks
        raw = re.sub(r"[ \t]+", " ", raw)
        raw = re.sub(r"\n{3,}", "\n\n", raw)
        return raw.strip()

    @property
    def title(self) -> str:
        return re.sub(r"\s+", " ", self._title).strip()


def _extract_main_text(html_bytes: bytes) -> tuple[str, str]:
    try:
        html_str = html_bytes.decode("utf-8", errors="replace")
    except Exception:
        return "", ""
    ex = _ArticleTextExtractor()
    try:
        ex.feed(html_str)
    except Exception as e:
        print(f"  [parse-error] {e}", file=sys.stderr)
    return ex.title, ex.text


# ---------------------------------------------------------------------------
# HTTP client (rate-limited per-domain, retry-aware)
# ---------------------------------------------------------------------------

class _RateLimitedClient:
    def __init__(self):
        self._last_at: dict[str, float] = {}

    def _wait(self, domain: str) -> None:
        last = self._last_at.get(domain, 0.0)
        elapsed = time.time() - last
        if elapsed < PER_DOMAIN_INTERVAL:
            time.sleep(PER_DOMAIN_INTERVAL - elapsed)
        self._last_at[domain] = time.time()

    def fetch(self, url: str, *, max_retries: int = 3) -> bytes | None:
        domain = urllib.parse.urlparse(url).netloc
        self._wait(domain)
        req = urllib.request.Request(url, headers={
            "User-Agent": USER_AGENT,
            "Accept": "text/html,application/xhtml+xml,application/xml,application/rss+xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
        })
        backoff = 10
        for attempt in range(max_retries):
            try:
                with urllib.request.urlopen(req, timeout=30) as resp:
                    return resp.read()
            except urllib.error.HTTPError as e:
                if e.code in (403, 429):
                    print(f"  [{e.code}] {url} — sleep {backoff}s", file=sys.stderr)
                    time.sleep(backoff)
                    backoff = min(backoff * 2, 300)
                    continue
                if e.code == 404:
                    return None
                if e.code in (500, 502, 503, 504):
                    print(f"  [{e.code}] {url} — retry", file=sys.stderr)
                    time.sleep(5 * (attempt + 1))
                    continue
                print(f"  [HTTP {e.code}] {url}", file=sys.stderr)
                return None
            except (urllib.error.URLError, TimeoutError) as e:
                print(f"  [net] {url}: {e}", file=sys.stderr)
                time.sleep(5 * (attempt + 1))
        return None


# ---------------------------------------------------------------------------
# Discovery: convert source spec → list of article URLs
# ---------------------------------------------------------------------------

def _discover_rss(client: _RateLimitedClient, source: Source) -> list[tuple[str, str | None]]:
    """Returns list of (url, pub_date_iso_or_None)."""
    body = client.fetch(source.discovery_url)
    if body is None:
        return []
    try:
        root = ET.fromstring(body)
    except ET.ParseError as e:
        print(f"  [{source.key}] RSS parse error: {e}", file=sys.stderr)
        return []
    # Handle both RSS 2.0 (<item>) and Atom (<entry>)
    items: list[tuple[str, str | None]] = []
    ns_atom = "{http://www.w3.org/2005/Atom}"
    for item in root.iter("item"):
        link_el = item.find("link")
        date_el = item.find("pubDate")
        url = (link_el.text or "").strip() if link_el is not None else ""
        date_text = (date_el.text or "").strip() if date_el is not None else None
        if url and re.match(source.article_url_filter, url):
            items.append((url, date_text))
    for entry in root.iter(f"{ns_atom}entry"):
        link_el = entry.find(f"{ns_atom}link")
        date_el = entry.find(f"{ns_atom}published") or entry.find(f"{ns_atom}updated")
        url = link_el.attrib.get("href", "") if link_el is not None else ""
        date_text = (date_el.text or "").strip() if date_el is not None else None
        if url and re.match(source.article_url_filter, url):
            items.append((url, date_text))
    return items


def _discover_sitemap(client: _RateLimitedClient, source: Source) -> list[tuple[str, str | None]]:
    body = client.fetch(source.discovery_url)
    if body is None:
        return []
    try:
        root = ET.fromstring(body)
    except ET.ParseError as e:
        print(f"  [{source.key}] sitemap parse error: {e}", file=sys.stderr)
        return []
    # sitemaps use <url><loc>...</loc><lastmod>...</lastmod></url>
    ns = "{http://www.sitemaps.org/schemas/sitemap/0.9}"
    items: list[tuple[str, str | None]] = []
    for url_el in root.iter(f"{ns}url"):
        loc = url_el.find(f"{ns}loc")
        lastmod = url_el.find(f"{ns}lastmod")
        url = (loc.text or "").strip() if loc is not None else ""
        date_text = (lastmod.text or "").strip() if lastmod is not None else None
        if url and re.match(source.article_url_filter, url):
            items.append((url, date_text))
    # Also recurse into nested sitemaps (sitemap index)
    for sitemap_el in root.iter(f"{ns}sitemap"):
        loc = sitemap_el.find(f"{ns}loc")
        if loc is not None and loc.text:
            nested = client.fetch(loc.text.strip())
            if nested:
                try:
                    nroot = ET.fromstring(nested)
                    for url_el in nroot.iter(f"{ns}url"):
                        nloc = url_el.find(f"{ns}loc")
                        nlastmod = url_el.find(f"{ns}lastmod")
                        url = (nloc.text or "").strip() if nloc is not None else ""
                        date_text = (nlastmod.text or "").strip() if nlastmod is not None else None
                        if url and re.match(source.article_url_filter, url):
                            items.append((url, date_text))
                except ET.ParseError:
                    pass
    return items


# ---------------------------------------------------------------------------
# Resume
# ---------------------------------------------------------------------------

def _load_existing_urls(path: Path) -> set[str]:
    if not path.exists():
        return set()
    seen: set[str] = set()
    with path.open(encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
                seen.add(rec["url"])
            except (json.JSONDecodeError, KeyError):
                continue
    return seen


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    p.add_argument("--only-source", action="append", default=None,
                   help="Restrict to specific source keys (repeatable). Default: all.")
    p.add_argument("--max-per-source", type=int, default=None,
                   help="Cap articles per source (smoke testing).")
    p.add_argument("--min-text-length", type=int, default=500,
                   help="Skip articles whose extracted text is shorter than this.")
    args = p.parse_args(argv)

    args.output.parent.mkdir(parents=True, exist_ok=True)
    seen = _load_existing_urls(args.output)
    print(f"[init] Resuming with {len(seen)} previously-scraped URLs", file=sys.stderr)

    sources = SOURCES
    if args.only_source:
        sources = [s for s in sources if s.key in args.only_source]
        print(f"[init] Restricted to {len(sources)} sources: "
              f"{[s.key for s in sources]}", file=sys.stderr)

    client = _RateLimitedClient()
    out_fh = args.output.open("a", encoding="utf-8")

    total_articles = 0
    total_skipped = 0

    try:
        for source in sources:
            print(f"\n[{source.key}] discovering from {source.discovery_url}",
                  file=sys.stderr)
            try:
                if source.discovery_type == "rss":
                    urls = _discover_rss(client, source)
                elif source.discovery_type == "sitemap":
                    urls = _discover_sitemap(client, source)
                else:
                    print(f"  [skip] unsupported discovery type "
                          f"'{source.discovery_type}'", file=sys.stderr)
                    continue
            except Exception as e:
                print(f"  [discover-error] {e}", file=sys.stderr)
                continue

            print(f"  discovered {len(urls)} article URLs", file=sys.stderr)

            if args.max_per_source:
                urls = urls[: args.max_per_source]

            for url, pub_date in urls:
                if url in seen:
                    continue
                body = client.fetch(url)
                if body is None:
                    total_skipped += 1
                    continue
                title, text = _extract_main_text(body)
                if len(text) < args.min_text_length:
                    total_skipped += 1
                    continue
                rec = {
                    "url": url,
                    "source": source.key,
                    "title": title,
                    "published_at": pub_date,
                    "text": text,
                    "scraped_at": datetime.now(timezone.utc).isoformat(),
                }
                out_fh.write(json.dumps(rec) + "\n")
                out_fh.flush()
                seen.add(url)
                total_articles += 1
                if total_articles % 20 == 0:
                    print(f"  [{source.key}] {total_articles} articles, "
                          f"{total_skipped} skipped", file=sys.stderr)
            print(f"  [{source.key}] done: cumulative {total_articles} articles",
                  file=sys.stderr)
    finally:
        out_fh.close()
        print(f"\n[final] {total_articles} articles scraped, "
              f"{total_skipped} skipped, {len(seen)} total in output",
              file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
