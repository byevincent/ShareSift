r"""v0.9.5: construct a realistic share on disk from writeup-mined paths.

Builds a synthetic share at ``data/external/constructed_share/`` whose
directory tree mirrors writeup-labeled paths, populated with real
business-document content from the v0.8 docx-corpus cache and salted
with real-shape credentials from the v0.6/v0.8 Kingfisher findings.
The output supports an end-to-end ``truffler scan-files`` evaluation
that tests the orchestration — path triage → tier-filter → content
scan — that the existing eval scripts skip.

Construction approach:

* All paths get converted to local-Linux equivalents under the share
  root. Windows-style backslashes don't survive on a Linux filesystem
  cleanly, so:
    - ``\\server\share\path`` → ``<root>/_unc/<server>/<share>/<path>``
    - ``C:\Users\...``        → ``<root>/_winc/Users/...``
    - ``/etc/shadow``         → ``<root>/_linux/etc/shadow``
* This means the path-classifier-routing benchmark at v0.9.3 is the
  *path-shape* test, and this constructed-share benchmark is the
  *file-contents + orchestration* test. They're complementary.
* File contents:
  - juicy=true paths get one of:
    (a) docx-corpus content + a salted credential at a random position
        (mimics "credential embedded in a real business doc"), or
    (b) raw credential-bearing file (id_rsa-style PEM, .env file,
        connection string config) if the path's filename suggests
        a credential file shape.
  - juicy=false paths get plain docx-corpus content (no credential).
* Ground-truth label per file: ``is_juicy`` from the writeup labels +
  ``salted`` flag indicating whether we injected a credential.

Output:
* ``data/external/constructed_share/`` — the directory tree.
* ``data/external/constructed_share_manifest.jsonl`` — per-file
  manifest mapping (original_path, local_path, ground_truth, salted,
  source_box). Gitignored along with the share itself.
* ``data/eval/constructed_share_paths.txt`` — input file for
  ``truffler scan-files --input <this>``. Tracked.

The companion ``tools/eval_constructed_share.py`` (next) runs the
``truffler scan-files`` pipeline against this and measures end-to-end
P/R/F1.
"""

from __future__ import annotations

import argparse
import json
import random
import re
import shutil
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_LABELED = REPO_ROOT / "data" / "eval" / "writeups" / "labeled_paths.jsonl"
DEFAULT_KINGFISHER_RAW = REPO_ROOT / "reports" / "creddata_training_kingfisher.jsonl"
DEFAULT_DOCX_CACHE = REPO_ROOT / "data" / "external" / "docx_corpus_cache"
DEFAULT_SHARE_ROOT = REPO_ROOT / "data" / "external" / "constructed_share"
DEFAULT_MANIFEST = REPO_ROOT / "data" / "external" / "constructed_share_manifest.jsonl"
DEFAULT_PATHS_LIST = REPO_ROOT / "data" / "eval" / "constructed_share_paths.txt"


_INJECTION_PREFIXES = (
    "The password is: ",
    "API key: ",
    "Connection string: ",
    "Auth token: ",
    "Admin: ",
    "Database URL: ",
    "Private key: ",
)


def _to_local_path(p: str) -> Path | None:
    """Map a UNC / Windows-drive / Linux absolute path to a local
    filesystem equivalent. Returns None for paths we can't host
    safely (parent traversal, suspicious patterns)."""
    if ".." in p or "\x00" in p:
        return None
    if p.startswith("\\\\"):
        # \\server\share\... → _unc/server/share/...
        rest = p[2:].replace("\\", "/")
        return Path("_unc") / rest
    m = re.match(r"^([A-Za-z]):[\\/](.*)", p)
    if m:
        letter = m.group(1).upper()
        rest = m.group(2).replace("\\", "/")
        return Path(f"_win{letter.lower()}") / rest
    if p.startswith("/"):
        return Path("_linux") / p.lstrip("/")
    return None


def _safe_filename(p: Path) -> Path:
    """Truncate ultra-long filename components to something the
    filesystem will accept (typically max 255 bytes per segment)."""
    parts = []
    for seg in p.parts:
        if len(seg) > 200:
            seg = seg[:200]
        parts.append(seg)
    return Path(*parts) if parts else p


def _load_kingfisher_creds(path: Path, min_chars: int = 12, max_chars: int = 200) -> list[str]:
    creds: list[str] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            continue
        snippet = rec.get("finding", {}).get("snippet", "")
        if min_chars <= len(snippet) <= max_chars:
            creds.append(snippet)
    return creds


def _docx_content(docx_cache: Path, rng: random.Random) -> str:
    """Random docx-corpus file's extracted text. Falls back to a
    minimal placeholder if extraction fails or cache is empty."""
    try:
        from docx import Document  # type: ignore[import-not-found]
    except ImportError:
        return "Placeholder content (python-docx not installed).\n"
    files = list(docx_cache.glob("*.docx"))
    if not files:
        return "Placeholder content (docx cache empty).\n"
    for _ in range(5):
        f = rng.choice(files)
        try:
            doc = Document(str(f))
            text = "\n".join(p.text for p in doc.paragraphs if p.text)
            if text.strip():
                return text
        except Exception:
            continue
    return "Placeholder content (docx extraction failed).\n"


def _salt_text(text: str, cred: str, rng: random.Random) -> str:
    lines = text.splitlines() or [""]
    insert_at = rng.randint(0, len(lines))
    if rng.random() < 0.8:
        line = rng.choice(_INJECTION_PREFIXES) + cred
    else:
        line = cred
    return "\n".join(lines[:insert_at] + [line] + lines[insert_at:])


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--labeled", type=Path, default=DEFAULT_LABELED)
    p.add_argument("--kingfisher-raw", type=Path, default=DEFAULT_KINGFISHER_RAW)
    p.add_argument("--docx-cache", type=Path, default=DEFAULT_DOCX_CACHE)
    p.add_argument("--share-root", type=Path, default=DEFAULT_SHARE_ROOT)
    p.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    p.add_argument("--paths-list", type=Path, default=DEFAULT_PATHS_LIST)
    p.add_argument(
        "--max-records",
        type=int,
        default=None,
        help="Cap on number of paths to construct (for smoke tests).",
    )
    p.add_argument("--seed", type=int, default=2026)
    p.add_argument(
        "--reset",
        action="store_true",
        help="Wipe the share-root before constructing.",
    )
    args = p.parse_args(argv)

    if not args.labeled.exists():
        print(f"ERROR: {args.labeled} missing — run v0.9.2 first", file=sys.stderr)
        return 1

    rng = random.Random(args.seed)

    if args.reset and args.share_root.exists():
        print(f"Wiping {args.share_root}...", file=sys.stderr)
        shutil.rmtree(args.share_root)
    args.share_root.mkdir(parents=True, exist_ok=True)

    records = [json.loads(line) for line in args.labeled.read_text().splitlines() if line.strip()]
    records = [r for r in records if r.get("is_juicy") is not None]
    if args.max_records:
        records = records[: args.max_records]
    print(f"Building share from {len(records)} labeled paths", file=sys.stderr)

    creds = _load_kingfisher_creds(args.kingfisher_raw)
    print(f"  loaded {len(creds)} candidate credentials", file=sys.stderr)
    rng.shuffle(creds)

    manifest_records: list[dict] = []
    paths_to_scan: list[str] = []
    n_constructed = 0
    n_salted = 0
    n_skipped = 0
    for i, rec in enumerate(records):
        if (i + 1) % 200 == 0:
            print(f"  [{i + 1}/{len(records)}]", file=sys.stderr)
        local_rel = _to_local_path(rec["path"])
        if local_rel is None:
            n_skipped += 1
            continue
        local_rel = _safe_filename(local_rel)
        local_abs = args.share_root / local_rel
        try:
            local_abs.parent.mkdir(parents=True, exist_ok=True)
        except OSError:
            n_skipped += 1
            continue

        salted = False
        # Salt ~80% of juicy paths so the content stage has signal to
        # find. Some juicy paths are about path-shape itself (a bare
        # ~/.ssh dir, for instance) — those don't need salt.
        salt_this = rec["is_juicy"] and rng.random() < 0.8 and creds
        content = _docx_content(args.docx_cache, rng)
        if salt_this:
            cred = creds[n_salted % len(creds)]
            content = _salt_text(content, cred, rng)
            salted = True
            n_salted += 1

        try:
            local_abs.write_text(content, encoding="utf-8", errors="replace")
        except OSError as e:
            print(f"  ! write failed: {local_abs} ({e})", file=sys.stderr)
            n_skipped += 1
            continue
        n_constructed += 1

        manifest_records.append({
            "original_path": rec["path"],
            "local_path": str(local_abs),
            "is_juicy_label": rec["is_juicy"],
            "tier_label": rec.get("tier"),
            "salted": salted,
            "source_box": rec.get("source_box"),
        })
        paths_to_scan.append(str(local_abs))

    args.manifest.parent.mkdir(parents=True, exist_ok=True)
    with args.manifest.open("w", encoding="utf-8") as f:
        for r in manifest_records:
            f.write(json.dumps(r) + "\n")
    args.paths_list.parent.mkdir(parents=True, exist_ok=True)
    args.paths_list.write_text("\n".join(paths_to_scan) + "\n", encoding="utf-8")

    print(
        f"\nConstructed: {n_constructed} files, {n_salted} salted, "
        f"{n_skipped} skipped (path not constructible)",
        file=sys.stderr,
    )
    print(f"  share root: {args.share_root}", file=sys.stderr)
    print(f"  manifest:   {args.manifest.relative_to(REPO_ROOT)}", file=sys.stderr)
    print(f"  paths list: {args.paths_list.relative_to(REPO_ROOT)}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
