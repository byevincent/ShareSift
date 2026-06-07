"""v0.11.x fair-benchmark builder — salt only at writeup-juicy-labeled paths.

The v0.9.5 ``tools/build_constructed_share.py`` salted credentials at
random writeup-mined paths. v0.11.x found that this disadvantages
path classifiers trained on writeup labels: v0p2 correctly identifies
many writeup paths as not-juicy, but if we drop credentials on those
not-juicy paths, v0p2 looks like it's missing credentials.

This script fixes the methodology bias. It builds a constructed share
from the v0.11 Linux test split (216 paths from 36 held-out boxes,
labeled by the v0.9.2 paste workflow against the same calibration
positions both v0p1 and v0p2 see):

  * 26 paths labeled juicy → docx-corpus content + salted Kingfisher
    credential. Ground truth: should be flagged by Stage 1, should
    detect cred by Stage 2.
  * 190 paths labeled not_juicy → plain docx-corpus content. Ground
    truth: should NOT be flagged.

This is the right test for whether a path classifier correctly
distinguishes share paths a pentester would flag vs would not, AND
whether the content classifier then catches the actual credential.

Reuses the path mapping + salt + docx content helpers from
``tools/build_constructed_share.py`` (imported via filename, not
restructured).
"""

from __future__ import annotations

import argparse
import json
import random
import shutil
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

# Reuse helpers from the original builder via importlib (the file lives
# alongside this one but uses Path-traversal-style relative naming).
import importlib.util
spec = importlib.util.spec_from_file_location(
    "csb", REPO_ROOT / "tools" / "build_constructed_share.py"
)
csb = importlib.util.module_from_spec(spec)  # type: ignore[arg-type]
sys.modules["csb"] = csb
spec.loader.exec_module(csb)  # type: ignore[union-attr]


DEFAULT_LABELED = REPO_ROOT / "data" / "eval" / "test_split_linux_v0p11_writeup.jsonl"
DEFAULT_KINGFISHER_RAW = REPO_ROOT / "reports" / "creddata_training_kingfisher.jsonl"
DEFAULT_DOCX_CACHE = REPO_ROOT / "data" / "external" / "docx_corpus_cache"
DEFAULT_SHARE_ROOT = REPO_ROOT / "data" / "external" / "constructed_share_v2"
DEFAULT_MANIFEST = REPO_ROOT / "data" / "external" / "constructed_share_v2_manifest.jsonl"
DEFAULT_PATHS_LIST = REPO_ROOT / "data" / "eval" / "constructed_share_v2_paths.txt"


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--labeled", type=Path, default=DEFAULT_LABELED)
    p.add_argument("--kingfisher-raw", type=Path, default=DEFAULT_KINGFISHER_RAW)
    p.add_argument("--docx-cache", type=Path, default=DEFAULT_DOCX_CACHE)
    p.add_argument("--share-root", type=Path, default=DEFAULT_SHARE_ROOT)
    p.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    p.add_argument("--paths-list", type=Path, default=DEFAULT_PATHS_LIST)
    p.add_argument("--seed", type=int, default=2026)
    p.add_argument("--reset", action="store_true", default=True)
    args = p.parse_args(argv)

    if not args.labeled.exists():
        print(f"ERROR: {args.labeled} missing", file=sys.stderr)
        return 1

    rng = random.Random(args.seed)

    if args.reset and args.share_root.exists():
        print(f"Wiping {args.share_root}...", file=sys.stderr)
        shutil.rmtree(args.share_root)
    args.share_root.mkdir(parents=True, exist_ok=True)

    # Records here are from train_split_linux_v0p11.jsonl shape, which
    # has label="juicy"/"not_juicy" + path. (We re-export from the v0.9
    # labeling pipeline format via tools/build_v0p11_linux_corpus.py.)
    records = [json.loads(line) for line in args.labeled.read_text().splitlines() if line.strip()]
    juicy_records = [r for r in records if r.get("label") == "juicy"]
    not_juicy_records = [r for r in records if r.get("label") == "not_juicy"]
    print(
        f"Input: {len(records)} held-out paths "
        f"({len(juicy_records)} juicy / {len(not_juicy_records)} not_juicy)",
        file=sys.stderr,
    )

    creds = csb._load_kingfisher_creds(args.kingfisher_raw)
    print(f"  loaded {len(creds)} candidate credentials", file=sys.stderr)
    rng.shuffle(creds)

    manifest_records: list[dict] = []
    paths_to_scan: list[str] = []
    n_constructed = 0
    n_salted = 0
    n_skipped = 0

    for i, rec in enumerate(records):
        local_rel = csb._to_local_path(rec["path"])
        if local_rel is None:
            n_skipped += 1
            continue
        local_rel = csb._safe_filename(local_rel)
        local_abs = args.share_root / local_rel
        try:
            local_abs.parent.mkdir(parents=True, exist_ok=True)
        except OSError:
            n_skipped += 1
            continue

        is_juicy_label = rec.get("label") == "juicy"
        content = csb._docx_content(args.docx_cache, rng)
        salted = False
        # SALT ONLY at writeup-juicy-labeled paths.
        if is_juicy_label and creds:
            cred = creds[n_salted % len(creds)]
            content = csb._salt_text(content, cred, rng)
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
            "is_juicy_label": is_juicy_label,
            "tier_label": rec.get("tier"),
            "salted": salted,
        })
        paths_to_scan.append(str(local_abs))

    args.manifest.parent.mkdir(parents=True, exist_ok=True)
    with args.manifest.open("w", encoding="utf-8") as f:
        for r in manifest_records:
            f.write(json.dumps(r) + "\n")
    args.paths_list.parent.mkdir(parents=True, exist_ok=True)
    args.paths_list.write_text("\n".join(paths_to_scan) + "\n", encoding="utf-8")

    print(
        f"\nConstructed: {n_constructed} files, {n_salted} salted "
        f"(salt = is_juicy_label), {n_skipped} skipped",
        file=sys.stderr,
    )
    print(f"  share root: {args.share_root}", file=sys.stderr)
    print(f"  manifest:   {args.manifest.relative_to(REPO_ROOT)}", file=sys.stderr)
    print(f"  paths list: {args.paths_list.relative_to(REPO_ROOT)}", file=sys.stderr)
    print(
        f"\nKey property: salted == is_juicy_label. Run "
        f"`tools/eval_constructed_share.py --manifest <this manifest> "
        f"--paths-list <this paths list>` against each path classifier "
        f"variant to compare them on the same fair surface.",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
