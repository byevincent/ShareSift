"""v0.9.2 ingest: parse Sonnet's chunk responses into labeled JSONL.

Companion to ``tools/build_writeup_labeling_kit.py``. Reads the
per-chunk response files (saved as ``responses/chunk_NN.jsonl``) and
the manifest from the labeling kit, joins them back to original
record metadata (source_url, kind, etc.), and emits the labeled
benchmark records to a single output JSONL.

Resumable: re-running with partial responses leaves un-responded
chunks out of the output and prints a summary of what's missing.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_CHUNKS_DIR = REPO_ROOT / "labeling_kit_v0p9"
DEFAULT_RESPONSES_DIR = REPO_ROOT / "labeling_kit_v0p9" / "responses"
DEFAULT_OUTPUT = REPO_ROOT / "data" / "eval" / "writeups" / "labeled_paths.jsonl"


_CODE_FENCE_RE = re.compile(r"```(?:jsonl|json)?\s*\n(.*?)\n```", re.DOTALL)


def _parse_response(text: str) -> list[dict]:
    """Extract JSONL records from a Claude.ai response. Tolerates
    common copy-paste issues:
    - The text may include surrounding markdown/prose
    - May or may not be wrapped in a code fence
    - Each record on its own line; trailing commas would be illegal JSON
    """
    blocks = _CODE_FENCE_RE.findall(text)
    candidates = blocks if blocks else [text]
    records: list[dict] = []
    for block in candidates:
        for line in block.splitlines():
            line = line.strip().rstrip(",")
            if not line or not line.startswith("{"):
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            records.append(rec)
    return records


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--chunks-dir", type=Path, default=DEFAULT_CHUNKS_DIR)
    p.add_argument("--responses-dir", type=Path, default=DEFAULT_RESPONSES_DIR)
    p.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = p.parse_args(argv)

    manifest_path = args.chunks_dir / "manifest.jsonl"
    if not manifest_path.exists():
        print(f"ERROR: {manifest_path} missing", file=sys.stderr)
        return 1
    manifest = [json.loads(line) for line in manifest_path.read_text().splitlines() if line.strip()]
    by_key: dict[tuple[int, int], dict] = {(r["chunk_id"], r["idx"]): r for r in manifest}
    chunk_ids = sorted({r["chunk_id"] for r in manifest})
    print(f"Manifest: {len(manifest)} records across {len(chunk_ids)} chunks", file=sys.stderr)

    out_records: list[dict] = []
    missing_chunks: list[int] = []
    bad_chunks: list[tuple[int, str]] = []

    for chunk_id in chunk_ids:
        resp_path = args.responses_dir / f"chunk_{chunk_id:02d}.jsonl"
        # Also accept .txt or .md extensions as fallbacks.
        if not resp_path.exists():
            for alt in (".txt", ".md", ""):
                cand = args.responses_dir / f"chunk_{chunk_id:02d}{alt}"
                if cand.exists():
                    resp_path = cand
                    break
        if not resp_path.exists():
            missing_chunks.append(chunk_id)
            continue
        text = resp_path.read_text(encoding="utf-8")
        records = _parse_response(text)
        # Expected count: number of manifest entries for this chunk.
        expected = sum(1 for r in manifest if r["chunk_id"] == chunk_id)
        if len(records) != expected:
            bad_chunks.append((chunk_id, f"got {len(records)}, expected {expected}"))
        for rec in records:
            idx = rec.get("idx")
            if idx is None:
                continue
            key = (chunk_id, int(idx))
            base = by_key.get(key)
            if base is None:
                continue
            out_records.append({
                "path": base["path"],
                "kind": base["kind"],
                "source_url": base["source_url"],
                "source_box": base["source_box"],
                "is_juicy": rec.get("is_juicy"),
                "tier": rec.get("tier"),
                "category": rec.get("category"),
                "reason": rec.get("reason"),
                "labeled_by": "claude_via_paste_workflow",
            })

    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", encoding="utf-8") as f:
        for r in out_records:
            f.write(json.dumps(r) + "\n")

    n_juicy = sum(1 for r in out_records if r["is_juicy"])
    n_not = sum(1 for r in out_records if r["is_juicy"] is False)
    print(
        f"\nWrote {len(out_records)} labeled records to "
        f"{args.output.relative_to(REPO_ROOT)} ({n_juicy} juicy / {n_not} not)",
        file=sys.stderr,
    )
    if missing_chunks:
        print(
            f"Missing chunks (no response file): {missing_chunks}",
            file=sys.stderr,
        )
    if bad_chunks:
        print("Chunks with wrong record count:", file=sys.stderr)
        for cid, msg in bad_chunks:
            print(f"  chunk {cid}: {msg}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
