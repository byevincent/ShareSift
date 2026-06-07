"""Strip Claude.ai web-UI copy-paste artifacts from a label dump.

The chat workflow (``tools/llm_label_chunkify.py`` → manual paste → save
to ``everything.txt``) is prone to retaining UI noise when copy-pasting
from Sonnet's syntax-highlighted code blocks:

* Private-use-area Unicode glyphs (``\\ue064\\ue056\\ue03b``) used as
  fence-rendering decorations
* The fence language tag (``jsonl``) appearing on the same line as the
  first record
* Inline "pasted3:31 PM" timestamp tooltips
* The next chunk's input (numbered path list) accidentally interleaved
  between chunks because the user pasted consecutively without a blank
  separator

The well-formed JSON objects ARE still in the file, just buried. This
script scans the whole text, extracts every balanced ``{...}`` that
parses as JSON and contains a ``path`` field, dedups by path (keeping
first-seen), and writes a clean JSONL ready for ``llm_label_ingest.py``.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_INPUT = REPO_ROOT / "labeling_kit" / "everything.txt"
DEFAULT_OUTPUT = REPO_ROOT / "data" / "eval" / "eval_set_claude_linux_manual.jsonl"


def extract_json_objects(text: str) -> list[dict]:
    """Find every balanced ``{...}`` substring that parses as a JSON
    object with a ``path`` field. Brace counting is string-aware so
    braces inside JSON string literals don't throw off depth.
    """
    out: list[dict] = []
    i = 0
    n = len(text)
    while i < n:
        if text[i] != "{":
            i += 1
            continue
        # Walk forward maintaining brace depth and string state.
        depth = 1
        j = i + 1
        in_string = False
        escape_next = False
        while j < n and depth > 0:
            c = text[j]
            if escape_next:
                escape_next = False
            elif c == "\\":
                escape_next = True
            elif c == '"':
                in_string = not in_string
            elif not in_string:
                if c == "{":
                    depth += 1
                elif c == "}":
                    depth -= 1
            j += 1
        if depth == 0:
            candidate = text[i:j]
            try:
                obj = json.loads(candidate)
            except json.JSONDecodeError:
                i += 1
                continue
            if isinstance(obj, dict) and "path" in obj:
                out.append(obj)
                i = j
                continue
        i += 1
    return out


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--input", type=Path, default=DEFAULT_INPUT)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()

    text = args.input.read_text(encoding="utf-8")
    objects = extract_json_objects(text)
    # Dedup by path, keep first occurrence.
    seen: set[str] = set()
    unique: list[dict] = []
    for obj in objects:
        path = obj.get("path", "")
        if not path or path in seen:
            continue
        seen.add(path)
        unique.append(obj)

    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", encoding="utf-8") as f:
        for obj in unique:
            f.write(json.dumps(obj) + "\n")

    print(f"input bytes:           {len(text):,}")
    print(f"json objects found:    {len(objects):,}")
    print(f"unique by path:        {len(unique):,}")
    print(f"wrote {len(unique)} records to {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
