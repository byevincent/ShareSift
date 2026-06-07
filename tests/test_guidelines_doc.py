import re
from pathlib import Path

from src.eval.categories import CATEGORY_SLUGS

DOC_PATH = Path(__file__).resolve().parent.parent / "docs" / "labeling_guidelines.md"
SLUG_HEADING_RE = re.compile(r"^### `([a-z0-9_]+)`\s*$", re.MULTILINE)


def test_category_subsection_headings_match_slug_constants_in_order():
    text = DOC_PATH.read_text(encoding="utf-8")
    headings = tuple(SLUG_HEADING_RE.findall(text))
    assert headings == CATEGORY_SLUGS, (
        f"labeling_guidelines.md category subsections drifted from CATEGORY_SLUGS.\n"
        f"  doc:        {headings}\n"
        f"  categories: {CATEGORY_SLUGS}"
    )
