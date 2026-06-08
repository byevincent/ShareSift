"""v0.23: OOXML traversal in load_content."""

from __future__ import annotations

import io
import xml.etree.ElementTree as ET
import zipfile
from pathlib import Path

from sharesift.extract import load_content


def _make_docx(path: Path, paragraphs: list[str]) -> None:
    """Build a minimal valid-enough docx for the extractor to read."""
    # OOXML docx structure: word/document.xml is the main body.
    ns = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"
    body = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
    body += f'<w:document xmlns:w="{ns}"><w:body>'
    for p in paragraphs:
        body += f'<w:p><w:r><w:t>{p}</w:t></w:r></w:p>'
    body += '</w:body></w:document>'
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("word/document.xml", body)


def _make_xlsx(path: Path, strings: list[str]) -> None:
    """Build a minimal valid-enough xlsx for the extractor to read."""
    ns = "http://schemas.openxmlformats.org/spreadsheetml/2006/main"
    ss = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
    ss += f'<sst xmlns="{ns}"><si>'
    for s in strings:
        ss += f'<t>{s}</t>'
    ss += '</si></sst>'
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("xl/sharedStrings.xml", ss)


def test_load_content_extracts_docx_text(tmp_path):
    p = tmp_path / "report.docx"
    _make_docx(p, [
        "Q4 revenue summary",
        "Connection string: secret123",
        "End of document",
    ])
    out = load_content(p)
    assert out is not None
    assert "Q4 revenue summary" in out
    assert "secret123" in out


def test_load_content_extracts_xlsx_text(tmp_path):
    p = tmp_path / "passwords.xlsx"
    _make_xlsx(p, [
        "Account",
        "AdminPassword: hunter2",
        "Comments",
    ])
    out = load_content(p)
    assert out is not None
    assert "hunter2" in out


def test_load_content_returns_none_for_corrupt_docx(tmp_path):
    """Random bytes named .docx — caller falls back to None."""
    p = tmp_path / "corrupt.docx"
    p.write_bytes(b"not actually a zip")
    assert load_content(p) is None


def test_load_content_returns_none_for_empty_ooxml(tmp_path):
    """Valid ZIP but no recognised OOXML members → None."""
    p = tmp_path / "empty.docx"
    with zipfile.ZipFile(p, "w") as zf:
        zf.writestr("unrelated.txt", "hi")
    assert load_content(p) is None
