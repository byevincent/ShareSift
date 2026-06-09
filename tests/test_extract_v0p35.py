"""v0.35 Sprint 3.5 — extract.py refactor tests.

Covers the new pure ``extract_text(bytes, ext)`` function and the
share-aware ``load_content_from_share``. The existing
``load_content(Path)`` is exercised by the legacy test suite —
this file only adds the new surface.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

import pytest

from sharesift.extract import (
    DEFAULT_MAX_BYTES,
    DEFAULT_MAX_READ_BYTES,
    extract_text,
    load_content,
    load_content_from_share,
)
from sharesift.share import LocalShare


class TestExtractTextPureFn:
    def test_plain_text_decoded_utf8(self):
        assert extract_text(b"hello world", ".txt") == "hello world"

    def test_invalid_utf8_replaced(self):
        # ``errors="replace"`` substitutes the replacement character;
        # never raises.
        result = extract_text(b"hello \xff\xfe world", ".txt")
        assert result is not None
        assert "hello" in result and "world" in result

    def test_max_bytes_caps_output(self):
        result = extract_text(b"0123456789", ".txt", max_bytes=5)
        assert result == "01234"

    def test_max_bytes_none_means_no_cap(self):
        data = b"x" * 100
        result = extract_text(data, ".txt", max_bytes=0)
        assert len(result) == 100

    def test_unknown_ext_treated_as_text(self):
        assert extract_text(b"content", ".weirdext") == "content"

    def test_pdf_garbage_returns_none(self):
        assert extract_text(b"not a real pdf", ".pdf") is None

    def test_ooxml_garbage_returns_none(self):
        assert extract_text(b"not a real zip", ".docx") is None


class TestExtractTextParityWithLoadContent:
    """The new ``extract_text(bytes, ext)`` must produce the same
    output as the legacy ``load_content(Path)`` for the same bytes
    + extension. Guards against silent behavior drift."""

    def test_plain_text_parity(self, tmp_path):
        p = tmp_path / "f.txt"
        p.write_text("hello")
        from_path = load_content(p)
        from_bytes = extract_text(p.read_bytes(), ".txt")
        assert from_path == from_bytes == "hello"

    def test_empty_text_parity(self, tmp_path):
        p = tmp_path / "f.txt"
        p.write_text("")
        from_path = load_content(p)
        from_bytes = extract_text(p.read_bytes(), ".txt")
        assert from_path == from_bytes == ""

    def test_large_text_capped_consistently(self, tmp_path):
        p = tmp_path / "f.txt"
        p.write_text("X" * 5000)
        from_path = load_content(p, max_bytes=100)
        from_bytes = extract_text(p.read_bytes(), ".txt", max_bytes=100)
        assert from_path == from_bytes
        assert len(from_path) == 100


class TestLoadContentBackwardCompat:
    """v0.35 must not change behavior of the existing path-based
    ``load_content`` — the refactor went through ``extract_text``
    but the wrapper preserves all observable semantics."""

    def test_nonexistent_file_returns_none(self):
        assert load_content(Path("/no/such/file.txt")) is None

    def test_directory_returns_none(self, tmp_path):
        assert load_content(tmp_path) is None

    def test_plain_text_works(self, tmp_path):
        p = tmp_path / "f.txt"
        p.write_text("hello world")
        assert load_content(p) == "hello world"

    def test_max_bytes_caps_output(self, tmp_path):
        p = tmp_path / "f.txt"
        p.write_text("X" * 1000)
        assert load_content(p, max_bytes=10) == "XXXXXXXXXX"


class TestLoadContentFromShare:
    def test_localshare_parity_with_load_content(self, tmp_path):
        """Same file, same caps — share path and Path path must
        produce identical output."""
        p = tmp_path / "secrets.txt"
        p.write_text("password=hunter2")

        via_path = load_content(p)
        via_share = load_content_from_share(LocalShare(), str(p))
        assert via_path == via_share == "password=hunter2"

    def test_returns_none_when_share_returns_none(self):
        """If share.read_bytes returns None (file unreadable), the
        loader returns None without trying to parse."""
        share = MagicMock()
        share.read_bytes.return_value = None
        assert load_content_from_share(share, "anything.txt") is None

    def test_passes_max_read_bytes_to_share(self):
        share = MagicMock()
        share.read_bytes.return_value = b"content"
        load_content_from_share(
            share, "f.txt", max_read_bytes=42
        )
        assert share.read_bytes.call_args.kwargs["max_bytes"] == 42

    def test_default_max_read_bytes_is_10mb(self):
        share = MagicMock()
        share.read_bytes.return_value = b"content"
        load_content_from_share(share, "f.txt")
        assert (
            share.read_bytes.call_args.kwargs["max_bytes"]
            == DEFAULT_MAX_READ_BYTES
        )
        assert DEFAULT_MAX_READ_BYTES == 10 * 1024 * 1024

    def test_extension_extracted_from_path_string(self):
        """``Path(path_str).suffix`` is used for dispatch — should
        work for UNC paths the same as posix."""
        share = MagicMock()
        share.read_bytes.return_value = b"not a real pdf"
        # UNC with .pdf extension routes to PDF extractor (which
        # returns None for garbage)
        result = load_content_from_share(
            share, r"\\host\share\file.PDF"
        )
        assert result is None  # PDF extractor rejects garbage

    def test_max_bytes_caps_output_text(self):
        share = MagicMock()
        share.read_bytes.return_value = b"X" * 1000
        result = load_content_from_share(
            share, "f.txt", max_bytes=10
        )
        assert result == "XXXXXXXXXX"
