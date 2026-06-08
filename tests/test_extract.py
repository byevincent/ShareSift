"""v0.20 Phase 1: file content extraction wrapper."""

from __future__ import annotations

import io

from sharesift.extract import _read_text, load_content


def test_load_content_text_file_round_trips(tmp_path):
    p = tmp_path / "hello.txt"
    p.write_text("alpha beta\n", encoding="utf-8")
    assert load_content(p) == "alpha beta\n"


def test_load_content_returns_none_for_missing_file(tmp_path):
    assert load_content(tmp_path / "ghost.txt") is None


def test_load_content_respects_max_bytes(tmp_path):
    p = tmp_path / "big.txt"
    p.write_text("x" * 5000, encoding="utf-8")
    truncated = load_content(p, max_bytes=128)
    assert truncated is not None
    assert len(truncated) == 128


def test_load_content_falls_back_when_pdf_extraction_unavailable(tmp_path, monkeypatch):
    """If pypdf isn't installed, a .pdf path returns None — graceful
    degradation rather than raise."""
    p = tmp_path / "doc.pdf"
    p.write_bytes(b"not actually a pdf, just .pdf-named")

    # Force the lazy import to fail.
    import sys
    monkeypatch.setitem(sys.modules, "pypdf", None)

    assert load_content(p) is None


def test_load_content_base64_decoder_appends_decoded(tmp_path):
    """``decode_base64=True`` should surface a decoded credential
    inside a JSON/XML/.ps1 config so the rule engine catches it."""
    p = tmp_path / "config.json"
    # base64('password=secret123') = cGFzc3dvcmQ9c2VjcmV0MTIz
    payload = (
        '{"setting": "ok", "encoded": "cGFzc3dvcmQ9c2VjcmV0MTIzc2VjcmV0MTIz"}'
    )
    p.write_text(payload, encoding="utf-8")
    decoded = load_content(p, decode_base64=True)
    assert decoded is not None
    assert "TRUFFLER_DECODED" in decoded  # delimiter added by recursive_base64_decode


def test_load_content_base64_decoder_off_by_default(tmp_path):
    p = tmp_path / "config.json"
    p.write_text('{"v": "cGFzc3dvcmQ9c2VjcmV0MTIzc2VjcmV0MTIz"}', encoding="utf-8")
    raw = load_content(p)
    assert raw is not None
    assert "TRUFFLER_DECODED" not in raw
