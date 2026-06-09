"""v0.20: file content extraction wrapper.

Replaces the bare ``path.read_text()`` call in ``Scanner.scan_batch``
with a dispatch that handles PDFs (via ``pypdf``, opt-in via the
``pdf-extraction`` group) and falls back to UTF-8 text for
everything else. Includes the base64 preprocessor as an optional
post-step so credentials nested inside JSON/XML/.ps1 configs surface
to the rule engine.

Design:

* ``load_content(path, *, max_bytes)`` returns the file's text
  representation, or None if it can't be read. Never raises.
* PDFs route through ``_extract_pdf`` which lazy-imports pypdf —
  if pypdf isn't installed, returns None (the file becomes invisible
  to content stage, same as v0.19).
* The base64 decoder is invoked when ``decode_base64=True`` and
  appends decoded blobs to the original text. v0.19 found base64-
  encoded credentials inside ``.xml``/``.json`` configs that
  Scanner.scan_batch wasn't surfacing.
"""

from __future__ import annotations

import io
from pathlib import Path
from typing import TYPE_CHECKING, Final

if TYPE_CHECKING:
    from sharesift.share import Share

DEFAULT_MAX_BYTES: Final[int] = 1_048_576  # 1 MB cap on extracted text
# v0.35 Sprint 3.5: cap on raw bytes read from a share before
# extraction. Larger than DEFAULT_MAX_BYTES because PDFs / OOXML
# can be 10× their extracted text size.
DEFAULT_MAX_READ_BYTES: Final[int] = 10 * 1024 * 1024


def _extract_pdf_from_bytes(data: bytes) -> str | None:
    """Best-effort text extraction from PDF bytes. Returns None if
    pypdf isn't installed or the bytes don't parse."""
    try:
        import pypdf
    except ImportError:
        return None
    try:
        reader = pypdf.PdfReader(io.BytesIO(data))
    except Exception:
        # Encrypted PDFs without a password, malformed PDFs, etc.
        return None
    chunks: list[str] = []
    for page in reader.pages:
        try:
            chunks.append(page.extract_text() or "")
        except Exception:
            continue
    if not chunks:
        return None
    return "\n".join(chunks)


def _extract_pdf(path: Path) -> str | None:
    """Backward-compat wrapper. New callers should pass bytes via
    ``_extract_pdf_from_bytes`` directly."""
    try:
        data = path.read_bytes()
    except OSError:
        return None
    return _extract_pdf_from_bytes(data)


# v0.23: OOXML (docx/xlsx/pptx) traversal. These files are ZIP archives
# of XML. The stdlib has everything we need — zipfile + ElementTree —
# so no new dependency.
_OOXML_TEXT_MEMBERS = {
    ".docx": ("word/document.xml",),
    ".xlsx": (
        "xl/sharedStrings.xml",
        # Sheet data lives in xl/worksheets/sheet*.xml; enumerated at extract time.
    ),
    ".pptx": (),  # enumerated dynamically
}


def _extract_ooxml_from_bytes(data: bytes, ext: str) -> str | None:
    """Best-effort text extraction from OOXML bytes.

    The file is a ZIP of XML. We open the relevant entries, strip the
    XML tags, and concatenate the text content. Anything that doesn't
    parse cleanly returns None.
    """
    import xml.etree.ElementTree as ET
    import zipfile

    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
    except (zipfile.BadZipFile, OSError):
        return None

    chunks: list[str] = []
    try:
        names = set(zf.namelist())
        targets: list[str] = []
        # Static entries per extension.
        for member in _OOXML_TEXT_MEMBERS.get(ext, ()):
            if member in names:
                targets.append(member)
        # Dynamic worksheet / slide enumeration.
        if ext == ".xlsx":
            targets.extend(
                n for n in sorted(names)
                if n.startswith("xl/worksheets/sheet") and n.endswith(".xml")
            )
        elif ext == ".pptx":
            targets.extend(
                n for n in sorted(names)
                if n.startswith("ppt/slides/slide") and n.endswith(".xml")
            )

        for member in targets:
            try:
                xml_bytes = zf.read(member)
            except KeyError:
                continue
            try:
                root = ET.fromstring(xml_bytes)
            except ET.ParseError:
                continue
            # Concatenate every text node — the XML schema differs across
            # OOXML doc types but every text-carrying element is a tag
            # containing #text.
            for el in root.iter():
                if el.text:
                    chunks.append(el.text)
    finally:
        zf.close()

    if not chunks:
        return None
    return "\n".join(chunks)


def _read_text(path: Path) -> str | None:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None


def _extract_ooxml(path: Path, ext: str) -> str | None:
    """Backward-compat path-based wrapper. New callers pass bytes via
    ``_extract_ooxml_from_bytes`` directly."""
    try:
        data = path.read_bytes()
    except OSError:
        return None
    return _extract_ooxml_from_bytes(data, ext)


def extract_text(
    data: bytes,
    ext: str,
    *,
    max_bytes: int = DEFAULT_MAX_BYTES,
    decode_base64: bool = False,
) -> str | None:
    """v0.35: pure bytes-in extractor. Dispatches on ``ext`` to the
    right decoder, applies base64 post-processing, caps output text.

    No I/O. Easy to test. Shared by both the path-based
    ``load_content`` and the share-aware ``load_content_from_share``.
    """
    if ext == ".pdf":
        text = _extract_pdf_from_bytes(data)
    elif ext in (".docx", ".xlsx", ".pptx"):
        text = _extract_ooxml_from_bytes(data, ext)
    else:
        try:
            text = data.decode("utf-8", errors="replace")
        except Exception:
            return None

    if text is None:
        return None

    if decode_base64:
        text = _apply_base64_decoder(text)

    if max_bytes and len(text) > max_bytes:
        text = text[:max_bytes]
    return text


def load_content(
    path: Path,
    *,
    max_bytes: int = DEFAULT_MAX_BYTES,
    decode_base64: bool = False,
) -> str | None:
    """Best-effort content extraction from a local file. Returns
    None for unreadable files.

    ``max_bytes`` caps the returned string. PDFs are extracted first,
    then capped — partial extraction is preferred over silent skip.

    ``decode_base64`` triggers the recursive base64 preprocessor.
    Disabled by default because it doubles content size for files
    that have legitimate base64 blobs (cert files, signed payloads)
    and the rule engine catches those at the surface level too.

    v0.35: backward-compat shim around :func:`extract_text`. Share-aware
    callers should use :func:`load_content_from_share` instead.
    """
    if not path.exists() or not path.is_file():
        return None
    try:
        data = path.read_bytes()
    except OSError:
        return None
    return extract_text(
        data, path.suffix.lower(),
        max_bytes=max_bytes, decode_base64=decode_base64,
    )


def load_content_from_share(
    share: "Share",
    path: str,
    *,
    max_bytes: int = DEFAULT_MAX_BYTES,
    decode_base64: bool = False,
    max_read_bytes: int = DEFAULT_MAX_READ_BYTES,
) -> str | None:
    """v0.35: share-aware content load. Works for both ``LocalShare``
    (any local path) and ``SmbShare`` (UNC paths from ``walk``).

    ``max_bytes`` caps the extracted text (same semantic as
    :func:`load_content`). ``max_read_bytes`` caps the raw bytes
    read off the share — larger than ``max_bytes`` because OOXML /
    PDF compress text by 5-10×. v0.36's ``--max-file-size`` flag
    will surface this parameter to operators.
    """
    data = share.read_bytes(path, max_bytes=max_read_bytes)
    if data is None:
        return None
    ext = Path(path).suffix.lower()
    return extract_text(
        data, ext,
        max_bytes=max_bytes, decode_base64=decode_base64,
    )


def _apply_base64_decoder(text: str) -> str:
    """Run the base64 preprocessor and concatenate decoded content.

    Lazy import so the preprocess module's overhead is only paid by
    callers that want it.
    """
    try:
        from sharesift.preprocess.base64_decode import recursive_base64_decode
    except ImportError:
        return text
    try:
        expanded, _log = recursive_base64_decode(text)
    except Exception:
        return text
    # recursive_base64_decode already prepends its own delimiter
    # (``<<<TRUFFLER_DECODED>>>``) inside ``expanded``. We just need
    # to return whichever is larger — if no decoding happened, the
    # input is returned unchanged.
    return expanded
