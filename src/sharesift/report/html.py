"""Jinja2 renderer that turns a list of hit records into one HTML file.

The renderer also pre-computes summary stats (counts by tier, by
verification status, by share, top rules) so the template can be
mostly markup with minimal computation. JS does sort / filter /
search / row-expand interactively.
"""

from __future__ import annotations

import json
import os
from collections import Counter
from datetime import datetime
from pathlib import Path

_TIER_ORDER = ["Black", "Red", "Yellow", "Green", "Gray"]
_VERIFY_ORDER = ["passed", "failed", "inconclusive", "skipped"]


def _share_of(path: str) -> str:
    """Best-effort share/host extractor.

    UNC paths (``\\\\server\\share\\...``) → ``\\\\server\\share``.
    POSIX paths (``/foo/bar/...``) → first path component.
    Anything else → ``unknown``.
    """
    if not path:
        return "unknown"
    if path.startswith("\\\\"):
        parts = path.lstrip("\\").split("\\")
        if len(parts) >= 2:
            return f"\\\\{parts[0]}\\{parts[1]}"
        return path
    if path.startswith("/"):
        parts = [p for p in path.split("/") if p]
        if parts:
            return "/" + parts[0]
    return "unknown"


def _ext_of(path: str) -> str:
    base = os.path.basename(path or "")
    if "." not in base:
        return "(none)"
    return "." + base.rsplit(".", 1)[-1].lower()


_TIER_COLORS = {
    "Black": "#111",
    "Red": "#d93636",
    "Yellow": "#e6a800",
    "Green": "#2eb872",
    "Gray": "#7a8597",
}

_VERIFY_COLORS = {
    "passed": "#2eb872",
    "failed": "#d93636",
    "inconclusive": "#e6a800",
    "skipped": "#7a8597",
}


def _donut_segments(items: list[tuple[str, int]], colors: dict) -> list[dict]:
    """Convert (label, count) pairs into SVG stroke-dasharray segments.

    Each segment dict has: label, count, color, dasharray, dashoffset.
    Donut renders with stroke-width on a circle; segments come from
    different colored circles stacked at the same center.
    """
    total = sum(c for _, c in items)
    if total == 0:
        return []
    circumference = 2 * 3.14159265 * 40  # radius=40
    out = []
    cumulative = 0.0
    for label, count in items:
        frac = count / total
        seg_len = frac * circumference
        gap = circumference - seg_len
        out.append(
            {
                "label": label,
                "count": count,
                "fraction": frac,
                "color": colors.get(label, "#888"),
                "dasharray": f"{seg_len:.2f} {gap:.2f}",
                "dashoffset": f"{-cumulative:.2f}",
            }
        )
        cumulative += seg_len
    return out


def _summary(records: list[dict]) -> dict:
    by_tier: Counter[str] = Counter()
    by_verify: Counter[str] = Counter()
    by_share: Counter[str] = Counter()
    by_ext: Counter[str] = Counter()
    n_with_content = 0
    for r in records:
        by_tier[r.get("path_tier") or "Gray"] += 1
        if r.get("verification_status"):
            by_verify[r["verification_status"]] += 1
        by_share[_share_of(r.get("path", ""))] += 1
        by_ext[_ext_of(r.get("path", ""))] += 1
        if r.get("content_excerpt"):
            n_with_content += 1
    by_tier_pairs = [(t, by_tier.get(t, 0)) for t in _TIER_ORDER if by_tier.get(t)]
    by_verify_pairs = [
        (s, by_verify.get(s, 0)) for s in _VERIFY_ORDER if by_verify.get(s)
    ]
    return {
        "total": len(records),
        "by_tier": by_tier_pairs,
        "by_verify": by_verify_pairs,
        "tier_donut": _donut_segments(by_tier_pairs, _TIER_COLORS),
        "verify_donut": _donut_segments(by_verify_pairs, _VERIFY_COLORS),
        "top_shares": by_share.most_common(10),
        "top_extensions": by_ext.most_common(10),
        "n_with_content": n_with_content,
        "has_verification": any(r.get("verification_status") for r in records),
    }


def _fingerprint(record: dict) -> str:
    """Stable identifier for a hit record across scan / label / retrain.

    Hashes path + content_excerpt so labels.jsonl can be joined back to
    the originating hit record even after re-scans with non-deterministic
    record ordering.
    """
    import hashlib

    h = hashlib.sha256()
    h.update((record.get("path") or "").encode("utf-8", errors="replace"))
    h.update(b"\x00")
    h.update((record.get("content_excerpt") or "").encode("utf-8", errors="replace"))
    return "sha256:" + h.hexdigest()[:32]


def _normalize(record: dict) -> dict:
    """Prep a record for the template: derived columns + safe-truncate snippet."""
    snippet = record.get("content_excerpt") or ""
    return {
        "path": record.get("path", ""),
        "share": _share_of(record.get("path", "")),
        "extension": _ext_of(record.get("path", "")),
        "tier": record.get("path_tier") or "Gray",
        "prob": (
            f"{record['path_probability']:.3f}"
            if isinstance(record.get("path_probability"), (int, float))
            else ""
        ),
        "content_check": record.get("content_check") or "—",
        "verification_status": record.get("verification_status") or "",
        "snippet_preview": snippet[:160].replace("\n", " "),
        "snippet_full": snippet,
        "verification_results": record.get("verification_results") or [],
        "extracted_credential_types": record.get("extracted_credential_types") or [],
        "extracted_fields": record.get("extracted_fields") or [],
        "fingerprint": _fingerprint(record),
    }


def render_html(
    records: list[dict],
    output_path: str | Path,
    title: str | None = None,
) -> Path:
    """Render ``records`` to ``output_path`` and return the path.

    Single self-contained HTML — no CDN, no external assets.
    """
    try:
        from jinja2 import Environment, FileSystemLoader, select_autoescape
    except ImportError as exc:
        raise SystemExit(
            f"render_html requires Jinja2; install with `uv sync --group report` ({exc})"
        ) from exc

    template_dir = Path(__file__).parent
    env = Environment(
        loader=FileSystemLoader(template_dir),
        autoescape=select_autoescape(["html", "j2"]),
    )
    tpl = env.get_template("template.html.j2")

    normalized = [_normalize(r) for r in records]
    summary = _summary(records)

    html = tpl.render(
        title=title or "ShareSift results",
        generated_at=datetime.now().isoformat(timespec="seconds"),
        summary=summary,
        records=normalized,
        records_json=json.dumps(normalized, ensure_ascii=False),
    )
    out = Path(output_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(html, encoding="utf-8")
    return out
