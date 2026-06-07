"""Subprocess wrapper around the ``kingfisher`` CLI.

Kingfisher is the v0 weak-labeling oracle for content-classifier training
data, per ``docs/build_plan.md`` Phase 3. Its 925+ rules cover the
breadth of secret patterns (API keys, private keys, db connection
strings, JWT, etc.); its optional live-validation step (``--validate``)
upgrades a regex match to a "verified" status when the secret is still
active against its origin service.

We map kingfisher's three confidence levels to a positive-label
gradient:

* ``high``   → strong positive (validated or strict-shape match)
* ``medium`` → soft positive   (regex match passes entropy + structure
                                 heuristics but unvalidated)
* ``low``    → weak positive   (matches a permissive rule; many of
                                 these will be false positives — useful
                                 as hard-negative training material if
                                 audited)

We always run with ``--no-validate`` in the pipeline so no live
credential checks fire during dataset construction (avoids accidental
auth attempts against third-party services). Validation can be re-run
in a separate audited pass against a controlled subset.
"""

from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Finding:
    """One kingfisher match — a (path, line, rule, confidence, snippet)
    tuple sufficient for downstream snippet extraction and labeling.

    ``snippet`` is the exact matched substring from kingfisher's output
    (not the surrounding context — call ``snippet.extract_context()``
    to get the training window around this position).
    """

    path: Path
    line: int
    column_start: int
    column_end: int
    rule_id: str
    rule_name: str
    confidence: str  # "low" | "medium" | "high"
    snippet: str
    fingerprint: str
    entropy: float


def _parse_findings(raw: dict) -> list[Finding]:
    out: list[Finding] = []
    for f in raw.get("findings", []):
        rule = f.get("rule", {})
        d = f.get("finding", {})
        try:
            out.append(
                Finding(
                    path=Path(d["path"]),
                    line=int(d.get("line", 0)),
                    column_start=int(d.get("column_start", 0)),
                    column_end=int(d.get("column_end", 0)),
                    rule_id=rule.get("id", ""),
                    rule_name=rule.get("name", ""),
                    confidence=d.get("confidence", "low"),
                    snippet=d.get("snippet", ""),
                    fingerprint=d.get("fingerprint", ""),
                    entropy=float(d.get("entropy", 0.0) or 0.0),
                )
            )
        except (KeyError, ValueError, TypeError):
            # Malformed entry — kingfisher's output schema is stable
            # but rules vary; skip rather than crash the run.
            continue
    return out


def scan(
    paths: list[Path],
    *,
    confidence: str = "low",
    jobs: int = 16,
    extra_args: tuple[str, ...] = (),
) -> list[Finding]:
    """Scan ``paths`` with kingfisher and return parsed findings.

    ``confidence`` is the lower bound (kingfisher emits everything at or
    above this level). Default ``"low"`` captures the full gradient
    (low/medium/high) so the dataset builder can stratify on it
    downstream. Validation is always disabled to avoid network-side
    effects during dataset construction.
    """
    if not paths:
        return []
    cmd = [
        "kingfisher",
        "scan",
        "-f",
        "json",
        "-n",  # no validation — strictly path/content matching
        "-c",
        confidence,
        "-j",
        str(jobs),
        *extra_args,
        *(str(p) for p in paths),
    ]
    result = subprocess.run(cmd, capture_output=True, text=True, check=False)
    # Kingfisher's JSON format emits TWO concatenated JSON objects on
    # stdout — the findings object, then a newline, then a summary
    # object. ``json.loads`` rejects that; ``raw_decode`` parses just
    # the first. Kingfisher's return code is non-zero (200) when
    # findings exist, so ``check=False`` is intentional — we treat any
    # parseable stdout as a successful scan and the summary as
    # uninteresting. stderr carries human-readable progress lines.
    raw = result.stdout.lstrip()
    if not raw:
        return []
    try:
        obj, _idx = json.JSONDecoder().raw_decode(raw)
    except json.JSONDecodeError:
        return []
    return _parse_findings(obj)
