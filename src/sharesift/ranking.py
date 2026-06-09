"""v0.44: filename-frequency dedup penalty.

The v0.22 versatility plan added this penalty to the eval_harness:

    rank_score = max(path_prob, cascade_pseudo_p) / sqrt(filename_frequency)

It dropped MIN top-10 on MSF3 from 0.10 → 0.20 by demoting
package-manager installer scripts (Boxstarter, Chocolatey, npm
post-install scripts) that appear N times in different paths.

**Until v0.44 the penalty was harness-only.** Production
``cmd_score_paths`` returned raw classifier probabilities, so an
operator running ``sharesift score-paths`` on MSF3 saw Boxstarter
``.ps1`` files dominating their top-10 — the exact failure mode
the harness was working around.

v0.44 ports the penalty to production. Top-K precision improvement
visible in real operator output, not just internal benchmarks.

Why ``sqrt`` and not a harsher penalty:
- 1 occurrence  → divisor 1.0    (unchanged)
- 4 occurrences → divisor 2.0    (halved)
- 16 occurrences → divisor 4.0   (quartered)
- 64 occurrences → divisor 8.0   (eighth)

Sub-linear so legitimate-but-common credential filenames (``.env``,
``credentials``, ``id_rsa``) still rank well when other signals
agree, while saturated installer-script names get heavily demoted.

The v0.28 attempt to add extension-frequency penalty was
falsified — see ``docs/v0p28_results.md``. Real Linux credential
files live in common-extension types (``.conf``, ``.cnf``, ``.php``)
which an extension penalty tanked. The hypothesis was
wrong-shaped; the fix discipline was back out rather than iterate
against the harness.
"""

from __future__ import annotations

import math
from collections import Counter
from pathlib import PurePosixPath


# Pseudo-probabilities for cascade tiers. Values match the v0.22
# eval_harness's _TIER_PSEUDO_P exactly so production ranking
# tracks the harness:
#
#   Black = 0.99   (high confidence; reserve 1.0 for cascade-confirmed)
#   Red   = 0.85
#   Yellow= 0.65
#   Green = 0.0    (v0.21 MSF3 finding: Relay matches fire on entire
#                   categories — every .ps1, every .config — and
#                   drown genuine credentials when given any weight)
#   None  = 0.0
_TIER_PSEUDO_P = {
    "Black": 0.99,
    "Red": 0.85,
    "Yellow": 0.65,
    "Green": 0.0,
    None: 0.0,
}


def basename(path: str) -> str:
    """Leaf filename for UNC / Windows / POSIX paths.

    UNC paths use backslashes; ``PurePosixPath`` would parse them as
    a single component. Normalize to forward-slash first."""
    if not path:
        return ""
    normalized = path.replace("\\", "/")
    return PurePosixPath(normalized).name


def apply_dedup_penalty(records: list[dict]) -> list[dict]:
    """Add a ``rank_score`` field to each record reflecting the
    filename-frequency penalty.

    Records are expected to be the v0.20 cascade output shape
    (``path``, ``probability``, ``tier`` for Stage 1; optionally
    ``cascade_tier`` for the content cascade).

    The returned list is the same objects (mutated in place) with
    ``rank_score`` added. Original ``probability`` and ``tier``
    are preserved unchanged so downstream consumers that expect the
    raw signal still get it.

    Operator-facing tools should sort by ``rank_score`` descending
    for top-K presentation; ``probability`` alone is the
    pre-dedup signal.
    """
    filenames = [basename(r.get("path", "")) for r in records]
    freq = Counter(filenames)

    for r, fname in zip(records, filenames):
        per_file_evidence = max(
            float(r.get("probability") or 0.0),
            _TIER_PSEUDO_P.get(r.get("cascade_tier"), 0.0),
            _TIER_PSEUDO_P.get(r.get("tier"), 0.0),
        )
        penalty_divisor = max(1.0, float(freq[fname])) ** 0.5
        r["rank_score"] = round(per_file_evidence / penalty_divisor, 6)
        r["filename_frequency"] = freq[fname]
    return records


def sort_by_rank(records: list[dict]) -> list[dict]:
    """Return records sorted by ``rank_score`` descending. Falls back
    to ``probability`` then ``path`` for stable ordering when the
    rank_score wasn't computed."""
    return sorted(
        records,
        key=lambda r: (
            -float(r.get("rank_score", r.get("probability", 0.0))),
            r.get("path", ""),
        ),
    )
