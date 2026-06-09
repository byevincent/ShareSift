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
    filename-frequency penalty + the v0.21 Green-tier zero-out.

    Records are expected to be the v0.20 cascade output shape
    (``path``, ``probability``, ``tier`` for Stage 1; optionally
    ``cascade_tier`` for the content cascade).

    The returned list is the same objects (mutated in place) with
    ``rank_score`` added. Original ``probability`` and ``tier``
    are preserved unchanged.

    **v0.44 step 2: Green-tier zero-out.** When the cascade tier
    is explicitly Green (Relay-action match — RelayPsByExtension,
    RelayVBScriptByExtension, RelayConfigByExtension, etc. fire on
    every ``.ps1`` / ``.vbs`` / ``.config``), the path classifier's
    probability is IGNORED. The v0.21 MSF3 validation showed Relay
    matches drown genuine credentials when given any positive
    weight — but the previous ``max(prob, tier_pseudo_p)`` logic
    let path_probability=1.0 override cascade_tier=Green via the
    max. That defeated the v0.21 lesson. v0.44 fixes it by
    short-circuiting to 0 when cascade_tier is Green.

    Operator-facing tools sort by ``rank_score`` descending for
    top-K presentation.
    """
    filenames = [basename(r.get("path", "")) for r in records]
    freq = Counter(filenames)

    for r, fname in zip(records, filenames):
        # v0.44 step 2: explicit Green cascade tier zeros evidence
        # (no Relay-rule-only file ranks against credentials).
        if r.get("cascade_tier") == "Green":
            per_file_evidence = 0.0
        else:
            per_file_evidence = max(
                float(r.get("probability") or 0.0),
                _TIER_PSEUDO_P.get(r.get("cascade_tier"), 0.0),
                _TIER_PSEUDO_P.get(r.get("tier"), 0.0),
            )
        penalty_divisor = max(1.0, float(freq[fname])) ** 0.5
        r["rank_score"] = round(per_file_evidence / penalty_divisor, 6)
        r["filename_frequency"] = freq[fname]
    return records


_VERIFICATION_RANK = {
    "passed": 4,         # LIVE — verified-now credential
    "failed": 3,         # was real (revoked / wrong / expired)
    "inconclusive": 2,   # couldn't determine
    "skipped": 1,        # no verifier ran
    None: 0,
}

_TIER_RANK = {
    "Black": 4,
    "Red": 3,
    "Yellow": 2,
    "Green": 1,
    None: 0,
}


def sort_verifier_first(records: list[dict]) -> list[dict]:
    """Sort hits so verified-live credentials surface first.

    This is the **structural ShareSift advantage Snaffler can't
    match**: Snaffler finds files; ShareSift finds files AND tells
    operators which contain credentials that actually authenticate
    right now. Reordering output to put ``verification_status="passed"``
    records first turns "20 of 400 hits are live" from a footnote
    into the operator's first impression.

    Sort key (descending priority):

    1. verification_status — ``passed`` > ``failed`` > ``inconclusive``
       > ``skipped`` > missing
    2. content_tier / path_tier — Black > Red > Yellow > Green > none
    3. rank_score — the v0.44 dedup-penalized signal
    4. path — stable tiebreaker

    Records without verification fields fall back gracefully; mixing
    verified and unverified records in one list works correctly
    (unverified land at the bottom, ranked by tier + score among
    themselves).
    """
    def key(r: dict) -> tuple:
        tier = r.get("content_tier") or r.get("path_tier")
        return (
            -_VERIFICATION_RANK.get(r.get("verification_status"), 0),
            -_TIER_RANK.get(tier, 0),
            -float(r.get("rank_score") or r.get("probability") or 0.0),
            r.get("path", ""),
        )
    return sorted(records, key=key)


def live_marker(record: dict) -> str:
    """Compact marker for tabular display.

    ``[LIVE]`` for verified-passed records, ``[FAIL]`` for
    failed-verification (was-real-but-now-revoked), empty string
    otherwise. Used by the Snaffler-TSV converter and HTML report
    to surface verification status at a glance.
    """
    status = record.get("verification_status")
    if status == "passed":
        return "[LIVE]"
    if status == "failed":
        return "[FAIL]"
    return ""


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
