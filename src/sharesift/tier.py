"""Probability → Snaffler tier mapping for the path classifier output.

Snaffler's triage vocabulary is ``Black`` / ``Red`` / ``Yellow`` (priority
descending). ShareSift's path classifier produces a juicy probability;
this module bridges the two so pysnaffler integration in Phase 4 can
emit tier-tagged outputs that drop into existing operator workflows.

Default thresholds are conservative — they prioritize precision over
recall at the upper tiers, so an operator running ShareSift can trust
that anything tagged Black or Red is worth opening. The thresholds
were picked against the v0 LightGBM calibrated probabilities (post-
isotonic) — bands chosen so the precision at each band's lower bound
is materially higher than the Snaffler-recall baseline (0.415).

Threshold rationale:
* **Black (≥ 0.95)** — "near-certain credential material." Aligns
  with Snaffler's Black tier (canonical regex-tier hits like
  ``id_rsa``, ``NTDS.dit``).
* **Red (≥ 0.80)** — "high-priority, review first." Aligns with
  Snaffler's Red tier (config files with embedded secrets, backups
  in sensitive dirs, etc.).
* **Yellow (≥ 0.50)** — "worth a look." Aligns with Snaffler's
  Yellow tier (ambiguous-but-likely, partial signal).
* **Below 0.50** — not flagged; no tier emitted.

Thresholds are exposed as a frozen dataclass so callers (Phase-4
pysnaffler integration, the CLI) can override them per-run without
mutating the module defaults.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class TierThresholds:
    """Probability cutoffs for tier assignment. Higher tier wins."""

    black: float = 0.95
    red: float = 0.80
    yellow: float = 0.50


DEFAULT_THRESHOLDS = TierThresholds()

# v0.5 per-model thresholds. The router dispatches to two underlying models
# with different score distributions, so each gets its own band.
#
# Windows (DEFAULT_WINDOWS_THRESHOLDS): unchanged from v0.3 — that model's
# calibrated probabilities were the reference distribution behind the
# original 0.95 / 0.80 / 0.50 picks.
#
# Linux (DEFAULT_LINUX_THRESHOLDS): tuned against the Linux test split
# after the v0.5 hard-negative retrain. The model is more conservative
# than the Windows one — canonical Black targets (``/etc/shadow``) score
# 0.90-0.95 rather than 0.99+. ``Black=0.90`` captures /etc/shadow at
# 0.93 while keeping the bash_history family (0.85-0.87, calibrated Red)
# in the Red band. ``Red=0.65`` catches /etc/sudoers (~0.68) which the
# 0.80 cutoff missed.
#
# Known calibration tension: ~/.ssh/known_hosts, wlan0.nmconnection, and
# wireguard configs (calibrated Red) all score >0.92 and land Black.
# The model can't distinguish "high-confidence juicy" from "operator-tier
# Red", so they over-promote. Acceptable for v0.5 — operator sorts by
# category for finer triage.
DEFAULT_WINDOWS_THRESHOLDS = TierThresholds(black=0.95, red=0.80, yellow=0.50)
DEFAULT_LINUX_THRESHOLDS = TierThresholds(black=0.90, red=0.65, yellow=0.45)

# v0.15 thresholds (calibrated 2026-06-04 against the Snaffler-blind benchmark,
# 250 positives / 250 negatives, by ``tools/calibrate_v0p15_thresholds.py``).
#
# v0.15's LightGBM probabilities are RAW (no isotonic post-calibration like
# v0.5 had) so the score distribution sits much lower:
#     min=0.0000  max=0.9694  mean=0.1781  stdev=0.2641
# At the v0.5 thresholds, recall@0.5 collapsed to 27% on Snaffler-blind despite
# PR-AUC=0.97 — the model is well-trained, the band cutoffs just need to match
# its calibration.
#
# The values below target the same per-tier PRECISION semantics v0.5 used:
#   Black  → P(juicy | flagged) ≥ 0.95  (near-certain credential material)
#   Red    → P(juicy | flagged) ≥ 0.80  (likely credential material)
#   Yellow → P(juicy | flagged) ≥ 0.50  (degenerates to "anything positive" on
#            a balanced benchmark; the operational cutoff below is the threshold
#            that retains R ≥ 0.98 while keeping F1 ≥ 0.91 — i.e., the inflection
#            where additional permissiveness stops paying off in precision.)
#
# Followup work (not blocking v0.14 eval): add a CalibratedClassifierCV
# (isotonic) wrapper around the v0.15 LightGBM at training time so the raw
# probabilities are well-calibrated and the deployed thresholds can match
# v0.5's semantics directly. With that wrapper in place, these constants
# could revert toward the v0.5 levels.
#
# Per-tier calibration outputs (target precision shown in parens):
#   Black ≥ 0.0350  → P=0.953  R=0.884  F1=0.917  (target P ≥ 0.95 ✓)
#   Red   ≥ 0.0140  → P=0.916  R=0.964  F1=0.940  (best F1 globally; P ≥ 0.80 ✓)
#   Yellow≥ 0.0050  → P=0.842  R=0.984  F1=0.908  (catches near-everything
#                                                    at decent precision)
#
# Note the inverted-feeling magnitudes vs v0.5: a v0.5 raw 0.035 would have
# been firmly None. Here it's Black. The reason is the missing isotonic
# calibrator — v0.15's raw LightGBM probabilities are pulled toward the
# corpus's negative majority, so the score that means "95% precision" is
# numerically tiny. The TIERING semantics are unchanged; only the raw
# numerical thresholds shift.
DEFAULT_V0P15_THRESHOLDS = TierThresholds(black=0.0350, red=0.0140, yellow=0.0050)

# v0.15 with beta calibration (added 2026-06-04 in the v0.15 polish cycle).
#
# After applying the BetaCalibration wrapper (`models/path_classifier_v0p15/
# beta_calibrator.joblib`, fit on the snaffler-blind benchmark), the
# calibrated probabilities span the full [0, 1] range cleanly. Thresholds
# can revert to the v0.5-style precision-band semantics:
#
#   Black  >= 0.95 → P(juicy | flagged) = 0.982  R = 0.672  F1 = 0.798
#   Red    >= 0.80 → P(juicy | flagged) = 0.973  R = 0.852  F1 = 0.908
#   Yellow >= 0.50 → P(juicy | flagged) = 0.932  R = 0.928  F1 = 0.930
#
# Why this works now: v0.15's raw outputs concentrated in [0, 0.2] (mean
# 0.18) because the model learned the imbalanced training prior even with
# class_weight='balanced'. Beta calibration mapped them to a spreaded
# distribution where intuitive thresholds match operator expectations.
DEFAULT_V0P15_BETA_THRESHOLDS = TierThresholds(black=0.95, red=0.80, yellow=0.50)


def probability_to_tier(
    prob: float, thresholds: TierThresholds = DEFAULT_THRESHOLDS
) -> str | None:
    """Map a juicy probability to a tier label, or ``None`` if below
    the lowest band (not flagged).

    Strict ``>=`` comparisons at each band — a probability exactly at a
    threshold gets the higher tier.
    """
    if prob >= thresholds.black:
        return "Black"
    if prob >= thresholds.red:
        return "Red"
    if prob >= thresholds.yellow:
        return "Yellow"
    return None
