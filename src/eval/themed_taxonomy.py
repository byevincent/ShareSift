"""v0.19 failure-mode taxonomy for themed-benchmark triage.

A fixed vocabulary of labels prevents the iteration loop in
``docs/v0p19_themed_benchmark_plan.md`` from accumulating noise
across themes. Each per-theme run identifies its worst misses and
tags each one with exactly one of the labels below; the v0.20 fix
is then scoped to the dominant category for that theme.

Why a fixed vocabulary? Open-ended triage produces incomparable
labels ("misses payroll docs" vs "doesn't flag wire instructions")
which both encode the same ``naming-ood`` failure mode. The fixed
set lets us compare across themes and decide whether a fix is
shared infrastructure (e.g. a new path-feature) or theme-specific
(e.g. one extra regex).
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class FailureLabel(str, Enum):
    NAMING_OOD = "naming-ood"
    """Path classifier didn't flag a file whose name should have been
    obvious in the theme — filename-token distribution shifted out of
    the training data's distribution. Fix side: Stage 1 retrain with
    augmented naming patterns."""

    CONTENT_OOD = "content-ood"
    """Stage 2 said 'no' on content the model should have caught —
    document template shift. Fix side: Stage 2 training data."""

    TEMPLATE_MISMATCH = "template-mismatch"
    """Content classifier said 'yes' on a template-shaped FP (legal
    boilerplate using 'password' as a word; EHR fields with
    credential-shape numerics). Fix side: Stage 2 training data +
    adversarial negative examples."""

    EXTRACTION_MISSING = "extraction-missing"
    """The juicy file exists but the pipeline can't read it (PDF,
    encrypted blob, binary). Fix side: extractor extension. PDF text
    extraction is the obvious v0.20 candidate."""

    CALIBRATION_DRIFT = "calibration-drift"
    """Tier band assignment was honestly wrong — Black-tier claim on
    Yellow-quality content, or vice versa. Fix side: recalibrate
    thresholds against the theme distribution."""

    PARSER_GAP = "parser-gap"
    """Structured parser doesn't recognise the format (a new vault
    layout, a new credential file). Fix side: new parser."""


@dataclass
class TriagedMiss:
    """One row in a per-theme failure report.

    Filled in during step 4 ("triage") of the iteration loop.
    """

    path: str
    label: FailureLabel
    note: str
    salted_credential_type: str | None = None
    path_probability: float | None = None
    path_tier: str | None = None

    def to_dict(self) -> dict:
        return {
            "path": self.path,
            "label": self.label.value,
            "note": self.note,
            "salted_credential_type": self.salted_credential_type,
            "path_probability": self.path_probability,
            "path_tier": self.path_tier,
        }


def all_labels() -> list[str]:
    """Public enumeration of the taxonomy for docs / reports."""
    return [label.value for label in FailureLabel]
