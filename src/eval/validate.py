"""Post-label integrity checker for ``data/eval/eval_set.jsonl``.

The schema (``EvalRecord``) enforces invariants at write time. This
checker re-validates the file on disk against the *current* sources of
truth — because a record may have been written under an older schema
version, hand-edited, merged from another source, or labeled before a
heuristic was added/removed/renamed. The whole reason a separate
integrity checker exists is "the data on disk may not match the code
that's supposed to describe it."

Two-tier failure model
----------------------

* **Hard errors** — record fails ``EvalRecord`` validation outright
  (malformed JSON, missing required field, schema constraint violated).
  The file is broken; CLI exits nonzero always.
* **Integrity warnings** — record is individually valid but violates a
  cross-record or cross-source-of-truth invariant (duplicate path,
  enum drift on a load-bearing field, ``pre_category`` drift, unknown
  heuristic name in ``validator_warnings``, validator-firing
  inconsistency). The file is suspect but parseable; default mode
  reports them and exits 0, ``--strict`` makes them fatal.

Stats are first-class output, always printed regardless of error state:
record count, label distribution, category histogram, source breakdown,
uncertainty-flagged count, and per-heuristic activity with override
rates. The override rate table is the canary monitor for mis-tuned
heuristics; the ⚠ marker fires only when override rate ≥ 30% AND
fires_count ≥ 10, to protect against a low-volume heuristic
(e.g. ``registry_hive_extensionless``) crying wolf about itself before
the data has signal.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

from pydantic import ValidationError

from src.eval._paths import normalize_for_dedup
from src.eval.categories import (
    CATEGORY_SLUGS,
    LABELER_FLAGS,
    MODERN_SAAS_SUBTYPES,
    SEVERITY_TIERS,
    SOURCES,
)
from src.eval.negative_validator import _HEURISTICS, check_path
from src.eval.schema import EvalRecord

# Override-rate canary thresholds. Both must hold to render the ⚠ marker:
# rate alone is too noisy on small denominators (especially for the
# ``registry_hive_extensionless`` canary, which is the prime suspect
# but also the lowest-volume heuristic). Marker thresholds are policy,
# not constants of the system — change in a code review.
OVERRIDE_WARN_THRESHOLD = 0.30
OVERRIDE_WARN_MIN_FIRES = 10

# ANSI yellow for ⚠ rows when colored output is enabled.
_ANSI_YELLOW = "\033[33m"
_ANSI_RESET = "\033[0m"


# ============================================================================
# Result dataclasses
# ============================================================================


@dataclass
class HardError:
    line_num: int
    message: str


@dataclass
class IntegrityWarning:
    """An invariant violation that doesn't make the file unparseable.

    ``kind`` is a short tag used to group warnings in the report:
    ``duplicate_path``, ``enum_drift``, ``pre_category_drift``,
    ``unknown_heuristic_name``, ``validator_drift``. Adding a new kind
    is fine; the formatter groups whatever is present.

    ``line_num`` is None for cross-record warnings (duplicates) where
    the violation spans multiple lines; the affected lines are named
    in ``message``.
    """

    line_num: int | None
    kind: str
    message: str


@dataclass
class HeuristicStats:
    name: str
    fires_count: int
    juicy_count: int
    not_juicy_count: int
    override_count: int

    @property
    def override_rate(self) -> float:
        return self.override_count / self.fires_count if self.fires_count else 0.0

    @property
    def warn(self) -> bool:
        return (
            self.fires_count >= OVERRIDE_WARN_MIN_FIRES
            and self.override_rate >= OVERRIDE_WARN_THRESHOLD
        )


@dataclass
class Stats:
    record_count: int = 0
    label_dist: Counter = field(default_factory=Counter)
    category_hist: Counter = field(default_factory=Counter)
    source_dist: Counter = field(default_factory=Counter)
    uncertainty_count: int = 0
    per_heuristic: list[HeuristicStats] = field(default_factory=list)


@dataclass
class ValidationReport:
    hard_errors: list[HardError] = field(default_factory=list)
    integrity_warnings: list[IntegrityWarning] = field(default_factory=list)
    stats: Stats = field(default_factory=Stats)


# ============================================================================
# Per-record integrity checks
# ============================================================================


def _check_enum_drift(record: EvalRecord, line_num: int) -> list[IntegrityWarning]:
    """Re-validate load-bearing enum fields against current constants.

    Each check would have failed schema validation at write time under
    the *current* constants; if it didn't, the constants have changed
    since the record was written.
    """
    warnings: list[IntegrityWarning] = []
    if record.source not in SOURCES:
        warnings.append(
            IntegrityWarning(
                line_num=line_num,
                kind="enum_drift",
                message=f"source {record.source!r} is not in current SOURCES {SOURCES}",
            )
        )
    if record.category not in CATEGORY_SLUGS:
        warnings.append(
            IntegrityWarning(
                line_num=line_num,
                kind="enum_drift",
                message=(f"category {record.category!r} is not in current CATEGORY_SLUGS"),
            )
        )
    if record.sub_type is not None and record.sub_type not in MODERN_SAAS_SUBTYPES:
        warnings.append(
            IntegrityWarning(
                line_num=line_num,
                kind="enum_drift",
                message=(f"sub_type {record.sub_type!r} is not in current MODERN_SAAS_SUBTYPES"),
            )
        )
    if record.tier is not None and record.tier not in SEVERITY_TIERS:
        warnings.append(
            IntegrityWarning(
                line_num=line_num,
                kind="enum_drift",
                message=f"tier {record.tier!r} is not in current SEVERITY_TIERS",
            )
        )
    return warnings


def _check_pre_category_drift(record: EvalRecord, line_num: int) -> list[IntegrityWarning]:
    """Separate kind from ``enum_drift`` because ``pre_category`` is a
    disposable hint, lower-severity than the load-bearing fields."""
    if record.pre_category is not None and record.pre_category not in CATEGORY_SLUGS:
        return [
            IntegrityWarning(
                line_num=line_num,
                kind="pre_category_drift",
                message=(
                    f"pre_category {record.pre_category!r} is not in current "
                    f"CATEGORY_SLUGS (hint field; lower severity than enum_drift)"
                ),
            )
        ]
    return []


def _check_validator_warnings_names(record: EvalRecord, line_num: int) -> list[IntegrityWarning]:
    """Every name in ``validator_warnings`` must belong to one of the
    two namespaces: the validator's ``_HEURISTICS`` registry or
    ``LABELER_FLAGS``."""
    heuristic_names = {h for h, _ in _HEURISTICS}
    allowed = heuristic_names | set(LABELER_FLAGS)
    unknown = [name for name in record.validator_warnings if name not in allowed]
    if not unknown:
        return []
    return [
        IntegrityWarning(
            line_num=line_num,
            kind="unknown_heuristic_name",
            message=(
                f"validator_warnings contains unknown name(s) {sorted(set(unknown))} "
                f"— not in _HEURISTICS and not in LABELER_FLAGS "
                f"(heuristic was removed/renamed, or the name is a typo)"
            ),
        )
    ]


def _check_validator_firing_consistency(
    record: EvalRecord, line_num: int
) -> list[IntegrityWarning]:
    """Compare the record's recorded validator namespace against what
    the current registry would fire on this path. Three directions of
    drift, each named explicitly in the message:

    * ``missing`` only — current registry fires names the record
      doesn't list. The record predates those heuristics (or their
      predicates were broadened to match this path).
    * ``extra`` only — record references registered names that no
      longer fire on this path. Heuristic predicate was narrowed.
    * both — both directions; message names both sets.

    Only applies to ``not_juicy`` records; the validator never runs at
    label time for ``juicy`` submissions.
    """
    if record.label != "not_juicy":
        return []

    heuristic_names = {h for h, _ in _HEURISTICS}
    labeler_set = set(LABELER_FLAGS)
    # Filter to validator namespace AND known heuristics; unknown names
    # are reported by ``_check_validator_warnings_names`` and shouldn't
    # contribute a second warning here.
    recorded_known = (set(record.validator_warnings) - labeler_set) & heuristic_names
    current_firing = set(check_path(record.path))

    if recorded_known == current_firing:
        return []

    missing = current_firing - recorded_known
    extra = recorded_known - current_firing

    if missing and not extra:
        detail = (
            f"current registry fires {sorted(missing)} that record doesn't list "
            f"— record was labeled before these heuristics were added, "
            f"or their predicates were broadened to match this path"
        )
    elif extra and not missing:
        detail = (
            f"record references {sorted(extra)} which is registered but no longer "
            f"fires on this path — heuristic predicate was narrowed since label time"
        )
    else:
        detail = (
            f"both directions of drift. Currently fires: {sorted(current_firing)}. "
            f"Record has: {sorted(recorded_known)}. "
            f"Missing from record (registry added or predicate broadened): "
            f"{sorted(missing)}. "
            f"Present in record but no longer firing (predicate narrowed): "
            f"{sorted(extra)}"
        )

    return [
        IntegrityWarning(
            line_num=line_num,
            kind="validator_drift",
            message=detail,
        )
    ]


# ============================================================================
# Cross-record integrity checks
# ============================================================================


def _check_duplicates(
    records: list[tuple[int, EvalRecord]],
) -> list[IntegrityWarning]:
    """One warning per duplicate group; each group lists every line
    number and a representative normalized form so the reader can see
    what the case/separator normalization collapsed."""
    by_norm: dict[str, list[tuple[int, str]]] = {}
    for line_num, record in records:
        norm = normalize_for_dedup(record.path)
        by_norm.setdefault(norm, []).append((line_num, record.path))

    warnings: list[IntegrityWarning] = []
    for norm, group in by_norm.items():
        if len(group) < 2:
            continue
        line_list = ", ".join(str(ln) for ln, _ in group)
        originals = sorted({orig for _, orig in group})
        warnings.append(
            IntegrityWarning(
                line_num=None,
                kind="duplicate_path",
                message=(
                    f"path appears at lines {line_list} "
                    f"(normalized: {norm!r}; original forms: {originals})"
                ),
            )
        )
    return warnings


# ============================================================================
# Stats
# ============================================================================


def _compute_stats(records: list[EvalRecord]) -> Stats:
    stats = Stats(record_count=len(records))
    if not records:
        # Per-heuristic table still enumerates every registered
        # heuristic with zero counts so the report shape is consistent
        # for both empty and populated files.
        stats.per_heuristic = [
            HeuristicStats(
                name=name,
                fires_count=0,
                juicy_count=0,
                not_juicy_count=0,
                override_count=0,
            )
            for name, _ in _HEURISTICS
        ]
        return stats

    for record in records:
        stats.label_dist[record.label] += 1
        stats.category_hist[record.category] += 1
        stats.source_dist[record.source] += 1
        if "uncertainty_prior" in record.validator_warnings:
            stats.uncertainty_count += 1

    # Per-heuristic activity: run check_path against every record once
    # and tabulate. Iterating every registered heuristic (even zero-
    # fires ones) gives a complete picture of registry coverage.
    fires_by_heuristic: dict[str, list[EvalRecord]] = {name: [] for name, _ in _HEURISTICS}
    for record in records:
        for h in check_path(record.path):
            if h in fires_by_heuristic:
                fires_by_heuristic[h].append(record)

    for name, _ in _HEURISTICS:
        firing_records = fires_by_heuristic[name]
        juicy = sum(1 for r in firing_records if r.label == "juicy")
        not_juicy = sum(1 for r in firing_records if r.label == "not_juicy")
        overrides = sum(1 for r in records if name in r.validator_warnings)
        stats.per_heuristic.append(
            HeuristicStats(
                name=name,
                fires_count=len(firing_records),
                juicy_count=juicy,
                not_juicy_count=not_juicy,
                override_count=overrides,
            )
        )
    return stats


# ============================================================================
# Orchestrator
# ============================================================================


def _format_pydantic_error(e: ValidationError) -> str:
    first = e.errors()[0]
    loc = ".".join(str(x) for x in first["loc"])
    return f"{loc}: {first['msg']}"


def validate_file(path: Path) -> ValidationReport:
    """Read ``path``, run every check, return a full report."""
    if not path.exists():
        raise FileNotFoundError(f"eval set not found: {path}")

    report = ValidationReport()
    records: list[tuple[int, EvalRecord]] = []

    with path.open("r", encoding="utf-8") as f:
        for line_num, raw_line in enumerate(f, start=1):
            line = raw_line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError as e:
                report.hard_errors.append(
                    HardError(line_num=line_num, message=f"invalid JSON: {e}")
                )
                continue
            try:
                record = EvalRecord(**obj)
            except ValidationError as e:
                report.hard_errors.append(
                    HardError(line_num=line_num, message=_format_pydantic_error(e))
                )
                continue
            records.append((line_num, record))

    for line_num, record in records:
        report.integrity_warnings.extend(_check_enum_drift(record, line_num))
        report.integrity_warnings.extend(_check_pre_category_drift(record, line_num))
        report.integrity_warnings.extend(_check_validator_warnings_names(record, line_num))
        report.integrity_warnings.extend(_check_validator_firing_consistency(record, line_num))

    report.integrity_warnings.extend(_check_duplicates(records))
    report.stats = _compute_stats([r for _, r in records])
    return report


# ============================================================================
# Report formatting
# ============================================================================


def _format_report(report: ValidationReport, path: Path, *, use_color: bool = False) -> str:
    out: list[str] = []
    out.append(f"Eval set: {path}")
    out.append("")

    if report.hard_errors:
        out.append(f"HARD ERRORS ({len(report.hard_errors)}):")
        for err in report.hard_errors:
            out.append(f"  line {err.line_num}: {err.message}")
        out.append("")

    if report.integrity_warnings:
        out.append(f"INTEGRITY WARNINGS ({len(report.integrity_warnings)}):")
        out.append("")
        by_kind: dict[str, list[IntegrityWarning]] = {}
        for w in report.integrity_warnings:
            by_kind.setdefault(w.kind, []).append(w)
        # Stable kind order: alphabetical for predictable scanning.
        for kind in sorted(by_kind):
            warnings = by_kind[kind]
            out.append(f"  {kind} ({len(warnings)}):")
            for w in warnings:
                prefix = f"line {w.line_num}: " if w.line_num is not None else ""
                out.append(f"    {prefix}{w.message}")
            out.append("")

    out.append("STATISTICS:")
    out.append("")
    s = report.stats
    out.append(f"  Records: {s.record_count}")
    if s.record_count > 0:
        for label in ("juicy", "not_juicy"):
            count = s.label_dist.get(label, 0)
            pct = 100.0 * count / s.record_count
            out.append(f"    {label:<22}{count:>4}  ({pct:5.1f}%)")
        pct = 100.0 * s.uncertainty_count / s.record_count
        out.append(f"    {'uncertainty-flagged':<22}{s.uncertainty_count:>4}  ({pct:5.1f}%)")
    out.append("")

    if s.record_count > 0:
        out.append("  Category histogram (sorted by count desc):")
        for slug, count in s.category_hist.most_common():
            pct = 100.0 * count / s.record_count
            out.append(f"    {slug:<28}{count:>4}  ({pct:5.1f}%)")
        out.append("")

        out.append("  Source breakdown:")
        for src, count in s.source_dist.most_common():
            pct = 100.0 * count / s.record_count
            out.append(f"    {src:<28}{count:>4}  ({pct:5.1f}%)")
        out.append("")

    out.append("  Per-heuristic activity (computed from current check_path):")
    for hs in s.per_heuristic:
        if hs.fires_count == 0:
            row = (
                f"    {hs.name:<36}{hs.fires_count:>3} fires    "
                f"{'—':>3} juicy / {'—':>3} not_juicy    "
                f"override rate:   —"
            )
        else:
            rate_pct = 100.0 * hs.override_rate
            marker = ""
            annotation = ""
            if hs.warn:
                marker = "  ⚠"  # ⚠
            elif (
                hs.override_rate >= OVERRIDE_WARN_THRESHOLD
                and hs.fires_count < OVERRIDE_WARN_MIN_FIRES
            ):
                # Rate is above threshold but sample is too small; show
                # the rate, suppress the marker, annotate so the reader
                # knows we deliberately didn't escalate.
                annotation = "  (n<10)"
            row = (
                f"    {hs.name:<36}{hs.fires_count:>3} fires    "
                f"{hs.juicy_count:>3} juicy / {hs.not_juicy_count:>3} not_juicy    "
                f"override rate: {rate_pct:5.1f}%{annotation}{marker}"
            )
            if use_color and hs.warn:
                row = f"{_ANSI_YELLOW}{row}{_ANSI_RESET}"
        out.append(row)
    out.append("")

    if not report.hard_errors and not report.integrity_warnings:
        out.append("RESULT: clean")
    elif report.hard_errors:
        out.append(f"RESULT: {len(report.hard_errors)} hard error(s) — FILE IS BROKEN")
    else:
        out.append(
            f"RESULT: {len(report.integrity_warnings)} integrity warning(s) "
            f"— file parseable but suspect"
        )
    return "\n".join(out)


# ============================================================================
# CLI
# ============================================================================


def _main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="validate",
        description="Integrity check the labeled eval set.",
    )
    parser.add_argument(
        "--input",
        type=Path,
        default=Path("data/eval/eval_set.jsonl"),
        help="Path to the labeled JSONL file (default: data/eval/eval_set.jsonl).",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Treat integrity warnings as fatal (nonzero exit).",
    )
    parser.add_argument(
        "--no-color",
        action="store_true",
        help="Disable ANSI color in the per-heuristic warn marker.",
    )
    args = parser.parse_args(argv)

    try:
        report = validate_file(args.input)
    except FileNotFoundError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1

    use_color = (not args.no_color) and sys.stdout.isatty()
    print(_format_report(report, args.input, use_color=use_color))

    if report.hard_errors:
        return 1
    if args.strict and report.integrity_warnings:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(_main())
