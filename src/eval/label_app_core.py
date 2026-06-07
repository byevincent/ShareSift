"""Pure logic for the labeling GUI — no Streamlit import.

The Streamlit UI lives in ``label_app.py`` and is a thin shell over the
functions in this file. The reason for the split: the load-bearing
parts of the labeling pipeline (queue derivation, partial-line
recovery, undo-as-atomic-rewrite, the validator submit state machine)
need close reading and unit-testable in isolation. The Streamlit glue
is mechanical and tested by manual smoke.

Cardinal rule (mirrored from the step 6 plan): never anchor the
labeler's judgment. Nothing here returns suggested labels, similar
paths, autofill values, or any pre-decision hint. The validator is
queried only AFTER the labeler has chosen ``not_juicy`` and clicked
submit; never before.

State-model summary: only ``eval_set.jsonl`` matters at the end of the
day. Session_state in the GUI is ephemeral — losing it (refresh,
crash, tab close) never costs a committed label. Undo is single-slot
and exists for the very last commit only; once a session ends, the
undo affordance is gone but the labeled data is intact.
"""

from __future__ import annotations

import json
import os
import re
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import date, datetime, timezone
from enum import Enum
from pathlib import Path

from pydantic import ValidationError

from src.eval._paths import normalize_for_dedup
from src.eval.build_queue import QueueRecord
from src.eval.negative_validator import check_path
from src.eval.schema import EvalRecord

LOCK_FILENAME = ".eval_set.lock"
LOCK_STALE_THRESHOLD_HOURS = 24


# ============================================================================
# Submit state machine — data shapes
# ============================================================================


class ValidatorState(Enum):
    """The validator-warning pane's state across reruns.

    ``IDLE``: no warning pending. The next submit on a ``not_juicy``
    label will run ``check_path``; if it fires, transitions to
    ``WARNING_SHOWN`` and waits for a second submit.

    ``WARNING_SHOWN``: a warning has been displayed for an unchanged
    ``not_juicy`` submit. The next submit IS the override and commits
    with the previously-fired heuristic names logged. Any widget
    change between the two submits resets the state back to ``IDLE``
    so the next submit re-runs the validator from scratch.
    """

    IDLE = "idle"
    WARNING_SHOWN = "warning_shown"


class SubmitAction(Enum):
    COMMIT = "commit"
    SHOW_VALIDATOR_WARNING = "show_validator_warning"
    REJECT_INVALID = "reject_invalid"


@dataclass
class SubmitDecision:
    """The labeler's pending choices, captured from the widgets at
    submit time. ``tier`` is None unless the label is ``juicy``;
    ``sub_type`` is None unless ``category == 'modern_saas_tokens'``;
    ``notes`` is the raw text-area contents (validation rules apply
    inside ``_build_eval_record``)."""

    label: str | None
    tier: str | None
    category: str | None
    sub_type: str | None
    notes: str


@dataclass
class SubmitOutcome:
    """The pure result of one submit click.

    The UI handler reads this and mutates session_state accordingly:
    on ``COMMIT`` it appends the record and clears widgets; on
    ``SHOW_VALIDATOR_WARNING`` it transitions to ``WARNING_SHOWN`` and
    re-renders without clearing widgets; on ``REJECT_INVALID`` it
    displays ``schema_error`` and DOES NOT clear widgets (per design:
    the labeler fixes one field, not all of them)."""

    action: SubmitAction
    record: EvalRecord | None = None
    pending_validator_warnings: list[str] = field(default_factory=list)
    schema_error: str | None = None


# ============================================================================
# Record construction — source flows from QueueRecord, untouched
# ============================================================================


def _build_eval_record(
    queue_record: QueueRecord,
    decision: SubmitDecision,
    today: date | None = None,
) -> EvalRecord:
    """Materialize an ``EvalRecord`` from the queue + labeler decision.

    ``source`` and ``pre_category`` flow directly from ``queue_record``
    — the labeler never touches them. ``validator_warnings`` is set to
    empty here; the state machine overrides it to the fired list only
    on the WARNING_SHOWN → COMMIT path.

    Raises ``ValidationError`` if the candidate fails schema. The
    caller surfaces that to the UI as a REJECT_INVALID outcome,
    preserving all pending widget values so the labeler fixes one
    field rather than re-entering everything.
    """
    return EvalRecord(
        path=queue_record.path,
        label=decision.label,
        tier=decision.tier,
        category=decision.category,
        sub_type=decision.sub_type,
        source=queue_record.source,
        notes=decision.notes,
        added_date=today if today is not None else date.today(),
        pre_category=queue_record.pre_category,
        validator_warnings=[],
    )


def _format_validation_error(e: ValidationError) -> str:
    parts = []
    for err in e.errors():
        loc = ".".join(str(x) for x in err["loc"])
        parts.append(f"{loc}: {err['msg']}")
    return "; ".join(parts)


# ============================================================================
# Submit state machine — the load-bearing function
# ============================================================================


def _compute_submit_outcome(
    state: ValidatorState,
    decision: SubmitDecision,
    pending_warnings: list[str],
    queue_record: QueueRecord,
    validator_fn: Callable[[str], list[str]] = check_path,
    today: date | None = None,
) -> SubmitOutcome:
    """The validator submit state machine, as a pure function.

    Transitions (all on a single submit click):

    1. Any state + schema-invalid candidate → REJECT_INVALID. Widgets
       preserved by the caller; labeler fixes the bad field.

    2. Any state + juicy label → COMMIT with ``validator_warnings=[]``.
       The validator never runs for juicy submissions — by design, the
       negative_validator is a ``not_juicy`` tripwire only and firing
       on juicy submissions would be the wrong direction of warning.

    3. WARNING_SHOWN + not_juicy + no widget change since the warning
       (caller's responsibility to reset state on widget change) →
       COMMIT with ``validator_warnings = pending_warnings``. This
       click IS the override.

    4. IDLE + not_juicy:
       - validator returns empty → COMMIT with ``validator_warnings=[]``.
       - validator returns non-empty → SHOW_VALIDATOR_WARNING with
         ``pending_validator_warnings = fired``. State will be set to
         WARNING_SHOWN by the caller; next submit hits case 3.

    No third confirmation. One warning, one override, done.

    ``validator_fn`` is injectable so tests don't depend on
    ``negative_validator._HEURISTICS`` to stay stable.
    """
    try:
        record = _build_eval_record(queue_record=queue_record, decision=decision, today=today)
    except ValidationError as e:
        return SubmitOutcome(
            action=SubmitAction.REJECT_INVALID,
            schema_error=_format_validation_error(e),
        )

    if decision.label == "juicy":
        return SubmitOutcome(action=SubmitAction.COMMIT, record=record)

    if state == ValidatorState.WARNING_SHOWN:
        return SubmitOutcome(
            action=SubmitAction.COMMIT,
            record=record.model_copy(update={"validator_warnings": list(pending_warnings)}),
        )

    fired = validator_fn(queue_record.path)
    if not fired:
        return SubmitOutcome(action=SubmitAction.COMMIT, record=record)
    return SubmitOutcome(
        action=SubmitAction.SHOW_VALIDATOR_WARNING,
        pending_validator_warnings=list(fired),
    )


# ============================================================================
# Queue derivation — the labeled-data-is-truth function
# ============================================================================


def _derive_remaining_queue(queue_path: Path, eval_set_path: Path) -> list[QueueRecord]:
    """Return the unlabeled subset of the queue, in queue order.

    Reads both files fresh on every call — no caching, no cursor file.
    The labeled set IS the source of truth; recomputing rather than
    trusting a side-file is the same discipline as ``validate.py``.

    Skips malformed eval_set lines silently (recovery and validation
    are handled elsewhere — partial-line recovery at startup,
    structural integrity by ``validate.py``).

    Skips malformed queue lines silently. A bad queue file would have
    failed ``build_queue.py``'s validation at write time; if the file
    has been hand-edited, ``validate.py`` is the place to surface it,
    not the labeling UI.
    """
    labeled_norm: set[str] = set()
    if eval_set_path.exists():
        for line in eval_set_path.read_text(encoding="utf-8").splitlines():
            stripped = line.strip()
            if not stripped:
                continue
            try:
                obj = json.loads(stripped)
            except json.JSONDecodeError:
                continue
            p = obj.get("path", "")
            if p:
                labeled_norm.add(normalize_for_dedup(p))

    if not queue_path.exists():
        return []

    queue_records: list[QueueRecord] = []
    for line in queue_path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        try:
            qr = QueueRecord.model_validate_json(stripped)
        except ValidationError:
            continue
        queue_records.append(qr)

    return [r for r in queue_records if normalize_for_dedup(r.path) not in labeled_norm]


def _queue_file_has_records(queue_path: Path) -> bool:
    """Whether ``queue_path`` exists AND contains at least one non-blank
    line.

    Used by the UI to distinguish three startup states that
    ``_derive_remaining_queue`` returning ``[]`` would otherwise
    conflate:

    1. Queue file missing → labeler needs to run ``build_queue.py``.
    2. Queue file exists but is empty (no records were built — maybe
       the input CSV was empty or fully filtered) → labeler needs to
       check the source CSV.
    3. Queue file exists, has records, all labeled → real success.

    Does not parse the lines — any non-blank line counts as
    inhabited. A queue with malformed records still ranks as
    "contains records" here; the GUI surfaces the dedicated message
    for case 3 and the labeler can run ``validate.py`` if the file
    looks suspect.
    """
    if not queue_path.exists():
        return False
    for line in queue_path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            return True
    return False


# ============================================================================
# Raw-line atomic rewrite — internal helper used by undo and recovery
# ============================================================================


def _atomic_rewrite_text_lines(path: Path, lines: list[str]) -> None:
    """Atomic rewrite of ``path`` with the given text lines.

    Each line is written exactly as given; a trailing newline is added
    if absent. Used by ``_undo_last_commit`` and
    ``_recover_partial_last_line`` because both need to manipulate raw
    bytes (records that may not pass current schema, partial-JSON
    trailing lines). ``_io.atomic_write_jsonl`` would re-validate every
    record on rewrite, which is wrong for these use cases.

    Same tempfile + fsync + ``os.replace`` pattern as the JSONL
    primitive in ``_io.py``.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    try:
        with tmp.open("w", encoding="utf-8") as f:
            for line in lines:
                f.write(line if line.endswith("\n") else line + "\n")
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    except Exception:
        if tmp.exists():
            try:
                tmp.unlink()
            except OSError:
                pass
        raise


# ============================================================================
# Partial-line recovery — startup hook
# ============================================================================


def _recover_partial_last_line(eval_set_path: Path) -> bool:
    """If the last line of ``eval_set_path`` fails to parse as JSON,
    atomically rewrite the file without it. Return True if a recovery
    happened, False otherwise.

    Handles the crash-inside-fsync-window case for
    ``atomic_append_jsonl``: a crash mid-fsync may leave a partial
    trailing line. The GUI runs this once on startup so subsequent
    appends start from a clean tail.

    Only the LAST line is examined. Earlier corrupt lines (e.g.,
    hand-editing damage) are NOT touched here; that's
    ``validate.py``'s domain (hard error, surfaces for explicit
    cleanup). The recovery contract is strictly "trailing partial
    line from the last interrupted append."
    """
    if not eval_set_path.exists():
        return False
    lines = eval_set_path.read_text(encoding="utf-8").splitlines(keepends=True)
    if not lines:
        return False
    # Find the last non-blank line.
    last_idx = len(lines) - 1
    while last_idx >= 0 and not lines[last_idx].strip():
        last_idx -= 1
    if last_idx < 0:
        return False
    try:
        json.loads(lines[last_idx])
        return False  # Last line parses; no recovery needed.
    except json.JSONDecodeError:
        pass
    remaining = lines[:last_idx] + lines[last_idx + 1 :]
    _atomic_rewrite_text_lines(eval_set_path, remaining)
    return True


# ============================================================================
# Undo — atomic rewrite dropping the last record
# ============================================================================


def _undo_last_commit(eval_set_path: Path) -> EvalRecord | None:
    """Atomically remove the last record from ``eval_set_path`` and
    return it. Return None if the file is empty, missing, or contains
    no parseable last line.

    Implementation: read all lines as raw text, drop the last non-blank
    line, write the rest back atomically. Does NOT re-parse the
    remaining lines — they're written byte-for-byte, so a record that
    fails CURRENT schema validation (e.g., labeled before a taxonomy
    revision) does not block undo. ``validate.py`` is the place where
    those records would surface.

    The LAST line IS parsed, into an ``EvalRecord``, so we can return
    it to the caller (which will push the path back onto the in-session
    remaining queue). If the last line is unparseable, raises
    ``ValidationError`` — this indicates a corrupted commit, and the
    GUI's startup recovery should have caught it. Reaching this
    condition is a bug.
    """
    if not eval_set_path.exists():
        return None
    lines = eval_set_path.read_text(encoding="utf-8").splitlines(keepends=True)
    last_idx = len(lines) - 1
    while last_idx >= 0 and not lines[last_idx].strip():
        last_idx -= 1
    if last_idx < 0:
        return None
    last_record = EvalRecord.model_validate_json(lines[last_idx])
    remaining = lines[:last_idx] + lines[last_idx + 1 :]
    _atomic_rewrite_text_lines(eval_set_path, remaining)
    return last_record


# ============================================================================
# Single-session lock
# ============================================================================


def _acquire_lock(
    eval_set_path: Path, stale_threshold_hours: int = LOCK_STALE_THRESHOLD_HOURS
) -> bool:
    """Try to acquire the labeling-session lock. Return True on
    success, False if another session holds a fresh lock.

    Stale-lock policy: if the lock file's mtime is older than
    ``stale_threshold_hours``, reclaim it. Default 24h — long enough
    that a forgotten lock from a crashed session yesterday gets
    cleaned up automatically, short enough that two genuine
    same-day sessions are reliably caught.

    This is not concurrency-safe in the strict sense (TOCTOU between
    the existence check and the write) but adequate for the single-
    user-machine assumption: one labeler, occasional accidental
    second-tab.
    """
    lock_path = eval_set_path.parent / LOCK_FILENAME
    if lock_path.exists():
        age_hours = (time.time() - lock_path.stat().st_mtime) / 3600
        if age_hours < stale_threshold_hours:
            return False
        # Stale: fall through and overwrite.
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    lock_path.write_text(
        f"pid={os.getpid()} acquired={datetime.now(timezone.utc).isoformat()}\n",
        encoding="utf-8",
    )
    return True


def _release_lock(eval_set_path: Path) -> None:
    """Best-effort lock release. No error on missing lock."""
    lock_path = eval_set_path.parent / LOCK_FILENAME
    try:
        lock_path.unlink()
    except (FileNotFoundError, OSError):
        pass


# ============================================================================
# Widget-change → reset predicate
# ============================================================================


def _new_last_error_for_outcome(outcome: SubmitOutcome) -> str | None:
    """Map a ``SubmitOutcome`` to the error string the UI should display
    (or ``None`` to clear any previously-displayed error).

    The UI MUST call this and unconditionally assign the result to its
    error session-state slot on every submit:

        st.session_state.last_error = _new_last_error_for_outcome(outcome)

    The unconditional assignment is the load-bearing part. A non-
    REJECT outcome returns ``None``, which clears any stale
    REJECT_INVALID error from a prior submit attempt. Without this
    pattern, a labeler could see a "Cannot commit: notes too short"
    banner, fix notes, hit submit, get SHOW_VALIDATOR_WARNING, and
    have both the (stale) error AND the new warning rendered side by
    side — contradictory UI state, real bug observed in dogfooding.

    Keeping the mapping pure (returns the string, doesn't touch
    session_state) lets tests pin all three branches without
    Streamlit; the UI's job is only the unconditional assignment.
    """
    if outcome.action == SubmitAction.REJECT_INVALID:
        return f"Cannot commit: {outcome.schema_error}"
    return None


def _should_reset_validator_state_on_widget_change(
    current_state: ValidatorState,
) -> bool:
    """Whether a widget change should reset the validator state to IDLE.

    Called by the UI on every widget ``on_change``. When the predicate
    returns True, the UI MUST set ``validator_state`` back to ``IDLE``
    and clear ``pending_validator_warnings`` so the next submit
    re-runs ``check_path`` from scratch against the modified decision.

    Without this reset, a labeler could see a validator warning, change
    the category (or any other widget), and have the next submit
    commit with the *stale* validator_warnings logged against the
    *new* decision — a silent label-integrity bug. The predicate
    exists as a separate function so the cycle (warning → widget
    change → reset → re-submit invokes validator from scratch) is
    pinned by ``test_widget_change_resets_state_so_next_submit_reruns_validator``.
    """
    return current_state == ValidatorState.WARNING_SHOWN


# ============================================================================
# Form-revision advance — fresh widgets for the next path
# ============================================================================


def _next_form_revision_state(current_revision: int) -> dict:
    """Return the session_state values for the next labeling attempt.

    Called by the UI on every path advance — after a successful commit
    AND after an undo re-presents a path. The UI assigns the returned
    dict into ``st.session_state``:

        for k, v in _next_form_revision_state(rev).items():
            st.session_state[k] = v

    Bumping ``form_revision`` is the load-bearing part. Widget keys in
    ``label_app.py`` are derived as ``f"pending_{name}_r{rev}"``, so a
    new revision means every widget gets a fresh key and Streamlit
    instantiates new widgets with their declared empty defaults
    (``index=None``, empty string). This is the robust Streamlit reset
    pattern; the older ``del st.session_state[key]`` then ``st.rerun()``
    pattern is known-fragile for ``text_area`` and
    ``selectbox(index=None)`` and was the cause of the dogfood
    form-doesn't-clear bug.

    The validator state also resets here: a path advance means any
    pending warning belongs to a path that's no longer current.
    ``last_error`` clears for the same reason.
    """
    return {
        "form_revision": current_revision + 1,
        "validator_state": ValidatorState.IDLE,
        "pending_validator_warnings": [],
        "last_error": None,
    }


# ============================================================================
# Guideline-doc parsers — surfaces canonical definitions inline in the GUI
#
# Shared-source discipline: the labeling GUI reads category boundaries and
# tier criteria from ``docs/labeling_guidelines.md`` at startup so the
# in-GUI help can't drift from the canonical doc. The parser extracts the
# first paragraph after each ``### `<slug>` `` heading (the convention is
# pinned in the doc itself). For tiers, it extracts the bold-prefixed
# header line under ``## Tier Criteria``.
# ============================================================================

_CATEGORY_HEADING_RE = re.compile(r"^### `([a-z0-9_]+)`\s*$", re.MULTILINE)


def parse_category_definitions(guideline_path: Path) -> dict[str, str]:
    """Return ``{slug: first-paragraph-markdown}`` for every
    ``### `<slug>` `` heading found in ``guideline_path``.

    "First paragraph" = the contiguous run of non-blank lines starting at
    the first non-blank line after the heading, terminated by either the
    next blank line or the next ``##``/``###`` heading (whichever comes
    first). Subsequent paragraphs (examples, distinguishing tests, tier
    guidance) are doc-only and intentionally not surfaced inline.

    Raises ``FileNotFoundError`` if the doc is missing. The labeling
    GUI's startup wires this into a fast-fail with a clear message;
    callers expecting a defaultable behavior should catch.
    """
    text = guideline_path.read_text(encoding="utf-8")
    matches = list(_CATEGORY_HEADING_RE.finditer(text))
    out: dict[str, str] = {}
    for i, m in enumerate(matches):
        slug = m.group(1)
        section_start = m.end()
        section_end = matches[i + 1].start() if i + 1 < len(matches) else len(text)
        section = text[section_start:section_end]
        out[slug] = _extract_first_paragraph(section)
    return out


def _extract_first_paragraph(section: str) -> str:
    """First contiguous run of non-blank, non-heading lines in ``section``.

    Empty string if no such run exists (caller's job to flag the empty
    via the load-time validation in ``label_app.py``).
    """
    lines = section.split("\n")
    paragraph: list[str] = []
    in_paragraph = False
    for line in lines:
        stripped = line.strip()
        if not in_paragraph:
            if not stripped:
                continue
            if stripped.startswith("#"):
                break
            in_paragraph = True
            paragraph.append(line)
        else:
            if not stripped or stripped.startswith("#"):
                break
            paragraph.append(line)
    return "\n".join(paragraph).strip()


_TIER_LINE_RE = re.compile(r"\*\*(Black|Red|Yellow)\s*[—\-][^*]+\*\*")


def parse_tier_definitions(guideline_path: Path) -> dict[str, str]:
    """Return ``{tier: bold-header-markdown}`` for each tier found in
    the ``## Tier Criteria`` section.

    Captures the bold-bracketed header (e.g. ``**Black — immediate
    compromise.**``) and uses that as the inline GUI display — short
    enough to render all three tiers side-by-side above the radio so
    the Red/Yellow boundary is comparable at a glance.

    Doc must have exactly one bold-header per tier matching the
    pattern. Drift tests pin that the parsed keys match ``SEVERITY_TIERS``.
    """
    text = guideline_path.read_text(encoding="utf-8")
    out: dict[str, str] = {}
    for m in _TIER_LINE_RE.finditer(text):
        tier = m.group(1)
        if tier not in out:  # first occurrence wins
            out[tier] = m.group(0)
    return out
