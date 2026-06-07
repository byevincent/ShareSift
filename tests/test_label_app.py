"""Tests for the labeling-GUI core logic.

Tests target ``label_app_core.py`` only; the Streamlit UI in
``label_app.py`` is exercised by manual smoke. The functions tested
here are the ones Vincent flagged for close reading:

* ``_derive_remaining_queue`` — the source-of-truth-is-labels function
* ``_recover_partial_last_line`` — startup recovery for crashed appends
* ``_undo_last_commit`` — atomic rewrite dropping last record
* ``_compute_submit_outcome`` — the validator submit state machine

Plus: the undo round-trip property (commit → undo → recommit = exactly
one record), source-flow-through (queue → record without UI touching
source), and schema-rejection-preserves-widgets (the REJECT_INVALID
outcome path).
"""

from __future__ import annotations

import json
import time
from datetime import date
from pathlib import Path

import pytest
from pydantic import ValidationError

from src.eval._io import atomic_append_jsonl
from src.eval.build_queue import QueueRecord
from src.eval.categories import CATEGORY_SLUGS, SEVERITY_TIERS
from src.eval.label_app_core import (
    LOCK_FILENAME,
    SubmitAction,
    SubmitDecision,
    SubmitOutcome,
    ValidatorState,
    _acquire_lock,
    _build_eval_record,
    _compute_submit_outcome,
    _derive_remaining_queue,
    _new_last_error_for_outcome,
    _next_form_revision_state,
    _queue_file_has_records,
    _recover_partial_last_line,
    _release_lock,
    _should_reset_validator_state_on_widget_change,
    _undo_last_commit,
    parse_category_definitions,
    parse_tier_definitions,
)
from src.eval.schema import EvalRecord

# ---------------------------------------------------------------------------
# Fixture helpers
# ---------------------------------------------------------------------------


def _queue_record(
    path: str = r"C:\Users\admin\secrets.kdbx",
    source: str = "engagement",
    pre_category: str | None = "credential_containers",
    queue_index: int = 0,
    build_id: str = "test-build-id",
) -> QueueRecord:
    return QueueRecord(
        path=path,
        source=source,
        pre_category=pre_category,
        queue_index=queue_index,
        build_id=build_id,
    )


def _juicy_decision(**overrides) -> SubmitDecision:
    base = dict(
        label="juicy",
        tier="Red",
        category="credential_containers",
        sub_type=None,
        notes="KeePass vault on admin profile.",
    )
    base.update(overrides)
    return SubmitDecision(**base)


def _not_juicy_decision(**overrides) -> SubmitDecision:
    base = dict(
        label="not_juicy",
        tier=None,
        category="decoy_docs",
        sub_type=None,
        notes="Just a regular document path with no juiciness.",
    )
    base.update(overrides)
    return SubmitDecision(**base)


def _write_queue(tmp_path: Path, records: list[QueueRecord]) -> Path:
    queue_path = tmp_path / "queue.jsonl"
    queue_path.write_text(
        "\n".join(r.model_dump_json() for r in records) + "\n",
        encoding="utf-8",
    )
    return queue_path


def _write_eval_set(tmp_path: Path, records: list[EvalRecord]) -> Path:
    eval_path = tmp_path / "eval_set.jsonl"
    eval_path.write_text(
        "\n".join(r.model_dump_json() for r in records) + ("\n" if records else ""),
        encoding="utf-8",
    )
    return eval_path


# =========================================================================
# _derive_remaining_queue
# =========================================================================


def test_derive_remaining_queue_empty_eval_set(tmp_path):
    queue_path = _write_queue(
        tmp_path,
        [
            _queue_record(path=r"C:\a.kdbx", queue_index=0),
            _queue_record(path=r"C:\b.kdbx", queue_index=1),
        ],
    )
    eval_path = tmp_path / "eval_set.jsonl"  # doesn't exist
    remaining = _derive_remaining_queue(queue_path, eval_path)
    assert [r.path for r in remaining] == [r"C:\a.kdbx", r"C:\b.kdbx"]


def test_derive_remaining_queue_filters_already_labeled(tmp_path):
    queue_path = _write_queue(
        tmp_path,
        [
            _queue_record(path=r"C:\a.kdbx", queue_index=0),
            _queue_record(path=r"C:\b.kdbx", queue_index=1),
            _queue_record(path=r"C:\c.kdbx", queue_index=2),
        ],
    )
    labeled = EvalRecord(
        path=r"C:\b.kdbx",
        label="juicy",
        tier="Red",
        category="credential_containers",
        source="engagement",
        notes="KeePass vault somewhere reasonable.",
        added_date=date(2026, 5, 24),
    )
    eval_path = _write_eval_set(tmp_path, [labeled])
    remaining = _derive_remaining_queue(queue_path, eval_path)
    assert [r.path for r in remaining] == [r"C:\a.kdbx", r"C:\c.kdbx"]


def test_derive_remaining_queue_case_insensitive_match(tmp_path):
    queue_path = _write_queue(
        tmp_path,
        [_queue_record(path=r"C:\Users\bob\File.kdbx", queue_index=0)],
    )
    labeled = EvalRecord(
        path=r"c:\users\bob\file.kdbx",  # different casing
        label="juicy",
        tier="Red",
        category="credential_containers",
        source="engagement",
        notes="Same path, different casing — should match for dedup.",
        added_date=date(2026, 5, 24),
    )
    eval_path = _write_eval_set(tmp_path, [labeled])
    remaining = _derive_remaining_queue(queue_path, eval_path)
    assert remaining == []


def test_derive_remaining_queue_skips_malformed_eval_lines(tmp_path):
    queue_path = _write_queue(tmp_path, [_queue_record(path=r"C:\a.kdbx", queue_index=0)])
    eval_path = tmp_path / "eval_set.jsonl"
    eval_path.write_text("not valid json\n{also bad\n", encoding="utf-8")
    # Should not raise; should return all queue records (no labels matched).
    remaining = _derive_remaining_queue(queue_path, eval_path)
    assert [r.path for r in remaining] == [r"C:\a.kdbx"]


def test_derive_remaining_queue_missing_queue_file(tmp_path):
    queue_path = tmp_path / "no_queue.jsonl"
    eval_path = tmp_path / "no_eval.jsonl"
    assert _derive_remaining_queue(queue_path, eval_path) == []


# =========================================================================
# _queue_file_has_records — three-way startup state distinguisher
# =========================================================================


def test_queue_file_has_records_missing_file(tmp_path):
    """Distinguishes 'queue file missing' (False) from 'queue file
    exists' (True / False depending on content) so the UI can show the
    right message for each case."""
    assert _queue_file_has_records(tmp_path / "missing.jsonl") is False


def test_queue_file_has_records_empty_file(tmp_path):
    f = tmp_path / "queue.jsonl"
    f.write_text("", encoding="utf-8")
    assert _queue_file_has_records(f) is False


def test_queue_file_has_records_whitespace_only(tmp_path):
    f = tmp_path / "queue.jsonl"
    f.write_text("\n\n   \n", encoding="utf-8")
    assert _queue_file_has_records(f) is False


def test_queue_file_has_records_with_one_line(tmp_path):
    f = tmp_path / "queue.jsonl"
    f.write_text('{"a": 1}\n', encoding="utf-8")
    assert _queue_file_has_records(f) is True


def test_queue_file_has_records_does_not_parse_lines(tmp_path):
    """Any non-blank line counts. The function answers 'is this file
    inhabited or vacant?' — malformed records would be a build_queue
    issue, not a startup-message issue."""
    f = tmp_path / "queue.jsonl"
    f.write_text("not even json\n", encoding="utf-8")
    assert _queue_file_has_records(f) is True


# =========================================================================
# _recover_partial_last_line
# =========================================================================


def test_recover_partial_last_line_no_file(tmp_path):
    assert _recover_partial_last_line(tmp_path / "missing.jsonl") is False


def test_recover_partial_last_line_empty_file(tmp_path):
    f = tmp_path / "eval.jsonl"
    f.write_text("", encoding="utf-8")
    assert _recover_partial_last_line(f) is False


def test_recover_partial_last_line_clean_file(tmp_path):
    f = tmp_path / "eval.jsonl"
    f.write_text('{"a": 1}\n{"b": 2}\n', encoding="utf-8")
    assert _recover_partial_last_line(f) is False
    # File unchanged.
    assert f.read_text(encoding="utf-8") == '{"a": 1}\n{"b": 2}\n'


def test_recover_partial_last_line_drops_unparseable_tail(tmp_path):
    f = tmp_path / "eval.jsonl"
    f.write_text('{"a": 1}\n{"b": 2}\n{"partial\n', encoding="utf-8")
    assert _recover_partial_last_line(f) is True
    # The partial line is gone; the clean prefix is preserved.
    lines = f.read_text(encoding="utf-8").splitlines()
    assert lines == ['{"a": 1}', '{"b": 2}']


def test_recover_partial_last_line_does_not_touch_earlier_corruption(tmp_path):
    # Earlier corrupt line; trailing line is fine. Recovery must NOT
    # touch the file — that's validate.py's domain.
    f = tmp_path / "eval.jsonl"
    f.write_text('{"a": 1}\nbroken-line\n{"c": 3}\n', encoding="utf-8")
    assert _recover_partial_last_line(f) is False
    assert f.read_text(encoding="utf-8") == '{"a": 1}\nbroken-line\n{"c": 3}\n'


def test_recover_partial_last_line_handles_no_trailing_newline(tmp_path):
    # File ends with a partial line, no newline. Recovery drops it.
    f = tmp_path / "eval.jsonl"
    f.write_text('{"a": 1}\n{"partial', encoding="utf-8")
    assert _recover_partial_last_line(f) is True
    assert f.read_text(encoding="utf-8").splitlines() == ['{"a": 1}']


# =========================================================================
# _undo_last_commit
# =========================================================================


def test_undo_last_commit_no_file(tmp_path):
    assert _undo_last_commit(tmp_path / "missing.jsonl") is None


def test_undo_last_commit_empty_file(tmp_path):
    f = tmp_path / "eval.jsonl"
    f.write_text("", encoding="utf-8")
    assert _undo_last_commit(f) is None
    assert f.read_text(encoding="utf-8") == ""


def test_undo_last_commit_single_record(tmp_path):
    rec = EvalRecord(
        path=r"C:\a.kdbx",
        label="juicy",
        tier="Red",
        category="credential_containers",
        source="engagement",
        notes="A KeePass vault sitting in a user share.",
        added_date=date(2026, 5, 24),
    )
    eval_path = _write_eval_set(tmp_path, [rec])
    removed = _undo_last_commit(eval_path)
    assert removed is not None
    assert removed.path == r"C:\a.kdbx"
    assert eval_path.read_text(encoding="utf-8") == ""


def test_undo_last_commit_keeps_earlier_records_byte_exact(tmp_path):
    """Undo must NOT re-parse earlier records — they're written
    byte-for-byte. This protects against a record that fails CURRENT
    schema validation (e.g., labeled before a taxonomy revision)
    blocking undo."""
    eval_path = tmp_path / "eval.jsonl"
    # Write a "stale" earlier record that current schema would reject:
    # category not in current CATEGORY_SLUGS.
    stale_line = json.dumps(
        {
            "path": r"C:\old.kdbx",
            "label": "juicy",
            "tier": "Red",
            "category": "very_old_taxonomy_slug",
            "source": "engagement",
            "notes": "Written under an older taxonomy version.",
            "added_date": "2026-05-20",
        }
    )
    current = EvalRecord(
        path=r"C:\new.kdbx",
        label="juicy",
        tier="Red",
        category="credential_containers",
        source="engagement",
        notes="A current KeePass vault from today's labeling.",
        added_date=date(2026, 5, 24),
    )
    eval_path.write_text(stale_line + "\n" + current.model_dump_json() + "\n", encoding="utf-8")

    removed = _undo_last_commit(eval_path)
    assert removed is not None
    assert removed.path == r"C:\new.kdbx"
    # Stale line preserved byte-exact.
    assert eval_path.read_text(encoding="utf-8") == stale_line + "\n"


def test_undo_then_relabel_yields_exactly_one_record(tmp_path):
    """The load-bearing undo property: an undo followed by a relabel of
    the same path produces exactly one record for that path, not zero
    and not two."""
    eval_path = tmp_path / "eval.jsonl"

    first = EvalRecord(
        path=r"C:\a.kdbx",
        label="juicy",
        tier="Red",
        category="credential_containers",
        source="engagement",
        notes="First labeling pass — Red tier.",
        added_date=date(2026, 5, 24),
    )
    atomic_append_jsonl(eval_path, first)

    removed = _undo_last_commit(eval_path)
    assert removed is not None
    assert removed.path == r"C:\a.kdbx"
    assert eval_path.read_text(encoding="utf-8") == ""

    relabeled = EvalRecord(
        path=r"C:\a.kdbx",
        label="juicy",
        tier="Black",
        category="credential_containers",
        source="engagement",
        notes="Reconsidered; this one is Black (unprotected vault).",
        added_date=date(2026, 5, 24),
    )
    atomic_append_jsonl(eval_path, relabeled)

    lines = eval_path.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 1, "exactly one record for the relabeled path"
    record = EvalRecord.model_validate_json(lines[0])
    assert record.tier == "Black"


def test_undo_then_skip_leaves_zero_records_for_path(tmp_path):
    """If the labeler undoes and then ends the session without
    relabeling, the path is absent from eval_set entirely. Next
    session's queue derivation should present the path again."""
    eval_path = tmp_path / "eval.jsonl"
    rec = EvalRecord(
        path=r"C:\a.kdbx",
        label="juicy",
        tier="Red",
        category="credential_containers",
        source="engagement",
        notes="A KeePass vault path that was committed then undone.",
        added_date=date(2026, 5, 24),
    )
    atomic_append_jsonl(eval_path, rec)

    _undo_last_commit(eval_path)
    # Session ends; eval_set has 0 records.
    assert eval_path.read_text(encoding="utf-8") == ""


def test_two_commits_then_undo_keeps_first(tmp_path):
    eval_path = tmp_path / "eval.jsonl"
    a = EvalRecord(
        path=r"C:\a.kdbx",
        label="juicy",
        tier="Red",
        category="credential_containers",
        source="engagement",
        notes="The first commit; should survive the undo of the second.",
        added_date=date(2026, 5, 24),
    )
    b = EvalRecord(
        path=r"C:\b.kdbx",
        label="juicy",
        tier="Red",
        category="credential_containers",
        source="engagement",
        notes="The second commit; this is the one being undone.",
        added_date=date(2026, 5, 24),
    )
    atomic_append_jsonl(eval_path, a)
    atomic_append_jsonl(eval_path, b)

    removed = _undo_last_commit(eval_path)
    assert removed is not None
    assert removed.path == r"C:\b.kdbx"
    lines = eval_path.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 1
    assert EvalRecord.model_validate_json(lines[0]).path == r"C:\a.kdbx"


def test_undo_on_corrupt_last_line_raises_and_leaves_file_unchanged(tmp_path):
    """Regression pin for the parse-before-rewrite ordering in
    ``_undo_last_commit``. The last line is parsed (via
    ``EvalRecord.model_validate_json``) BEFORE
    ``_atomic_rewrite_text_lines`` is called; if the last line fails
    schema, the parse raises and the rewrite never runs — file
    untouched.

    A future reorder of those two lines (rewrite first, parse second)
    would silently mangle the file on corrupt input: the rewrite would
    succeed, dropping the corrupt last line, and the parse would then
    raise too late to recover the original state. This test catches
    that regression by asserting both: ``ValidationError`` raised AND
    file is byte-identical to the pre-undo content.
    """
    eval_path = tmp_path / "eval.jsonl"
    valid_line = json.dumps(
        {
            "path": r"C:\valid.kdbx",
            "label": "juicy",
            "tier": "Red",
            "category": "credential_containers",
            "source": "engagement",
            "notes": "A valid prior record that must not be touched.",
            "added_date": "2026-05-24",
        }
    )
    # Last line is JSON-parseable but fails EvalRecord schema (invalid label).
    corrupt_last_line = json.dumps(
        {
            "path": r"C:\corrupt.kdbx",
            "label": "INVALID_LABEL_NOT_IN_LABELS",
            "category": "credential_containers",
            "source": "engagement",
            "notes": "Last line that fails current schema validation.",
            "added_date": "2026-05-24",
        }
    )
    original_content = valid_line + "\n" + corrupt_last_line + "\n"
    eval_path.write_text(original_content, encoding="utf-8")

    with pytest.raises(ValidationError):
        _undo_last_commit(eval_path)

    # Critical: file is byte-identical. No rewrite happened.
    assert eval_path.read_text(encoding="utf-8") == original_content


# =========================================================================
# _compute_submit_outcome — the validator state machine
# =========================================================================


def test_submit_juicy_commits_immediately():
    out = _compute_submit_outcome(
        state=ValidatorState.IDLE,
        decision=_juicy_decision(),
        pending_warnings=[],
        queue_record=_queue_record(),
        validator_fn=lambda _: pytest.fail("validator must not run for juicy labels"),
    )
    assert out.action == SubmitAction.COMMIT
    assert out.record is not None
    assert out.record.label == "juicy"
    assert out.record.validator_warnings == []


def test_submit_not_juicy_empty_fire_commits_immediately():
    out = _compute_submit_outcome(
        state=ValidatorState.IDLE,
        decision=_not_juicy_decision(),
        pending_warnings=[],
        queue_record=_queue_record(),
        validator_fn=lambda _: [],
    )
    assert out.action == SubmitAction.COMMIT
    assert out.record.label == "not_juicy"
    assert out.record.validator_warnings == []


def test_submit_not_juicy_non_empty_fire_shows_warning():
    out = _compute_submit_outcome(
        state=ValidatorState.IDLE,
        decision=_not_juicy_decision(),
        pending_warnings=[],
        queue_record=_queue_record(),
        validator_fn=lambda _: ["kdbx_extension"],
    )
    assert out.action == SubmitAction.SHOW_VALIDATOR_WARNING
    assert out.pending_validator_warnings == ["kdbx_extension"]
    assert out.record is None  # no commit yet


def test_submit_warning_shown_second_click_commits_with_overrides_logged():
    out = _compute_submit_outcome(
        state=ValidatorState.WARNING_SHOWN,
        decision=_not_juicy_decision(),
        pending_warnings=["kdbx_extension", "another_one"],
        queue_record=_queue_record(),
        # Validator must NOT be re-called on the second click.
        validator_fn=lambda _: pytest.fail("validator must not run again on the override click"),
    )
    assert out.action == SubmitAction.COMMIT
    assert out.record.validator_warnings == ["kdbx_extension", "another_one"]


def test_submit_validator_only_runs_for_idle_not_juicy():
    """Validator is queried only on the first not_juicy submit. Juicy
    never triggers it (asserted above), and the override click in
    WARNING_SHOWN reuses the previously-fired set (asserted above).
    This test pins the third combination: WARNING_SHOWN + juicy never
    invokes the validator either (the labeler changed their mind to
    juicy while a warning was pending; caller resets state on widget
    change, but if somehow this state is reached, juicy still wins
    cleanly)."""
    out = _compute_submit_outcome(
        state=ValidatorState.WARNING_SHOWN,
        decision=_juicy_decision(),
        pending_warnings=["whatever"],
        queue_record=_queue_record(),
        validator_fn=lambda _: pytest.fail("validator must not run for juicy"),
    )
    assert out.action == SubmitAction.COMMIT
    assert out.record.label == "juicy"
    assert out.record.validator_warnings == []


def test_submit_schema_invalid_returns_reject_with_error_message():
    # Juicy without tier → schema rejects.
    decision = _juicy_decision(tier=None)
    out = _compute_submit_outcome(
        state=ValidatorState.IDLE,
        decision=decision,
        pending_warnings=[],
        queue_record=_queue_record(),
        validator_fn=lambda _: pytest.fail(
            "validator must not run before schema validation passes"
        ),
    )
    assert out.action == SubmitAction.REJECT_INVALID
    assert out.record is None
    assert out.schema_error is not None
    assert "tier" in out.schema_error


def test_submit_schema_error_naming_helps_labeler_fix_one_field():
    # Notes too short — labeler can fix this single field.
    decision = _juicy_decision(notes="x")
    out = _compute_submit_outcome(
        state=ValidatorState.IDLE,
        decision=decision,
        pending_warnings=[],
        queue_record=_queue_record(),
    )
    assert out.action == SubmitAction.REJECT_INVALID
    assert "notes" in out.schema_error


# =========================================================================
# Source flow + pre_category flow (the "labeler never touches these" pin)
# =========================================================================


def test_source_flows_from_queue_record_untouched():
    qr = _queue_record(source="public")
    out = _compute_submit_outcome(
        state=ValidatorState.IDLE,
        decision=_juicy_decision(),
        pending_warnings=[],
        queue_record=qr,
        validator_fn=lambda _: [],
    )
    assert out.record.source == "public"


def test_pre_category_flows_from_queue_record_untouched():
    qr = _queue_record(pre_category="iac")
    out = _compute_submit_outcome(
        state=ValidatorState.IDLE,
        decision=_juicy_decision(),
        pending_warnings=[],
        queue_record=qr,
        validator_fn=lambda _: [],
    )
    assert out.record.pre_category == "iac"


def test_pre_category_none_passes_through():
    qr = _queue_record(pre_category=None)
    out = _compute_submit_outcome(
        state=ValidatorState.IDLE,
        decision=_juicy_decision(),
        pending_warnings=[],
        queue_record=qr,
        validator_fn=lambda _: [],
    )
    assert out.record.pre_category is None


# =========================================================================
# _build_eval_record direct tests
# =========================================================================


def test_build_eval_record_uses_today_default():
    qr = _queue_record()
    rec = _build_eval_record(queue_record=qr, decision=_juicy_decision())
    assert rec.added_date == date.today()


def test_build_eval_record_injectable_today():
    qr = _queue_record()
    rec = _build_eval_record(queue_record=qr, decision=_juicy_decision(), today=date(2026, 1, 1))
    assert rec.added_date == date(2026, 1, 1)


# =========================================================================
# Lock acquisition
# =========================================================================


def test_lock_acquire_when_none_present(tmp_path):
    eval_path = tmp_path / "eval.jsonl"
    assert _acquire_lock(eval_path) is True
    assert (tmp_path / LOCK_FILENAME).exists()


def test_lock_blocked_when_fresh_lock_held(tmp_path):
    eval_path = tmp_path / "eval.jsonl"
    assert _acquire_lock(eval_path) is True
    # Second attempt should fail (fresh lock).
    assert _acquire_lock(eval_path) is False


def test_lock_reclaimed_when_stale(tmp_path):
    eval_path = tmp_path / "eval.jsonl"
    assert _acquire_lock(eval_path) is True
    lock_path = tmp_path / LOCK_FILENAME
    # Backdate the lock by 48 hours.
    old_mtime = time.time() - 48 * 3600
    os_utime_path(lock_path, old_mtime)
    # Should reclaim with the default 24h threshold.
    assert _acquire_lock(eval_path) is True


def test_lock_release_removes_file(tmp_path):
    eval_path = tmp_path / "eval.jsonl"
    _acquire_lock(eval_path)
    _release_lock(eval_path)
    assert not (tmp_path / LOCK_FILENAME).exists()


def test_lock_release_when_no_lock_does_not_raise(tmp_path):
    eval_path = tmp_path / "eval.jsonl"
    # No lock present; release should be a no-op.
    _release_lock(eval_path)


def os_utime_path(path: Path, mtime: float) -> None:
    """tiny shim for readability in lock tests"""
    import os as _os

    _os.utime(path, (mtime, mtime))


# =========================================================================
# Widget-change → reset cycle
# =========================================================================


def test_should_reset_validator_state_predicate():
    """The predicate that the UI calls on every widget on_change."""
    assert _should_reset_validator_state_on_widget_change(ValidatorState.WARNING_SHOWN) is True
    assert _should_reset_validator_state_on_widget_change(ValidatorState.IDLE) is False


def test_widget_change_resets_state_so_next_submit_reruns_validator():
    """The widget-change → reset → re-submit cycle as an integration
    over the pure functions in label_app_core.

    A labeler can see a validator warning, change a widget (e.g.,
    category), and click submit again. If the predicate didn't fire on
    the widget change and the UI committed with the stale
    ``pending_validator_warnings`` against the *new* decision, that
    would be a silent label-integrity bug — the validator names logged
    would not reflect what the current registry fires on the current
    decision.

    This test simulates the full cycle and proves the validator
    re-runs from scratch after the reset:

    1. First submit (not_juicy, IDLE) → validator fires → outcome is
       SHOW_VALIDATOR_WARNING. Call count = 1.
    2. UI transitions state to WARNING_SHOWN, stores pending_warnings.
    3. Widget change occurs. Predicate fires (WARNING_SHOWN → True).
       UI resets state to IDLE, clears pending_warnings.
    4. Labeler submits again with a changed decision. Outcome must
       invoke check_path AGAIN (call count = 2), not commit with the
       previously-stored override.
    """
    call_count = [0]

    def counting_validator(_path: str) -> list[str]:
        call_count[0] += 1
        return ["kdbx_extension"]

    qr = _queue_record()

    # Step 1: first submit.
    out1 = _compute_submit_outcome(
        state=ValidatorState.IDLE,
        decision=_not_juicy_decision(),
        pending_warnings=[],
        queue_record=qr,
        validator_fn=counting_validator,
    )
    assert out1.action == SubmitAction.SHOW_VALIDATOR_WARNING
    assert call_count[0] == 1

    # Step 2: UI moves to WARNING_SHOWN, stashes pending_warnings.
    state = ValidatorState.WARNING_SHOWN
    pending_warnings = list(out1.pending_validator_warnings)

    # Step 3: widget change. Predicate fires; UI resets.
    assert _should_reset_validator_state_on_widget_change(state) is True
    state = ValidatorState.IDLE
    pending_warnings = []

    # Step 4: re-submit with changed decision. Validator MUST re-run.
    changed_decision = _not_juicy_decision(category="decoy_docs")
    out2 = _compute_submit_outcome(
        state=state,
        decision=changed_decision,
        pending_warnings=pending_warnings,
        queue_record=qr,
        validator_fn=counting_validator,
    )

    assert call_count[0] == 2, (
        "validator must re-run from scratch after a widget change; "
        f"got call count {call_count[0]} (would be 1 if the stale override "
        f"committed without re-evaluating)"
    )
    # Outcome reflects fresh validator evaluation against the changed
    # decision — not a COMMIT carrying the stale pending_warnings.
    assert out2.action == SubmitAction.SHOW_VALIDATOR_WARNING
    assert out2.pending_validator_warnings == ["kdbx_extension"]
    assert out2.record is None  # no commit happened


# =========================================================================
# _new_last_error_for_outcome — stale-error-banner fix
# =========================================================================


def test_new_last_error_for_reject_returns_formatted_string():
    outcome = SubmitOutcome(
        action=SubmitAction.REJECT_INVALID,
        schema_error="tier: tier is required when label is 'juicy'",
    )
    assert (
        _new_last_error_for_outcome(outcome)
        == "Cannot commit: tier: tier is required when label is 'juicy'"
    )


def test_new_last_error_for_commit_returns_none():
    """COMMIT outcome → None. Unconditional assignment in the UI then
    clears any stale REJECT_INVALID error from a prior submit."""
    outcome = SubmitOutcome(action=SubmitAction.COMMIT)
    assert _new_last_error_for_outcome(outcome) is None


def test_new_last_error_for_show_validator_warning_returns_none():
    """SHOW_VALIDATOR_WARNING outcome → None. This is the exact branch
    the dogfood bug hit: prior REJECT_INVALID left ``last_error`` set,
    then a subsequent submit produced SHOW_VALIDATOR_WARNING which
    didn't clear it, so the page rendered both the stale error and
    the new warning. The fix is the helper returning None here AND
    the UI assigning the result unconditionally."""
    outcome = SubmitOutcome(
        action=SubmitAction.SHOW_VALIDATOR_WARNING,
        pending_validator_warnings=["kdbx_extension"],
    )
    assert _new_last_error_for_outcome(outcome) is None


# =========================================================================
# _next_form_revision_state — form-revision advance for path change
# =========================================================================


def test_next_form_revision_bumps_revision_and_resets_state():
    """The pure helper called on every path advance. Bumps form_revision
    by one (UI uses this to derive widget keys, so fresh widgets render
    with empty defaults), and resets validator state + last_error to
    their initial values."""
    out = _next_form_revision_state(current_revision=5)
    assert out == {
        "form_revision": 6,
        "validator_state": ValidatorState.IDLE,
        "pending_validator_warnings": [],
        "last_error": None,
    }


def test_next_form_revision_from_zero():
    """First advance after init: 0 → 1."""
    out = _next_form_revision_state(current_revision=0)
    assert out["form_revision"] == 1


def test_next_form_revision_clears_pending_warnings_list_not_reference():
    """The returned list must be a fresh empty list, not a shared
    reference. Otherwise mutating session_state.pending_validator_warnings
    after assignment would leak back into subsequent advances."""
    out1 = _next_form_revision_state(current_revision=1)
    out1["pending_validator_warnings"].append("kdbx_extension")
    out2 = _next_form_revision_state(current_revision=2)
    assert out2["pending_validator_warnings"] == []


# =========================================================================
# Guideline-doc parsers — inline-help shared-source pin
# =========================================================================

_GUIDELINE_PATH = Path(__file__).resolve().parents[1] / "docs" / "labeling_guidelines.md"


def test_category_parser_covers_every_slug_no_drift():
    """The labeling GUI parses category definitions from the guideline
    doc and renders them inline under the category dropdown. If a
    `CATEGORY_SLUGS` entry is missing its ``### `<slug>` `` heading
    (or vice versa), the in-GUI help would silently be missing or
    extraneous. Drift test pins the two sources match."""
    defs = parse_category_definitions(_GUIDELINE_PATH)
    assert set(defs.keys()) == set(CATEGORY_SLUGS), (
        f"Category definition drift between doc and CATEGORY_SLUGS.\n"
        f"  missing from doc: {sorted(set(CATEGORY_SLUGS) - set(defs.keys()))}\n"
        f"  extra in doc:     {sorted(set(defs.keys()) - set(CATEGORY_SLUGS))}"
    )


def test_category_definitions_are_non_empty():
    """The silent-empty-tooltip guard. An empty first-paragraph in the
    doc would parse to an empty string, and the inline GUI display
    would show a blank info box — defeating the whole point of putting
    boundaries at the point of choice. Every category definition must
    contain non-whitespace content."""
    defs = parse_category_definitions(_GUIDELINE_PATH)
    empty = [slug for slug, definition in defs.items() if not definition.strip()]
    assert empty == [], (
        f"Categories with empty/whitespace-only first paragraphs: {empty}. "
        f"Each ``### `<slug>` `` section's first paragraph is surfaced "
        f"inline in the GUI; empty paragraphs would silently show blank tooltips."
    )


def test_category_definition_has_expected_content_for_known_slug():
    """Spot check that the parser is actually capturing the boundary
    content, not some other adjacent text. ``embedded_secrets`` is the
    most overlap-prone category, so its definition is the most
    load-bearing one to verify."""
    defs = parse_category_definitions(_GUIDELINE_PATH)
    embedded = defs["embedded_secrets"]
    assert "real secret" in embedded.lower()
    assert "ordinary" in embedded.lower()
    # Boundary text must be captured (it's part of the first paragraph
    # in this section).
    assert "windows_credential_artifacts" in embedded


def test_category_parser_does_not_include_subsequent_paragraphs():
    """For sections with multiple paragraphs (decoy_docs, benign_noise
    have examples + distinguishing tests + tier guidance below the
    first paragraph), the parser must take ONLY the first paragraph.
    Including subsequent paragraphs would bloat the inline display and
    push the doc's offline-only content into the GUI."""
    defs = parse_category_definitions(_GUIDELINE_PATH)
    benign_def = defs["benign_noise"]
    # The first paragraph is the definition + boundary. Examples appear
    # in a later paragraph and start with "Examples:" — must NOT be in
    # the extracted definition.
    assert "Examples:" not in benign_def, (
        "Parser captured the Examples paragraph; should stop at first blank line."
    )
    assert "spring_banner.jpg" not in benign_def, (
        "Parser captured the examples list; should stop at first blank line."
    )


def test_tier_parser_covers_every_tier_no_drift():
    """Same shared-source pin as categories, for tiers."""
    defs = parse_tier_definitions(_GUIDELINE_PATH)
    assert set(defs.keys()) == set(SEVERITY_TIERS), (
        f"Tier definition drift between doc and SEVERITY_TIERS.\n"
        f"  missing from doc: {sorted(set(SEVERITY_TIERS) - set(defs.keys()))}\n"
        f"  extra in doc:     {sorted(set(defs.keys()) - set(SEVERITY_TIERS))}"
    )


def test_tier_parser_does_not_match_removed_green_tier():
    """Regression pin for the Green-tier removal. If a future edit
    reintroduces a ``**Green — ...**`` bold header to the doc without
    updating SEVERITY_TIERS, the drift test catches it — but this
    direct assertion makes the intent explicit."""
    defs = parse_tier_definitions(_GUIDELINE_PATH)
    assert "Green" not in defs


def test_tier_definitions_are_non_empty_and_bold_formatted():
    """Each tier definition must be non-empty AND must be a bold
    markdown span (so st.markdown renders it bold inline). The parser
    captures the full ``**Tier — criterion.**`` substring."""
    defs = parse_tier_definitions(_GUIDELINE_PATH)
    for tier, definition in defs.items():
        assert definition.strip(), f"tier {tier} has empty definition"
        assert definition.startswith("**") and definition.endswith("**"), (
            f"tier {tier} definition not bold-markdown formatted: {definition!r}"
        )
        assert tier in definition, (
            f"tier {tier} definition doesn't include the tier name: {definition!r}"
        )
