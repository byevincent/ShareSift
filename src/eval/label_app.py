"""Streamlit labeling GUI — eval set entry point.

The UI is intentionally thin. All load-bearing logic (queue
derivation, undo, partial-line recovery, the validator submit state
machine) lives in ``label_app_core.py`` and is tested in isolation.
This file is the Streamlit glue: widget rendering and the mapping
from ``SubmitOutcome`` actions to ``st.session_state`` mutations.

Cardinal rule (mirrored from the step 6 plan): never anchor the
labeler's judgment. Each widget below is checked against this:

* Path display: raw string only, no annotations.
* ``pre_category``: read from the queue record (used for ordering at
  build time) but NEVER rendered.
* Label radio: no preselection (``index=None``).
* Tier/sub-type: hidden until applicable; no preselection when shown.
* Category dropdown: no preselection; NOT seeded from ``pre_category``.
* Notes: empty default.
* Validator warning: rendered only AFTER a not_juicy submit fires
  ``check_path``; never before. State machine in ``_core``.
* Session pane: total commit count, juicy/not_juicy split, session
  timer. NO per-category running breakdown (subtle anchoring).

Keyboard shortcuts intentionally absent: ``streamlit-shortcuts`` at
v1.2.1 was rejected because its global keydown listener does not
exempt focused text inputs, so typing characters in the notes
textarea would mis-trigger button clicks. Re-evaluate when an
alternative lib gains focus-filtering. Mouse-only by design.

Run with: ``uv run --group labeling streamlit run src/eval/label_app.py``
"""

from __future__ import annotations

import os
import sys
from datetime import datetime, timezone
from pathlib import Path

# Streamlit's ``streamlit run`` only adds the script's directory
# (``src/eval/``) to ``sys.path``, not the project root — so the
# ``from src.eval.*`` absolute imports below would fail with
# ``ModuleNotFoundError: No module named 'src'``. Pytest works around
# this via ``pythonpath = ["."]`` in pyproject.toml; Streamlit has no
# equivalent. Add the project root to sys.path before any ``src.eval.*``
# import so this entry point is invocation-independent.
_PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

import streamlit as st  # noqa: E402

from src.eval._io import atomic_append_jsonl  # noqa: E402
from src.eval.categories import (  # noqa: E402
    CATEGORY_SLUGS,
    MODERN_SAAS_SUBTYPES,
    SEVERITY_TIERS,
)
from src.eval.label_app_core import (  # noqa: E402
    SubmitAction,
    SubmitDecision,
    ValidatorState,
    _acquire_lock,
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

QUEUE_PATH = Path(os.environ.get("TRUFFLER_QUEUE_PATH", "data/eval/queue.jsonl"))
EVAL_SET_PATH = Path(os.environ.get("TRUFFLER_EVAL_SET_PATH", "data/eval/eval_set.jsonl"))
_GUIDELINE_PATH = _PROJECT_ROOT / "docs" / "labeling_guidelines.md"

# Parse canonical category and tier definitions from the guideline doc
# at startup. Surfaced inline in `_render_decision_pane` so the in-GUI
# help reads from the same source as the labeler's offline reference —
# can't drift by construction (same shared-source discipline as
# `_paths.normalize_for_dedup`). Drift and non-empty pins live in
# `tests/test_label_app.py`; fast-fail below catches anything the tests
# don't.
try:
    _CATEGORY_DEFS: dict[str, str] = parse_category_definitions(_GUIDELINE_PATH)
    _TIER_DEFS: dict[str, str] = parse_tier_definitions(_GUIDELINE_PATH)
except FileNotFoundError as e:
    raise RuntimeError(
        f"Cannot start labeling GUI: guideline doc missing at {_GUIDELINE_PATH}. "
        f"The GUI reads inline category/tier definitions from this file at startup."
    ) from e

_missing_categories = set(CATEGORY_SLUGS) - set(_CATEGORY_DEFS.keys())
if _missing_categories:
    raise RuntimeError(
        f"Guideline doc missing definitions for: {sorted(_missing_categories)}. "
        f"Each CATEGORY_SLUGS entry must have a `### `<slug>`` heading in "
        f"docs/labeling_guidelines.md."
    )
_empty_categories = sorted(s for s, d in _CATEGORY_DEFS.items() if not d.strip())
if _empty_categories:
    raise RuntimeError(
        f"Guideline doc has empty first paragraphs for: {_empty_categories}. "
        f"The first paragraph after each `### `<slug>`` heading is surfaced "
        f"inline in the GUI; empty paragraphs would silently show blank info "
        f"boxes — defeating the whole point of putting boundaries at the "
        f"point of choice."
    )
_missing_tiers = set(SEVERITY_TIERS) - set(_TIER_DEFS.keys())
if _missing_tiers:
    raise RuntimeError(
        f"Guideline doc missing tier criteria for: {sorted(_missing_tiers)}. "
        f"Each SEVERITY_TIERS entry must have a `**<Tier> — <criterion>.**` "
        f"bold header in the Tier Criteria section of docs/labeling_guidelines.md."
    )


def _init_session_state() -> None:
    if "_initialized" in st.session_state:
        return
    st.session_state._initialized = True
    st.session_state.session_start = datetime.now(timezone.utc)
    st.session_state.commits_this_session = 0
    st.session_state.juicy_count = 0
    st.session_state.not_juicy_count = 0
    st.session_state.undo_buffer = None
    st.session_state.validator_state = ValidatorState.IDLE
    st.session_state.pending_validator_warnings = []
    st.session_state.recovery_warning = None
    st.session_state.queue_build_id = None
    st.session_state.lock_acquired = False
    st.session_state.last_error = None
    st.session_state.form_revision = 0


def _advance_form_revision() -> None:
    """Advance to a fresh form for the next path.

    Called after both a successful commit AND an undo re-presents a
    path. Widget keys in ``_render_decision_pane`` are derived from
    ``form_revision`` as ``f"pending_{name}_r{rev}"``; bumping the
    revision makes each widget a new Streamlit instance with its
    declared empty default. This is the robust reset pattern — the
    older ``del`` + ``rerun`` pattern was the cause of the dogfood
    form-doesn't-clear bug.

    Hygienically drops the previous revision's widget keys from
    session_state so it doesn't accumulate stale entries across a long
    labeling session. Decision logic lives in
    ``label_app_core._next_form_revision_state`` so the cycle is
    testable without Streamlit.
    """
    old_rev = st.session_state.form_revision
    for prefix in (
        "pending_label",
        "pending_tier",
        "pending_category",
        "pending_sub_type",
        "pending_notes",
    ):
        old_key = f"{prefix}_r{old_rev}"
        if old_key in st.session_state:
            del st.session_state[old_key]
    for k, v in _next_form_revision_state(old_rev).items():
        st.session_state[k] = v


def _reset_validator_on_widget_change() -> None:
    """Invalidate a pending override if any widget changed since the
    warning was shown. Decision logic lives in
    ``label_app_core._should_reset_validator_state_on_widget_change``
    so the cycle is unit-testable without Streamlit."""
    current = st.session_state.get("validator_state", ValidatorState.IDLE)
    if _should_reset_validator_state_on_widget_change(current):
        st.session_state.validator_state = ValidatorState.IDLE
        st.session_state.pending_validator_warnings = []


def main() -> None:
    st.set_page_config(page_title="ShareSift labeling", layout="wide")
    _init_session_state()

    if not st.session_state.lock_acquired:
        if not _acquire_lock(EVAL_SET_PATH):
            lock_path = EVAL_SET_PATH.parent / ".eval_set.lock"
            st.error(
                f"Another labeling session is active (lock at `{lock_path}`). "
                f"If no other tab is open, delete the lock file and refresh."
            )
            st.stop()
        st.session_state.lock_acquired = True
        if _recover_partial_last_line(EVAL_SET_PATH):
            st.session_state.recovery_warning = (
                "Recovered from an incomplete final write on a previous session."
            )

    if st.session_state.recovery_warning:
        st.warning(st.session_state.recovery_warning)
        st.session_state.recovery_warning = None

    remaining = _derive_remaining_queue(QUEUE_PATH, EVAL_SET_PATH)

    if remaining:
        current_build_id = remaining[0].build_id
        if st.session_state.queue_build_id is None:
            st.session_state.queue_build_id = current_build_id
        elif st.session_state.queue_build_id != current_build_id:
            st.error(
                f"Queue file changed underneath this session "
                f"(was {st.session_state.queue_build_id}, now {current_build_id}). "
                f"Refresh the page to continue with the new queue."
            )
            st.stop()

    if not remaining:
        if not QUEUE_PATH.exists():
            _render_queue_missing()
        elif _queue_file_has_records(QUEUE_PATH):
            _render_queue_complete()
        else:
            _render_queue_empty()
        return

    current = remaining[0]

    path_col, decision_col, session_col = st.columns([2, 3, 1])
    with path_col:
        _render_path_pane(current.path)
    with decision_col:
        _render_decision_pane(current)
    with session_col:
        _render_session_pane()


def _render_path_pane(path: str) -> None:
    st.subheader("Path")
    st.code(path, language=None)


def _render_decision_pane(current) -> None:
    st.subheader("Decision")

    rev = st.session_state.form_revision

    st.radio(
        "Label",
        options=["juicy", "not_juicy"],
        index=None,
        key=f"pending_label_r{rev}",
        on_change=_reset_validator_on_widget_change,
    )

    if st.session_state.get(f"pending_label_r{rev}") == "juicy":
        # Tier criteria block — placed ABOVE the radio so the criteria
        # are visible at the moment of choosing (not below, where the
        # labeler would have already picked). All three shown together
        # so Red/Yellow boundary is comparable at a glance. Pure
        # definitions, never a suggestion for THIS path.
        st.markdown("\n\n".join(_TIER_DEFS[t] for t in SEVERITY_TIERS))
        st.radio(
            "Tier",
            options=list(SEVERITY_TIERS),
            index=None,
            key=f"pending_tier_r{rev}",
            on_change=_reset_validator_on_widget_change,
        )

    st.selectbox(
        "Category",
        options=list(CATEGORY_SLUGS),
        index=None,
        key=f"pending_category_r{rev}",
        on_change=_reset_validator_on_widget_change,
    )

    # Inline category definition + boundary calls, sourced from the
    # guideline doc at startup. Renders only when a category is
    # selected — no clutter, no anchor before the labeler decides.
    # Pure definition, never a suggestion for THIS path.
    _selected_category = st.session_state.get(f"pending_category_r{rev}")
    if _selected_category is not None:
        st.info(_CATEGORY_DEFS[_selected_category])

    if st.session_state.get(f"pending_category_r{rev}") == "modern_saas_tokens":
        st.selectbox(
            "Sub-type",
            options=list(MODERN_SAAS_SUBTYPES),
            index=None,
            key=f"pending_sub_type_r{rev}",
            on_change=_reset_validator_on_widget_change,
        )

    st.text_area(
        "Notes",
        key=f"pending_notes_r{rev}",
        height=120,
        on_change=_reset_validator_on_widget_change,
    )

    if st.session_state.validator_state == ValidatorState.WARNING_SHOWN:
        fired = st.session_state.pending_validator_warnings
        st.warning(
            f"Validator fires on this path: **{', '.join(fired)}**. "
            f"Click Submit again to confirm the not_juicy override "
            f"(these names will be logged in `validator_warnings`)."
        )
        submit_label = (
            f"Confirm not_juicy override "
            f"(logs {len(fired)} heuristic{'s' if len(fired) != 1 else ''})"
        )
    else:
        submit_label = "Submit"

    if st.session_state.last_error:
        st.error(st.session_state.last_error)

    if st.button(submit_label, type="primary"):
        _handle_submit(current)

    if st.button(
        "Undo last commit",
        disabled=st.session_state.undo_buffer is None,
        help=(
            "Removes the most recent commit from eval_set.jsonl and "
            "pushes that path back to the front of the queue. Single-slot — "
            "you can't undo twice."
        ),
    ):
        _handle_undo()


def _render_session_pane() -> None:
    st.subheader("Session")
    st.metric("Commits", st.session_state.commits_this_session)
    elapsed = datetime.now(timezone.utc) - st.session_state.session_start
    minutes = int(elapsed.total_seconds() / 60)
    st.metric("Time", f"{minutes} min")
    st.write(f"juicy: {st.session_state.juicy_count}")
    st.write(f"not_juicy: {st.session_state.not_juicy_count}")
    if minutes >= 45:
        st.info("45+ minutes — consider a break.")
    if st.button("End session"):
        _end_session()


def _render_queue_complete() -> None:
    st.subheader("Queue complete")
    st.success("All paths in the queue have been labeled.")
    st.metric("Commits this session", st.session_state.commits_this_session)
    elapsed = datetime.now(timezone.utc) - st.session_state.session_start
    minutes = int(elapsed.total_seconds() / 60)
    st.metric("Session time", f"{minutes} min")
    st.write(
        "Recommend running:\n\n"
        f"```\npython -m src.eval.validate --input {EVAL_SET_PATH}\n```\n\n"
        "before further work."
    )
    if st.button("End session"):
        _end_session()


def _render_queue_missing() -> None:
    st.subheader("No queue file found")
    st.error(
        f"Expected queue at `{QUEUE_PATH}`. Run `build_queue.py` first to "
        f"create one, then refresh this page."
    )
    st.write(
        "Example:\n\n"
        "```bash\n"
        "python -m src.eval.build_queue \\\n"
        "    --input <paths>.csv \\\n"
        "    --output data/eval/queue.jsonl \\\n"
        "    --source-default engagement\n"
        "```"
    )


def _render_queue_empty() -> None:
    st.subheader("Queue is empty")
    st.warning(
        f"Queue at `{QUEUE_PATH}` was built but contains no paths. "
        f"This usually means either the input CSV had no rows, or "
        f"cross-file dedup against `eval_set.jsonl` filtered everything "
        f"out (every input path was already labeled). Check the source "
        f"CSV / verify whether the inputs were already in the eval set, "
        f"then rebuild the queue."
    )


def _handle_submit(current) -> None:
    rev = st.session_state.form_revision
    decision = SubmitDecision(
        label=st.session_state.get(f"pending_label_r{rev}"),
        tier=st.session_state.get(f"pending_tier_r{rev}"),
        category=st.session_state.get(f"pending_category_r{rev}"),
        sub_type=st.session_state.get(f"pending_sub_type_r{rev}"),
        notes=st.session_state.get(f"pending_notes_r{rev}") or "",
    )
    outcome = _compute_submit_outcome(
        state=st.session_state.validator_state,
        decision=decision,
        pending_warnings=list(st.session_state.pending_validator_warnings),
        queue_record=current,
    )

    # Unconditional assignment — a non-REJECT outcome returns None,
    # clearing any stale REJECT_INVALID error from a prior submit so
    # it can't render alongside a fresh SHOW_VALIDATOR_WARNING or
    # COMMIT. See ``_new_last_error_for_outcome`` docstring.
    st.session_state.last_error = _new_last_error_for_outcome(outcome)

    if outcome.action == SubmitAction.REJECT_INVALID:
        # Preserve all pending_* widgets per the design: the labeler
        # fixes the one wrong field, doesn't re-enter everything.
        return

    if outcome.action == SubmitAction.SHOW_VALIDATOR_WARNING:
        st.session_state.validator_state = ValidatorState.WARNING_SHOWN
        st.session_state.pending_validator_warnings = outcome.pending_validator_warnings
        st.rerun()
        return

    atomic_append_jsonl(EVAL_SET_PATH, outcome.record)
    st.session_state.undo_buffer = outcome.record
    st.session_state.commits_this_session += 1
    if outcome.record.label == "juicy":
        st.session_state.juicy_count += 1
    else:
        st.session_state.not_juicy_count += 1
    _advance_form_revision()
    st.rerun()


def _handle_undo() -> None:
    if st.session_state.undo_buffer is None:
        return
    removed = _undo_last_commit(EVAL_SET_PATH)
    if removed is None:
        st.warning("Nothing to undo (eval_set is empty).")
        st.session_state.undo_buffer = None
        return
    st.session_state.undo_buffer = None
    st.session_state.commits_this_session = max(0, st.session_state.commits_this_session - 1)
    if removed.label == "juicy":
        st.session_state.juicy_count = max(0, st.session_state.juicy_count - 1)
    else:
        st.session_state.not_juicy_count = max(0, st.session_state.not_juicy_count - 1)
    _advance_form_revision()
    st.rerun()


def _end_session() -> None:
    summary = _build_session_summary()
    print(summary)
    summary_file = EVAL_SET_PATH.parent / "last_session_summary.txt"
    summary_file.parent.mkdir(parents=True, exist_ok=True)
    summary_file.write_text(summary, encoding="utf-8")
    _release_lock(EVAL_SET_PATH)
    st.success(f"Session summary written to `{summary_file}`. Copy from there for the journal.")
    st.session_state._initialized = False
    st.stop()


def _build_session_summary() -> str:
    now = datetime.now(timezone.utc)
    elapsed = now - st.session_state.session_start
    minutes = int(elapsed.total_seconds() / 60)
    return (
        "ShareSift labeling session summary\n"
        f"Started:  {st.session_state.session_start.isoformat()}\n"
        f"Ended:    {now.isoformat()}\n"
        f"Duration: {minutes} min\n"
        f"Commits:  {st.session_state.commits_this_session}\n"
        f"  juicy:     {st.session_state.juicy_count}\n"
        f"  not_juicy: {st.session_state.not_juicy_count}\n"
    )


if __name__ == "__main__":
    main()
