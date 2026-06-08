"""Verbosity helper — level gating + warn/error always emit."""

from __future__ import annotations

import io

from sharesift._output import Output, Verbosity


def _drain(out: Output, stream: io.StringIO) -> str:
    value = stream.getvalue()
    stream.seek(0)
    stream.truncate()
    return value


def test_default_verbosity_is_normal():
    assert Output().verbosity == Verbosity.NORMAL


def test_normal_emits_info_not_debug():
    stream = io.StringIO()
    out = Output(stream=stream)
    out.configure(verbosity=Verbosity.NORMAL)
    out.info("normal-info")
    out.debug("normal-debug")
    captured = _drain(out, stream)
    assert "normal-info" in captured
    assert "normal-debug" not in captured


def test_quiet_silences_info_and_debug():
    stream = io.StringIO()
    out = Output(stream=stream)
    out.configure(verbosity=Verbosity.QUIET)
    out.info("quiet-info")
    out.debug("quiet-debug")
    assert _drain(out, stream) == ""


def test_verbose_emits_both():
    stream = io.StringIO()
    out = Output(stream=stream)
    out.configure(verbosity=Verbosity.VERBOSE)
    out.info("verbose-info")
    out.debug("verbose-debug")
    captured = _drain(out, stream)
    assert "verbose-info" in captured
    assert "verbose-debug" in captured


def test_warn_emits_at_every_level():
    for level in (Verbosity.QUIET, Verbosity.NORMAL, Verbosity.VERBOSE):
        stream = io.StringIO()
        out = Output(stream=stream)
        out.configure(verbosity=level)
        out.warn(f"warn-at-{level.name}")
        captured = _drain(out, stream)
        assert f"warn-at-{level.name}" in captured, f"warn was suppressed at {level.name}"


def test_error_emits_at_every_level():
    for level in (Verbosity.QUIET, Verbosity.NORMAL, Verbosity.VERBOSE):
        stream = io.StringIO()
        out = Output(stream=stream)
        out.configure(verbosity=level)
        out.error(f"error-at-{level.name}")
        captured = _drain(out, stream)
        assert f"error-at-{level.name}" in captured, f"error was suppressed at {level.name}"


def test_module_singleton_is_importable():
    """`from sharesift._output import out` is the contract subcommand
    handlers will rely on. Smoke test the import shape."""
    from sharesift._output import out as singleton

    assert isinstance(singleton, Output)
    assert singleton.verbosity == Verbosity.NORMAL


# --- progress() ---


def test_progress_disabled_returns_iterable_unchanged_under_quiet():
    """QUIET avoids the tqdm import entirely. Returned object is the
    raw iterable (no tqdm wrapper), no overhead."""
    out = Output()
    out.configure(verbosity=Verbosity.QUIET)
    src = range(5)
    wrapped = out.progress(src, desc="x")
    assert wrapped is src


def test_progress_passes_items_through_at_every_level():
    """Iteration must yield the same items in the same order regardless
    of verbosity. The bar is decoration; the iterable is the contract."""
    for level in (Verbosity.QUIET, Verbosity.NORMAL, Verbosity.VERBOSE):
        stream = io.StringIO()
        out = Output(stream=stream)
        out.configure(verbosity=level)
        items = list(out.progress(range(5), desc=f"at-{level.name}", total=5))
        assert items == [0, 1, 2, 3, 4], f"items mismatch at {level.name}"


def test_summary_is_noop_when_json_disabled():
    """Default state: summary() emits nothing on stderr."""
    stream = io.StringIO()
    out = Output(stream=stream)
    out.configure(verbosity=Verbosity.NORMAL, json=False)
    out.summary({"command": "score-paths", "exit_code": 0})
    assert stream.getvalue() == ""


def test_summary_emits_single_json_line_when_enabled():
    import json as _json

    stream = io.StringIO()
    out = Output(stream=stream)
    out.configure(verbosity=Verbosity.NORMAL, json=True)
    payload = {
        "command": "score-paths",
        "elapsed_s": 1.23,
        "input_count": 5,
        "exit_code": 0,
    }
    out.summary(payload)
    captured = stream.getvalue()
    assert captured.endswith("\n"), "summary line must end with newline"
    parsed = _json.loads(captured.strip())
    assert parsed == payload


def test_summary_emits_regardless_of_verbosity():
    """``--quiet --json`` still emits the summary block. ``--verbose
    --json`` likewise. The summary is structured data, not chatter."""
    for level in (Verbosity.QUIET, Verbosity.NORMAL, Verbosity.VERBOSE):
        stream = io.StringIO()
        out = Output(stream=stream)
        out.configure(verbosity=level, json=True)
        out.summary({"command": "x", "exit_code": 0})
        assert stream.getvalue() != "", f"summary suppressed at {level.name}"


def test_progress_verbose_emits_bar_even_to_non_tty():
    """At VERBOSE, the bar should appear in captured output even when
    the stream isn't a TTY (StringIO emulates a piped stderr)."""
    stream = io.StringIO()
    out = Output(stream=stream)
    out.configure(verbosity=Verbosity.VERBOSE)
    # Consume the wrapped iterable to trigger tqdm rendering.
    for _ in out.progress(range(3), desc="verbose-bar", total=3):
        pass
    captured = stream.getvalue()
    assert "verbose-bar" in captured, (
        f"expected tqdm to emit bar header at VERBOSE; captured: {captured!r}"
    )
