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
