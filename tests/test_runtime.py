"""Tests for the Phase-4 runtime module + CLI.

Coverage:
* ``ScanResult.as_record()`` — pure dataclass, no model needed.
* ``PathClassifier`` — load + single/batch scoring, error handling for
  missing artifact. Conditional on the trained model existing
  (skipped if not).
* ``Scanner`` lazy construction — content classifier is NOT loaded
  unless content scoring is actually triggered.
* CLI argparse — ``--help`` for both subcommands returns 0; missing
  subcommand raises.
* CLI ``score-paths`` end-to-end — actual invocation reads paths,
  writes JSONL.

Content-classifier inference + ``scan-files`` end-to-end are NOT
unit-tested here because they require a model load (~3GB) and CUDA
or several seconds of CPU compute per record. Those paths are
covered by the ``tools/eval_content_classifier.py`` integration run.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from sharesift.cli import main as cli_main
from sharesift.path import PathClassifier, PathResult
from sharesift.pipeline import Scanner, ScanResult

REPO_ROOT = Path(__file__).resolve().parent.parent
PATH_MODEL_DIR = REPO_ROOT / "models" / "path_classifier_v0"
HAVE_PATH_MODEL = (PATH_MODEL_DIR / "calibrated.joblib").exists()
SKIP_NO_PATH_MODEL = pytest.mark.skipif(
    not HAVE_PATH_MODEL,
    reason=(
        "path classifier artifact not present "
        "(run tools/calibrate_path_classifier.py to build it)"
    ),
)


# --- ScanResult shape ------------------------------------------------------


def test_scan_result_as_record_omits_debug_by_default():
    r = ScanResult(
        path=r"\\fs\share\foo.txt",
        path_probability=0.9,
        path_tier="Yellow",
        content_check="yes",
        content_excerpt="api_key='abc'",
        raw_content_response="<think>\n\n</think>\n\nyes",
    )
    rec = r.as_record()
    assert "raw_content_response" not in rec
    assert rec["path_tier"] == "Yellow"
    assert rec["content_check"] == "yes"


def test_scan_result_as_record_includes_debug_when_asked():
    r = ScanResult(
        path="p",
        path_probability=0.5,
        path_tier="Yellow",
        content_check="yes",
        content_excerpt="x",
        raw_content_response="raw model out",
    )
    rec = r.as_record(include_debug=True)
    assert rec["raw_content_response"] == "raw model out"


def test_scan_result_with_skipped_content_serializes_nulls():
    r = ScanResult(
        path="p",
        path_probability=0.1,
        path_tier=None,
        content_check=None,
        content_excerpt=None,
        raw_content_response=None,
    )
    rec = r.as_record()
    assert rec["content_check"] is None
    assert rec["path_tier"] is None
    # JSON-roundtrippable.
    json.dumps(rec)


# --- PathClassifier --------------------------------------------------------


def test_path_classifier_missing_artifact_raises(tmp_path: Path):
    with pytest.raises(FileNotFoundError):
        PathClassifier(windows_model_dir=tmp_path / "nope")


@SKIP_NO_PATH_MODEL
def test_path_classifier_score_returns_path_result():
    clf = PathClassifier()
    result = clf.score(r"\\fs\share\id_rsa")
    assert isinstance(result, PathResult)
    assert 0.0 <= result.probability <= 1.0


@SKIP_NO_PATH_MODEL
def test_path_classifier_score_batch_preserves_order():
    clf = PathClassifier()
    paths = [
        r"\\fs\share\file.txt",
        r"\\fs\share\.ssh\id_rsa",
        "/etc/shadow",
    ]
    results = clf.score_batch(paths)
    assert [r.path for r in results] == paths
    assert all(isinstance(r, PathResult) for r in results)


@SKIP_NO_PATH_MODEL
def test_path_classifier_empty_batch_returns_empty():
    assert PathClassifier().score_batch([]) == []


# --- Scanner lazy construction ---------------------------------------------


@SKIP_NO_PATH_MODEL
def test_scanner_does_not_construct_content_when_only_path_used():
    """Lazy property: accessing ``path_classifier`` must NOT construct
    the content classifier. Important because content construction
    triggers torch + transformers imports."""
    s = Scanner()
    _ = s.path_classifier  # force lazy construction of path
    assert s._content is None


@SKIP_NO_PATH_MODEL
def test_scanner_skips_content_when_no_content_provided():
    s = Scanner()
    result = s.scan(r"\\fs\share\foo.txt", content=None)
    assert result.content_check is None
    assert result.content_excerpt is None


# --- CLI argparse ----------------------------------------------------------


def test_cli_version_flag(capsys):
    """v0.18: ``sharesift --version`` prints ``sharesift <pep440>`` and exits 0."""
    import re

    with pytest.raises(SystemExit) as exc:
        cli_main(["--version"])
    assert exc.value.code == 0
    out = capsys.readouterr().out
    assert re.match(r"^sharesift \d+\.\d+", out), f"unexpected version line: {out!r}"


def test_warning_suppression_default(recwarn):
    """v0.18: FutureWarning/DeprecationWarning from noisy 3rd-party modules
    are suppressed once ``main()`` installs filters.

    Verified by emitting a synthetic warning that looks like it came from
    ``transformers.foo`` after installing filters — the filter should swallow
    it. (Real transformers warnings only fire under scan-files, which we don't
    invoke here; the filter logic itself is what we're testing.)
    """
    import warnings

    from sharesift.cli import _install_warning_filters

    _install_warning_filters()
    # Emit a FutureWarning that claims to come from a suppressed module.
    warnings.warn_explicit(
        "synthetic transformers deprecation",
        category=FutureWarning,
        filename="transformers/foo.py",
        lineno=1,
        module="transformers.foo",
    )
    captured = [w for w in recwarn.list if issubclass(w.category, FutureWarning)]
    assert captured == [], (
        f"expected FutureWarning to be filtered; got {[str(w.message) for w in captured]}"
    )


def test_cli_score_paths_help_exits_zero():
    with pytest.raises(SystemExit) as exc:
        cli_main(["score-paths", "--help"])
    assert exc.value.code == 0


def test_cli_scan_files_help_exits_zero():
    with pytest.raises(SystemExit) as exc:
        cli_main(["scan-files", "--help"])
    assert exc.value.code == 0


def test_cli_requires_subcommand():
    with pytest.raises(SystemExit) as exc:
        cli_main([])
    assert exc.value.code != 0


def test_cli_score_paths_requires_input_or_stdin():
    with pytest.raises(SystemExit):
        cli_main(["score-paths"])


# --- CLI end-to-end --------------------------------------------------------


@SKIP_NO_PATH_MODEL
def test_cli_score_paths_writes_jsonl(tmp_path: Path):
    input_file = tmp_path / "paths.txt"
    output_file = tmp_path / "out.jsonl"
    input_file.write_text(
        "\n".join(
            [
                r"\\fs\share\id_rsa",
                r"\\fs\share\boring.txt",
                "/etc/shadow",
            ]
        ),
        encoding="utf-8",
    )
    rc = cli_main(
        [
            "score-paths",
            "--input",
            str(input_file),
            "--output",
            str(output_file),
        ]
    )
    assert rc == 0
    lines = output_file.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 3
    for line in lines:
        rec = json.loads(line)
        assert "path" in rec
        assert "probability" in rec
        assert "tier" in rec
        assert 0.0 <= rec["probability"] <= 1.0
