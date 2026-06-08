"""ShareSift CLI — user-facing entry point.

Two subcommands:

* ``sharesift score-paths`` — Stage-1 only. Takes a list of paths,
  scores them with the LightGBM path classifier, emits JSONL with
  (path, probability, tier). Path-only triage; doesn't require
  content access. Fast: ~ms per path. This is the bread-and-butter
  workflow — pipe in share enumeration output, get a tier-prioritized
  list of paths to actually open.

* ``sharesift scan-files`` — Stage 1 + Stage 2. Takes a list of local
  file paths, reads each file's content, runs both classifiers,
  emits JSONL with the combined result. Content stage runs only on
  tier-flagged paths (override with ``--force-content``). Slow:
  ~5-8s per content-checked file on CPU; ~150ms on CUDA.

Input is paths-per-line via ``--input <file>`` or ``--stdin``.
Output is JSONL to ``--output <file>`` or stdout.

The content classifier import is deferred until ``scan-files`` is
actually invoked, so ``sharesift score-paths --help`` returns
instantly even without the heavy content-inference deps installed.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import warnings
from pathlib import Path

from sharesift import __version__
from sharesift._output import Verbosity, out
from sharesift.path import PathClassifier
from sharesift.pipeline import Scanner


_NOISY_3P_MODULES = ("transformers", "peft", "urllib3", "bitsandbytes", "sklearn")
_NOISY_3P_CATEGORIES = (FutureWarning, DeprecationWarning, UserWarning)


def _install_warning_filters(verbosity: Verbosity) -> None:
    # --verbose surfaces everything for debugging.
    if verbosity >= Verbosity.VERBOSE:
        return
    for category in _NOISY_3P_CATEGORIES:
        for prefix in _NOISY_3P_MODULES:
            warnings.filterwarnings(
                "ignore",
                category=category,
                module=rf"{prefix}(\..*)?",
            )
    os.environ.setdefault("TRANSFORMERS_VERBOSITY", "error")


def _read_paths(input_arg: Path | None, use_stdin: bool) -> list[str]:
    """Load paths from --input file or stdin, one per line, skipping blanks."""
    if use_stdin:
        return [line.strip() for line in sys.stdin if line.strip()]
    if input_arg is None:
        raise SystemExit("error: --input or --stdin required")
    return [
        line.strip()
        for line in input_arg.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def _emit_jsonl(records: list[dict], output: Path | None) -> None:
    """Write JSONL to --output or stdout."""
    if output:
        with output.open("w", encoding="utf-8") as f:
            for r in records:
                f.write(json.dumps(r) + "\n")
    else:
        for r in records:
            print(json.dumps(r))


def _read_jsonl(input_arg: Path | None, use_stdin: bool) -> list[dict]:
    """Load JSONL records from --input file or stdin."""
    if use_stdin:
        lines = [line for line in sys.stdin if line.strip()]
    elif input_arg is not None:
        lines = [
            line
            for line in input_arg.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
    else:
        raise SystemExit("error: --input or --stdin required")
    return [json.loads(line) for line in lines]


def _parse_target_file(target_file: Path | None) -> dict:
    """Parse a YAML target file for network verifiers.

    Format::

        ssh:
          - host: target.example.com
            port: 22
            usernames: [root, admin]
        smb:
          - host: dc01.corp.local
        ldap:
          - url: ldap://dc01.corp.local
        databricks:
          - https://my-workspace.cloud.databricks.com

    Missing keys default to empty lists.
    """
    if target_file is None:
        return {}
    try:
        import yaml
    except ImportError as exc:
        raise SystemExit(
            f"--target-file requires PyYAML; install with `uv sync --group verify`. ({exc})"
        ) from exc
    data = yaml.safe_load(target_file.read_text(encoding="utf-8")) or {}
    if not isinstance(data, dict):
        raise SystemExit("--target-file: top-level must be a mapping")
    return data


def cmd_score_paths(args: argparse.Namespace) -> int:
    paths = _read_paths(args.input, args.stdin)
    out.info(f"Loaded {len(paths)} paths")
    clf = _build_path_classifier(args)
    out.debug(
        f"path models: windows={args.windows_model_dir or 'default'}, "
        f"linux={args.linux_model_dir or 'default'}"
    )
    results = clf.score_batch(paths)
    records = [
        {
            "path": r.path,
            "probability": round(r.probability, 4),
            "tier": r.tier,
        }
        for r in results
    ]
    _emit_jsonl(records, args.output)
    n_tiered = sum(1 for r in results if r.tier is not None)
    out.info(f"Wrote {len(records)} records ({n_tiered} tier-flagged)")
    return 0


def cmd_scan_files(args: argparse.Namespace) -> int:
    # Defer the content-classifier import to here so ``score-paths``
    # users don't pay for it.
    from sharesift.content import ContentClassifier

    paths = _read_paths(args.input, args.stdin)
    out.info(f"Loaded {len(paths)} paths")
    out.debug(
        f"content_model_dir={args.content_model_dir or 'default'}, "
        f"device={args.device or 'auto'}, "
        f"max_snippet_bytes={args.max_snippet_bytes}, "
        f"force_content={args.force_content}"
    )

    items: list[tuple[str, str | None]] = []
    for p_str in paths:
        p = Path(p_str)
        if not p.exists() or not p.is_file():
            items.append((p_str, None))
            continue
        try:
            content = p.read_text(encoding="utf-8", errors="replace")
        except OSError:
            items.append((p_str, None))
            continue
        if args.max_snippet_bytes and len(content) > args.max_snippet_bytes:
            content = content[: args.max_snippet_bytes]
        items.append((p_str, content))

    n_with_content = sum(1 for _, c in items if c is not None)
    out.info(f"{n_with_content}/{len(items)} files accessible for content scan")

    scanner = Scanner(
        path_classifier=_build_path_classifier(args),
        content_classifier=ContentClassifier(
            model_dir=args.content_model_dir,
            device=args.device,
        ),
    )
    results = scanner.scan_batch(items, force_content=args.force_content)
    records = [r.as_record(include_debug=args.debug) for r in results]
    _emit_jsonl(records, args.output)

    n_yes = sum(1 for r in results if r.content_check == "yes")
    n_no = sum(1 for r in results if r.content_check == "no")
    n_skipped = sum(1 for r in results if r.content_check is None)
    out.info(
        f"Wrote {len(records)} records "
        f"(content: {n_yes} yes / {n_no} no / {n_skipped} skipped)"
    )
    return 0


def cmd_retrain_ranker(args: argparse.Namespace) -> int:
    """Thin wrapper around ``tools/retrain_ranker.py`` for v0.17 active learning."""
    import sys as _sys

    sys_path_extra = str(Path(__file__).resolve().parents[2] / "tools")
    if sys_path_extra not in _sys.path:
        _sys.path.insert(0, sys_path_extra)
    import retrain_ranker

    argv = [
        "--hits", str(args.hits),
        "--labels", str(args.labels),
        "--output", str(args.output),
    ]
    if args.base_ranker:
        argv.extend(["--base-ranker", str(args.base_ranker)])
    if args.n_estimators:
        argv.extend(["--n-estimators", str(args.n_estimators)])
    return retrain_ranker.main(argv)


def cmd_render_report(args: argparse.Namespace) -> int:
    from sharesift.report import render_html

    records = _read_jsonl(args.input, args.stdin)
    out.info(f"Loaded {len(records)} records")
    report_path = render_html(records, args.output, title=args.title)
    out.info(f"Wrote {report_path} ({report_path.stat().st_size // 1024} KB)")
    return 0


def cmd_verify(args: argparse.Namespace) -> int:
    from sharesift.verify import VerifyConfig, verify_records

    records = _read_jsonl(args.input, args.stdin)
    out.info(f"Loaded {len(records)} hit records")
    out.debug(
        f"rate_limit={args.rate_limit}, timeout={args.timeout}, "
        f"dry_run={args.dry_run}, target_file={args.target_file}, "
        f"only={args.only}"
    )

    config = VerifyConfig(
        dry_run=args.dry_run,
        rate_limit_per_sec=args.rate_limit,
        timeout_sec=args.timeout,
        only=set(args.only) if args.only else None,
        targets=_parse_target_file(args.target_file),
        confirm_banner=not args.no_banner,
    )

    if not args.dry_run and config.confirm_banner:
        # Safety banner — warn() so --quiet can't suppress it.
        out.warn(
            "[!] Live verification will generate authentication attempts "
            "against external services."
        )
        out.warn("    Use --dry-run first. Press Ctrl+C in 3s to abort.")
        try:
            import time as _time

            _time.sleep(3)
        except KeyboardInterrupt:
            out.warn("Aborted by user.")
            return 1

    verified = verify_records(records, config)
    _emit_jsonl(verified, args.output)

    by_status: dict[str, int] = {}
    for r in verified:
        s = r.get("verification_status", "skipped")
        by_status[s] = by_status.get(s, 0) + 1
    summary = ", ".join(f"{k}={v}" for k, v in sorted(by_status.items()))
    out.info(f"Verification summary: {summary}")
    return 0


def _add_input_args(p: argparse.ArgumentParser) -> None:
    g = p.add_mutually_exclusive_group(required=True)
    g.add_argument("--input", type=Path, help="File of paths (one per line)")
    g.add_argument("--stdin", action="store_true", help="Read paths from stdin")
    p.add_argument(
        "--output",
        type=Path,
        default=None,
        help="Output JSONL file (default: stdout)",
    )


def _add_path_model_args(p: argparse.ArgumentParser) -> None:
    """v0.5: PathClassifier is a router over two per-shape models."""
    p.add_argument(
        "--windows-model-dir",
        type=Path,
        default=None,
        help="Override Windows (UNC) path-classifier model directory.",
    )
    p.add_argument(
        "--linux-model-dir",
        type=Path,
        default=None,
        help="Override Linux (Unix) path-classifier model directory.",
    )


def _build_path_classifier(args: argparse.Namespace) -> "PathClassifier":
    from sharesift.path import DEFAULT_LINUX_MODEL_DIR, DEFAULT_WINDOWS_MODEL_DIR

    return PathClassifier(
        windows_model_dir=args.windows_model_dir or DEFAULT_WINDOWS_MODEL_DIR,
        linux_model_dir=args.linux_model_dir or DEFAULT_LINUX_MODEL_DIR,
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="sharesift",
        description=(
            "ML-augmented SMB share hunter — Snaffler successor with "
            "LightGBM path triage + Qwen3-1.7B LoRA content classifier."
        ),
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )
    verbosity_group = parser.add_mutually_exclusive_group()
    verbosity_group.add_argument(
        "-q", "--quiet",
        action="store_true",
        help="Suppress progress and info messages on stderr; errors still print.",
    )
    verbosity_group.add_argument(
        "-v", "--verbose",
        action="store_true",
        help=(
            "Emit debug detail (model dirs, batch sizes, timings) and "
            "re-enable 3rd-party deprecation warnings."
        ),
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    # score-paths
    sp = sub.add_parser(
        "score-paths",
        help="Stage-1 path triage only (fast, no content access needed).",
    )
    _add_input_args(sp)
    _add_path_model_args(sp)
    sp.set_defaults(func=cmd_score_paths)

    # scan-files
    sf = sub.add_parser(
        "scan-files",
        help="Stage-1 + Stage-2 scan of locally-accessible files.",
    )
    _add_input_args(sf)
    _add_path_model_args(sf)
    sf.add_argument(
        "--content-model-dir",
        type=Path,
        default=None,
        help="Override content-classifier model directory.",
    )
    sf.add_argument(
        "--device",
        choices=["cuda", "cpu"],
        default=None,
        help="Force device for content classifier (default: auto-detect).",
    )
    sf.add_argument(
        "--max-snippet-bytes",
        type=int,
        default=4096,
        help="Cap content snippet size (default 4096).",
    )
    sf.add_argument(
        "--force-content",
        action="store_true",
        help="Run content scan even on paths the path stage didn't flag.",
    )
    sf.add_argument(
        "--debug",
        action="store_true",
        help="Include raw model responses in output records.",
    )
    sf.set_defaults(func=cmd_scan_files)

    # verify
    vf = sub.add_parser(
        "verify",
        help="Live-verify credentials extracted from scan-files output.",
    )
    vf.add_argument(
        "--input",
        type=Path,
        help="hits.jsonl from scan-files (or pass via --stdin)",
    )
    vf.add_argument(
        "--stdin",
        action="store_true",
        help="Read hit records from stdin (JSONL)",
    )
    vf.add_argument(
        "--output",
        type=Path,
        default=None,
        help="Output JSONL (default stdout)",
    )
    vf.add_argument(
        "--target-file",
        type=Path,
        default=None,
        help="YAML file with network-verifier targets (ssh/smb/ldap/databricks)",
    )
    vf.add_argument(
        "--rate-limit",
        type=float,
        default=1.0,
        help="Global rate cap (req/sec, default 1.0)",
    )
    vf.add_argument(
        "--timeout",
        type=float,
        default=10.0,
        help="Per-request timeout (seconds, default 10)",
    )
    vf.add_argument(
        "--dry-run",
        action="store_true",
        help="Print what would be verified, send no traffic",
    )
    vf.add_argument(
        "--only",
        action="append",
        default=None,
        help=(
            "Restrict to specific credential types (repeatable, e.g. "
            "--only anthropic_api_key --only github_pat_classic)"
        ),
    )
    vf.add_argument(
        "--no-banner",
        action="store_true",
        help="Skip the 3s safety banner (CI / scripted use)",
    )
    vf.set_defaults(func=cmd_verify)

    # render-report
    rr = sub.add_parser(
        "render-report",
        help="Render verified.jsonl (or hits.jsonl) into a self-contained HTML report.",
    )
    rr.add_argument("--input", type=Path, help="JSONL records (or use --stdin)")
    rr.add_argument("--stdin", action="store_true", help="Read records from stdin")
    rr.add_argument(
        "--output",
        type=Path,
        default=Path("report.html"),
        help="Output HTML path (default report.html)",
    )
    rr.add_argument(
        "--title",
        type=str,
        default=None,
        help="Title for the report (e.g. 'Acme Q3 2026 engagement')",
    )
    rr.set_defaults(func=cmd_render_report)

    # retrain-ranker
    rt = sub.add_parser(
        "retrain-ranker",
        help="Retrain the LightGBM ranker on labels.jsonl exported from the HTML report.",
    )
    rt.add_argument("--hits", type=Path, required=True, help="hits.jsonl from scan-files")
    rt.add_argument(
        "--labels", type=Path, required=True, help="labels.jsonl from the HTML report"
    )
    rt.add_argument(
        "--base-ranker",
        type=Path,
        default=None,
        help="Production ranker to compare against (metadata only in v0.17)",
    )
    rt.add_argument("--output", type=Path, required=True, help="Output .joblib path")
    rt.add_argument(
        "--n-estimators", type=int, default=200, help="LightGBM n_estimators (default 200)"
    )
    rt.set_defaults(func=cmd_retrain_ranker)

    args = parser.parse_args(argv)
    if args.quiet:
        verbosity = Verbosity.QUIET
    elif args.verbose:
        verbosity = Verbosity.VERBOSE
    else:
        verbosity = Verbosity.NORMAL
    out.configure(verbosity=verbosity)
    _install_warning_filters(verbosity)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
