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
import time
import warnings
from pathlib import Path

from sharesift import __version__
from sharesift._output import Verbosity, out
from sharesift.path import PathClassifier
from sharesift.pipeline import Scanner

# v0.35: subcommand set used by the implicit-scan argv rewriter to
# distinguish "the user typed a subcommand" from "the user typed a
# share/target as the first positional." Update if subcommands change.
_KNOWN_SUBCOMMANDS = frozenset({
    "scan",
    "score-paths",
    "scan-files",
    "verify",
    "render-report",
    "retrain-ranker",
    "to-snaffler-tsv",
})


def _rewrite_argv_for_implicit_scan(argv: list[str]) -> list[str]:
    """v0.35: when the first non-flag arg looks like an SMB target,
    inject ``scan`` so argparse dispatches to that subcommand.

    Local filesystem paths are NOT auto-detected — too easy to
    confuse with a filename like ``report.jsonl``. SMB-shaped targets
    (``//host/share``, ``\\\\host\\share``) are unambiguous.

    Any explicit subcommand wins; the rewriter is a no-op when the
    user typed one.
    """
    from sharesift.share import is_smb_target

    for i, arg in enumerate(argv):
        if arg.startswith("-"):
            continue
        if arg in _KNOWN_SUBCOMMANDS:
            return argv
        if is_smb_target(arg):
            return argv[:i] + ["scan"] + argv[i:]
        return argv
    return argv


def _add_smb_auth_args(p: argparse.ArgumentParser) -> None:
    """v0.35: add nxc-style SMB auth flags to a subparser.

    Flag set deliberately mirrors ``netexec`` so muscle-memory
    transfers. ``-H`` is "hash" (PtH), never "host" — target host
    comes from the positional ``target``.
    """
    p.add_argument("-u", "--user", help="Username for SMB auth.")
    p.add_argument(
        "-p", "--password", help="Password for NTLM auth."
    )
    p.add_argument(
        "-H", "--hash",
        help=(
            "NT hash or ``LM:NT`` for Pass-the-Hash. Bare NT-only "
            "form fills LM with the standard blank hash."
        ),
    )
    p.add_argument(
        "-k", "--kerberos", action="store_true",
        help="Use Kerberos auth (ticket read from ``KRB5CCNAME``).",
    )
    p.add_argument(
        "--use-kcache", action="store_true",
        help="Alias for ``--kerberos``; matches netexec convention.",
    )
    p.add_argument(
        "-d", "--domain", help="Auth domain (qualifies the user as DOMAIN\\\\user)."
    )
    p.add_argument(
        "--no-pass", "--anonymous", dest="anonymous", action="store_true",
        help="Null session / anonymous auth.",
    )
    p.add_argument(
        "--encrypt", dest="encrypt", action="store_true", default=True,
        help="SMB3 message encryption (default on).",
    )
    p.add_argument(
        "--no-encrypt", dest="encrypt", action="store_false",
        help="Disable SMB3 encryption (legacy Samba configs).",
    )
    p.add_argument(
        "--check", action="store_true",
        help=(
            "Pre-flight: auth + tree-connect, then exit. No walk, "
            "no content scan. Confirm creds before committing to a "
            "long scan."
        ),
    )


def _build_auth_from_args(args: argparse.Namespace):
    """Build :class:`sharesift.share.Auth` from CLI args, or return
    None if no auth flags were set."""
    from sharesift.share import Auth

    kerberos = bool(getattr(args, "kerberos", False) or getattr(args, "use_kcache", False))
    password = getattr(args, "password", None)
    hash_ = getattr(args, "hash", None)
    anonymous = bool(getattr(args, "anonymous", False))

    if not any([password, hash_, kerberos, anonymous]):
        return None

    return Auth(
        user=getattr(args, "user", None),
        password=password,
        hash=hash_,
        kerberos=kerberos,
        domain=getattr(args, "domain", None),
        anonymous=anonymous,
    )


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
    start = time.monotonic()
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
    out.summary({
        "command": "score-paths",
        "version": __version__,
        "elapsed_s": round(time.monotonic() - start, 3),
        "input_count": len(paths),
        "output_count": len(records),
        "tier_flagged": n_tiered,
        "output_path": str(args.output) if args.output else None,
        "exit_code": 0,
    })
    return 0


def cmd_scan_files(args: argparse.Namespace) -> int:
    # Defer the content-classifier import to here so ``score-paths``
    # users don't pay for it.
    from sharesift.content import ContentClassifier

    start = time.monotonic()
    paths = _read_paths(args.input, args.stdin)
    out.info(f"Loaded {len(paths)} paths")
    out.debug(
        f"content_model_dir={args.content_model_dir or 'default'}, "
        f"device={args.device or 'auto'}, "
        f"max_snippet_bytes={args.max_snippet_bytes}, "
        f"force_content={args.force_content}"
    )

    # v0.20: route through load_content so PDFs (via pypdf) and the
    # base64 preprocessor become available. PDFs that previously
    # returned UnicodeDecodeError (then empty) now extract text.
    # v0.35 Sprint 3.5: when ``share`` is provided (e.g. cmd_scan
    # threading an SmbShare), content reads go through the share
    # interface so SMB targets work end-to-end.
    from sharesift.extract import load_content, load_content_from_share

    items: list[tuple[str, str | None]] = []
    cap = args.max_snippet_bytes or 1_048_576
    share_obj = getattr(args, "_share", None)
    for p_str in paths:
        if share_obj is not None:
            content = load_content_from_share(share_obj, p_str, max_bytes=cap)
        else:
            content = load_content(Path(p_str), max_bytes=cap)
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
    out.summary({
        "command": "scan-files",
        "version": __version__,
        "elapsed_s": round(time.monotonic() - start, 3),
        "input_count": len(paths),
        "output_count": len(records),
        "content_yes": n_yes,
        "content_no": n_no,
        "content_skipped": n_skipped,
        "model": {
            "content_model_dir": (
                str(args.content_model_dir) if args.content_model_dir else None
            ),
            "device": args.device,
        },
        "output_path": str(args.output) if args.output else None,
        "exit_code": 0,
    })
    return 0


def _ns(**kwargs: object) -> argparse.Namespace:
    """Build an argparse.Namespace from kwargs — used by cmd_scan to call
    existing subcommand handlers without having argparse parse a synthetic
    argv. Tighter than the alternatives (subprocess, full _run_* refactor)
    for the v0.18 scope."""
    return argparse.Namespace(**kwargs)


def cmd_scan(args: argparse.Namespace) -> int:
    """One-shot pipeline: enumerate → score-paths → scan-files → verify → report.

    Each stage prints a ``[N/5] ...`` banner. ``--skip-verify`` and
    ``--skip-report`` drop the late stages. The sub-handlers each emit
    their own JSON summary at end-of-run — we silence that during sub-calls
    and emit one combined summary here, so ``sharesift scan --json``
    produces one block, not five.
    """
    start = time.monotonic()

    # v0.35: target resolution. Positional ``target`` (the canonical
    # form) wins over the legacy ``--share`` flag. SMB-shaped targets
    # build an ``SmbShare`` with the auth flag bundle; everything
    # else falls through to the v0.18 ``LocalShare`` / file-list path.
    from sharesift.share import (
        LocalShare,
        SmbShare,
        is_smb_target,
        parse_target,
    )

    target_str: str | None = args.target
    if target_str is None and args.share is not None:
        target_str = str(args.share)
    if target_str is None:
        raise SystemExit(
            "scan: target required — pass a UNC/path as positional or "
            "use the legacy --share flag"
        )
    if args.target and args.share:
        raise SystemExit(
            "scan: target and --share are mutually exclusive"
        )

    is_smb = is_smb_target(target_str)
    smb_target = parse_target(target_str) if is_smb else None
    smb_share: SmbShare | None = None
    if is_smb:
        auth = _build_auth_from_args(args)
        if auth is None:
            raise SystemExit(
                "SMB target requires auth — pass one of: "
                "-u/-p (password), -H (PtH), -k/--use-kcache (Kerberos), "
                "or --no-pass for anonymous"
            )
        smb_share = SmbShare(smb_target, auth, encrypt=args.encrypt)

    # ``--check`` short-circuits: auth + tree-connect + exit.
    if args.check:
        if not is_smb:
            raise SystemExit("--check only applies to SMB targets")
        try:
            with smb_share:
                pass  # __enter__ does Connection + Session + TreeConnect
            out.info(f"auth ok; tree-connected to {smb_share.root}")
            return 0
        except Exception as exc:
            out.error(f"auth failed: {exc}")
            return 1

    # Output dir default.
    output_dir: Path | None = args.output_dir
    if output_dir is None:
        if is_smb:
            output_dir = Path(f"./sharesift-{smb_target.host}-{smb_target.share}")
        else:
            output_dir = Path(f"./sharesift-{Path(target_str).name}")
    output_dir.mkdir(parents=True, exist_ok=True)

    # Stage 0: enumerate. The Share for content reads is decided
    # here: SmbShare for UNC targets, LocalShare for local paths.
    # The SMB session stays open through cmd_scan_files so reads
    # reuse the connection — closed in the ``finally`` at the end
    # of cmd_scan.
    files_path = output_dir / "files.txt"
    share_for_reads: SmbShare | LocalShare | None = None
    if is_smb:
        share_for_reads = smb_share
        out.info(f"[1/5] enumerating files under {smb_share.root}")
        entries = list(smb_share.walk())
        files_path.write_text(
            "\n".join(e.path for e in entries) + "\n", encoding="utf-8"
        )
        n_enumerated = len(entries)
    else:
        share_path = Path(target_str)
        if share_path.is_dir():
            share_for_reads = LocalShare(share_path)
            out.info(f"[1/5] enumerating files under {share_path}")
            entries = list(share_for_reads.walk())
            files_path.write_text(
                "\n".join(e.path for e in entries) + "\n", encoding="utf-8"
            )
            n_enumerated = len(entries)
        elif share_path.is_file():
            # Treat as a pre-existing file list. Reads go through a
            # rootless LocalShare so absolute paths in the file list
            # work without per-file Path() construction.
            share_for_reads = LocalShare()
            out.info(f"[1/5] using file list {share_path}")
            files_path.write_text(
                share_path.read_text(encoding="utf-8"), encoding="utf-8"
            )
            n_enumerated = sum(
                1 for line in files_path.read_text(encoding="utf-8").splitlines()
                if line.strip()
            )
        else:
            raise SystemExit(f"target: {share_path} does not exist")
    out.debug(f"enumerated {n_enumerated} files → {files_path}")

    # Silence sub-handler summaries — we emit one combined summary at the end.
    was_json = out.json_enabled
    if was_json:
        out.configure(verbosity=out.verbosity, json=False)

    paths_path = output_dir / "paths.jsonl"
    hits_path = output_dir / "hits.jsonl"
    report_input = hits_path
    verified_path: Path | None = None
    report_path: Path | None = None
    stages_run: list[str] = ["enumerate", "score-paths", "scan-files"]

    try:
        # Stage 1: score-paths
        out.info(f"[2/5] path triage → {paths_path}")
        cmd_score_paths(_ns(
            input=files_path,
            stdin=False,
            output=paths_path,
            windows_model_dir=args.windows_model_dir,
            linux_model_dir=args.linux_model_dir,
        ))

        # Stage 2: scan-files. Share-aware via ``_share`` namespace
        # attribute — cmd_scan_files routes reads through the share
        # when set (so SMB content reads use the live session).
        out.info(f"[3/5] content scan → {hits_path}")
        cmd_scan_files(_ns(
            input=files_path,
            stdin=False,
            output=hits_path,
            windows_model_dir=args.windows_model_dir,
            linux_model_dir=args.linux_model_dir,
            content_model_dir=args.content_model_dir,
            device=args.device,
            max_snippet_bytes=args.max_snippet_bytes,
            force_content=args.force_content,
            debug=False,
            _share=share_for_reads,
        ))

        # Stage 3: verify (optional)
        if not args.skip_verify:
            verified_path = output_dir / "verified.jsonl"
            out.info(f"[4/5] verify → {verified_path}")
            cmd_verify(_ns(
                input=hits_path,
                stdin=False,
                output=verified_path,
                target_file=args.target_file,
                rate_limit=args.rate_limit,
                timeout=args.timeout,
                dry_run=args.dry_run,
                only=None,
                no_banner=True,  # one-shot is non-interactive; banner skipped
            ))
            report_input = verified_path
            stages_run.append("verify")

        # Stage 4: render-report (optional)
        if not args.skip_report:
            report_path = output_dir / "report.html"
            out.info(f"[5/5] report → {report_path}")
            cmd_render_report(_ns(
                input=report_input,
                stdin=False,
                output=report_path,
                title=args.title,
            ))
            stages_run.append("render-report")
    finally:
        if was_json:
            out.configure(verbosity=out.verbosity, json=True)
        # v0.35: close the SMB session held open across walk + reads.
        if is_smb and smb_share is not None:
            smb_share.close()

    out.summary({
        "command": "scan",
        "version": __version__,
        "elapsed_s": round(time.monotonic() - start, 3),
        "target": target_str,
        "target_kind": "smb" if is_smb else "local",
        "output_dir": str(output_dir),
        "input_count": n_enumerated,
        "stages_run": stages_run,
        "intermediates": {
            "files": str(files_path),
            "paths": str(paths_path),
            "hits": str(hits_path),
            "verified": str(verified_path) if verified_path else None,
            "report": str(report_path) if report_path else None,
        },
        "exit_code": 0,
    })
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


def cmd_to_snaffler_tsv(args: argparse.Namespace) -> int:
    """v0.36 step 4: convert ``hits.jsonl`` to Snaffler-compatible TSV.

    Operator workflow: run a scan, then pipe the JSONL output through
    this command to produce TSV that SnafflerParser / Efflanrs /
    Parsler / snafflepy can ingest unchanged.

        sharesift //host/share -u u -p p
        sharesift to-snaffler-tsv < ./sharesift-host-share/hits.jsonl \\
            > scan.snaf.tsv
    """
    from sharesift.output import iter_snaffler_tsv_lines

    start = time.monotonic()
    records = _read_jsonl(args.input, args.stdin)
    out.debug(f"Loaded {len(records)} records")

    sink = sys.stdout if args.output is None else open(args.output, "w", encoding="utf-8")
    try:
        n = 0
        for line in iter_snaffler_tsv_lines(records):
            sink.write(line + "\n")
            n += 1
    finally:
        if sink is not sys.stdout:
            sink.close()

    out.summary({
        "command": "to-snaffler-tsv",
        "version": __version__,
        "elapsed_s": round(time.monotonic() - start, 3),
        "input_count": len(records),
        "output_count": n,
        "output_path": str(args.output) if args.output else None,
        "exit_code": 0,
    })
    return 0


def cmd_render_report(args: argparse.Namespace) -> int:
    from sharesift.report import render_html

    start = time.monotonic()
    records = _read_jsonl(args.input, args.stdin)
    out.info(f"Loaded {len(records)} records")
    report_path = render_html(records, args.output, title=args.title)
    size_kb = report_path.stat().st_size // 1024
    out.info(f"Wrote {report_path} ({size_kb} KB)")
    out.summary({
        "command": "render-report",
        "version": __version__,
        "elapsed_s": round(time.monotonic() - start, 3),
        "input_count": len(records),
        "output_path": str(report_path),
        "output_size_kb": size_kb,
        "title": args.title,
        "exit_code": 0,
    })
    return 0


def cmd_verify(args: argparse.Namespace) -> int:
    from sharesift.verify import VerifyConfig, verify_records

    start = time.monotonic()
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
    out.summary({
        "command": "verify",
        "version": __version__,
        "elapsed_s": round(time.monotonic() - start, 3),
        "input_count": len(records),
        "output_count": len(verified),
        "by_status": by_status,
        "dry_run": args.dry_run,
        "output_path": str(args.output) if args.output else None,
        "exit_code": 0,
    })
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
    parser.add_argument(
        "--json",
        action="store_true",
        help=(
            "Emit a structured end-of-run JSON summary on stderr. "
            "Independent of -q/-v; stdout stays pure JSONL."
        ),
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    # scan (one-shot pipeline)
    sc = sub.add_parser(
        "scan",
        help=(
            "One-shot pipeline: enumerate → score-paths → scan-files → "
            "verify → render-report. The recommended entry point."
        ),
    )
    sc.add_argument(
        "target",
        nargs="?",
        default=None,
        help=(
            "Scan target — SMB UNC (``//host/share`` or "
            "``\\\\host\\share``) or local path. The recommended "
            "canonical form; pass auth flags alongside for SMB."
        ),
    )
    sc.add_argument(
        "--share",
        type=Path,
        default=None,
        help=(
            "(Legacy v0.18 alias) directory to scan, or a file "
            "listing paths. Use the positional target instead."
        ),
    )
    sc.add_argument(
        "--output-dir",
        type=Path,
        default=None,
        help=(
            "Directory where intermediates land. Defaults to "
            "``./sharesift-<host>-<share>/`` for SMB targets or "
            "``./sharesift-<basename>/`` for local paths."
        ),
    )
    _add_smb_auth_args(sc)
    sc.add_argument(
        "--skip-verify",
        action="store_true",
        help="Skip the live-credential verification stage.",
    )
    sc.add_argument(
        "--skip-report",
        action="store_true",
        help="Skip the HTML report rendering stage.",
    )
    _add_path_model_args(sc)
    sc.add_argument("--content-model-dir", type=Path, default=None)
    sc.add_argument("--device", choices=["cuda", "cpu"], default=None)
    sc.add_argument("--max-snippet-bytes", type=int, default=4096)
    sc.add_argument("--force-content", action="store_true")
    sc.add_argument(
        "--target-file",
        type=Path,
        default=None,
        help="YAML file with verifier targets (required unless --skip-verify).",
    )
    sc.add_argument("--rate-limit", type=float, default=1.0)
    sc.add_argument("--timeout", type=float, default=10.0)
    sc.add_argument("--dry-run", action="store_true")
    sc.add_argument(
        "--title",
        type=str,
        default=None,
        help="Title for the HTML report.",
    )
    sc.set_defaults(func=cmd_scan)

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

    # v0.36 step 4: to-snaffler-tsv
    ts = sub.add_parser(
        "to-snaffler-tsv",
        help=(
            "Convert a hits.jsonl file to Snaffler-compatible TSV that "
            "SnafflerParser / Efflanrs / Parsler / snafflepy ingest "
            "unchanged. Reads stdin or --input; writes stdout or --output."
        ),
    )
    ts.add_argument("--input", type=Path, help="hits.jsonl path (or use --stdin)")
    ts.add_argument("--stdin", action="store_true", help="Read JSONL from stdin")
    ts.add_argument("--output", type=Path, default=None, help="Output TSV path (default stdout)")
    ts.set_defaults(func=cmd_to_snaffler_tsv)

    # v0.35: implicit-scan dispatch. If the first non-flag positional
    # looks like an SMB target, inject ``scan`` so argparse routes there.
    if argv is None:
        argv = sys.argv[1:]
    argv = _rewrite_argv_for_implicit_scan(argv)

    args = parser.parse_args(argv)
    if args.quiet:
        verbosity = Verbosity.QUIET
    elif args.verbose:
        verbosity = Verbosity.VERBOSE
    else:
        verbosity = Verbosity.NORMAL
    out.configure(verbosity=verbosity, json=args.json)
    _install_warning_filters(verbosity)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
