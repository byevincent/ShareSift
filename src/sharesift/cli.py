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
    "batch",
    "discover",
    "query",
    "sort",
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
    # v0.44: apply the filename-frequency dedup penalty so
    # production output matches what the eval harness has been
    # using since v0.22. Top-K precision on MSF3 was 0.20 without
    # this, 0.0 with the raw classifier output. Records gain
    # ``rank_score`` and ``filename_frequency`` fields; the
    # original ``probability`` and ``tier`` are preserved.
    from sharesift.ranking import apply_dedup_penalty
    apply_dedup_penalty(records)
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
    # v0.38: parallel reads via thread pool for SMB targets. Lab tested
    # safe with smbprotocol up to 8 workers on one Connection; default
    # 4 is the sweet spot (diminishing returns above, credit-flow
    # failures at 16+). Local-FS reads skip threading — overhead
    # exceeds any benefit on sub-millisecond opens.
    n_threads = max(1, getattr(args, "read_threads", 4) or 1)
    use_threads = share_obj is not None and n_threads > 1 and len(paths) > 1

    # v0.40: --max-file-size cap on raw bytes read from the share.
    # Already-parsed by cmd_scan into max_file_size_bytes (a plain
    # int); falls back to DEFAULT_MAX_READ_BYTES from extract.py.
    from sharesift.extract import DEFAULT_MAX_READ_BYTES
    max_read = getattr(args, "max_file_size_bytes", None) or DEFAULT_MAX_READ_BYTES

    if share_obj is None:
        for p_str in paths:
            items.append((p_str, load_content(Path(p_str), max_bytes=cap)))
    elif not use_threads:
        for p_str in paths:
            items.append((p_str, load_content_from_share(
                share_obj, p_str, max_bytes=cap, max_read_bytes=max_read,
            )))
    else:
        from concurrent.futures import ThreadPoolExecutor

        def _read(p: str) -> tuple[str, str | None]:
            return p, load_content_from_share(
                share_obj, p, max_bytes=cap, max_read_bytes=max_read,
            )

        out.debug(f"parallel reads: {n_threads} threads, max_file_size={max_read}")
        with ThreadPoolExecutor(max_workers=n_threads) as ex:
            items = list(ex.map(_read, paths))

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


_SIZE_SUFFIXES = {"": 1, "k": 1024, "m": 1024**2, "g": 1024**3}


def _parse_size(text: str | None) -> int | None:
    """Parse a human-readable size like ``100K``, ``5M``, ``1G``,
    or a bare int. Returns bytes. None passes through."""
    if text is None:
        return None
    t = text.strip().lower()
    if not t:
        return None
    suffix = ""
    if t[-1] in _SIZE_SUFFIXES:
        suffix = t[-1]
        t = t[:-1]
    try:
        return int(float(t) * _SIZE_SUFFIXES[suffix])
    except (KeyError, ValueError):
        raise SystemExit(
            f"invalid size: {text!r} — use N, NK, NM, or NG"
        )


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

    # v0.40: --stealth preset wires OpSec-conscious defaults.
    # Operator can override individual settings by passing them
    # explicitly alongside --stealth.
    if getattr(args, "stealth", False):
        if not getattr(args, "max_file_size", None):
            args.max_file_size = "256K"
        if getattr(args, "read_threads", None) is None or args.read_threads == 4:
            args.read_threads = 1
        # encrypt is already True by default; --stealth doesn't undo --no-encrypt

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

    # ``--check`` short-circuits: auth + tree-connect + share-access
    # probe + exit. The probe is two cheap CREATE round-trips; closes
    # Snaffler #184 by reporting accurate R/W status (Snaffler reports
    # writable shares as R).
    if args.check:
        if not is_smb:
            raise SystemExit("--check only applies to SMB targets")
        try:
            with smb_share as live:
                access = live.probe_share_access()
            out.info(f"auth ok; tree-connected to {smb_share.root} [{access.display}]")
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
        # v0.36 step 3: probe share-level R/W (Snaffler #184). Cheap
        # 2 round-trips, runs before walk so the summary always has
        # the verdict even on empty shares.
        share_access = smb_share.probe_share_access()
        out.info(f"share access: {share_access.display}")
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

    # v0.43: --resume — skip files already in the engagement DB.
    # Requires --db; without --db, --resume errors. Files are recorded
    # in the DB during cmd_scan_files so a subsequent --resume run on
    # the same engagement skips them.
    engagement_db = None
    db_host_share: tuple[str, str] | None = None
    if getattr(args, "db", None):
        from sharesift.engagement import EngagementDB
        engagement_db = EngagementDB(args.db)
        if is_smb:
            db_host_share = (smb_target.host, smb_target.share)
            engagement_db.record_host(
                smb_target.host, alive=True, port=smb_target.port,
            )
            engagement_db.record_share(
                smb_target.host, smb_target.share, type_="disk",
            )
        else:
            db_host_share = ("local", Path(target_str).name)
        out.info(f"engagement db: {args.db}")

    if getattr(args, "resume", False):
        if engagement_db is None or db_host_share is None:
            raise SystemExit("--resume requires --db")
        seen = engagement_db.seen_files(*db_host_share)
        if seen:
            raw_paths = files_path.read_text(encoding="utf-8").splitlines()
            host, share = db_host_share
            if is_smb:
                prefix = rf"\\{host}\{share}\\"
            else:
                prefix = str(Path(target_str)) + "/"
            kept = []
            n_skipped = 0
            for p in raw_paths:
                if not p.strip():
                    continue
                rel = p[len(prefix):] if p.startswith(prefix) else p
                if rel in seen:
                    n_skipped += 1
                else:
                    kept.append(p)
            if n_skipped:
                files_path.write_text("\n".join(kept) + "\n", encoding="utf-8")
                out.info(f"  resume: skipping {n_skipped} files already in db; {len(kept)} new")
                n_enumerated = len(kept)

    # v0.40: noise-exclusion filtering. Default globs strip
    # Windows/System32/*.dll, node_modules/, .git/, etc. so the
    # path classifier doesn't waste budget on guaranteed-noise.
    from sharesift.share.exclusions import filter_paths

    if not getattr(args, "no_default_excludes", False) or getattr(args, "exclude_glob", None):
        raw_paths = files_path.read_text(encoding="utf-8").splitlines()
        raw_paths = [p for p in raw_paths if p.strip()]
        kept, n_excluded = filter_paths(
            raw_paths,
            extra_globs=getattr(args, "exclude_glob", None) or (),
            use_defaults=not getattr(args, "no_default_excludes", False),
        )
        if n_excluded:
            files_path.write_text("\n".join(kept) + "\n", encoding="utf-8")
            out.info(f"  excluded {n_excluded} noise files; {len(kept)} remain")
            n_enumerated = len(kept)

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
            read_threads=getattr(args, "read_threads", 4),
            max_file_size_bytes=_parse_size(getattr(args, "max_file_size", None)),
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
        # v0.43: persist walked files to engagement DB so --resume
        # works on the next run. Done in finally so even partial
        # progress is recoverable.
        if engagement_db is not None and db_host_share is not None:
            try:
                host, share = db_host_share
                if is_smb:
                    prefix = rf"\\{host}\{share}\\"
                else:
                    prefix = str(Path(target_str)) + "/"
                rel_paths: list[tuple[str, int | None]] = []
                if files_path.exists():
                    for p in files_path.read_text(encoding="utf-8").splitlines():
                        p = p.strip()
                        if not p:
                            continue
                        rel = p[len(prefix):] if p.startswith(prefix) else p
                        rel_paths.append((rel, None))
                n_recorded = engagement_db.record_files_bulk(host, share, rel_paths)
                if n_recorded:
                    out.debug(f"db: recorded {n_recorded} new files")
            except Exception as exc:
                out.warn(f"db record failed: {exc}")
            finally:
                engagement_db.close()

    out.summary({
        "command": "scan",
        "version": __version__,
        "elapsed_s": round(time.monotonic() - start, 3),
        "target": target_str,
        "target_kind": "smb" if is_smb else "local",
        "share_access": (
            smb_share.share_access.display
            if (is_smb and smb_share is not None and smb_share.share_access)
            else None
        ),
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


def cmd_query(args: argparse.Namespace) -> int:
    """v0.40: ad-hoc SQL queries against an engagement datastore.

    Operator workflow:

        sharesift query --db engagement.db --summary
        sharesift query --db engagement.db "SELECT host, share FROM shares WHERE can_write = 1"
        sharesift query --db engagement.db --preset live-creds

    Pre-baked presets cover the common engagement questions
    (Black/Red findings, writable shares, hosts with most hits).
    """
    from sharesift.engagement import EngagementDB

    import json as _json

    db = EngagementDB(args.db)
    try:
        if args.summary:
            summary = db.summary()
            if args.json:
                print(_json.dumps(summary, indent=2))
            else:
                for k, v in summary.items():
                    print(f"  {k:24} {v}")
            return 0

        if args.preset:
            sql = _PRESET_QUERIES.get(args.preset)
            if not sql:
                raise SystemExit(
                    f"unknown preset: {args.preset!r}. Known: "
                    + ", ".join(sorted(_PRESET_QUERIES.keys()))
                )
        elif args.sql:
            sql = args.sql
        else:
            raise SystemExit(
                "query: pass --summary, --preset NAME, or SQL as positional"
            )

        rows = db.query(sql)
        if not rows:
            out.info("0 rows")
            return 0

        if args.json:
            for row in rows:
                print(_json.dumps(dict(row)))
        else:
            cols = list(rows[0].keys())
            widths = {c: max(len(c), max(len(str(r[c])) for r in rows)) for c in cols}
            header = "  ".join(c.ljust(widths[c]) for c in cols)
            print(header)
            print("  ".join("-" * widths[c] for c in cols))
            for r in rows:
                print("  ".join(str(r[c]).ljust(widths[c]) for c in cols))
            out.info(f"({len(rows)} rows)")
        return 0
    finally:
        db.close()


_PRESET_QUERIES = {
    "live-creds": (
        "SELECT host, share, rel_path, rule, tier, snippet FROM hits "
        "WHERE tier IN ('Black', 'Red') ORDER BY tier, host, share"
    ),
    "writable-shares": (
        "SELECT host, share, type FROM shares WHERE can_write = 1 "
        "ORDER BY host, share"
    ),
    "hosts-by-hits": (
        "SELECT host, COUNT(*) AS hit_count FROM hits "
        "GROUP BY host ORDER BY hit_count DESC"
    ),
    "rules-by-hits": (
        "SELECT rule, COUNT(*) AS hit_count, COUNT(DISTINCT host) AS hosts "
        "FROM hits GROUP BY rule ORDER BY hit_count DESC LIMIT 30"
    ),
    "blacks": (
        "SELECT host, share, rel_path, rule, snippet FROM hits "
        "WHERE tier = 'Black' ORDER BY host, share"
    ),
}


def cmd_discover(args: argparse.Namespace) -> int:
    """v0.39 step 1: list shares on a remote SMB host.

    Composes with ``batch``:

        sharesift discover //10.10.10.5 -u u -p p > targets.txt
        sharesift batch --targets targets.txt -u u -p p \\
            --output-dir ./engagement

    Default output is one UNC per line for disk shares. Non-file
    shares (IPC, printer, device) are commented out so they pass
    through ``batch`` (which strips ``#`` comments) without
    triggering scans. Pass ``--all-types`` to include them
    uncommented.
    """
    start = time.monotonic()

    from sharesift.share.discovery import (
        enumerate_shares,
        expand_target_to_hosts,
        probe_smb_alive,
    )

    port = args.port or 445
    # Extract port from target if present (preserves CIDR parsing —
    # ``10.0.0.0/24:1445`` isn't valid but we tolerate ``host:port``).
    bare_target = args.target.lstrip("/\\").replace("\\", "/")
    if ":" in bare_target and "/" not in bare_target.partition(":")[0]:
        head, _, port_str = bare_target.partition(":")
        try:
            port = int(port_str.partition("/")[0])
            bare_target = head + ("/" + port_str.partition("/")[2] if "/" in port_str else "")
        except ValueError:
            pass

    hosts = expand_target_to_hosts(args.target)
    is_cidr = len(hosts) > 1

    auth = _build_auth_from_args(args)
    if auth is None:
        from sharesift.share import Auth
        auth = Auth(anonymous=True)

    if is_cidr:
        out.info(f"discover: {len(hosts)} hosts in {args.target}")
        # Concurrent TCP liveness probe — skip dead hosts before impacket
        from concurrent.futures import ThreadPoolExecutor
        with ThreadPoolExecutor(max_workers=min(32, len(hosts))) as ex:
            live_map = list(ex.map(
                lambda h: (h, probe_smb_alive(h, port=port)),
                hosts,
            ))
        live_hosts = [h for h, alive in live_map if alive]
        out.info(f"{len(live_hosts)}/{len(hosts)} hosts have SMB on :{port}")
    else:
        out.info(f"discover: {hosts[0]}:{port}")
        live_hosts = hosts

    total_shares = 0
    total_file_shares = 0
    hosts_succeeded = 0
    hosts_failed = 0

    import json as _json
    for host in live_hosts:
        try:
            shares = enumerate_shares(host, auth, port=port)
            hosts_succeeded += 1
        except SystemExit:
            # missing-extra error — re-raise; can't recover
            raise
        except Exception as exc:
            hosts_failed += 1
            if is_cidr:
                out.warn(f"  {host}: {type(exc).__name__}: {exc}")
            else:
                out.error(f"discover failed: {type(exc).__name__}: {exc}")
                return 1
            continue

        total_shares += len(shares)
        total_file_shares += sum(1 for s in shares if s.is_file_share())

        if args.format == "json":
            for s in shares:
                print(_json.dumps({
                    "host": host, "share": s.name,
                    "type": s.type, "comment": s.comment,
                    "unc": rf"\\{host}\{s.name}",
                }))
        else:
            for s in shares:
                comment_marker = "" if (s.is_file_share() or args.all_types) else "# "
                type_note = f"  # {s.type}" + (f" — {s.comment}" if s.comment else "")
                print(f"{comment_marker}//{host}/{s.name}{type_note}")

    out.summary({
        "command": "discover",
        "version": __version__,
        "elapsed_s": round(time.monotonic() - start, 3),
        "target": args.target,
        "port": port,
        "hosts_total": len(hosts),
        "hosts_live": len(live_hosts),
        "hosts_succeeded": hosts_succeeded,
        "hosts_failed": hosts_failed,
        "shares_total": total_shares,
        "shares_file_type": total_file_shares,
        "exit_code": 0,
    })
    return 0


def cmd_batch(args: argparse.Namespace) -> int:
    """v0.37 step 3: scan multiple shares listed in a targets file.

    Operator workflow:

        nxc smb 10.10.10.0/24 -u u -p p --shares | awk '...' > targets.txt
        sharesift batch --targets targets.txt -u user -p pass \\
            --output-dir ./engagement

    Each target gets its own subdirectory under ``--output-dir``
    (named after host+share). A top-level ``batch_summary.jsonl``
    records one record per target with the per-scan result.
    """
    start = time.monotonic()

    targets_text = args.targets.read_text(encoding="utf-8")
    targets = [
        line.strip()
        for line in targets_text.splitlines()
        if line.strip() and not line.strip().startswith("#")
    ]
    if not targets:
        raise SystemExit(f"batch: no targets in {args.targets}")

    base_output = args.output_dir
    base_output.mkdir(parents=True, exist_ok=True)
    summary_path = base_output / "batch_summary.jsonl"
    out.info(f"batch: {len(targets)} target(s); summary → {summary_path}")

    # v0.40: optional engagement DB. When --db is set, populate
    # hosts / shares / hits as targets process so the operator gets
    # a queryable .sharesift.db at the end (or to resume from).
    engagement_db = None
    if getattr(args, "db", None):
        from sharesift.engagement import EngagementDB
        engagement_db = EngagementDB(args.db)
        out.info(f"engagement db: {args.db}")

    succeeded = 0
    failed = 0
    with summary_path.open("w", encoding="utf-8") as sink:
        for i, target in enumerate(targets, 1):
            out.info(f"[{i}/{len(targets)}] {target}")
            # Compute per-target subdir
            from sharesift.share import is_smb_target, parse_target

            if is_smb_target(target):
                t = parse_target(target)
                subdir = base_output / f"sharesift-{t.host}-{t.share}"
                if engagement_db is not None:
                    engagement_db.record_host(t.host, alive=True, port=t.port)
                    engagement_db.record_share(t.host, t.share, type_="disk")
            else:
                subdir = base_output / f"sharesift-{Path(target).name}"

            inner_ns = _ns(
                target=target,
                share=None,
                output_dir=subdir,
                user=args.user,
                password=args.password,
                hash=args.hash,
                kerberos=args.kerberos,
                use_kcache=args.use_kcache,
                domain=args.domain,
                anonymous=args.anonymous,
                encrypt=args.encrypt,
                check=False,
                skip_verify=args.skip_verify,
                skip_report=args.skip_report,
                windows_model_dir=None,
                linux_model_dir=None,
                content_model_dir=None,
                device=None,
                max_snippet_bytes=4096,
                force_content=False,
                read_threads=getattr(args, "read_threads", 4),
                target_file=None,
                rate_limit=1.0,
                timeout=10.0,
                dry_run=False,
                title=None,
            )

            try:
                rc = cmd_scan(inner_ns)
                ok = rc == 0
            except SystemExit as exc:
                ok = False
                out.warn(f"  target failed: {exc}")
            except Exception as exc:
                ok = False
                out.warn(f"  target raised: {type(exc).__name__}: {exc}")

            record = {
                "target": target,
                "output_dir": str(subdir),
                "ok": ok,
            }
            sink.write(json.dumps(record) + "\n")
            sink.flush()
            if ok:
                succeeded += 1
            else:
                failed += 1

            # v0.40: harvest per-target hits.jsonl into the
            # engagement DB so it stays the source of truth.
            if ok and engagement_db is not None:
                hits_jsonl = subdir / "hits.jsonl"
                if hits_jsonl.exists():
                    _ingest_hits_into_db(engagement_db, hits_jsonl, target)

    db_summary = engagement_db.summary() if engagement_db is not None else None
    if engagement_db is not None:
        engagement_db.close()

    out.summary({
        "command": "batch",
        "version": __version__,
        "elapsed_s": round(time.monotonic() - start, 3),
        "targets_total": len(targets),
        "targets_succeeded": succeeded,
        "targets_failed": failed,
        "summary_path": str(summary_path),
        "db_path": str(args.db) if getattr(args, "db", None) else None,
        "db_summary": db_summary,
        "exit_code": 0 if failed == 0 else 1,
    })
    return 0 if failed == 0 else 1


def _ingest_hits_into_db(db, hits_jsonl: Path, target: str) -> None:
    """Load a per-target hits.jsonl into the engagement DB. The
    record schema comes from cmd_scan_files. ``host`` and ``share``
    derive from the target UNC; ``rel_path`` is the path field."""
    from sharesift.share import is_smb_target, parse_target

    if is_smb_target(target):
        t = parse_target(target)
        host = t.host
        share = t.share
        prefix = rf"\\{host}\{share}\\"
    else:
        host = "local"
        share = Path(target).name
        prefix = str(Path(target)) + "/"

    for line in hits_jsonl.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            continue
        path = rec.get("path") or ""
        if path.startswith(prefix):
            rel = path[len(prefix):]
        else:
            rel = path
        size = rec.get("size")
        if size is not None:
            db.record_file(host, share, rel, size=size)
        else:
            db.record_file(host, share, rel)
        # Each matched rule emits a hit row
        for m in (rec.get("content_matches") or []):
            rule = m.get("rule_name") or "?"
            tier = m.get("tier") or rec.get("content_tier") or rec.get("path_tier")
            snippet = m.get("match_context") or rec.get("content_excerpt") or ""
            db.record_hit(
                host, share, rel, rule,
                tier=tier, snippet=snippet[:512] if snippet else None,
            )


def cmd_sort(args: argparse.Namespace) -> int:
    """v0.45: re-sort a hits.jsonl by the verifier-first key.

    Useful after combining multiple per-target hits.jsonl files
    from a batch scan into one engagement-level list — re-sorting
    surfaces the verified-live credentials regardless of which
    target they came from.

        cat engagement/*/hits.jsonl > combined.jsonl
        sharesift sort --input combined.jsonl --output ranked.jsonl

    Records without verification_status fields fall back gracefully
    to tier + rank_score sorting.
    """
    from sharesift.ranking import sort_verifier_first

    start = time.monotonic()
    records = _read_jsonl(args.input, args.stdin)
    out.debug(f"Loaded {len(records)} records")

    records = sort_verifier_first(records)

    sink = sys.stdout if args.output is None else open(args.output, "w", encoding="utf-8")
    try:
        n = 0
        for r in records:
            sink.write(json.dumps(r) + "\n")
            n += 1
    finally:
        if sink is not sys.stdout:
            sink.close()

    # Tally for the operator
    by_status: dict[str, int] = {}
    for r in records:
        s = r.get("verification_status") or "no-verifier"
        by_status[s] = by_status.get(s, 0) + 1
    summary_line = ", ".join(f"{k}={v}" for k, v in sorted(by_status.items()))
    out.info(f"sorted {n} records by verifier-first key: {summary_line}")

    out.summary({
        "command": "sort",
        "version": __version__,
        "elapsed_s": round(time.monotonic() - start, 3),
        "input_count": len(records),
        "output_count": n,
        "verification_breakdown": by_status,
        "output_path": str(args.output) if args.output else None,
        "exit_code": 0,
    })
    return 0


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
    from sharesift.ranking import sort_verifier_first

    start = time.monotonic()
    records = _read_jsonl(args.input, args.stdin)
    out.debug(f"Loaded {len(records)} records")

    # v0.45: verifier-first sort. Live-verified credentials surface
    # at the top of the TSV. Snaffler-TSV format itself unchanged
    # (11 columns, downstream-tool-compatible) — just reordered.
    if not getattr(args, "no_sort", False):
        records = sort_verifier_first(records)

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

    # v0.45: verifier-first sort. Live-passing credentials surface
    # at the top — the structural ShareSift advantage Snaffler can't
    # match. Operators see [LIVE] hits before tier-only hits.
    from sharesift.ranking import sort_verifier_first
    verified = sort_verifier_first(verified)

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
        "--read-threads",
        type=int,
        default=4,
        help=(
            "Worker threads for parallel content reads on SMB targets "
            "(default 4; pass 1 to force sequential)."
        ),
    )
    sc.add_argument(
        "--exclude-glob",
        action="append",
        default=None,
        help=(
            "Glob pattern excluded from enumeration; repeatable. "
            "Operator's patterns add to the default exclusions unless "
            "--no-default-excludes is also set."
        ),
    )
    sc.add_argument(
        "--no-default-excludes",
        action="store_true",
        help=(
            "Disable the v0.40 default exclusion patterns "
            "(Windows/System32/*.dll, node_modules/, .git/, *.iso, "
            "media files, etc.). Use when you want to scan everything."
        ),
    )
    sc.add_argument(
        "--max-file-size",
        type=str,
        default=None,
        help=(
            "Cap bytes read per file. Accepts human-readable: 100K, "
            "5M, 1G. Default 10M; stops accidentally pulling a "
            "5GB VMDK or NTUSER.DAT over the wire. Files larger than "
            "the cap are read up to the cap (partial extraction "
            "rather than skip)."
        ),
    )
    sc.add_argument(
        "--stealth",
        action="store_true",
        help=(
            "OpSec-conscious preset: SMB3 encryption on (default), "
            "1 read thread, default noise exclusions, --max-file-size "
            "256K (cap reads aggressively). Use when scan visibility "
            "matters more than throughput."
        ),
    )
    sc.add_argument(
        "--db",
        type=Path,
        default=None,
        help=(
            "Path to a SQLite engagement datastore (.sharesift.db). "
            "When set, hosts/shares/files are recorded as the scan "
            "runs so the engagement is queryable via "
            "``sharesift query --db ...``. Required for --resume."
        ),
    )
    sc.add_argument(
        "--resume",
        action="store_true",
        help=(
            "Skip files already recorded in the engagement datastore "
            "(requires --db). Use when a previous scan crashed or "
            "was interrupted — re-run the same command with --resume "
            "and ShareSift picks up where it left off."
        ),
    )
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
        "--read-threads",
        type=int,
        default=4,
        help=(
            "Worker threads for parallel content reads on SMB targets "
            "(default 4; pass 1 to force sequential; effective only "
            "with --share that's an SmbShare). Lab-validated thread-"
            "safe with smbprotocol up to 8 workers; 16+ may hit SMB "
            "credit-flow control limits."
        ),
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

    # v0.40 step 3: query — ad-hoc SQL against an engagement datastore
    qr = sub.add_parser(
        "query",
        help=(
            "Run SQL or pre-baked queries against a SQLite "
            "engagement datastore (.sharesift.db file)."
        ),
    )
    qr.add_argument("--db", type=Path, required=True, help="Path to .sharesift.db")
    qr.add_argument("--summary", action="store_true",
                    help="Print high-level engagement stats and exit.")
    qr.add_argument(
        "--preset", default=None,
        choices=sorted(_PRESET_QUERIES.keys()),
        help="Run a pre-baked query by name.",
    )
    qr.add_argument(
        "sql", nargs="?", default=None,
        help="Raw SELECT statement (read-only; writes go through scan).",
    )
    qr.add_argument("--json", action="store_true", dest="json",
                    help="Emit one JSON record per row.")
    qr.set_defaults(func=cmd_query)

    # v0.39 step 1: discover — list shares on a remote host
    ds = sub.add_parser(
        "discover",
        help=(
            "List shares on a remote SMB host via NetrShareEnum. "
            "Composes with ``batch``: pipe stdout into a targets "
            "file, then ``sharesift batch --targets ...``."
        ),
    )
    ds.add_argument(
        "target",
        help=(
            "Host or CIDR to enumerate. Accepts ``//host``, "
            "``\\\\host``, bare host, or CIDR like ``//10.0.0.0/24`` "
            "(network + broadcast excluded). Single host: enumerate "
            "shares directly. CIDR: concurrent TCP probe on :445 "
            "first, then enumerate the live hosts."
        ),
    )
    ds.add_argument(
        "--port", type=int, default=None,
        help="SMB port (default 445; ignored if target includes ``:port``).",
    )
    ds.add_argument(
        "--format", choices=["text", "json"], default="text",
        help=(
            "Output format. ``text`` (default) emits one ``//host/share`` "
            "UNC per line — disk shares uncommented, others as ``# ...`` "
            "so they pass through ``batch`` without scanning. ``json`` "
            "emits one record per share with host/share/type/comment/unc."
        ),
    )
    ds.add_argument(
        "--all-types", action="store_true",
        help="Emit non-file shares (IPC, printer, device) uncommented too.",
    )
    _add_smb_auth_args(ds)
    ds.set_defaults(func=cmd_discover)

    # v0.37 step 3: batch — scan multiple shares from a targets file
    bt = sub.add_parser(
        "batch",
        help=(
            "Scan multiple shares from a targets file. Each line is a "
            "UNC or local path; same auth applies to all. Each target "
            "gets its own output subdir."
        ),
    )
    bt.add_argument(
        "--targets", type=Path, required=True,
        help="Text file with one target per line (# comments allowed).",
    )
    bt.add_argument(
        "--output-dir", type=Path, required=True,
        help="Base directory; per-target subdirs land here.",
    )
    bt.add_argument(
        "--skip-verify", action="store_true",
        help="Skip live verification stage per target.",
    )
    bt.add_argument(
        "--skip-report", action="store_true",
        help="Skip HTML report rendering per target.",
    )
    bt.add_argument(
        "--read-threads", type=int, default=4,
        help="Parallel content-read threads per target (default 4).",
    )
    bt.add_argument(
        "--db", type=Path, default=None,
        help=(
            "Path to a SQLite engagement datastore (.sharesift.db). "
            "When set, populates hosts/shares/files/hits across all "
            "targets so the engagement is queryable via "
            "``sharesift query --db ...``."
        ),
    )
    _add_smb_auth_args(bt)
    bt.set_defaults(func=cmd_batch)

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
    ts.add_argument(
        "--no-sort", action="store_true",
        help=(
            "Disable the v0.45 verifier-first sort. By default, "
            "records are reordered so verified-passed (LIVE) "
            "credentials appear at the top, then by tier + rank. "
            "Pass --no-sort to preserve input order."
        ),
    )
    ts.set_defaults(func=cmd_to_snaffler_tsv)

    # v0.45: sort — re-sort a JSONL by the verifier-first key
    so = sub.add_parser(
        "sort",
        help=(
            "Re-sort a hits.jsonl by the verifier-first key. "
            "Live-passing credentials surface first, then by tier "
            "+ rank. Useful after combining batch results."
        ),
    )
    so.add_argument("--input", type=Path, help="hits.jsonl path (or use --stdin)")
    so.add_argument("--stdin", action="store_true", help="Read JSONL from stdin")
    so.add_argument("--output", type=Path, default=None, help="Output JSONL (default stdout)")
    so.set_defaults(func=cmd_sort)

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
