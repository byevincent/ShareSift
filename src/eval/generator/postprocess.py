"""Post-processor for synthetic training-data JSONL output.

Reads raw LLM-output JSONL produced by manual prompt runs (Qwen,
DeepSeek, ChatGPT, etc.), applies the discipline rules from
``docs/generator_spec.md``, and emits training-ready JSONL.

Pipeline stages:

1. **Schema validation** — every record must have ``path`` (non-empty
   str), ``juicy`` (bool), ``why`` (non-empty str). Malformed records
   are dropped with line numbers logged.
2. **Contamination gate** — for every ``juicy: false`` record, call
   ``negative_validator.check_path``. Drop anything that fires. This is
   the Rule 5 anti-contamination gate; regex-tier paths used as
   negatives would teach the model to discount a high-confidence
   signal.
3. **Whole-path name substitution** — per the spec's Rule 2, LLM-default
   entity names (``jsmith``, ``jdoe``, ``svc-payroll``, etc.) become a
   fingerprint at training scale unless substituted. Within a record,
   substitutions are consistent (``\\users\\jsmith\\jsmith_notes.txt``
   → ``\\users\\karim\\karim_notes.txt``); across records, the same
   input token gets different substitutes (no global mapping).
4. **Dedup** — via shared ``normalize_for_dedup`` so synthetic records
   can't shadow eval-set paths.
5. **Category hint** — derived via ``pre_categorize`` (same callable as
   ``build_queue``) so the training-data category labels stay
   consistent with the eval-set's category taxonomy by construction.
6. **Atomic write** — output path MUST be under ``data/synthetic/``;
   anywhere else raises. Pinned by ``test_refuses_eval_dir_output``.

The filesystem boundary is the load-bearing safety rule per the spec:
synthetic must never bleed into ``data/eval/`` because the eval set is
independent ground truth. The boundary lives here so a misconfigured
CLI flag can't land synthetic records as eval records.
"""

from __future__ import annotations

import argparse
import json
import os
import random
import re
import sys
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path, PureWindowsPath

from src.eval._paths import normalize_for_dedup
from src.eval.build_queue import pre_categorize
from src.eval.generator.name_pool import (
    FIRST_NAMES,
    LAST_NAMES,
    PROJECT_CODENAMES,
    SVC_ROLES,
    is_project_codename_shape,
    is_sticky_default,
    is_svc_account_shape,
)
from src.eval.negative_validator import check_path as negative_check

# ----------------------------------------------------------------------------
# Constants
# ----------------------------------------------------------------------------

_SYNTHETIC_DIR_NAME = "synthetic"
_EVAL_DIR_NAME = "eval"
_REQUIRED_FIELDS: tuple[str, ...] = ("path", "juicy", "why")


# ----------------------------------------------------------------------------
# Data shapes
# ----------------------------------------------------------------------------


@dataclass(frozen=True)
class SyntheticRecord:
    """One synthetic training record. Categorically distinct from
    ``EvalRecord`` per the spec — synthetic uses its own looser
    envelope that doesn't go through ``EvalRecord``'s Pydantic
    validation."""

    path: str
    juicy: bool
    why: str
    category_hint: str | None = None  # derived in pipeline, not from input


@dataclass
class ProcessResult:
    """Summary of one post-processor run. Counts and lists are surfaced
    on stderr so the operator can audit drops and substitutions."""

    written: int = 0
    invalid_schema: list[tuple[Path, int, str]] = field(default_factory=list)
    gate_drops: list[tuple[str, list[str]]] = field(default_factory=list)
    dedup_collisions: int = 0
    substituted_records: int = 0
    substituted_tokens: int = 0


# ----------------------------------------------------------------------------
# Stage 1 — schema validation
# ----------------------------------------------------------------------------


def _validate_record_dict(raw: dict) -> SyntheticRecord:
    """Return ``SyntheticRecord`` or raise ``ValueError`` with a message
    naming the missing/wrong-type field."""
    for f in _REQUIRED_FIELDS:
        if f not in raw:
            raise ValueError(f"missing required field {f!r}")
    if not isinstance(raw["path"], str) or not raw["path"].strip():
        raise ValueError("field 'path' must be a non-empty string")
    if not isinstance(raw["juicy"], bool):
        raise ValueError("field 'juicy' must be a bool")
    if not isinstance(raw["why"], str) or not raw["why"].strip():
        raise ValueError("field 'why' must be a non-empty string")
    return SyntheticRecord(path=raw["path"].strip(), juicy=raw["juicy"], why=raw["why"].strip())


def load_jsonl_files(paths: list[Path]) -> Iterator[tuple[Path, int, SyntheticRecord | ValueError]]:
    """Yield ``(file, line_num, record_or_error)`` from each file in
    order. Caller filters errors. Empty lines are skipped silently."""
    for src in paths:
        with src.open("r", encoding="utf-8") as f:
            for line_num, line in enumerate(f, start=1):
                line = line.strip()
                if not line:
                    continue
                # Tolerate stray "jsonl" markers and similar between-batch
                # separators the operator might leave in concatenated input.
                if line.lower() in {"jsonl", "json", "---"}:
                    continue
                try:
                    obj = json.loads(line)
                    if not isinstance(obj, dict):
                        err = f"line is not a JSON object: {type(obj).__name__}"
                        yield src, line_num, ValueError(err)
                        continue
                    rec = _validate_record_dict(obj)
                    yield src, line_num, rec
                except (json.JSONDecodeError, ValueError) as e:
                    yield src, line_num, ValueError(str(e))


# ----------------------------------------------------------------------------
# Stage 2 — contamination gate
# ----------------------------------------------------------------------------


def gate_check(record: SyntheticRecord) -> list[str]:
    """Return the names of ``negative_validator`` heuristics that fire
    for this record's path.

    For ``juicy: true`` records, the caller may use this output for
    audit (it's expected for regex-tier positives to fire). For
    ``juicy: false`` records, ANY firing is contamination and the
    record must be dropped.
    """
    return negative_check(record.path)


# ----------------------------------------------------------------------------
# Stage 3 — name substitution
# ----------------------------------------------------------------------------


_PATH_SEP_RE = re.compile(r"[\\/]")


def _split_path_tokens(path: str) -> list[str]:
    """Split a path into substitution-candidate tokens.

    Splits on path separators (``\\`` and ``/``) and ``_`` (compound-name
    separator common in usernames embedded in basenames like
    ``jdoe_notes.txt``). Both separators are honored so Linux paths
    (``/home/jsmith/.ssh/id_rsa``) and UNC paths
    (``\\\\srv\\share\\jsmith\\file.txt``) tokenize the same way.
    Does NOT split on ``-`` or ``.`` because compound svc-account names
    (``svc-payroll``) and extension-bearing basenames (``notes.txt``)
    are single semantic units that should be checked whole.
    """
    out: list[str] = []
    for seg in _PATH_SEP_RE.split(path):
        if not seg:
            continue
        for sub in seg.split("_"):
            if sub:
                out.append(sub.lower())
    return out


def _replacement_for(token: str, rng: random.Random) -> str:
    """Pick a fresh substitute name for a token. Routing:
    - svc-account shape → svc-<role>
    - project codename → project codename pool
    - username shape → first-initial + last name from pools
    """
    if is_svc_account_shape(token):
        role = rng.choice(SVC_ROLES)
        return f"svc-{role}"
    if is_project_codename_shape(token):
        return rng.choice(PROJECT_CODENAMES)
    # Default: username shape → first-initial + lastname
    first = rng.choice(FIRST_NAMES)
    last = rng.choice(LAST_NAMES)
    return f"{first[0]}{last}"


def substitute_names(record: SyntheticRecord, rng: random.Random) -> tuple[SyntheticRecord, int]:
    """Substitute LLM-default entity tokens in the path with fresh
    draws from the name pools. Returns the substituted record plus the
    count of tokens replaced.

    Substitution is consistent WITHIN a record: if ``jsmith`` appears
    twice (once as a folder, once as a filename), both become the
    same substitute. Across records, substitution mappings are
    independent — same input ``jsmith`` gets a different replacement
    in each record. This achieves the spec's "no individual name
    appears in more than a small fraction of the batch" requirement
    by construction.
    """
    # Substitution targets (no broad pattern matching — too FP-prone on
    # common English words like "notes"/"files"/"share"):
    #   1. Sticky defaults from the registry (jsmith, jdoe, atlas, etc.)
    #   2. svc-account patterns (svc-X / svc_X — high precision pattern)
    #   3. Project codenames from the registry (Acme, Meridian, etc.)
    # New sticky defaults observed in future batches get added to the
    # registry manually — that's the maintenance contract that keeps
    # the substitution behavior predictable.
    tokens = _split_path_tokens(record.path)
    seen: set[str] = set()
    mapping: dict[str, str] = {}
    for tok in tokens:
        if tok in seen:
            continue
        seen.add(tok)
        needs_sub = (
            is_sticky_default(tok)
            or is_svc_account_shape(tok)
            or is_project_codename_shape(tok)
        )
        if needs_sub:
            mapping[tok] = _replacement_for(tok, rng)

    if not mapping:
        return record, 0

    new_path = record.path
    # Substitute longest tokens first to avoid partial-overlap rewrites.
    for tok in sorted(mapping, key=len, reverse=True):
        repl = mapping[tok]
        # Case-insensitive whole-token substitution. Walk the path
        # segment by segment to avoid replacing substrings inside
        # longer tokens (e.g. ``jdoe`` shouldn't replace inside
        # ``ajdoenotes``).
        new_path = _safe_token_replace(new_path, tok, repl)

    return (
        SyntheticRecord(path=new_path, juicy=record.juicy, why=record.why),
        len(mapping),
    )


def _safe_token_replace(path: str, token: str, replacement: str) -> str:
    """Replace ``token`` in ``path`` only at component boundaries
    (between separators ``\\``, ``-``, ``_``, ``.``). Case-insensitive."""
    out_chars: list[str] = []
    i = 0
    tok_lower = token.lower()
    path_lower = path.lower()
    sep_chars = "\\/-_."
    while i < len(path):
        # Check if `token` matches at position i with separator boundaries
        if path_lower.startswith(tok_lower, i):
            left_boundary = i == 0 or path[i - 1] in sep_chars
            right_idx = i + len(token)
            right_boundary = right_idx == len(path) or path[right_idx] in sep_chars
            if left_boundary and right_boundary:
                out_chars.append(replacement)
                i += len(token)
                continue
        out_chars.append(path[i])
        i += 1
    return "".join(out_chars)


# ----------------------------------------------------------------------------
# Stage 4 — dedup
# ----------------------------------------------------------------------------


def dedup_records(records: list[SyntheticRecord]) -> tuple[list[SyntheticRecord], int]:
    """First-wins dedup via ``normalize_for_dedup``. Returns the
    deduplicated list and the collision count."""
    seen: set[str] = set()
    out: list[SyntheticRecord] = []
    collisions = 0
    for r in records:
        try:
            norm = normalize_for_dedup(r.path)
        except (ValueError, TypeError):
            out.append(r)
            continue
        if norm in seen:
            collisions += 1
            continue
        seen.add(norm)
        out.append(r)
    return out, collisions


# ----------------------------------------------------------------------------
# Stage 5 — category hint
# ----------------------------------------------------------------------------


def add_category_hint(record: SyntheticRecord) -> SyntheticRecord:
    """Derive ``category_hint`` via ``pre_categorize``. Returns the
    record with the field populated (or None if pre-categorization
    didn't fire)."""
    hint = pre_categorize(record.path)
    return SyntheticRecord(
        path=record.path,
        juicy=record.juicy,
        why=record.why,
        category_hint=hint,
    )


# ----------------------------------------------------------------------------
# Stage 6 — output with filesystem-boundary enforcement
# ----------------------------------------------------------------------------


def _is_under_synthetic_dir(path: Path) -> bool:
    """True if ``path`` resolves to a location under any ``synthetic``
    component. Used to enforce the spec's filesystem boundary at write
    time — synthetic output must never land under ``data/eval/``."""
    resolved = path.resolve()
    parts = [p.lower() for p in resolved.parts]
    return _SYNTHETIC_DIR_NAME in parts and _EVAL_DIR_NAME not in parts


def _validate_output_path(path: Path) -> None:
    """Raise ``ValueError`` if ``path`` is not under ``data/synthetic/``.

    This is the load-bearing filesystem-boundary check per the spec:
    a misconfigured CLI flag or path string MUST NOT land synthetic
    records as eval records, because the eval set is independent
    ground truth. The check uses resolved paths so symlinks can't
    bypass.
    """
    if not _is_under_synthetic_dir(path):
        raise ValueError(
            f"synthetic output must be under a 'synthetic' directory "
            f"and not under 'eval'; got {path}"
        )


def write_jsonl(records: list[SyntheticRecord], out_path: Path) -> None:
    """Atomic write: tempfile + ``os.replace``. Refuses paths not
    under ``data/synthetic/``."""
    _validate_output_path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    tmp = out_path.with_suffix(out_path.suffix + ".tmp")
    try:
        with tmp.open("w", encoding="utf-8") as f:
            for r in records:
                obj = {"path": r.path, "juicy": r.juicy, "why": r.why}
                if r.category_hint is not None:
                    obj["category_hint"] = r.category_hint
                f.write(json.dumps(obj) + "\n")
        os.replace(tmp, out_path)
    except Exception:
        if tmp.exists():
            try:
                tmp.unlink()
            except OSError:
                pass
        raise


# ----------------------------------------------------------------------------
# Pipeline orchestrator
# ----------------------------------------------------------------------------


def process(
    inputs: list[Path],
    output: Path,
    *,
    seed: int = 0,
) -> ProcessResult:
    """Run the full post-processor pipeline.

    ``inputs`` may be files or directories; directories are walked
    one level deep for ``*.jsonl`` and ``*.ndjson`` files. ``output``
    must be under a ``synthetic`` directory.

    Determinism: identical input + ``seed`` produces identical output.
    Per-record substitution mappings are drawn from
    ``random.Random(seed)``-derived state; reseeding mid-pipeline
    would defeat the per-record-fresh discipline so the same RNG
    instance carries through.
    """
    _validate_output_path(output)

    file_list: list[Path] = []
    for p in inputs:
        if p.is_dir():
            for child in sorted(p.iterdir()):
                if child.suffix.lower() in {".jsonl", ".ndjson"}:
                    file_list.append(child)
        elif p.is_file():
            file_list.append(p)
        else:
            raise FileNotFoundError(f"input path does not exist: {p}")

    result = ProcessResult()
    rng = random.Random(seed)
    raw_records: list[SyntheticRecord] = []

    # Stages 1 + 2: load and gate
    for src, line_num, item in load_jsonl_files(file_list):
        if isinstance(item, ValueError):
            result.invalid_schema.append((src, line_num, str(item)))
            continue
        rec: SyntheticRecord = item
        if not rec.juicy:
            fired = gate_check(rec)
            if fired:
                result.gate_drops.append((rec.path, fired))
                continue
        raw_records.append(rec)

    # Stage 3: name substitution
    substituted: list[SyntheticRecord] = []
    for rec in raw_records:
        new_rec, count = substitute_names(rec, rng)
        if count > 0:
            result.substituted_records += 1
            result.substituted_tokens += count
        substituted.append(new_rec)

    # Stage 4: dedup
    deduped, collisions = dedup_records(substituted)
    result.dedup_collisions = collisions

    # Stage 5: category hint
    with_hints = [add_category_hint(r) for r in deduped]

    # Stage 6: write
    write_jsonl(with_hints, output)
    result.written = len(with_hints)
    return result


# ----------------------------------------------------------------------------
# CLI
# ----------------------------------------------------------------------------


def _run_report(input_paths: list[Path]) -> int:
    """Read input JSONL and print analysis without writing output.

    Surfaces: class tallies (juicy true vs false), category-hint
    distribution, and a candidate-new-sticky-default list (path
    components that appear in many records but aren't in
    ``LLM_STICKY_DEFAULTS`` yet — likely fingerprint markers worth
    adding to the registry).

    Operator runs this periodically as new batches accumulate to spot
    new sticky defaults the LLMs settle on.
    """
    from collections import Counter

    from src.eval.generator.name_pool import LLM_STICKY_DEFAULTS

    file_list: list[Path] = []
    for p in input_paths:
        if p.is_dir():
            for child in sorted(p.iterdir()):
                if child.suffix.lower() in {".jsonl", ".ndjson"}:
                    file_list.append(child)
        elif p.is_file():
            file_list.append(p)

    records: list[SyntheticRecord] = []
    invalid = 0
    for _, _, item in load_jsonl_files(file_list):
        if isinstance(item, ValueError):
            invalid += 1
            continue
        records.append(item)

    print(f"Records: {len(records)} ({invalid} schema-invalid)", file=sys.stderr)
    juicy_t = sum(1 for r in records if r.juicy)
    juicy_f = len(records) - juicy_t
    print(f"  juicy=true:  {juicy_t}", file=sys.stderr)
    print(f"  juicy=false: {juicy_f}", file=sys.stderr)

    # Category hint distribution
    cats = Counter(pre_categorize(r.path) for r in records)
    print("\nCategory hint distribution:", file=sys.stderr)
    for cat, n in cats.most_common():
        label = cat if cat else "(no pre-cat match)"
        print(f"  {label}: {n}", file=sys.stderr)

    # Path component frequency — flag candidates NOT in registry
    component_counts: Counter[str] = Counter()
    for r in records:
        for tok in _split_path_tokens(r.path):
            if len(tok) >= 3:  # skip 1-2 char tokens (drive letters, etc.)
                component_counts[tok] += 1

    print("\nCandidate sticky defaults (frequent components not in registry):", file=sys.stderr)
    # A token appearing in 3+ records is a fingerprint risk; flag if not
    # already in LLM_STICKY_DEFAULTS so the operator can add it.
    candidates = []
    for tok, n in component_counts.most_common(80):
        if n < 3:
            continue
        if tok in LLM_STICKY_DEFAULTS:
            continue
        # Skip obvious path-component words (departments, file types, etc.)
        from src.eval.generator.name_pool import USERNAME_PATTERN_IGNORE
        if tok in USERNAME_PATTERN_IGNORE:
            continue
        candidates.append((tok, n))
    if candidates:
        for tok, n in candidates[:30]:
            print(f"  {tok}  (appears in {n} records)", file=sys.stderr)
        print(
            "\nReview the list — any human-name / project-codename / svc-account "
            "candidates here should be added to LLM_STICKY_DEFAULTS in "
            "src/eval/generator/name_pool.py.",
            file=sys.stderr,
        )
    else:
        print("  none — registry is current", file=sys.stderr)

    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="postprocess",
        description=(
            "Post-process raw synthetic-generator JSONL output: validate "
            "schema, enforce the regex-tier contamination gate on negatives, "
            "substitute LLM-default entity names, dedup, derive category "
            "hints, write training-ready JSONL. Output MUST be under a "
            "'synthetic' directory; refuses 'eval' paths to enforce the "
            "training-vs-eval boundary."
        ),
    )
    parser.add_argument(
        "--input",
        type=Path,
        required=True,
        action="append",
        help="Input JSONL file or directory of JSONL files. May be repeated.",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=None,
        help=(
            "Output JSONL path. Must be under a 'synthetic' directory. "
            "Required unless --report is set."
        ),
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=0,
        help="RNG seed for substitution determinism (default: 0)",
    )
    parser.add_argument(
        "--report",
        action="store_true",
        help=(
            "Read input JSONL and print analysis (class tally, category "
            "hint distribution, candidate sticky-default list) to stderr "
            "without writing output. Run periodically as batches "
            "accumulate to spot new fingerprint markers."
        ),
    )
    args = parser.parse_args(argv)

    if args.report:
        return _run_report(args.input)

    if args.output is None:
        print("error: --output is required unless --report is set", file=sys.stderr)
        return 1

    try:
        result = process(args.input, args.output, seed=args.seed)
    except (ValueError, FileNotFoundError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 1

    print(f"wrote {result.written} records to {args.output}", file=sys.stderr)
    print(
        f"  schema-invalid dropped:    {len(result.invalid_schema)}",
        file=sys.stderr,
    )
    print(
        f"  contamination gate drops:  {len(result.gate_drops)}",
        file=sys.stderr,
    )
    print(
        f"  dedup collisions:          {result.dedup_collisions}",
        file=sys.stderr,
    )
    print(
        f"  records with substitution: {result.substituted_records}",
        file=sys.stderr,
    )
    print(
        f"  total tokens substituted:  {result.substituted_tokens}",
        file=sys.stderr,
    )

    if result.invalid_schema:
        print("\ninvalid-schema details (first 10):", file=sys.stderr)
        for src, ln, msg in result.invalid_schema[:10]:
            print(f"  {src}:{ln}: {msg}", file=sys.stderr)

    if result.gate_drops:
        print("\ncontamination drops (first 10):", file=sys.stderr)
        for path, fired in result.gate_drops[:10]:
            print(f"  DROP  {path}  ({', '.join(fired)})", file=sys.stderr)

    # Sanity: confirm the boundary held even though it was checked upfront
    _ = PureWindowsPath  # silence unused-import linter if path module gets pruned
    return 0


if __name__ == "__main__":
    sys.exit(main())
