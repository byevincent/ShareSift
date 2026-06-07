"""Tests for the synthetic-generator post-processor.

The load-bearing invariants pinned here:

1. Filesystem boundary — output MUST NOT land under ``data/eval/`` or
   any path that isn't under a ``synthetic/`` directory. Per
   ``docs/generator_spec.md``, this is the safety rule that keeps
   synthetic training data from contaminating the eval set.
2. Regex-tier contamination gate — ``juicy: false`` records where
   ``negative_validator.check_path`` fires must be dropped. The two
   contamination canaries from the synthetic exploration session
   (``server_key.pem``, ``ssh/deploy_key``) are pinned in
   ``test_negative_validator.py``; the gate behavior here is pinned
   against them via end-to-end fixture.
3. Substitution discipline — same input token gets the same
   replacement WITHIN a record (consistent), and a DIFFERENT
   replacement ACROSS records (independent per-record mappings).
   This achieves the spec's "no individual name appears in more than
   a small fraction of the batch" requirement.
"""

from __future__ import annotations

import json
import random

import pytest

from src.eval.generator.name_pool import (
    LLM_STICKY_DEFAULTS,
    is_project_codename_shape,
    is_svc_account_shape,
    is_username_shape,
)
from src.eval.generator.postprocess import (
    SyntheticRecord,
    _validate_output_path,
    _validate_record_dict,
    add_category_hint,
    dedup_records,
    gate_check,
    load_jsonl_files,
    process,
    substitute_names,
    write_jsonl,
)

# ---------------------------------------------------------------------------
# Stage 1 — schema validation
# ---------------------------------------------------------------------------


def test_validate_record_accepts_well_formed():
    rec = _validate_record_dict({"path": r"\\fs\share\f", "juicy": True, "why": "ok"})
    assert rec.path == r"\\fs\share\f"
    assert rec.juicy is True
    assert rec.why == "ok"


def test_validate_record_rejects_missing_path():
    with pytest.raises(ValueError, match="missing required field 'path'"):
        _validate_record_dict({"juicy": False, "why": "x"})


def test_validate_record_rejects_missing_juicy():
    with pytest.raises(ValueError, match="missing required field 'juicy'"):
        _validate_record_dict({"path": r"\\fs\share\f", "why": "x"})


def test_validate_record_rejects_missing_why():
    with pytest.raises(ValueError, match="missing required field 'why'"):
        _validate_record_dict({"path": r"\\fs\share\f", "juicy": False})


def test_validate_record_rejects_wrong_juicy_type():
    with pytest.raises(ValueError, match="'juicy' must be a bool"):
        _validate_record_dict({"path": r"\\fs\share\f", "juicy": "yes", "why": "x"})


def test_validate_record_rejects_empty_path():
    with pytest.raises(ValueError, match="'path' must be a non-empty string"):
        _validate_record_dict({"path": "  ", "juicy": False, "why": "x"})


def test_load_jsonl_skips_between_batch_markers(tmp_path):
    """Operator might concat multiple LLM outputs with stray 'jsonl'
    separators between them — load should tolerate without error."""
    p = tmp_path / "in.jsonl"
    p.write_text(
        '{"path": "\\\\\\\\fs\\\\sh\\\\a", "juicy": true, "why": "x"}\n'
        "jsonl\n"
        '{"path": "\\\\\\\\fs\\\\sh\\\\b", "juicy": false, "why": "x"}\n',
        encoding="utf-8",
    )
    items = [x for _, _, x in load_jsonl_files([p])]
    assert all(isinstance(i, SyntheticRecord) for i in items)
    assert len(items) == 2


# ---------------------------------------------------------------------------
# Stage 2 — contamination gate
# ---------------------------------------------------------------------------


def test_gate_check_silent_on_clean_negative():
    rec = SyntheticRecord(
        path=r"\\HQFS1\Shared\Marketing\campaign\secret.txt",
        juicy=False,
        why="codename collision",
    )
    assert gate_check(rec) == []


def test_gate_check_fires_on_pem_contamination():
    """The synthetic exploration's first canonical contamination: a
    not_juicy ``server_key.pem``. Must fire so the post-processor
    drops it."""
    rec = SyntheticRecord(
        path=r"\\corp01\groups\security\certificates\server_key.pem",
        juicy=False,
        why="corrupted output, not a valid key",
    )
    fired = gate_check(rec)
    assert "pem_extension" in fired


def test_gate_check_fires_on_ssh_deploy_key_contamination():
    """The synthetic exploration's second canonical contamination:
    ``ssh/deploy_key``. Must fire so the post-processor drops it."""
    rec = SyntheticRecord(
        path=r"\\corp01\groups\engineering\infra\ssh\deploy_key",
        juicy=False,
        why="public half of the keypair only",
    )
    fired = gate_check(rec)
    assert "ssh_key_filename_pattern" in fired


# ---------------------------------------------------------------------------
# Stage 3 — name substitution
# ---------------------------------------------------------------------------


def test_substitution_replaces_sticky_default():
    """jsmith is a known LLM sticky-default; substitution required."""
    rec = SyntheticRecord(
        path=r"\\WIN-SRV4\users\jsmith\Documents\report.docx",
        juicy=False,
        why="routine doc",
    )
    rng = random.Random(0)
    sub, count = substitute_names(rec, rng)
    assert "jsmith" not in sub.path.lower()
    assert count >= 1


def test_substitution_is_consistent_within_record():
    """Same input token in two places in one record → same output in
    both places. Path coherence preserved."""
    rec = SyntheticRecord(
        path=r"\\fs\share\users\jdoe\jdoe_notes.txt",
        juicy=False,
        why="x",
    )
    rng = random.Random(42)
    sub, _ = substitute_names(rec, rng)
    # Whichever name jdoe became, it should appear twice in the result
    # (once as the user folder, once embedded in the filename).
    assert "jdoe" not in sub.path.lower()
    # Find what jdoe became by looking at the user-folder slot
    parts = sub.path.split("\\")
    user_slot = parts[parts.index("users") + 1]
    # That same string should also appear before "_notes"
    basename = parts[-1]
    assert basename.startswith(user_slot.lower() + "_notes") or basename.startswith(
        user_slot + "_notes"
    ), f"expected consistent substitution in basename; got {basename}"


def test_substitution_varies_across_records():
    """Two records with the same input token get DIFFERENT substitutes
    (no global mapping). At batch size N this is what gives "no name
    appears in more than a small fraction" by construction."""
    base = SyntheticRecord(
        path=r"\\fs\share\users\jsmith\file.txt",
        juicy=False,
        why="x",
    )
    rng = random.Random(7)
    subs = [substitute_names(base, rng)[0].path for _ in range(20)]
    unique_replacements = {p.split("\\users\\")[1].split("\\")[0] for p in subs}
    # 20 records, expect a healthy variety — at least 8 distinct
    # replacements given the name pool sizes.
    assert len(unique_replacements) >= 8, (
        f"substitution variation too low ({len(unique_replacements)}/20); "
        f"name pool may be too small or substitution is reusing a global mapping"
    )


def test_substitution_works_on_linux_paths():
    """Linux paths use ``/`` separators; the tokenizer + replacement
    pipeline must honor them so sticky-default usernames embedded in
    home directories get substituted the same way they do on UNC."""
    rec = SyntheticRecord(
        path="/home/jsmith/.ssh/id_rsa",
        juicy=True,
        why="x",
    )
    rng = random.Random(0)
    sub, count = substitute_names(rec, rng)
    assert "jsmith" not in sub.path.lower()
    assert count >= 1
    # Path shape preserved (still a Linux path, not mangled to UNC).
    assert sub.path.startswith("/home/")
    assert sub.path.endswith("/.ssh/id_rsa")


def test_substitution_replaces_svc_account_shape():
    rec = SyntheticRecord(
        path=r"\\WIN-SRV4\users\svc-payroll\Desktop\webhook.txt",
        juicy=True,
        why="x",
    )
    rng = random.Random(0)
    sub, count = substitute_names(rec, rng)
    assert "svc-payroll" not in sub.path.lower()
    assert "svc-" in sub.path.lower()  # still an svc account, just a different one
    assert count >= 1


def test_substitution_skips_safe_words():
    """Words like 'shared', 'users', 'documents' must NOT be
    substituted even though they look username-ish — they're real
    Windows / SMB share components."""
    rec = SyntheticRecord(
        path=r"\\HQFS1\Shared\Documents\users\report.docx",
        juicy=False,
        why="x",
    )
    rng = random.Random(0)
    sub, count = substitute_names(rec, rng)
    assert count == 0
    assert sub.path == rec.path


def test_username_shape_detection():
    assert is_username_shape("jsmith")
    assert is_username_shape("bwilson")
    assert is_username_shape("mchan")
    assert not is_username_shape("shared")
    assert not is_username_shape("documents")
    assert not is_username_shape("templates")


def test_svc_account_shape_detection():
    assert is_svc_account_shape("svc-payroll")
    assert is_svc_account_shape("svc-deploy")
    assert not is_svc_account_shape("payroll")
    assert not is_svc_account_shape("Service-Account")


def test_project_codename_detection():
    assert is_project_codename_shape("atlas")
    assert is_project_codename_shape("Acme")
    assert not is_project_codename_shape("infrastructure")


def test_sticky_default_registry_includes_observed_defaults():
    """Drift pin: defaults observed across audit passes are tracked."""
    for canonical in ("jsmith", "jdoe", "svc-payroll", "svc-backup", "atlas"):
        assert canonical in LLM_STICKY_DEFAULTS


# ---------------------------------------------------------------------------
# Stage 4 — dedup
# ---------------------------------------------------------------------------


def test_dedup_collapses_case_variants():
    recs = [
        SyntheticRecord(path=r"\\fs\share\file.txt", juicy=True, why="x"),
        SyntheticRecord(path=r"\\FS\SHARE\FILE.TXT", juicy=True, why="x"),
    ]
    out, collisions = dedup_records(recs)
    assert len(out) == 1
    assert collisions == 1


def test_dedup_keeps_distinct_paths():
    recs = [
        SyntheticRecord(path=r"\\fs\share\a.txt", juicy=True, why="x"),
        SyntheticRecord(path=r"\\fs\share\b.txt", juicy=True, why="x"),
    ]
    out, collisions = dedup_records(recs)
    assert len(out) == 2
    assert collisions == 0


# ---------------------------------------------------------------------------
# Stage 5 — category hint
# ---------------------------------------------------------------------------


def test_category_hint_derived_from_pre_categorize():
    rec = SyntheticRecord(
        path=r"\\fs\share\users\bob\.ssh\id_rsa",
        juicy=True,
        why="ssh key",
    )
    hinted = add_category_hint(rec)
    assert hinted.category_hint == "ssh_credentials"


def test_category_hint_none_when_pre_categorize_silent():
    rec = SyntheticRecord(
        path=r"\\fs\share\sales\Q3-report.pdf",
        juicy=False,
        why="routine report",
    )
    hinted = add_category_hint(rec)
    # PDF doesn't pre-categorize without a sensitivity keyword
    assert hinted.category_hint is None


# ---------------------------------------------------------------------------
# Stage 6 — filesystem-boundary enforcement (LOAD BEARING per spec)
# ---------------------------------------------------------------------------


def test_validate_output_path_refuses_eval_dir(tmp_path):
    """The spec's load-bearing safety rule: synthetic output must
    NEVER land under data/eval/. A misconfigured CLI flag MUST raise,
    not silently write."""
    eval_path = tmp_path / "data" / "eval" / "synthetic" / "out.jsonl"
    with pytest.raises(ValueError, match="synthetic output"):
        _validate_output_path(eval_path)


def test_validate_output_path_refuses_non_synthetic(tmp_path):
    other = tmp_path / "data" / "training" / "out.jsonl"
    with pytest.raises(ValueError, match="synthetic output"):
        _validate_output_path(other)


def test_validate_output_path_accepts_synthetic_dir(tmp_path):
    good = tmp_path / "data" / "synthetic" / "v0" / "out.jsonl"
    good.parent.mkdir(parents=True)
    # Should not raise
    _validate_output_path(good)


def test_write_refuses_eval_output(tmp_path):
    bad = tmp_path / "data" / "eval" / "out.jsonl"
    with pytest.raises(ValueError, match="synthetic output"):
        write_jsonl(
            [SyntheticRecord(path=r"\\fs\share\f", juicy=True, why="x")],
            bad,
        )


def test_write_creates_synthetic_output(tmp_path):
    good = tmp_path / "data" / "synthetic" / "v0" / "out.jsonl"
    rec = SyntheticRecord(
        path=r"\\fs\share\f", juicy=True, why="x", category_hint="ssh_credentials",
    )
    write_jsonl([rec], good)
    contents = good.read_text(encoding="utf-8")
    obj = json.loads(contents.strip())
    assert obj == {
        "path": r"\\fs\share\f",
        "juicy": True,
        "why": "x",
        "category_hint": "ssh_credentials",
    }


# ---------------------------------------------------------------------------
# End-to-end pipeline
# ---------------------------------------------------------------------------


def test_process_end_to_end_with_contamination(tmp_path):
    """Synthetic input includes one contaminated record. Pipeline drops
    it via the gate, substitutes names in the rest, writes clean
    output."""
    inp = tmp_path / "raw.jsonl"
    inp.write_text(
        "\n".join([
            # Clean negative — kept
            json.dumps({
                "path": r"\\HQFS1\Shared\Marketing\campaign\secret.txt",
                "juicy": False,
                "why": "codename Secret",
            }),
            # Contaminated negative — DROPPED by gate
            json.dumps({
                "path": r"\\corp01\groups\sec\certs\server_key.pem",
                "juicy": False,
                "why": "corrupted output not a valid key",
            }),
            # Positive — kept regardless of gate firing
            json.dumps({
                "path": r"\\WIN-SRV4\users\jsmith\.ssh\id_rsa",
                "juicy": True,
                "why": "ssh key for deploy account",
            }),
        ]),
        encoding="utf-8",
    )
    out = tmp_path / "data" / "synthetic" / "training.jsonl"
    result = process([inp], out, seed=0)
    assert result.written == 2
    assert len(result.gate_drops) == 1
    assert result.gate_drops[0][1] == ["pem_extension"]
    # Output: jsmith substituted
    lines = out.read_text(encoding="utf-8").strip().split("\n")
    out_objs = [json.loads(line) for line in lines]
    paths = [o["path"] for o in out_objs]
    assert not any("jsmith" in p.lower() for p in paths)


def test_process_refuses_eval_output(tmp_path):
    inp = tmp_path / "raw.jsonl"
    inp.write_text(
        json.dumps({"path": r"\\fs\share\f", "juicy": True, "why": "x"}),
        encoding="utf-8",
    )
    bad_out = tmp_path / "data" / "eval" / "out.jsonl"
    with pytest.raises(ValueError, match="synthetic output"):
        process([inp], bad_out, seed=0)


def test_process_directory_input(tmp_path):
    """Directory input walks one level deep for .jsonl files."""
    src_dir = tmp_path / "raw"
    src_dir.mkdir()
    (src_dir / "a.jsonl").write_text(
        json.dumps({"path": r"\\fs\share\a", "juicy": True, "why": "x"}) + "\n",
        encoding="utf-8",
    )
    (src_dir / "b.jsonl").write_text(
        json.dumps({"path": r"\\fs\share\b", "juicy": False, "why": "x"}) + "\n",
        encoding="utf-8",
    )
    out = tmp_path / "data" / "synthetic" / "merged.jsonl"
    result = process([src_dir], out, seed=0)
    assert result.written == 2


# ---------------------------------------------------------------------------
# Report mode
# ---------------------------------------------------------------------------


def test_report_mode_flags_candidate_sticky_default(tmp_path, capsys):
    """Report mode should surface a frequently-appearing username-like
    token that's not in LLM_STICKY_DEFAULTS as a candidate."""
    from src.eval.generator.postprocess import main

    inp = tmp_path / "batch.jsonl"
    # 'kchen' appears in 4 records and is NOT in LLM_STICKY_DEFAULTS.
    # Should surface as a candidate. Adding lots of "noise" tokens that
    # are already in IGNORE so they don't shadow the signal.
    inp.write_text(
        "\n".join([
            json.dumps({"path": r"\\fs\share\users\kchen\file1", "juicy": True, "why": "x"}),
            json.dumps({"path": r"\\fs\share\users\kchen\file2", "juicy": True, "why": "x"}),
            json.dumps({"path": r"\\fs\share\users\kchen\file3", "juicy": True, "why": "x"}),
            json.dumps({"path": r"\\fs\share\users\kchen\file4", "juicy": True, "why": "x"}),
        ]),
        encoding="utf-8",
    )
    rc = main(["--input", str(inp), "--report"])
    assert rc == 0
    captured = capsys.readouterr()
    assert "kchen" in captured.err
    assert "Candidate sticky defaults" in captured.err
