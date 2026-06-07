"""End-to-end retrain-ranker round trip on synthetic labels."""

from __future__ import annotations

import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
TOOLS = REPO_ROOT / "tools"
if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))


def _fingerprint(path, content):
    import hashlib

    h = hashlib.sha256()
    h.update(path.encode())
    h.update(b"\x00")
    h.update((content or "").encode())
    return "sha256:" + h.hexdigest()[:32]


def _write_jsonl(records, path):
    with path.open("w") as fh:
        for r in records:
            fh.write(json.dumps(r) + "\n")


def test_retrain_round_trip(tmp_path):
    import retrain_ranker

    hits = [
        {
            "path": "/share1/secrets.txt",
            "path_probability": 0.95,
            "path_tier": "Black",
            "content_check": "yes",
            "content_excerpt": "password=hunter2",
            "extracted_fields": [
                {"field_name": "password", "value": "hunter2", "confidence": 0.95, "parser": "x"}
            ],
        },
        {
            "path": "/share1/readme.txt",
            "path_probability": 0.05,
            "path_tier": None,
            "content_check": None,
            "content_excerpt": "no secrets here",
        },
        {
            "path": "/share1/maybe.conf",
            "path_probability": 0.40,
            "path_tier": "Yellow",
            "content_check": "yes",
            "content_excerpt": "key=value",
        },
        {
            "path": "/share2/cred.env",
            "path_probability": 0.90,
            "path_tier": "Red",
            "content_check": "yes",
            "content_excerpt": "API_KEY=sk-real",
        },
    ]
    labels = [
        {
            "record_fingerprint": _fingerprint(hits[0]["path"], hits[0]["content_excerpt"]),
            "label": "tp",
            "notes": "",
            "timestamp": "2026-06-05T00:00:00Z",
        },
        {
            "record_fingerprint": _fingerprint(hits[1]["path"], hits[1]["content_excerpt"]),
            "label": "fp",
            "notes": "",
            "timestamp": "2026-06-05T00:00:00Z",
        },
        {
            "record_fingerprint": _fingerprint(hits[2]["path"], hits[2]["content_excerpt"]),
            "label": "fp",
            "notes": "weak yellow",
            "timestamp": "2026-06-05T00:00:00Z",
        },
        {
            "record_fingerprint": _fingerprint(hits[3]["path"], hits[3]["content_excerpt"]),
            "label": "tp",
            "notes": "",
            "timestamp": "2026-06-05T00:00:00Z",
        },
    ]
    hits_path = tmp_path / "hits.jsonl"
    labels_path = tmp_path / "labels.jsonl"
    out_path = tmp_path / "ranker.joblib"
    _write_jsonl(hits, hits_path)
    _write_jsonl(labels, labels_path)

    rc = retrain_ranker.main(
        ["--hits", str(hits_path), "--labels", str(labels_path), "--output", str(out_path)]
    )
    assert rc == 0
    assert out_path.exists()
    assert out_path.stat().st_size > 100


def test_retrain_skips_discard_labels(tmp_path):
    """Records labeled 'discard' shouldn't be passed to training."""
    import retrain_ranker

    hits_path = tmp_path / "hits.jsonl"
    labels_path = tmp_path / "labels.jsonl"
    _write_jsonl(
        [{"path": "/a", "path_tier": "Black", "content_excerpt": "x"}], hits_path
    )
    _write_jsonl(
        [{"record_fingerprint": _fingerprint("/a", "x"), "label": "discard"}],
        labels_path,
    )
    rc = retrain_ranker.main(
        ["--hits", str(hits_path), "--labels", str(labels_path),
         "--output", str(tmp_path / "r.joblib")]
    )
    # No labelable records → exit code 1
    assert rc == 1
