"""HTML renderer — structure + summary stat correctness."""

from __future__ import annotations

import re

from sharesift.report import render_html


def _fixture_records():
    return [
        {
            "path": "\\\\dc01\\netlogon\\Groups.xml",
            "path_probability": 0.97,
            "path_tier": "Black",
            "content_check": "yes",
            "content_excerpt": "<Properties cpassword='abc' userName='svc_jenkins'/>",
            "verification_status": "passed",
            "extracted_credential_types": ["gpp_cpassword"],
            "verification_results": [
                {
                    "credential_type": "gpp_cpassword",
                    "service": "gpp",
                    "status": "passed",
                    "latency_ms": 14.3,
                    "metadata": {"decoded": "P@ssw0rd1!"},
                }
            ],
        },
        {
            "path": "/home/dev/.env",
            "path_probability": 0.82,
            "path_tier": "Red",
            "content_check": "yes",
            "content_excerpt": "ANTHROPIC_API_KEY=sk-ant-fake\nGITHUB=ghp_fake",
            "verification_status": "failed",
            "extracted_credential_types": ["anthropic_api_key", "github_pat_classic"],
            "verification_results": [
                {
                    "credential_type": "anthropic_api_key",
                    "service": "anthropic",
                    "status": "failed",
                    "latency_ms": 230.0,
                    "error": "http_401",
                }
            ],
        },
        {
            "path": "/var/log/syslog",
            "path_probability": 0.04,
            "path_tier": None,
            "content_check": None,
            "content_excerpt": None,
        },
    ]


def test_renders_to_self_contained_file(tmp_path):
    out = render_html(_fixture_records(), tmp_path / "report.html", title="Test run")
    html = out.read_text()
    # Self-contained: no script src= or link href=
    assert 'script src=' not in html.lower()
    assert 'link href=' not in html.lower()
    assert "<title>Test run</title>" in html


def test_summary_includes_tier_breakdown(tmp_path):
    html = render_html(_fixture_records(), tmp_path / "r.html").read_text()
    # v0.17 markup: <span class="tier tier-X">X</span> N
    assert ">Black</span> 1" in html
    assert ">Red</span> 1" in html
    assert ">Gray</span> 1" in html


def test_summary_includes_verification_breakdown(tmp_path):
    html = render_html(_fixture_records(), tmp_path / "r.html").read_text()
    assert ">passed</span> 1" in html
    assert ">failed</span> 1" in html


def test_renders_tier_donut_svg(tmp_path):
    """v0.17: SVG donut chart per tier breakdown."""
    html = render_html(_fixture_records(), tmp_path / "r.html").read_text()
    assert "<svg" in html
    assert "stroke-dasharray" in html


def test_renders_active_learning_export_button(tmp_path):
    html = render_html(_fixture_records(), tmp_path / "r.html").read_text()
    assert 'id="export-labels"' in html
    assert "sharesift_labels_v0p17" in html  # localStorage key


def test_records_embedded_as_json(tmp_path):
    html = render_html(_fixture_records(), tmp_path / "r.html").read_text()
    m = re.search(r"const RECORDS = (\[.*?\]);", html, re.DOTALL)
    assert m, "RECORDS array missing"
    # All three records present
    assert html.count('"path":') >= 3


def test_handles_empty_record_list(tmp_path):
    out = render_html([], tmp_path / "empty.html", title="Empty")
    html = out.read_text()
    assert "Total hits" in html
    assert ">0<" in html or "value\">0" in html  # zero count visible somewhere


def test_path_extension_extracted(tmp_path):
    html = render_html(_fixture_records(), tmp_path / "r.html").read_text()
    # .xml from Groups.xml, .env, (none) for syslog — at least one ext visible
    assert ".xml" in html
    assert ".env" in html


def test_share_extracted_from_unc_and_posix(tmp_path):
    html = render_html(_fixture_records(), tmp_path / "r.html").read_text()
    assert "\\\\\\\\dc01\\\\netlogon" in html or "\\\\dc01\\netlogon" in html
    assert "/home" in html or "/var" in html
