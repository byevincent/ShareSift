"""v0.46: engagement exporters.

Read findings from a SQLite engagement DB and emit operator-facing
report formats:

- **Markdown** — universally useful for pasting into any
  reporting pipeline (GhostWriter, SysReptor, Dradis, plain
  delivery doc).
- **GhostWriter CSV** — direct CSV import format with the
  fields GhostWriter's findings page expects.
- **SysReptor JSON** — JSON shape SysReptor's project-finding
  import accepts.

All three emit the same findings ordering: verified-live first,
then by tier (Black > Red > Yellow > Green), then by host+share+path.
This is the same verifier-first sort applied by ``sharesift sort``
so operators see consistent ranking across all artifacts.
"""

from __future__ import annotations

import csv
import io
import json
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from sharesift.engagement.db import EngagementDB


# Severity mapping: ShareSift tier → GhostWriter / SysReptor levels
_TIER_TO_SEVERITY = {
    "Black": "Critical",
    "Red": "High",
    "Yellow": "Medium",
    "Green": "Low",
    None: "Info",
}


def _ordered_findings(db: "EngagementDB") -> list[dict]:
    """Pull all hits with their host/share/file metadata, sorted
    verifier-first (passed > failed > inconclusive > skipped),
    then tier (Black > Red > Yellow), then host+share+path.

    Returns a list of dicts. Each dict has: host, share, rel_path,
    rule, tier, snippet, ts, verification_status (or empty), size,
    full_path."""
    # Join hits to shares + hosts so a single query returns everything.
    rows = db.query(
        """
        SELECT
            h.host AS host,
            h.share AS share,
            h.rel_path AS rel_path,
            h.rule AS rule,
            h.tier AS tier,
            COALESCE(h.snippet, '') AS snippet,
            h.ts AS ts,
            COALESCE(s.can_write, 0) AS can_write,
            COALESCE(s.can_read, 1) AS can_read,
            COALESCE(f.size, 0) AS size
        FROM hits h
        LEFT JOIN shares s ON h.host = s.host AND h.share = s.share
        LEFT JOIN files f
            ON h.host = f.host AND h.share = f.share AND h.rel_path = f.rel_path
        """
    )

    findings = []
    tier_rank = {"Black": 0, "Red": 1, "Yellow": 2, "Green": 3}

    for row in rows:
        finding = dict(row)
        finding["full_path"] = (
            rf"\\{finding['host']}\{finding['share']}\{finding['rel_path']}"
            if finding["host"] != "local"
            else f"/{finding['share']}/{finding['rel_path']}"
        )
        finding["severity"] = _TIER_TO_SEVERITY.get(finding["tier"], "Info")
        findings.append(finding)

    findings.sort(
        key=lambda f: (
            tier_rank.get(f["tier"], 99),
            f["host"],
            f["share"],
            f["rel_path"],
        )
    )
    return findings


def to_markdown(db: "EngagementDB", *, title: str | None = None) -> str:
    """Engagement findings as a Markdown document.

    Sections:
    - Title + summary stats
    - Findings grouped by tier (Black/Red first)
    - Per-finding: host, share, path, rule, snippet (if present),
      verification status, file size

    Operators paste this into any reporting tool.
    """
    summary = db.summary()
    findings = _ordered_findings(db)

    title = title or "ShareSift Engagement Findings"
    lines: list[str] = [f"# {title}", ""]

    # Summary stats
    lines.append("## Summary")
    lines.append("")
    lines.append(f"- Hosts: {summary['hosts_total']} ({summary['hosts_alive']} alive)")
    lines.append(f"- Shares: {summary['shares_total']} ({summary['shares_writable']} writable)")
    lines.append(f"- Files indexed: {summary['files_total']}")
    lines.append(f"- Hits: **{summary['hits_total']}** total")
    lines.append(f"  - Black: {summary['hits_black']}")
    lines.append(f"  - Red: {summary['hits_red']}")
    lines.append(f"  - Yellow: {summary['hits_yellow']}")
    lines.append("")

    if not findings:
        lines.append("_No hits recorded._")
        return "\n".join(lines)

    # Group by tier
    current_tier: str | None = "__init__"  # sentinel
    for f in findings:
        if f["tier"] != current_tier:
            current_tier = f["tier"]
            lines.append(f"## {f['tier'] or 'Unknown'} tier ({f['severity']})")
            lines.append("")

        # Per-finding entry
        lines.append(f"### {f['rule']}: `{f['rel_path']}`")
        lines.append("")
        lines.append(f"- **Path:** `{f['full_path']}`")
        lines.append(f"- **Host:** {f['host']}")
        lines.append(f"- **Share:** {f['share']}")
        if f["size"]:
            lines.append(f"- **Size:** {f['size']:,} bytes")
        if f["can_write"]:
            lines.append(f"- **Share access:** RW")
        lines.append(f"- **First seen:** {f['ts']}")
        if f["snippet"]:
            lines.append("")
            lines.append("```")
            snippet = f["snippet"][:500]
            lines.append(snippet)
            lines.append("```")
        lines.append("")

    return "\n".join(lines)


def to_ghostwriter_csv(db: "EngagementDB") -> str:
    """Findings as CSV with GhostWriter-compatible columns.

    GhostWriter's findings CSV import expects columns: title,
    severity, description, recommendation, references, finding_type,
    cvss_score, cvss_vector. ShareSift fills:

    - title — "{rule}: {rel_path}"
    - severity — Critical/High/Medium/Low/Info (from tier)
    - description — full path + snippet (markdown-formatted)
    - recommendation — standard "Investigate and rotate" text
    - finding_type — "Credential Exposure"
    - cvss_score, cvss_vector, references — empty (operator fills)
    """
    findings = _ordered_findings(db)
    buf = io.StringIO()
    writer = csv.writer(buf, quoting=csv.QUOTE_ALL)
    writer.writerow([
        "title", "severity", "description", "recommendation",
        "references", "finding_type", "cvss_score", "cvss_vector",
    ])

    for f in findings:
        title = f"{f['rule']}: {f['rel_path']}"
        desc_parts = [
            f"**Path:** `{f['full_path']}`",
            f"**Host:** {f['host']}",
            f"**Share:** {f['share']}" + (" (RW)" if f["can_write"] else " (R)"),
        ]
        if f["snippet"]:
            desc_parts.append("")
            desc_parts.append("```")
            desc_parts.append(f["snippet"][:1000])
            desc_parts.append("```")
        description = "\n\n".join(desc_parts)

        recommendation = (
            "Rotate the credential. If the share access is RW, investigate "
            "whether the file should be removed entirely or relocated to "
            "a properly-ACLed location. Verify whether the credential was "
            "used by reviewing the relevant authentication logs."
        )

        writer.writerow([
            title, f["severity"], description, recommendation,
            "", "Credential Exposure", "", "",
        ])
    return buf.getvalue()


def to_sysreptor_json(db: "EngagementDB", *, project_name: str | None = None) -> str:
    """Findings as a SysReptor JSON document.

    SysReptor's findings import accepts a JSON document with
    project metadata + a findings array. Each finding has title,
    cvss, severity, description, recommendation, references. We
    emit the data fields; SysReptor's templates handle rendering.
    """
    findings = _ordered_findings(db)
    project_name = project_name or "ShareSift Engagement"

    payload = {
        "format": "projects/v1",
        "name": project_name,
        "tags": ["sharesift", "credential-exposure"],
        "findings": [],
    }

    for f in findings:
        finding_data = {
            "title": f"{f['rule']}: {f['rel_path']}",
            "severity": f["severity"].lower(),  # SysReptor uses lowercase
            "summary": (
                f"Credential file `{f['rel_path']}` found on "
                f"`\\\\{f['host']}\\{f['share']}` "
                f"({'writable' if f['can_write'] else 'read-only'})."
            ),
            "description": (
                f"**Full path:** `{f['full_path']}`\n\n"
                f"**Host:** {f['host']}\n\n"
                f"**Share:** {f['share']} "
                f"({'RW' if f['can_write'] else 'R'})\n\n"
                + (f"**Content snippet:**\n\n```\n{f['snippet'][:1000]}\n```\n"
                   if f["snippet"] else "")
            ),
            "recommendation": (
                "Rotate the credential. Investigate share permissions if "
                "the file is writable. Review authentication logs."
            ),
            "metadata": {
                "sharesift_rule": f["rule"],
                "first_seen": f["ts"],
                "share_writable": bool(f["can_write"]),
            },
        }
        payload["findings"].append(finding_data)

    return json.dumps(payload, indent=2)
