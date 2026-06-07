"""Interactive HTML report for ``sharesift verify`` / ``sharesift scan-files`` output.

Produces a single self-contained ``report.html`` operators can open in
any browser, sort/filter the hits, and click into individual records.
No CDN calls — works in air-gapped engagement environments.

Public entry point::

    from sharesift.report import render_html
    render_html(records, output_path="report.html", title="...")
"""

from __future__ import annotations

from sharesift.report.html import render_html

__all__ = ["render_html"]
