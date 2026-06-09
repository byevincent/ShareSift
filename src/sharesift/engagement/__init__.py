"""v0.40: SQLite engagement datastore.

One ``.sharesift.db`` per engagement holds hosts, shares, files,
and hits across multi-day pentests. Operators query it directly
(``sharesift query``) or feed it back into ShareSift commands for
resume / dedup workflows.

This matches the ``smbcrawler``-shape that's become the operator-
preferred pattern for share-based findings: structured datastore
that survives crashes, supports incremental crawls, and answers
"what did we find at this engagement?" without re-grepping JSONL.
"""

from sharesift.engagement.db import EngagementDB
from sharesift.engagement.export import (
    to_ghostwriter_csv,
    to_markdown,
    to_sysreptor_json,
)

__all__ = [
    "EngagementDB",
    "to_ghostwriter_csv",
    "to_markdown",
    "to_sysreptor_json",
]
