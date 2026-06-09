"""Output formatters for ShareSift records.

v0.36 step 4: ``snaffler_tsv`` provides the 11-column TSV line
format Snaffler emits with ``-y``. The format is what SnafflerParser
/ Efflanrs / Parsler / snafflepy already parse — emitting it lets
ShareSift slot into existing operator tooling without rework.
"""

from sharesift.output.snaffler_tsv import (
    record_to_snaffler_tsv,
    iter_snaffler_tsv_lines,
)

__all__ = ["record_to_snaffler_tsv", "iter_snaffler_tsv_lines"]
