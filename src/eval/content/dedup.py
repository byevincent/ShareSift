"""Near-duplicate snippet removal via MinHash + LSH.

Wiz LoRA recipe explicitly calls out MinHash dedup as the secret-dataset
hygiene step. Without it, code-corpus snippets full of common boilerplate
(license headers, default configs, import lists) dominate the dataset
and the model learns "any code-like snippet is fine" rather than the
signal that distinguishes secret-bearing code.

We use ``datasketch.MinHashLSH`` with a Jaccard-similarity threshold
of 0.8 (default) — pairs at or above this threshold are considered
near-duplicates. The retained representative is whichever member of
the cluster was inserted first; deterministic given the input order.

Tokenization for hashing uses simple whitespace splits; secret-bearing
snippets vary mostly in non-token surroundings (which lines of import
boilerplate, where in the file), so the simple tokenization captures
the relevant similarity.
"""

from __future__ import annotations

from datasketch import MinHash, MinHashLSH


_NUM_PERM = 128
_DEFAULT_THRESHOLD = 0.8


def _minhash(text: str, num_perm: int = _NUM_PERM) -> MinHash:
    mh = MinHash(num_perm=num_perm)
    for token in text.split():
        mh.update(token.encode("utf-8"))
    return mh


def dedup_snippets(
    snippets: list[str],
    *,
    threshold: float = _DEFAULT_THRESHOLD,
    num_perm: int = _NUM_PERM,
) -> tuple[list[str], int]:
    """Return (kept_snippets, n_dropped) after near-duplicate removal.

    First-wins: when two snippets are near-duplicates, the one earlier
    in the input is kept. Ordering of the output preserves the input
    ordering of the kept snippets.
    """
    lsh = MinHashLSH(threshold=threshold, num_perm=num_perm)
    kept: list[str] = []
    dropped = 0
    for i, text in enumerate(snippets):
        mh = _minhash(text, num_perm=num_perm)
        if lsh.query(mh):
            dropped += 1
            continue
        lsh.insert(str(i), mh)
        kept.append(text)
    return kept, dropped
