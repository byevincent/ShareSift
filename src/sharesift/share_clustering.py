"""Share-similarity clustering — dedup near-duplicate share hits at top-N display.

Real engagements often discover the same logical share replicated under
different names: ``\\\\dc01\\NETLOGON`` and ``\\\\dc02\\NETLOGON`` host
identical content via AD replication; ``\\\\fs01\\projects$`` and
``\\\\fs01-bk\\projects$`` are backup copies. Without dedup, an analyst
reading the top-50 ranker output sees the same credential file 4 times.

This module clusters shares by filename TF-IDF similarity, picks one
canonical share per cluster, and demotes hits from non-canonical
shares when their filename also appears in the canonical share's hits.
The ranker output's per-hit score is preserved; this is purely a
post-processing dedup step.

Inspired by NetSPI PowerHuntShares 2.0's share-similarity clustering
("fix once, fix 90%" framing for ACL remediation).
"""

from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import dataclass


_UNC_RE = re.compile(r"^\\\\([^\\]+)\\([^\\]+)")


def _share_of(path: str) -> str | None:
    """Extract ``\\\\host\\share`` from a UNC path, lowercased for matching."""
    m = _UNC_RE.match(path)
    if not m:
        return None
    return f"\\\\{m.group(1).lower()}\\{m.group(2).lower()}"


def _basename(path: str) -> str:
    return path.replace("/", "\\").rsplit("\\", 1)[-1].lower()


@dataclass(frozen=True)
class ShareCluster:
    """Group of shares deemed near-duplicates."""
    canonical: str       # share kept "primary" for display
    members: tuple[str, ...]  # all shares in the cluster (incl. canonical)


def cluster_shares(
    hits: list[dict],
    *,
    similarity_threshold: float = 0.85,
    min_overlap: int = 3,
) -> list[ShareCluster]:
    """Group shares appearing in ``hits`` into similarity clusters.

    ``hits`` is a list of records with at least a ``"path"`` key.
    Returns list of clusters; each cluster has a canonical share
    (chosen as the lexically-earliest share name in the cluster, for
    determinism).

    Algorithm: build a set of basenames per share, compute Jaccard
    similarity between share pairs. Group with single-linkage above
    threshold.
    """
    # Filenames per share
    per_share: dict[str, set[str]] = defaultdict(set)
    for hit in hits:
        share = _share_of(hit.get("path", ""))
        if not share:
            continue
        per_share[share].add(_basename(hit["path"]))

    shares = sorted(per_share.keys())
    if len(shares) < 2:
        return [ShareCluster(canonical=s, members=(s,)) for s in shares]

    # Build adjacency via Jaccard similarity
    parent = {s: s for s in shares}
    def _find(s):
        while parent[s] != s:
            parent[s] = parent[parent[s]]
            s = parent[s]
        return s
    def _union(a, b):
        ra, rb = _find(a), _find(b)
        if ra != rb:
            parent[rb] = ra

    for i, a in enumerate(shares):
        fa = per_share[a]
        if len(fa) < min_overlap:
            continue
        for b in shares[i + 1:]:
            fb = per_share[b]
            if len(fb) < min_overlap:
                continue
            inter = len(fa & fb)
            if inter < min_overlap:
                continue
            union = len(fa | fb)
            jaccard = inter / max(1, union)
            if jaccard >= similarity_threshold:
                _union(a, b)

    # Materialize clusters
    clusters: dict[str, list[str]] = defaultdict(list)
    for s in shares:
        clusters[_find(s)].append(s)
    return [
        ShareCluster(canonical=sorted(members)[0], members=tuple(sorted(members)))
        for members in clusters.values()
    ]


def dedup_hits_within_clusters(
    hits: list[dict],
    clusters: list[ShareCluster],
) -> list[dict]:
    """Mark hits as ``"cluster_duplicate": True`` if their basename
    appears in the cluster's canonical share. Returns the same list of
    hits with the field set; does not remove records (so the operator
    can still inspect duplicates if they want)."""
    canonical_basenames: dict[str, set[str]] = {}
    share_to_cluster: dict[str, ShareCluster] = {}
    for cl in clusters:
        share_to_cluster.update({m: cl for m in cl.members})
        canonical_hits = [h for h in hits if _share_of(h.get("path", "")) == cl.canonical]
        canonical_basenames[cl.canonical] = {_basename(h["path"]) for h in canonical_hits}

    for hit in hits:
        share = _share_of(hit.get("path", ""))
        cl = share_to_cluster.get(share)
        if cl is None or share == cl.canonical:
            hit["cluster_duplicate"] = False
            hit["cluster_canonical"] = share
            continue
        bn = _basename(hit["path"])
        if bn in canonical_basenames[cl.canonical]:
            hit["cluster_duplicate"] = True
            hit["cluster_canonical"] = cl.canonical
        else:
            hit["cluster_duplicate"] = False
            hit["cluster_canonical"] = cl.canonical
    return hits


__all__ = ["ShareCluster", "cluster_shares", "dedup_hits_within_clusters"]
