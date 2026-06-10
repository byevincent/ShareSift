#!/usr/bin/env python3
"""v0.50 full benchmark sweep — batched."""
from __future__ import annotations

import json
import sys
import warnings
from pathlib import Path

warnings.filterwarnings("ignore")
sys.path.insert(0, "/home/george-5090/projects/truffler/src")

from sharesift.path import PathClassifier
from sharesift.content_rules import ContentRuleEngine

REPO = Path("/home/george-5090/projects/truffler")
RANKS = {"Black": 4, "Red": 3, "Yellow": 2, "Green": 1, None: 0}

print("[load] PathClassifier + ContentRuleEngine", flush=True)
clf = PathClassifier()
eng = ContentRuleEngine()


def cascade_tiers(paths: list[str]) -> list[str | None]:
    """Batched cascade scoring — path classifier + rule engine MAX-tier."""
    path_results = clf.score_batch(paths)
    out = []
    for path, pres in zip(paths, path_results):
        rv = eng.evaluate(path, None)
        a, b = RANKS.get(pres.tier, 0), RANKS.get(rv.tier, 0)
        out.append(pres.tier if a >= b else rv.tier)
    return out


def score_juicy(name: str, items: list[tuple[str, bool]]) -> dict:
    print(f"[score] {name} ({len(items)} paths)", flush=True)
    paths = [p for p, _ in items]
    labels = [j for _, j in items]
    tiers = cascade_tiers(paths)
    tp = fp = tn = fn = 0
    tier_dist: dict[str, int] = {}
    for is_juicy, t in zip(labels, tiers):
        tier_dist[str(t)] = tier_dist.get(str(t), 0) + 1
        kept = t is not None and t != "Green"
        if is_juicy and kept: tp += 1
        elif is_juicy: fn += 1
        elif kept: fp += 1
        else: tn += 1
    P = tp / max(1, tp + fp)
    R = tp / max(1, tp + fn) if (tp + fn) else float("nan")
    F1 = 2 * P * R / max(1e-9, P + R) if (tp + fn) else float("nan")
    return {
        "name": name, "N": len(items),
        "TP": tp, "FP": fp, "TN": tn, "FN": fn,
        "P": round(P, 3), "R": round(R, 3), "F1": round(F1, 3),
        "tiers": tier_dist,
    }


def score_recall_only(name: str, paths: list[str], gt: dict[str, bool]) -> dict:
    print(f"[score] {name} ({len(paths)} paths)", flush=True)
    tiers = cascade_tiers(paths)
    tp = fn = 0
    for path, t in zip(paths, tiers):
        label = gt.get(path.lower())
        if label is None: continue
        kept = t is not None
        if label and kept: tp += 1
        elif label: fn += 1
    R = tp / max(1, tp + fn) if (tp + fn) else float("nan")
    return {"name": name, "N": len(paths), "TP": tp, "FN": fn, "R": round(R, 3)}


results = []

for bench in ["metasploitable3", "metasploitable2", "diskforge_win10"]:
    paths = (REPO / "data" / "external" / bench / "file_list.txt").read_text().splitlines()
    gt = {}
    for line in (REPO / "data" / "external" / bench / "ground_truth.jsonl").read_text().splitlines():
        if line.strip():
            r = json.loads(line)
            gt[r["path"].lower()] = r.get("has_credential")
    results.append(score_recall_only(f"{bench} cascade-recall", paths, gt))


# diskforge_winshare_v1 — real-share-content corpus with full P/R/F1.
# Scored at all three keep policies (Yellow+ / Red+ / Black) — a tiered
# tool measured at one threshold lies about what it's actually doing.
ws_paths_file = REPO / "data" / "external" / "diskforge_winshare_v1" / "file_list.txt"
ws_gt_file = REPO / "data" / "external" / "diskforge_winshare_v1" / "ground_truth.jsonl"
if ws_paths_file.exists():
    ws_paths = ws_paths_file.read_text().splitlines()
    ws_labels = []
    for line in ws_gt_file.read_text().splitlines():
        if line.strip():
            r = json.loads(line)
            ws_labels.append((r["path"], bool(r["has_credential"])))
    items = ws_labels
    print(f"[score] diskforge_winshare_v1 (3 keep policies, {len(items)} paths)", flush=True)
    paths = [p for p, _ in items]
    labels = [j for _, j in items]
    tiers = cascade_tiers(paths)
    for label_name, threshold in [("Yellow+", 2), ("Red+", 3), ("Black-only", 4)]:
        tp = fp = tn = fn = 0
        for label, t in zip(labels, tiers):
            kept = RANKS.get(t, 0) >= threshold
            if label and kept: tp += 1
            elif label: fn += 1
            elif kept: fp += 1
            else: tn += 1
        P = tp / max(1, tp + fp)
        R = tp / max(1, tp + fn) if (tp + fn) else float("nan")
        F1 = 2 * P * R / max(1e-9, P + R) if (tp + fn) else float("nan")
        results.append({
            "name": f"diskforge_winshare_v1 ShareSift ({label_name})",
            "N": len(items),
            "TP": tp, "FP": fp, "TN": tn, "FN": fn,
            "P": round(P, 3), "R": round(R, 3), "F1": round(F1, 3),
        })

    # Same corpus scored with upstream Snaffler defaults only — head-to-head.
    try:
        from pysnaffler.ruleset import SnafflerRuleSet

        snaffler = SnafflerRuleSet.load_default_ruleset()

        class _SmbFile:
            __slots__ = ("fullpath", "name", "size")

            def __init__(self, fullpath: str, name: str, size: int = 1024):
                self.fullpath = fullpath
                self.name = name
                self.size = size

        def snaffler_tier(path: str) -> str | None:
            name = path.replace("\\", "/").rsplit("/", 1)[-1] or path
            try:
                keep, rules = snaffler.enum_file(_SmbFile(path, name))
            except Exception:
                return None
            if not keep or not rules:
                return None
            best = 0
            for r in rules:
                t = getattr(r, "triage", None)
                tname = t.name if hasattr(t, "name") else str(t)
                best = max(best, RANKS.get(tname, 0))
            inv = {v: k for k, v in RANKS.items()}
            return inv.get(best)

        print(f"[score] diskforge_winshare_v1 Snaffler-only ({len(items)} paths)", flush=True)
        snaffler_tiers = [snaffler_tier(p) for p in paths]
        for label_name, threshold in [("Yellow+", 2), ("Red+", 3), ("Black-only", 4)]:
            tp = fp = tn = fn = 0
            for label, t in zip(labels, snaffler_tiers):
                kept = RANKS.get(t, 0) >= threshold
                if label and kept: tp += 1
                elif label: fn += 1
                elif kept: fp += 1
                else: tn += 1
            P = tp / max(1, tp + fp)
            R = tp / max(1, tp + fn) if (tp + fn) else float("nan")
            F1 = 2 * P * R / max(1e-9, P + R) if (tp + fn) else float("nan")
            results.append({
                "name": f"diskforge_winshare_v1 Snaffler-only ({label_name})",
                "N": len(items),
                "TP": tp, "FP": fp, "TN": tn, "FN": fn,
                "P": round(P, 3), "R": round(R, 3), "F1": round(F1, 3),
            })
    except ImportError:
        print("[skip] pysnaffler not installed — head-to-head omitted "
              "(install via `uv sync --group pysnaffler-integration`)",
              flush=True)


def load_label_juicy(jsonl: Path) -> list[tuple[str, bool]]:
    items = []
    for line in jsonl.read_text().splitlines():
        if line.strip():
            r = json.loads(line)
            items.append((r["path"], r["label"] == "juicy"))
    return items


results.append(score_juicy(
    "snaffler_blind (Windows, 500)",
    load_label_juicy(REPO / "data" / "eval" / "snaffler_blind_benchmark.jsonl"),
))
results.append(score_juicy(
    "linux_rule_blind (Linux, 500)",
    load_label_juicy(REPO / "data" / "eval" / "linux_rule_blind_benchmark.jsonl"),
))

items = []
for line in (REPO / "data" / "eval" / "writeups" / "labeled_paths.jsonl").read_text().splitlines():
    if line.strip():
        r = json.loads(line)
        items.append((r["path"], bool(r.get("is_juicy"))))
results.append(score_juicy("writeups labeled (1499)", items))

for name, manifest in [
    ("constructed_share (1117)", REPO / "data" / "external" / "constructed_share_manifest.jsonl"),
    ("constructed_share_v2 (199)", REPO / "data" / "external" / "constructed_share_v2_manifest.jsonl"),
]:
    items = []
    for line in manifest.read_text().splitlines():
        if line.strip():
            r = json.loads(line)
            items.append((r["original_path"], bool(r.get("is_juicy_label"))))
    results.append(score_juicy(name, items))

for source_name, jsonl_path in [
    ("hacktricks (870)", REPO / "data" / "external" / "hacktricks" / "extracted_paths.jsonl"),
    ("kape (904)", REPO / "data" / "external" / "kape" / "extracted_paths.jsonl"),
    ("peas (73)", REPO / "data" / "external" / "peas" / "extracted_paths.jsonl"),
    ("engagement_corpus (401)", REPO / "data" / "external" / "engagement_corpus" / "extracted_paths_clean.jsonl"),
]:
    items = []
    for line in jsonl_path.read_text().splitlines():
        if line.strip():
            r = json.loads(line)
            extracted_tier = r.get("tier")
            is_juicy = RANKS.get(extracted_tier, 0) >= RANKS["Yellow"]
            items.append((r["verbatim_path"], is_juicy))
    results.append(score_juicy(source_name, items))


print()
print("=" * 100)
print(f"{'Benchmark':<40s} {'N':>5s}  {'TP':>5s} {'FP':>5s} {'TN':>5s} {'FN':>5s}  {'P':>5s} {'R':>5s} {'F1':>5s}")
print("-" * 100)
for r in results:
    if "P" in r:
        print(f"{r['name']:<40s} {r['N']:>5d}  {r['TP']:>5d} {r['FP']:>5d} {r['TN']:>5d} {r['FN']:>5d}  {r['P']:>5.3f} {r['R']:>5.3f} {r['F1']:>5.3f}")
    else:
        print(f"{r['name']:<40s} {r['N']:>5d}  {r['TP']:>5d} {'':>5s} {'':>5s} {r['FN']:>5d}  {'':>5s} {r['R']:>5.3f} {'':>5s}")
print("=" * 100)

out = REPO / "reports" / "v0p50_benchmark_sweep.json"
out.parent.mkdir(exist_ok=True)
out.write_text(json.dumps(results, indent=2))
print(f"\nResults saved: {out}", flush=True)
