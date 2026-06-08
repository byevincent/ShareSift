"""v0.20: Content-rule engine — runs the 88 vendored Snaffler rules
against ``(filename, content)`` during ``Scanner.scan_batch``.

The v0.19 themed benchmark surfaced ``content-ood`` (files with
benign-looking filenames that hide credentials inside) as the
dominant Stage-2 failure mode. The rules in
``src/sharesift/rules/snaffler_default.json`` already define what
the path classifier can't see — they just weren't executing in the
main Scanner flow. This engine wires them in.

The engine ignores ``ShareName`` rules (no share-level concept in
file-based scanning), ``Discard`` rules (those are for the
enumeration loop, not content-decision). It executes the rest:

* ``FileExtension`` — matched against ``Path(filename).suffix``
* ``FileName``      — matched against ``Path(filename).name``
* ``FilePath``      — matched against the full path string
* ``FileContentAsString`` — matched against the content body

Wordlist semantics map directly:

* ``Exact``  → fully-anchored regex match
* ``Contains`` → unanchored search
* ``StartsWith`` / ``EndsWith`` → anchored at the obvious end
* ``Regex`` → compiled as-is

The engine is intentionally cheap — pure regex compilation at
init, no ML. Designed to run before the LoRA classifier as the fast
cascade tier.

The ``extra_rules.py`` v0.12 blind-spot + Gitleaks-derived modern
SaaS rules are NOT loaded yet (they're constructed as
``SnaffleRule`` instances tied to the optional pysnaffler dep).
Port those to JSON in v0.20.1 if Phase 1 metrics show they'd add
material recall.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Literal

_RULES_JSON = Path(__file__).resolve().parent / "rules" / "snaffler_default.json"

Tier = Literal["Black", "Red", "Yellow", "Green"]
MatchLocation = Literal["FileExtension", "FileName", "FilePath", "FileContentAsString"]
_TIER_RANK: dict[str, int] = {"Black": 4, "Red": 3, "Yellow": 2, "Green": 1}


@dataclass(frozen=True)
class RuleMatch:
    """One rule firing against a file."""

    rule_name: str
    tier: Tier
    action: str  # Snaffle / Relay / CheckForKeys
    match_location: MatchLocation
    matched_pattern: str  # the wordlist entry that hit
    matched_span: str  # the substring that hit (truncated to 200 chars)


@dataclass(frozen=True)
class RuleVerdict:
    """Aggregate result of running every applicable rule against one file."""

    matches: list[RuleMatch] = field(default_factory=list)

    @property
    def tier(self) -> Tier | None:
        """Highest tier among the firing rules, or None if nothing fired."""
        if not self.matches:
            return None
        return max(self.matches, key=lambda m: _TIER_RANK[m.tier]).tier

    def has_any(self) -> bool:
        return bool(self.matches)


@dataclass
class _CompiledRule:
    rule_name: str
    tier: Tier
    action: str
    location: MatchLocation
    patterns: list[re.Pattern[str]]
    raw_wordlist: list[str]


def _compile_one(pattern: str, wordlist_type: str) -> re.Pattern[str]:
    if wordlist_type == "Regex":
        return re.compile(pattern, re.IGNORECASE)
    if wordlist_type == "Exact":
        return re.compile(rf"^{pattern}$", re.IGNORECASE)
    if wordlist_type == "Contains":
        return re.compile(pattern, re.IGNORECASE)
    if wordlist_type == "StartsWith":
        return re.compile(rf"^{pattern}", re.IGNORECASE)
    if wordlist_type == "EndsWith":
        return re.compile(rf"{pattern}$", re.IGNORECASE)
    # Conservative default — treat unknown as substring match.
    return re.compile(pattern, re.IGNORECASE)


class ContentRuleEngine:
    """Compile + evaluate the vendored content-side rules.

    Construct once at process startup, then call ``.evaluate(path,
    content)`` per file. The engine is stateless after init.
    """

    def __init__(self, rules_json_path: Path | None = None) -> None:
        path = rules_json_path or _RULES_JSON
        data = json.loads(path.read_text(encoding="utf-8"))
        self._compiled: list[_CompiledRule] = []
        for rec in data.get("rules", []):
            location = rec.get("match_location")
            action = rec.get("match_action")
            tier = rec.get("triage")
            wl_type = rec.get("wordlist_type", "Exact")
            wordlist = rec.get("wordlist") or []
            # We skip Discard (handled separately — those are for the
            # enumeration loop, not credential detection) and ShareName
            # (no share-level concept in file-based scanning).
            if action == "Discard" or location == "ShareName":
                continue
            if tier not in _TIER_RANK or not wordlist:
                continue
            try:
                compiled = [_compile_one(p, wl_type) for p in wordlist]
            except re.error:
                # Skip rules with malformed patterns (the port has been
                # audited but be defensive).
                continue
            self._compiled.append(_CompiledRule(
                rule_name=rec["rule_name"],
                tier=tier,
                action=action,
                location=location,
                patterns=compiled,
                raw_wordlist=wordlist,
            ))

    def __len__(self) -> int:
        return len(self._compiled)

    def evaluate(self, path: str, content: str | None) -> RuleVerdict:
        """Run every applicable rule against the file.

        ``content`` may be None when only path-side rules should fire
        (e.g., when the file failed to read). FileContentAsString rules
        are skipped in that case.
        """
        filename = Path(path).name
        extension = Path(path).suffix or ""
        matches: list[RuleMatch] = []
        for rule in self._compiled:
            target = self._target_for(rule.location, path, filename, extension, content)
            if target is None:
                continue
            for raw_pattern, compiled in zip(rule.raw_wordlist, rule.patterns):
                m = compiled.search(target)
                if m is not None:
                    span = m.group(0)
                    if len(span) > 200:
                        span = span[:200]
                    matches.append(RuleMatch(
                        rule_name=rule.rule_name,
                        tier=rule.tier,
                        action=rule.action,
                        match_location=rule.location,
                        matched_pattern=raw_pattern,
                        matched_span=span,
                    ))
                    # One match per rule is enough — don't double-count
                    # the same rule firing on multiple patterns within
                    # its own wordlist.
                    break
        return RuleVerdict(matches=matches)

    @staticmethod
    def _target_for(
        location: MatchLocation,
        path: str,
        filename: str,
        extension: str,
        content: str | None,
    ) -> str | None:
        if location == "FileExtension":
            return extension
        if location == "FileName":
            return filename
        if location == "FilePath":
            return path
        if location == "FileContentAsString":
            return content  # None signals "skip" upstream
        return None


@lru_cache(maxsize=1)
def get_default_engine() -> ContentRuleEngine:
    """Singleton accessor — the engine is large enough that the
    Scanner shouldn't recompile per call."""
    return ContentRuleEngine()
