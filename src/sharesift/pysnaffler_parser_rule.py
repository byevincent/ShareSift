"""ShareSift structured parsers as a pysnaffler ContentsEnumeration rule.

Mirrors the pattern used by :class:`ShareSiftContentRule` for v0p7 —
wraps the dispatch in ``sharesift.parsers`` as one pysnaffler-loadable
rule. When the rule fires it returns the highest-confidence extracted
field as the "match", with the credential's tier mapped from the
extractor's confidence (Black ≥ 0.95, Red ≥ 0.80, Yellow ≥ 0.50).

Loadable via ``build_ruleset(..., include_parsers=True)``.
"""

from __future__ import annotations

from pysnaffler.rules.constants import (
    EnumerationScope,
    MatchAction,
    MatchListType,
    MatchLoc,
    Triage,
)
from pysnaffler.rules.contents import SnafflerContentsEnumerationRule

from sharesift.parsers import parse_file


def _confidence_to_triage(conf: float) -> Triage:
    if conf >= 0.95:
        return Triage.Black
    if conf >= 0.80:
        return Triage.Red
    if conf >= 0.50:
        return Triage.Yellow
    return Triage.Green


class ShareSiftStructuredParserRule(SnafflerContentsEnumerationRule):
    """Single rule that dispatches to every registered structured parser
    in :mod:`sharesift.parsers`.

    Caches the highest-confidence extraction per file path so the ranker
    can read it back as a feature without re-parsing.
    """

    def __init__(self, rule_name: str = "ShareSiftStructuredParser") -> None:
        super().__init__(
            enumerationScope=EnumerationScope.ContentsEnumeration,
            ruleName=rule_name,
            matchAction=MatchAction.Snaffle,
            relayTargets=[],
            description=(
                "ShareSift structured config parsers — dispatches the file's "
                "content to format-specific parsers (web.config, unattend.xml, "
                "tomcat-users.xml, Groups.xml/cpassword, .pgpass, .my.cnf, "
                ".npmrc, FileZilla SiteManager, WinSCP.ini, Maven settings, "
                "KeePass.config, OpenVPN .ovpn, application.properties / Spring "
                "YAML). Higher precision than the generic regex content rules."
            ),
            matchLocation=MatchLoc.FileContentAsString,
            wordListType=MatchListType.Regex,
            matchLength=0,
            wordList=[],
            triage=Triage.Red,  # Placeholder — dynamic per-file via confidence
        )
        self.extractions: dict[str, list] = {}  # path -> list of ExtractedField

    def match(self, data, fullpath: str | None = None, **kwargs) -> bool:
        if data is None or fullpath is None:
            return False
        try:
            content = data.decode("utf-8", errors="replace") if isinstance(data, bytes) else data
        except Exception:
            return False
        try:
            fields = parse_file(fullpath, content)
        except Exception:
            return False
        if not fields:
            return False
        self.extractions[fullpath] = fields
        return True

    def determine_action(self, data, fullpath: str | None = None, **kwargs):
        if not self.match(data, fullpath=fullpath, **kwargs):
            return None, None
        fields = self.extractions.get(fullpath or "", [])
        if not fields:
            return None, None
        # Pick the highest-confidence extraction for the file's tier
        best = max(fields, key=lambda f: f.confidence)
        return MatchAction.Snaffle, _confidence_to_triage(best.confidence)
