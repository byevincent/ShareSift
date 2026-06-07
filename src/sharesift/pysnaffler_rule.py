"""ShareSift PathClassifier as a pysnaffler ``SnaffleRule``.

Wires the v0.5 router-based path classifier into pysnaffler's enumeration
loop so an operator running ``pysnaffler`` against an SMB target gets
ShareSift's ML-augmented triage applied alongside (or in place of) the
default Snaffler rule pack.

Integration model — pysnaffler walks shares via SMB, calling
``ruleset.enum_file(smbfile)`` on every discovered file. Each rule's
``determine_action()`` returns ``(MatchAction, Triage)`` — non-matching
rules return ``(None, None)`` and are ignored. This module provides a
single rule class whose ``determine_action`` calls a cached
:class:`sharesift.path.PathClassifier`, maps the predicted tier
(``Black``/``Red``/``Yellow``) to pysnaffler's ``Triage`` enum, and
queues the file for snaffling (``MatchAction.Snaffle``). Below-tier
paths return ``(None, None)``.

Both per-shape models (Windows for UNC, Linux for everything else) are
loaded once at construction; per-file inference is sub-millisecond.

Usage::

    from pysnaffler.ruleset import SnafflerRuleSet
    from sharesift.pysnaffler_rule import ShareSiftPathRule

    ruleset = SnafflerRuleSet()
    ruleset.load_rule(ShareSiftPathRule())
    # ... pass ruleset to pySnaffler(...)

Operators who want Snaffler's default rules ALSO active (hybrid mode)
can call ``SnafflerRuleSet.load_default_ruleset()`` first and then
``load_rule(ShareSiftPathRule())`` on the same ruleset.
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional

from pysnaffler.rules.constants import (
    EnumerationScope,
    MatchAction,
    MatchListType,
    MatchLoc,
    Triage,
)
from pysnaffler.rules.rule import SnaffleRule

from sharesift.path import PathClassifier

# ShareSift tier label → pysnaffler Triage enum. ShareSift doesn't emit
# Green or Gray; below-threshold paths return (None, None) and never
# enter this map.
_TIER_TO_TRIAGE = {
    "Black": Triage.Black,
    "Red": Triage.Red,
    "Yellow": Triage.Yellow,
}

# Sentinel: a SnaffleRule's `__init__` runs `_SnaffleRule__convert_wordlist`
# which compiles every entry in ``wordList`` as a regex. We pass an empty
# list so the conversion is a no-op — our rule overrides ``match`` and
# never consults the wordlist anyway.
_EMPTY_WORDLIST: list[str] = []


class ShareSiftPathRule(SnaffleRule):
    """SnaffleRule that delegates the match decision to ShareSift.

    Construction loads the path classifier (both Windows and Linux
    models) eagerly so first-file latency is not paid mid-enumeration.
    For test environments that want to swap in a mock classifier, pass
    one via ``classifier=``; otherwise the default constructor is used.

    The base ``SnaffleRule`` constructor demands a wordlist for its
    regex-match path. We pass an empty list — ``match()`` is overridden
    below and never consults it.
    """

    def __init__(
        self,
        classifier: PathClassifier | None = None,
        rule_name: str = "ShareSiftPathClassifier",
    ) -> None:
        super().__init__(
            enumerationScope=EnumerationScope.FileEnumeration,
            RuleName=rule_name,
            matchAction=MatchAction.Snaffle,
            relayTargets=[],
            description=(
                "ShareSift v0.5 ML path classifier (LightGBM, isotonic-"
                "calibrated). Routes by path shape: UNC paths score via "
                "the Windows model, all others via the Linux model."
            ),
            matchLocation=MatchLoc.FilePath,
            wordListType=MatchListType.Regex,
            matchLength=0,
            wordList=_EMPTY_WORDLIST,
            triage=Triage.Black,  # Placeholder; the per-file triage comes from the classifier.
        )
        self._classifier = classifier if classifier is not None else PathClassifier()

    def match(
        self,
        smbfile,
        fullpath: Optional[str] = None,
        name: Optional[str] = None,
        size: Optional[int] = None,
        **kwargs,
    ) -> bool:
        """True iff the classifier emits a non-null tier for the path.

        Mirrors ``SnafflerFileRule.match()``'s argument shape — pysnaffler
        either passes a populated ``smbfile`` or the unpacked
        ``fullpath/name/size`` triple from the dry-run path.
        """
        path = self._extract_path(smbfile, fullpath)
        if not path:
            return False
        result = self._classifier.score(path)
        return result.tier is not None

    def determine_action(
        self,
        smbfile,
        fullpath: Optional[str] = None,
        name: Optional[str] = None,
        size: Optional[int] = None,
        **kwargs,
    ):
        """Returns ``(MatchAction.Snaffle, Triage.<tier>)`` for flagged
        paths; ``(None, None)`` otherwise.

        Overrides the base implementation rather than calling ``match()``
        + reading ``self.triage`` because the per-file triage is dynamic
        (depends on the model's probability), not a static rule property.
        """
        path = self._extract_path(smbfile, fullpath)
        if not path:
            return None, None
        result = self._classifier.score(path)
        if result.tier is None:
            return None, None
        return MatchAction.Snaffle, _TIER_TO_TRIAGE[result.tier]

    @staticmethod
    def _extract_path(smbfile, fullpath: Optional[str]) -> Optional[str]:
        """Resolve the path string from pysnaffler's two-form call.

        pysnaffler's ``SnafflerFileRule.match()`` accepts either a
        populated ``smbfile`` (used during live SMB enumeration) or the
        unpacked ``fullpath/name/size`` triple (used by ``enum_unc()``
        and the ``whatif`` dry-run path). We mirror that contract.
        """
        if smbfile is not None and getattr(smbfile, "fullpath", None):
            return smbfile.fullpath
        return fullpath
