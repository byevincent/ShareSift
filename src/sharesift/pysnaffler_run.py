"""Convenience helper to build a pysnaffler ruleset with ShareSift loaded.

Spares operators the boilerplate of constructing a ``SnafflerRuleSet``
and wiring in the ShareSift rules by hand. Three composable layers:

* ``include_defaults`` — pysnaffler's bundled Snaffler ruleset (81 rules).
* ``include_extras`` — ShareSift's catch-up + blind-spot + binary
  preprocessor rules (see ``sharesift.rules.extra_rules``). 7 catch-up
  rules close the gap between pysnaffler's bundle and current Snaffler;
  7 blind-spot rules add wp-config.php/config.inc.php/etc. that v0.12
  confirmed Snaffler missed; 1 binary preprocessor discards image/font/
  compiled-binary extensions upstream of Stage 1.
* The ShareSift path classifier (always loaded) — ML-augmented triage.

Order matters: the binary preprocessor is loaded FIRST so its
``Discard`` short-circuits the rule chain before any Keep rule runs;
then defaults; then catch-up + blind-spot Keep rules; then the ML
path classifier last.

Example::

    from sharesift.pysnaffler_run import build_ruleset
    from pysnaffler.snaffler import pySnaffler

    # Full v0.14 stack: pysnaffler defaults + Snaffler catch-up + v0.12
    # blind-spot rules + binary preprocessor + ShareSift ML path rule
    ruleset = build_ruleset(include_defaults=True, include_extras=True)
    snaffler = pySnaffler(ruleset=ruleset, dry_run=True)
"""

from __future__ import annotations

from pysnaffler.ruleset import SnafflerRuleSet

from sharesift.pysnaffler_rule import ShareSiftPathRule
from sharesift.rules import get_extra_rules


def build_ruleset(
    include_defaults: bool = False,
    include_extras: bool = True,
    include_parsers: bool = False,
    classifier=None,
) -> SnafflerRuleSet:
    """Return a :class:`SnafflerRuleSet` with the ShareSift stack loaded.

    Parameters
    ----------
    include_defaults:
        If ``True``, load pysnaffler's bundled Snaffler defaults (81 rules)
        first. Off by default for ML-only mode; turn on for the v0.14
        Snaffler-beating stack.
    include_extras:
        If ``True`` (default), load ShareSift's catch-up + blind-spot +
        binary preprocessor rules from ``sharesift.rules.extra_rules``.
        Has no effect when ``include_defaults=False`` because the catch-up
        rules supplement defaults — though the blind-spot rules and binary
        preprocessor still apply standalone.
    classifier:
        Optional pre-built :class:`sharesift.path.PathClassifier` for
        tests or specialized configs. ``None`` triggers default model
        loading.
    """
    if include_defaults:
        ruleset = SnafflerRuleSet.load_default_ruleset()
    else:
        ruleset = SnafflerRuleSet()
    if include_extras:
        for rule in get_extra_rules():
            ruleset.load_rule(rule)
    if include_parsers:
        from sharesift.pysnaffler_parser_rule import ShareSiftStructuredParserRule
        ruleset.load_rule(ShareSiftStructuredParserRule())
    ruleset.load_rule(ShareSiftPathRule(classifier=classifier))
    return ruleset
