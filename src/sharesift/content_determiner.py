"""v0.20: ContentDeterminer — unified cascade over the content-side
detection mechanisms.

ShareSift accumulated four independent ways to look INSIDE a file
between v0.15 and v0.19:

1. **Structured parsers** (`parsers/`) — 18 file-format-aware parsers
   that emit `ExtractedField` records (high precision, narrow recall).
2. **Content rule engine** (`content_rules.ContentRuleEngine`,
   new in v0.20) — 78 vendored Snaffler regex patterns that produce
   tier verdicts (medium precision, broad recall).
3. **Verify extractor** (`verify/extractor.extract_credentials`) —
   21 modern SaaS credential-format regexes that produce typed
   `ExtractedCredential` records (very high precision, narrow recall).
4. **Content classifier** (`content.ContentClassifier`) — Qwen3-1.7B
   + LoRA binary yes/no classifier (medium precision, broad recall;
   3 GB model weights, expensive).

Pre-v0.20, only (1) and (4) ran inside `Scanner.scan_batch`. v0.20
wires (2) and (3) into the same path and unifies all four behind one
``ContentDeterminer.evaluate(path, content)`` call. The output is a
single ``ContentVerdict`` callers can reason about — no more "which
of these scattered signals do I look at?".

Cascade order (cheap → expensive, narrow → broad):

* (1) parsers — if any field extracted, return high-confidence verdict
* (2) rule engine — if any rule fires, return tier + matches
* (3) verify extractor — if any credential format matched, return
  typed list
* (4) content classifier — only when above tiers are inconclusive
  AND the caller opted in (`use_classifier=True`)

A caller without the 3 GB Qwen download can use (1)+(2)+(3) and get
useful results. The classifier becomes the smart fallback for hard
cases where regex + parsers don't conclude.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

Tier = Literal["Black", "Red", "Yellow", "Green"]
ContentSource = Literal["parsers", "rules", "extractor", "classifier", "none"]
_TIER_RANK = {"Black": 4, "Red": 3, "Yellow": 2, "Green": 1}


@dataclass
class ContentVerdict:
    """Unified content-side verdict.

    * ``tier``  — best tier across any firing detection layer; None
      means no layer flagged the file.
    * ``source`` — which cascade tier produced this verdict.
    * ``matches`` — heterogeneous list of structured match objects from
      the layer that fired; consumers can render or further verify.
    * ``confidence`` — 0..1 best-effort confidence (parsers report
      their own; rules use tier rank; extractor is high by construction;
      classifier reports yes/no with no scalar).
    """

    tier: Tier | None = None
    source: ContentSource = "none"
    matches: list[dict] = field(default_factory=list)
    confidence: float = 0.0

    def to_dict(self) -> dict:
        return {
            "tier": self.tier,
            "source": self.source,
            "matches": self.matches,
            "confidence": round(self.confidence, 3),
        }


def _parsers_to_verdict(extracted_fields: list[dict]) -> ContentVerdict | None:
    """Promote a parser-extracted field list to a content verdict.

    The parsers return `ExtractedField`-shaped dicts; if any field has
    high confidence (≥ 0.7), we flag the file as Red-tier with parser
    source. Parsers are precise — anything they extract is structurally
    interpretable as a credential / config secret.
    """
    if not extracted_fields:
        return None
    confident_fields = [
        f for f in extracted_fields if (f.get("confidence") or 0.0) >= 0.7
    ]
    if not confident_fields:
        # Fields exist but low confidence — defer to next tier.
        return None
    max_conf = max((f.get("confidence") or 0.0) for f in confident_fields)
    return ContentVerdict(
        tier="Red",
        source="parsers",
        matches=confident_fields,
        confidence=float(max_conf),
    )


def _rules_to_verdict(rule_verdict_obj) -> ContentVerdict | None:
    """Promote a RuleVerdict to a ContentVerdict if it fired."""
    if rule_verdict_obj is None or not rule_verdict_obj.has_any():
        return None
    return ContentVerdict(
        tier=rule_verdict_obj.tier,
        source="rules",
        matches=[
            {
                "rule_name": m.rule_name,
                "tier": m.tier,
                "action": m.action,
                "match_location": m.match_location,
                "matched_pattern": m.matched_pattern,
                "matched_span": m.matched_span,
            }
            for m in rule_verdict_obj.matches
        ],
        # Map tier to a coarse confidence — Black=0.95, Red=0.85,
        # Yellow=0.65, Green=0.45. The rules are pattern-based so we
        # can't compute a per-instance posterior.
        confidence={"Black": 0.95, "Red": 0.85, "Yellow": 0.65, "Green": 0.45}[
            rule_verdict_obj.tier
        ],
    )


def _extractor_to_verdict(creds: list) -> ContentVerdict | None:
    """Promote the verify extractor's output to a verdict."""
    if not creds:
        return None
    return ContentVerdict(
        tier="Red",
        source="extractor",
        matches=[
            {
                "credential_type": c.credential_type,
                "value": c.value[:40] + "..." if len(c.value) > 40 else c.value,
                "context": getattr(c, "context", None),
            }
            for c in creds
        ],
        # The extractor's patterns are strict — high confidence by
        # construction.
        confidence=0.9,
    )


def _classifier_to_verdict(content_result) -> ContentVerdict | None:
    """Promote the LoRA classifier's binary verdict."""
    if content_result is None:
        return None
    contains_secret = bool(getattr(content_result, "contains_secret", False))
    if not contains_secret:
        return None
    return ContentVerdict(
        tier="Yellow",  # classifier doesn't emit fine-grained tiers
        source="classifier",
        matches=[{
            "verdict": "yes",
            "raw_response": getattr(content_result, "raw_response", None),
        }],
        confidence=0.7,
    )


class ContentDeterminer:
    """Cascade four content-side detection mechanisms into one verdict."""

    def __init__(
        self,
        *,
        rule_engine=None,
        run_parsers_fn=None,
        extractor_fn=None,
        classifier=None,
    ) -> None:
        """All collaborators are injectable for test isolation.

        Defaults: ``rule_engine`` lazy-loads the JSON-backed singleton;
        ``run_parsers_fn`` and ``extractor_fn`` use the existing stable
        APIs; ``classifier`` defaults to None (callers explicitly pass
        the heavyweight model in).
        """
        self._rule_engine = rule_engine
        self._run_parsers_fn = run_parsers_fn
        self._extractor_fn = extractor_fn
        self._classifier = classifier

    def _get_rule_engine(self):
        if self._rule_engine is None:
            from sharesift.content_rules import get_default_engine

            self._rule_engine = get_default_engine()
        return self._rule_engine

    def _get_parsers_fn(self):
        if self._run_parsers_fn is None:
            from sharesift.parsers.dispatch import parse_file

            self._run_parsers_fn = parse_file
        return self._run_parsers_fn

    def _get_extractor_fn(self):
        if self._extractor_fn is None:
            from sharesift.verify.extractor import extract_credentials

            self._extractor_fn = extract_credentials
        return self._extractor_fn

    def evaluate(
        self,
        path: str,
        content: str | None,
        *,
        use_classifier: bool = False,
    ) -> ContentVerdict:
        """Run the cascade and return the first conclusive verdict.

        ``use_classifier`` gates the LoRA tier — callers without the
        3 GB Qwen download set False; the cascade still produces
        useful verdicts from parsers + rules + extractor.
        """
        # Tier 1: structured parsers
        try:
            fields = self._get_parsers_fn()(path, content or "")
        except Exception:
            fields = []
        # Normalise to dict — parsers return either dataclasses or dicts
        # depending on the parser; rely on duck typing.
        field_dicts = [
            f if isinstance(f, dict) else (
                f.__dict__ if hasattr(f, "__dict__") else {"value": str(f)}
            )
            for f in fields
        ]
        v = _parsers_to_verdict(field_dicts)
        if v is not None:
            return v

        # Tier 2: content rules
        rv = self._get_rule_engine().evaluate(path, content)
        v = _rules_to_verdict(rv)
        if v is not None:
            return v

        # Tier 3: verify extractor (only useful with content)
        if content:
            try:
                creds = self._get_extractor_fn()(content)
            except Exception:
                creds = []
            v = _extractor_to_verdict(creds)
            if v is not None:
                return v

        # Tier 4: LoRA classifier (opt-in)
        if use_classifier and self._classifier is not None and content:
            try:
                result = self._classifier.score(content)
            except Exception:
                result = None
            v = _classifier_to_verdict(result)
            if v is not None:
                return v

        return ContentVerdict()  # tier=None, source=none
