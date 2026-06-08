"""Two-stage scanner pipeline — path triage + optional content check.

The ``Scanner`` glues ``PathClassifier`` and ``ContentClassifier`` into
the workflow described in the build plan: every path goes through the
fast path-only classifier; the heavy content classifier runs only on
the subset where (a) the caller provided file content AND (b) the path
classifier flagged a tier (Black / Red / Yellow). The ``force_content``
escape hatch lets a caller override the second condition for cases
where they want to check content regardless of path verdict.

Lazy construction: passing ``None`` for either classifier defers the
construction to first use. ``Scanner()`` with no args constructs both
classifiers with their default model directories on first access. This
keeps the CLI startup cheap when only one stage is exercised.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Literal

from sharesift._output import out
from sharesift.content import ContentClassifier
from sharesift.path import PathClassifier

ContentVerdict = Literal["yes", "no"]


@dataclass(frozen=True)
class ScanResult:
    """One scanned path's combined result across both stages.

    ``content_check`` is ``None`` when the content stage was skipped
    (no content provided, or path wasn't flagged and ``force_content``
    was off). ``content_excerpt`` is the exact text the content stage
    saw — preserved for triage UX so an operator can sanity-check why
    a snippet was flagged.

    ``extracted_fields`` carries structured-parser output (v0.17). Each
    entry is the ``ExtractedField`` from ``sharesift.parsers.dispatch``
    serialized as a dict — ``field_name``, ``value``, ``confidence``,
    ``parser``, ``context``. Empty when no parser matched the filename
    or no content was available. Verifier dispatch (SMB/LDAP) reads
    user/password pairs out of this list; the ranker reads the maximum
    confidence as a feature.
    """

    path: str
    path_probability: float
    path_tier: str | None
    content_check: ContentVerdict | None
    content_excerpt: str | None
    raw_content_response: str | None
    extracted_fields: list[dict] = field(default_factory=list)
    # v0.20: ContentDeterminer cascade output. ``content_tier`` is the
    # rule-engine / extractor / classifier tier; ``content_source``
    # names the cascade tier that fired (parsers/rules/extractor/
    # classifier/none); ``content_matches`` carries the structured
    # match details for report rendering and downstream triage.
    content_tier: str | None = None
    content_source: str | None = None
    content_matches: list[dict] = field(default_factory=list)

    def as_record(self, include_debug: bool = False) -> dict:
        """JSON-serializable dict for JSONL output.

        ``raw_content_response`` is excluded by default (model
        chain-of-thought output is noisy for the operator-facing
        record) — pass ``include_debug=True`` when triaging false
        positives or evaluating the model.

        ``extracted_fields`` is omitted from the record when empty so
        v0.16 consumers don't see a noisy ``[]`` for every record that
        had no parser hit.
        """
        out = asdict(self)
        if not include_debug:
            out.pop("raw_content_response", None)
        if not out.get("extracted_fields"):
            out.pop("extracted_fields", None)
        return out


class Scanner:
    """Two-stage scanner combining path + content classifiers.

    The path classifier is always constructed; the content classifier
    is constructed lazily on first content scan. Re-uses both across
    calls — pass an explicit instance to inject a pre-loaded classifier
    (e.g., in tests, or to share one ContentClassifier across multiple
    Scanner instances).
    """

    def __init__(
        self,
        path_classifier: PathClassifier | None = None,
        content_classifier: ContentClassifier | None = None,
        *,
        use_classifier: bool = True,
    ) -> None:
        self._path = path_classifier
        self._content = content_classifier
        # v0.20: when False, the cascade stops at the regex tiers
        # (parsers/rules/extractor) and never invokes the LoRA. The CLI
        # forces False if --content-model-dir isn't usable, but tests
        # and bulk runs can opt in/out independently.
        self._use_classifier = use_classifier
        self._determiner = None  # lazy

    @property
    def path_classifier(self) -> PathClassifier:
        if self._path is None:
            self._path = PathClassifier()
        return self._path

    @property
    def content_classifier(self) -> ContentClassifier:
        if self._content is None:
            self._content = ContentClassifier()
        return self._content

    def scan(
        self,
        path: str,
        content: str | None = None,
        force_content: bool = False,
    ) -> ScanResult:
        """Score one path; optionally score content.

        Content stage runs when content is provided AND
        (path was tier-flagged OR ``force_content`` is True).
        """
        return self.scan_batch([(path, content)], force_content=force_content)[0]

    def scan_batch(
        self,
        items: list[tuple[str, str | None]],
        force_content: bool = False,
    ) -> list[ScanResult]:
        """Batch scan. Stage 1 is one-shot batched; stage 2 runs only
        on the qualifying subset (path flagged + content provided)."""
        if not items:
            return []
        paths = [p for p, _ in items]
        path_results = self.path_classifier.score_batch(paths)

        # v0.20: ContentDeterminer cascade — parsers → rules → extractor →
        # (optional) LoRA. Lazy because constructing it imports the rule
        # JSON; tests that bypass scan_batch shouldn't pay.
        if self._determiner is None:
            from sharesift.content_determiner import ContentDeterminer
            self._determiner = ContentDeterminer()

        results: list[ScanResult] = []
        iterator = out.progress(
            zip(items, path_results),
            desc="Content scan",
            total=len(items),
        )
        for (path, content), p_result in iterator:
            # Run parsers once and pass to the cascade — keeps existing
            # ScanResult.extracted_fields populated for downstream
            # consumers (ranker + verify dispatch).
            extracted = _run_parsers(path, content)

            verdict = self._determiner.evaluate(
                path,
                content,
                use_classifier=False,  # default: cascade stops at extractor
            )

            should_check_classifier = (
                self._use_classifier
                and content is not None
                and verdict.tier is None
                and (p_result.tier is not None or force_content)
            )

            content_check: str | None = None
            raw_response: str | None = None
            if verdict.source != "none":
                content_check = "yes"
            if should_check_classifier:
                c_result = self.content_classifier.score(content)
                if c_result.contains_secret:
                    content_check = "yes"
                    verdict.tier = "Yellow"
                    verdict.source = "classifier"
                    verdict.matches = [{"verdict": "yes"}]
                else:
                    content_check = "no"
                raw_response = c_result.raw_response

            content_excerpt = content if content_check is not None else None

            results.append(
                ScanResult(
                    path=path,
                    path_probability=p_result.probability,
                    path_tier=p_result.tier,
                    content_check=content_check,
                    content_excerpt=content_excerpt,
                    raw_content_response=raw_response,
                    extracted_fields=extracted,
                    content_tier=verdict.tier,
                    content_source=verdict.source if verdict.source != "none" else None,
                    content_matches=verdict.matches,
                )
            )
        return results


def _run_parsers(path: str, content: str | None) -> list[dict]:
    """Run the structured-parser dispatcher on ``content``.

    Returns ExtractedField records as dicts; empty list when no
    content is available or no parser matches the filename. Imported
    lazily so the path-only CLI doesn't pay for the parsers' imports.
    """
    if not content:
        return []
    from sharesift.parsers.dispatch import parse_file

    try:
        fields = parse_file(path, content)
    except Exception:
        return []
    return [
        {
            "field_name": f.field_name,
            "value": f.value,
            "confidence": f.confidence,
            "parser": f.parser,
            "context": f.context,
        }
        for f in fields
    ]
