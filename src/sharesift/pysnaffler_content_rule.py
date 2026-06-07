"""ShareSift v0p7 content classifier as a pysnaffler ContentsEnumeration rule.

Mirror of :class:`ShareSiftPathRule` but for the content stage. Wraps the
v0.13 literal-vs-referenced credential classifier so pysnaffler's
content-rule loop yields the ShareSift score alongside Snaffler's content
regex hits.

Integration model — pysnaffler downloads each Keep/Relay-flagged file
and runs every ``ContentsEnumeration`` rule against the file's bytes.
This rule receives the content as a string, runs v0p7 inference, and
emits ``(Snaffle, triage)`` per the model's P(literal):

- P(literal) >= ``red_threshold`` (default 0.80) → ``Triage.Red``
- P(literal) >= ``yellow_threshold`` (default 0.50) → ``Triage.Yellow``
- Below either threshold → ``(None, None)`` (rule doesn't flag)

The actual probability is cached on the rule instance keyed by the
hit's path so the ranker can read it back without re-inferring. This
is the wedge Snaffler structurally can't do — its regexes match shape
only, not "is the matched text a literal or a reference".

Usage::

    from sharesift.pysnaffler_content_rule import ShareSiftContentRule
    from sharesift.pysnaffler_run import build_ruleset

    ruleset = build_ruleset(include_defaults=True, include_extras=True)
    ruleset.load_rule(ShareSiftContentRule())  # auto-loads v0p7
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
from pysnaffler.rules.contents import SnafflerContentsEnumerationRule

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
DEFAULT_ADAPTER = REPO_ROOT / "models" / "content_classifier_v0p7_literal_vs_referenced"

# Snippet window — matches v0.13's training distribution (500-char window
# centered on a regex match). When pysnaffler hands us a full file we
# extract the same shape: locate the credential token and slice ±250.
import re
_CREDENTIAL_TOKEN = re.compile(
    r"[Pp]asswo?r?d|PASSWORD|api[Kk]ey|secret|token|oauth"
)
_SNIPPET_WINDOW = 500
_SNIPPET_HALF = _SNIPPET_WINDOW // 2


def _extract_snippet(content: str) -> str:
    """Find the first credential-shaped token in content; return the 500-char
    window centered on it. Falls back to content head when no token found."""
    m = _CREDENTIAL_TOKEN.search(content)
    if m is None:
        return content[:_SNIPPET_WINDOW]
    center = (m.start() + m.end()) // 2
    left = max(0, center - _SNIPPET_HALF)
    right = min(len(content), left + _SNIPPET_WINDOW)
    left = max(0, right - _SNIPPET_WINDOW)
    return content[left:right]


class ShareSiftContentRule(SnafflerContentsEnumerationRule):
    """ContentsEnumeration rule that delegates the match decision to v0p7.

    Construction loads the LoRA adapter eagerly so first-file latency is
    not paid mid-scan. The model and tokenizer are imported lazily so
    this module can be imported without the Unsloth/PyTorch stack present
    — useful when running eval scripts or unit tests that don't actually
    call the rule.
    """

    SYSTEM_PROMPT = (
        "You are a credential-snippet classifier. Given a short context "
        "window from a file flagged by a credential scanner, decide whether "
        "it contains a LITERAL credential value (a real password, key, or "
        "token written directly in the file) or a REFERENCED credential "
        "(a variable reference, function parameter, example block, or "
        "template pattern that mentions credentials but does not store one). "
        "Answer with exactly one word: literal or referenced."
    )

    def __init__(
        self,
        adapter_dir: Path | str = DEFAULT_ADAPTER,
        red_threshold: float = 0.80,
        yellow_threshold: float = 0.50,
        rule_name: str = "ShareSiftContentClassifier",
    ) -> None:
        super().__init__(
            enumerationScope=EnumerationScope.ContentsEnumeration,
            ruleName=rule_name,
            matchAction=MatchAction.Snaffle,
            relayTargets=[],
            description=(
                "ShareSift v0p7 literal-vs-referenced credential classifier "
                "(Qwen3-1.7B LoRA). Yields Red/Yellow/None per P(literal). "
                "Caches per-file probability on the rule instance for ranker "
                "consumption."
            ),
            matchLocation=MatchLoc.FileContentAsString,
            wordListType=MatchListType.Regex,
            matchLength=0,
            wordList=[],
            triage=Triage.Red,  # Placeholder — actual triage is dynamic.
        )
        self._adapter_dir = Path(adapter_dir)
        self._red_threshold = red_threshold
        self._yellow_threshold = yellow_threshold
        self._model = None
        self._tokenizer = None
        self._literal_tok = None
        self._referenced_tok = None
        # Cache: (path) → P(literal). Read by the ranker after scan.
        self.p_literal_cache: dict[str, float] = {}

    def _ensure_loaded(self) -> None:
        if self._model is not None:
            return
        if not self._adapter_dir.exists():
            raise FileNotFoundError(
                f"v0p7 adapter missing: {self._adapter_dir}. "
                f"Train via tools/train_literal_vs_referenced.py first."
            )
        from unsloth import FastLanguageModel  # type: ignore[import-not-found]
        model, tokenizer = FastLanguageModel.from_pretrained(
            model_name=str(self._adapter_dir),
            max_seq_length=512,
            load_in_4bit=True,
        )
        FastLanguageModel.for_inference(model)
        self._model = model
        self._tokenizer = tokenizer
        # Cache the single-token IDs for "literal" / "referenced"
        self._literal_tok = tokenizer.encode("literal", add_special_tokens=False)[0]
        self._referenced_tok = tokenizer.encode("referenced", add_special_tokens=False)[0]

    def _score(self, content: str, extension: str = "?") -> float:
        """Return P(literal) for the given content."""
        import math
        import torch
        self._ensure_loaded()
        snippet = _extract_snippet(content)
        messages = [
            {"role": "system", "content": self.SYSTEM_PROMPT},
            {"role": "user", "content": (
                f"File extension: .{extension}\n"
                f"Match: {snippet[:120]}\n"
                f"---\n"
                f"{snippet}\n"
                f"---\n"
                f"Classify the credential context."
            )},
        ]
        text = self._tokenizer.apply_chat_template(
            messages, tokenize=False, add_generation_prompt=True,
        )
        inputs = self._tokenizer(
            text, return_tensors="pt", truncation=True, max_length=512,
        ).to(self._model.device)
        with torch.no_grad():
            outputs = self._model(**inputs)
        last_logits = outputs.logits[0, -1, :]
        lit_logit = last_logits[self._literal_tok].item()
        ref_logit = last_logits[self._referenced_tok].item()
        m = max(lit_logit, ref_logit)
        return math.exp(lit_logit - m) / (math.exp(lit_logit - m) + math.exp(ref_logit - m))

    def match(self, data, fullpath: Optional[str] = None, **kwargs) -> bool:
        """data is the file content bytes/str pysnaffler hands the contents
        rule. We score it and cache; the rule "matches" when P(literal) >=
        yellow_threshold."""
        if data is None:
            return False
        try:
            content = data.decode("utf-8", errors="replace") if isinstance(data, bytes) else data
        except Exception:
            return False
        ext = "?"
        if fullpath:
            ext_match = re.search(r"\.([a-zA-Z0-9]+)$", fullpath)
            if ext_match:
                ext = ext_match.group(1).lower()
        try:
            p_lit = self._score(content, ext)
        except Exception as e:
            # Fail-open: if inference fails, let other rules decide.
            print(f"[ShareSiftContentRule] inference error on {fullpath!r}: {e}")
            return False
        if fullpath:
            self.p_literal_cache[fullpath] = p_lit
        return p_lit >= self._yellow_threshold

    def determine_action(self, data, fullpath: Optional[str] = None, **kwargs):
        """Returns (Snaffle, Red/Yellow) per P(literal); (None, None)
        when below yellow_threshold."""
        if not self.match(data, fullpath=fullpath, **kwargs):
            return None, None
        p_lit = self.p_literal_cache.get(fullpath or "", self._yellow_threshold)
        if p_lit >= self._red_threshold:
            return MatchAction.Snaffle, Triage.Red
        return MatchAction.Snaffle, Triage.Yellow
