"""Content-classifier runtime wrapper.

Qwen3-1.7B + LoRA via transformers + PEFT. CUDA-first, with a working
CPU fallback for laptop deployment.

Two design constraints worth knowing about:

1. **Lazy load.** ``import sharesift.content`` brings in only
   stdlib + the local prompt module — no torch, no transformers, no
   peft. The heavy stack imports inside ``load()`` so the path-only
   workflow can run from a lean install (no ~3GB content-inference
   group needed). Callers either invoke ``.load()`` explicitly or let
   ``.score()`` trigger it on first use.

2. **Two base-model variants.** Training used
   ``unsloth/Qwen3-1.7B-unsloth-bnb-4bit`` (pre-quantized). For CUDA
   inference we load the same base — matches training exactly. For
   CPU inference we load ``Qwen/Qwen3-1.7B`` (full precision, ~3.4GB
   RAM) because the bnb-4bit weights are CUDA-only in practice
   (bitsandbytes CPU support is experimental and far slower than just
   running bf16 on CPU). The LoRA adapter trained against the 4-bit
   base applies cleanly to the full-precision base — same weights,
   different storage format.

GGUF path was investigated and rejected — see ``docs/journal.md``
2026-05-30 entry. llama.cpp's runtime introduces ~50pt recall loss on
this fine-tuned small model regardless of quantization level, while
transformers + PEFT preserves the 0.83 recall the model was trained
for.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from sharesift.prompt import format_inference_messages

# v0p6 (docx-corpus + Kingfisher-salt-trained) is the canonical
# content classifier as of v0.10. It hits F1=0.776 on the v0.8 docx-
# salted business-document benchmark (vs v0p5=0.385) and 2.6× the
# end-to-end recall on the v0.9.5 constructed-share benchmark
# (0.091 → 0.240). Earlier models stay available via
# ``--content-model-dir`` for specific operating-point selection:
#   - v0p5 (CredData hand-labels): F1=0.853 on CredData (source-code
#     distribution). Drops to F1=0.385 on docx-salted — code-shape
#     dependency. Use when triaging source-code corpora.
#   - v0p4 (Kingfisher labels): precision-first alternative, F1=0.485
#     on CredData, F1=0.510 on docx. Pattern-coverage-dependent.
#   - v0p3 (LLM-rule labels): recall-heavy legacy. F1=0.612 on
#     CredData, F1=0.203 on docx (catastrophically over-flags
#     business prose mentioning credential concepts).
# See docs/v0p10_content_docx_retrain.md for the full v0.10 result.
DEFAULT_MODEL_DIR = Path("models/content_classifier_v0p6_docx_salted")
DEFAULT_BASE_MODEL_CUDA = "unsloth/Qwen3-1.7B-unsloth-bnb-4bit"
DEFAULT_BASE_MODEL_CPU = "Qwen/Qwen3-1.7B"


@dataclass(frozen=True)
class ContentResult:
    """One snippet scored by the content classifier.

    ``contains_secret`` is the binary verdict (``True`` = the model
    said "yes"). ``raw_response`` is the actual decoded model output,
    preserved for debugging and for callers that want to see the
    chain-of-thought block (Qwen3 wraps answers in
    ``<think>...</think>``).
    """

    snippet: str
    contains_secret: bool
    raw_response: str


def _parse_yes_no(generated: str) -> bool | None:
    """Reduce the model's response to True / False / None.

    Strips the Qwen3 ``<think>...</think>`` chain-of-thought wrapper,
    then checks the first non-whitespace token. Returns ``None`` for
    unparseable responses; the caller decides whether to treat
    abstention as a no-find.
    """
    txt = generated
    if "</think>" in txt:
        txt = txt.split("</think>", 1)[1]
    txt = txt.strip().lower()
    if txt.startswith("yes"):
        return True
    if txt.startswith("no"):
        return False
    return None


class ContentClassifier:
    """Qwen3-1.7B + LoRA content classifier.

    Instantiate cheaply; ``score()`` triggers the model load on first
    call. The CUDA path loads the bnb-4bit base used at training; the
    CPU path loads the full-precision base in bf16 (~3.4GB RAM, ~5-8s
    per snippet on a Ryzen 5 3600-class CPU).
    """

    def __init__(
        self,
        model_dir: Path | None = None,
        base_model: str | None = None,
        device: str | None = None,
        max_new_tokens: int = 32,
    ) -> None:
        self._model_dir = model_dir or DEFAULT_MODEL_DIR
        self._explicit_base_model = base_model
        self._device = device  # ``None`` triggers auto-detect at load
        self._max_new_tokens = max_new_tokens
        self._model = None
        self._tokenizer = None

    def load(self) -> None:
        """Load the model + tokenizer. Idempotent.

        Detects the model format from the model dir:
        - ``adapter_config.json`` present → Qwen3 LoRA (generative yes/no)
        - else → standalone sequence classifier (e.g. distilled DistilBERT)
        """
        if self._model is not None:
            return
        import torch

        if self._device is None:
            self._device = "cuda" if torch.cuda.is_available() else "cpu"

        self._is_standalone = not (self._model_dir / "adapter_config.json").exists()

        if self._is_standalone:
            from transformers import (
                AutoModelForSequenceClassification,
                AutoTokenizer,
            )
            self._tokenizer = AutoTokenizer.from_pretrained(str(self._model_dir))
            self._model = AutoModelForSequenceClassification.from_pretrained(
                str(self._model_dir)
            )
            self._model.to(self._device)
            self._model.eval()
            return

        from peft import PeftModel
        from transformers import (
            AutoModelForCausalLM,
            AutoTokenizer,
            BitsAndBytesConfig,
        )

        base_model = self._explicit_base_model or (
            DEFAULT_BASE_MODEL_CUDA
            if self._device == "cuda"
            else DEFAULT_BASE_MODEL_CPU
        )
        self._tokenizer = AutoTokenizer.from_pretrained(base_model)

        if self._device == "cuda":
            bnb = BitsAndBytesConfig(
                load_in_4bit=True,
                bnb_4bit_compute_dtype=torch.bfloat16,
                bnb_4bit_quant_type="nf4",
                bnb_4bit_use_double_quant=True,
            )
            base = AutoModelForCausalLM.from_pretrained(
                base_model,
                quantization_config=bnb,
                device_map="cuda",
                torch_dtype=torch.bfloat16,
            )
        else:
            base = AutoModelForCausalLM.from_pretrained(
                base_model,
                device_map="cpu",
                torch_dtype=torch.bfloat16,
            )
        self._model = PeftModel.from_pretrained(base, str(self._model_dir))
        self._model.eval()

    def score(self, snippet: str) -> ContentResult:
        """Classify one snippet. Triggers ``load()`` on first call."""
        if self._model is None:
            self.load()

        if self._is_standalone:
            import torch
            inputs = self._tokenizer(
                snippet,
                return_tensors="pt",
                truncation=True,
                max_length=512,
            ).to(self._device)
            with torch.no_grad():
                logits = self._model(**inputs).logits
            pred = int(logits.argmax(dim=-1).item())
            return ContentResult(
                snippet=snippet,
                contains_secret=bool(pred),
                raw_response=f"distil pred={pred} logits={logits[0].tolist()}",
            )

        messages = format_inference_messages(snippet)
        prompt = self._tokenizer.apply_chat_template(
            messages, tokenize=False, add_generation_prompt=True
        )
        inputs = self._tokenizer(prompt, return_tensors="pt").to(
            self._model.device
        )
        outputs = self._model.generate(
            **inputs,
            max_new_tokens=self._max_new_tokens,
            do_sample=False,
            pad_token_id=self._tokenizer.pad_token_id,
        )
        decoded = self._tokenizer.decode(
            outputs[0][inputs["input_ids"].shape[1] :],
            skip_special_tokens=True,
        )
        verdict = _parse_yes_no(decoded)
        return ContentResult(
            snippet=snippet,
            contains_secret=bool(verdict) if verdict is not None else False,
            raw_response=decoded,
        )

    def score_batch(self, snippets: list[str]) -> list[ContentResult]:
        """Sequential v0 — true batched generation requires padding +
        attention-mask plumbing that's not worth the complexity for
        v0's typical workload (Phase-1 path classifier filters to
        ~hundreds of content-check candidates, not millions)."""
        return [self.score(s) for s in snippets]
