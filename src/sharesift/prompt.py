"""Qwen3 chat-template SFT formatting for the content classifier.

The Phase-3 content classifier is a binary judge: given a code snippet,
does it contain a hardcoded secret (API key, password, private key,
db credentials, etc.) — yes or no. We frame this as a chat-style SFT
task so the base Qwen3-1.7B-Instruct's chat-template alignment
transfers to the fine-tuned model.

Prompt design choices:

* **System prompt** is short and prescriptive — the model's job is
  binary classification, not analysis-paragraph generation. Anything
  longer trains slower and bloats the answer.
* **User turn** is the snippet verbatim, no preamble.
* **Assistant turn** is one of two tokens: ``yes`` or ``no``. Short
  answers train the classification head efficiently and keep eval
  cheap (single-token argmax).

This matches the Wiz LoRA recipe's binary-judge shape adapted to
Qwen3's chat template. Per ``docs/build_plan.md`` §6.1, Qwen3-1.7B
replaces Llama-3.2-1B from the original Wiz recipe.
"""

from __future__ import annotations

from typing import Literal

Label = Literal["yes", "no"]

SYSTEM_PROMPT = (
    "You are a security analyst. Examine the code snippet below and "
    "determine whether it contains a hardcoded secret — an API key, "
    "password, private key, database credential, token, or other "
    "credential material embedded as a literal value in the code. "
    'Answer with exactly one word: "yes" or "no".'
)


def format_sft_example(snippet: str, label: Label) -> dict:
    """Return a single SFT training example in the ``messages`` format
    that TRL / Unsloth's SFTTrainer consumes by default.

    The ``messages`` list is rendered via the model's chat template at
    training time; we don't pre-render here because rendering depends
    on the tokenizer instance, which is loaded inside the training
    script. Keeping it as messages keeps the dataset portable across
    template variants.
    """
    return {
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": snippet},
            {"role": "assistant", "content": label},
        ]
    }


def format_inference_messages(snippet: str) -> list[dict]:
    """Return the prefix-only messages list for inference (no assistant
    turn). The caller renders this with the tokenizer's chat template
    and feeds the result to the model; the assistant's first token
    is ``yes`` or ``no``.
    """
    return [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": snippet},
    ]
