"""Pydantic schema for eval-set records.

One JSONL line per path. Enum membership is validated against tuple constants
in :mod:`src.eval.categories` — that module is the single source of truth for
allowed values, so the schema does not redeclare them as ``Literal`` types.
"""

from __future__ import annotations

from datetime import date
from pathlib import PureWindowsPath

from pydantic import BaseModel, Field, field_validator, model_validator

from src.eval.categories import (
    CATEGORY_SLUGS,
    LABELS,
    MODERN_SAAS_SUBTYPES,
    SEVERITY_TIERS,
    SOURCES,
)

MIN_NOTES_LEN = 15


class EvalRecord(BaseModel):
    path: str
    label: str
    tier: str | None = None
    category: str
    sub_type: str | None = None
    source: str
    notes: str
    added_date: date
    added_by: str = "vincent"
    pre_category: str | None = None
    validator_warnings: list[str] = Field(default_factory=list)

    @field_validator("path")
    @classmethod
    def _path_clean(cls, v: str) -> str:
        if not v:
            raise ValueError("path must be non-empty")
        if v.strip() != v:
            raise ValueError("path must not have leading/trailing whitespace")
        if any(ord(c) < 32 for c in v):
            raise ValueError("path must not contain control characters")
        # v0 scope: Windows-style paths only. PureWindowsPath parses without I/O.
        _ = PureWindowsPath(v)
        return v

    @field_validator("label")
    @classmethod
    def _label_valid(cls, v: str) -> str:
        if v not in LABELS:
            raise ValueError(f"label must be one of {LABELS}")
        return v

    @field_validator("tier")
    @classmethod
    def _tier_valid(cls, v: str | None) -> str | None:
        if v is not None and v not in SEVERITY_TIERS:
            raise ValueError(f"tier must be one of {SEVERITY_TIERS} or None")
        return v

    @field_validator("category")
    @classmethod
    def _category_valid(cls, v: str) -> str:
        if v not in CATEGORY_SLUGS:
            raise ValueError(f"category must be one of {CATEGORY_SLUGS}")
        return v

    @field_validator("sub_type")
    @classmethod
    def _sub_type_valid(cls, v: str | None) -> str | None:
        if v is not None and v not in MODERN_SAAS_SUBTYPES:
            raise ValueError(f"sub_type must be one of {MODERN_SAAS_SUBTYPES} or None")
        return v

    @field_validator("source")
    @classmethod
    def _source_valid(cls, v: str) -> str:
        if v not in SOURCES:
            raise ValueError(f"source must be one of {SOURCES}")
        return v

    @field_validator("notes")
    @classmethod
    def _notes_min_len(cls, v: str) -> str:
        if len(v.strip()) < MIN_NOTES_LEN:
            raise ValueError(f"notes must be at least {MIN_NOTES_LEN} non-whitespace characters")
        return v

    @model_validator(mode="after")
    def _tier_required_when_juicy(self) -> EvalRecord:
        if self.label == "juicy" and self.tier is None:
            raise ValueError("tier is required when label is 'juicy'")
        if self.label == "not_juicy" and self.tier is not None:
            raise ValueError("tier must be omitted when label is 'not_juicy'")
        return self

    @model_validator(mode="after")
    def _subtype_only_for_modern_saas(self) -> EvalRecord:
        if self.category == "modern_saas_tokens" and self.sub_type is None:
            raise ValueError("sub_type is required when category is 'modern_saas_tokens'")
        if self.category != "modern_saas_tokens" and self.sub_type is not None:
            raise ValueError("sub_type must be None unless category is 'modern_saas_tokens'")
        return self
