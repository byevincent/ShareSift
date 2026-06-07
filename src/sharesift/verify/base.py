"""Verifier base types — VerifyResult / BaseVerifier / VerifyConfig.

A verifier takes a credential string + optional context and returns a
status with structured metadata. Statuses are the same four TruffleHog
v3 uses:

* ``passed`` — credential authenticated successfully against the live
  service.
* ``failed`` — service responded definitively that the credential is
  invalid (401, 403, etc.).
* ``inconclusive`` — verification ran but the result was ambiguous
  (rate-limited, transient network error, missing operator-supplied
  target for network verifiers).
* ``skipped`` — verification was not attempted (dry-run, disabled
  verifier, no extractor available for this rule).
"""

from __future__ import annotations

import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Literal

VerifyStatus = Literal["passed", "failed", "inconclusive", "skipped"]


@dataclass(frozen=True)
class VerifyResult:
    """Outcome of one credential-verification attempt.

    ``credential_type`` is the registry key that picked this verifier
    (e.g., ``"anthropic_api_key"``). ``metadata`` is verifier-specific:
    the AWS verifier puts ``account_id`` and ``arn`` here on success;
    HTTP verifiers put HTTP status + response excerpt on failure.
    """

    status: VerifyStatus
    credential_type: str
    service: str
    latency_ms: float = 0.0
    metadata: dict = field(default_factory=dict)
    error: str | None = None

    def to_dict(self) -> dict:
        out = {
            "status": self.status,
            "credential_type": self.credential_type,
            "service": self.service,
            "latency_ms": round(self.latency_ms, 1),
        }
        if self.metadata:
            out["metadata"] = self.metadata
        if self.error:
            out["error"] = self.error
        return out


@dataclass
class VerifyConfig:
    """Runtime knobs for a verification run.

    ``rate_limit_per_sec`` is the global cap shared across all
    verifiers; individual verifiers may pick a tighter per-service cap.
    ``targets`` is the parsed target-file: a dict of
    ``{"ssh": [...], "smb": [...], "ldap": [...], "databricks": [...]}``.
    Network verifiers refuse to run without entries.
    """

    dry_run: bool = False
    rate_limit_per_sec: float = 1.0
    timeout_sec: float = 10.0
    only: set[str] | None = None
    targets: dict = field(default_factory=dict)
    confirm_banner: bool = True


class BaseVerifier(ABC):
    """ABC for one credential type's live-verification logic.

    Subclasses implement ``_verify_inner``; ``verify`` is the public
    wrapper that handles timing, error capture, and the dry-run
    short-circuit.
    """

    service: str = "unknown"
    credential_type: str = "unknown"

    def verify(
        self,
        credential: str,
        config: VerifyConfig,
        context: dict | None = None,
    ) -> VerifyResult:
        if config.dry_run:
            return VerifyResult(
                status="skipped",
                credential_type=(context or {}).get(
                    "credential_type", self.credential_type
                ),
                service=self.service,
                metadata={"reason": "dry_run"},
            )
        t0 = time.perf_counter()
        try:
            result = self._verify_inner(credential, config, context or {})
        except Exception as exc:
            return VerifyResult(
                status="inconclusive",
                credential_type=self.credential_type,
                service=self.service,
                latency_ms=(time.perf_counter() - t0) * 1000,
                error=f"{type(exc).__name__}: {exc}",
            )
        return result

    @abstractmethod
    def _verify_inner(
        self,
        credential: str,
        config: VerifyConfig,
        context: dict,
    ) -> VerifyResult:
        ...
