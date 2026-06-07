"""Live credential verification.

Takes scan records emitted by ``sharesift scan-files`` and attempts to
verify the embedded credentials against the live services they target
(STS GetCallerIdentity for AWS keys, /v1/models for Anthropic/OpenAI,
SSH bind for private keys, etc.). The output is the same record stream
enriched with ``verification_status`` and ``verification_metadata``.

Operationally this is the difference between "ShareSift found 1000
things to investigate" and "ShareSift found 12 credentials that
actually authenticated." Same precision lever TruffleHog v3's
``--only-verified`` UX is built around.

Public entry point::

    from sharesift.verify import verify_records, VerifyConfig
    verified = verify_records(records, VerifyConfig(dry_run=True))
"""

from __future__ import annotations

from sharesift.verify.base import (
    BaseVerifier,
    VerifyConfig,
    VerifyResult,
    VerifyStatus,
)
from sharesift.verify.runner import verify_records

__all__ = [
    "BaseVerifier",
    "VerifyConfig",
    "VerifyResult",
    "VerifyStatus",
    "verify_records",
]
