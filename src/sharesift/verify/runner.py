"""End-to-end verify driver.

Takes scan records, extracts credentials per record, dispatches each
to its registered verifier, attaches the verification results back
onto the record. Single-threaded for v0.16; parallelization is a v0.17
followup once we have a real engagement benchmark to tune against.
"""

from __future__ import annotations

from typing import Iterable

from sharesift._output import out
from sharesift.verify._pairs import CredentialPair, extract_user_password_pairs
from sharesift.verify.base import VerifyConfig, VerifyResult
from sharesift.verify.extractor import ExtractedCredential, extract_credentials
from sharesift.verify.rate_limiter import RateLimiter
from sharesift.verify.registry import get_verifier, supported_credential_types


def verify_records(
    records: Iterable[dict],
    config: VerifyConfig | None = None,
    *,
    rate_limiter: RateLimiter | None = None,
) -> list[dict]:
    """Verify credentials in each record; return enriched records.

    Records lacking a ``content_excerpt`` field, or with no detectable
    credential format, pass through unchanged with
    ``verification_status`` set to ``"skipped"``.
    """
    cfg = config or VerifyConfig()
    rl = rate_limiter or RateLimiter(default_rate_per_sec=cfg.rate_limit_per_sec)
    supported = set(supported_credential_types())

    results: list[dict] = []
    total_verified = 0
    for record in records:
        excerpt = record.get("content_excerpt")
        extracted_fields = record.get("extracted_fields") or []
        cred_pairs = extract_user_password_pairs(extracted_fields)

        regex_candidates = extract_credentials(excerpt) if excerpt else []
        if cfg.only:
            regex_candidates = [
                c for c in regex_candidates if c.credential_type in cfg.only
            ]
            cred_pairs = [
                p for p in cred_pairs
                if "smb_credential" in cfg.only or "ldap_credential" in cfg.only
            ]
        regex_candidates = [
            c for c in regex_candidates if c.credential_type in supported
        ]

        if not regex_candidates and not cred_pairs:
            reason = (
                "no_content_excerpt" if not excerpt else "no_extractable_credential"
            )
            results.append(_skipped(record, reason=reason))
            continue

        verifications = _verify_candidates(regex_candidates, excerpt or "", cfg, rl)
        verifications.extend(_verify_pairs(cred_pairs, cfg, rl))

        new_record = dict(record)
        new_record["extracted_credential_types"] = sorted(
            {v.credential_type for v in verifications}
        )
        new_record["verification_results"] = [v.to_dict() for v in verifications]
        new_record["verification_status"] = _aggregate_status(verifications)
        results.append(new_record)
        total_verified += 1
        if total_verified % 25 == 0:
            out.info(f"  verified {total_verified} records")
    return results


def _verify_candidates(
    candidates: list[ExtractedCredential],
    excerpt: str,
    config: VerifyConfig,
    rl: RateLimiter,
) -> list[VerifyResult]:
    results: list[VerifyResult] = []
    for cand in candidates:
        verifier = get_verifier(cand.credential_type)
        if verifier is None:
            results.append(
                VerifyResult(
                    status="skipped",
                    credential_type=cand.credential_type,
                    service="none",
                    metadata={"reason": "no_verifier_registered"},
                )
            )
            continue
        rl.acquire(verifier.service)
        results.append(
            verifier.verify(
                cand.value,
                config,
                context={
                    "credential_type": cand.credential_type,
                    "excerpt": excerpt,
                },
            )
        )
    return results


def _verify_pairs(
    pairs: list[CredentialPair],
    config: VerifyConfig,
    rl: RateLimiter,
) -> list[VerifyResult]:
    """Dispatch each user/password pair to BOTH SMB and LDAP verifiers.

    Real engagements typically don't know up-front whether a given
    extracted ``svc_jenkins:P@ssw0rd!`` is an AD account or a local
    SMB user. Trying both is cheap (skipped → inconclusive on the
    targets that don't apply) and gives the operator full visibility.
    """
    results: list[VerifyResult] = []
    for pair in pairs:
        context = {
            "username": pair.username,
            "password": pair.password,
            "source_parser": pair.parser,
            "source_field_username": pair.source_field_username,
            "source_field_password": pair.source_field_password,
        }
        for cred_type in ("smb_credential", "ldap_credential"):
            verifier = get_verifier(cred_type)
            if verifier is None:
                continue
            rl.acquire(verifier.service)
            results.append(
                verifier.verify(
                    credential=pair.password,
                    config=config,
                    context={**context, "credential_type": cred_type},
                )
            )
    return results


def _aggregate_status(verifications: list[VerifyResult]) -> str:
    """Roll up multiple per-credential verifications to one record-level status.

    Operator hierarchy: any ``passed`` → ``passed`` (the record contains
    a verified credential). Otherwise any ``failed`` → ``failed``.
    Otherwise inconclusive/skipped propagates.
    """
    statuses = {v.status for v in verifications}
    if "passed" in statuses:
        return "passed"
    if "failed" in statuses:
        return "failed"
    if "inconclusive" in statuses:
        return "inconclusive"
    return "skipped"


def _skipped(record: dict, reason: str) -> dict:
    new = dict(record)
    new["verification_status"] = "skipped"
    new["verification_results"] = []
    new["extracted_credential_types"] = []
    new.setdefault("verification_metadata", {})["skip_reason"] = reason
    return new
