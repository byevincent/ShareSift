"""SMB credential verifier.

Attempts SMB session setup against each operator-supplied target with
the extracted username + password. Verification path (anonymous SMB
or NTLMv2) is the standard impacket SMBConnection flow.

Today's hit record schema doesn't carry parser-extracted
``username`` + ``password`` fields, so this verifier is scaffolded:
it returns ``inconclusive`` with a clear pointer to the v0.17 work
that will wire structured parser output through.

When ``context`` does provide both ``username`` and ``password`` (e.g.,
from a future ExtractedField hookup, or a programmatic caller), the
verifier runs the SMB connect against each target in
``config.targets["smb"]``.
"""

from __future__ import annotations

import time

from sharesift.verify.base import BaseVerifier, VerifyConfig, VerifyResult


class SMBVerifier(BaseVerifier):
    service = "smb"
    credential_type = "smb_credential"

    def _verify_inner(
        self,
        credential: str,
        config: VerifyConfig,
        context: dict,
    ) -> VerifyResult:
        username = context.get("username")
        password = context.get("password") or credential
        domain = context.get("domain", "")
        if not username:
            return VerifyResult(
                status="inconclusive",
                credential_type=self.credential_type,
                service=self.service,
                metadata={
                    "reason": (
                        "SMB verification needs a username; not yet wired from "
                        "structured-parser extraction (v0.17). Pass programmatically "
                        "via context={'username': X, 'password': Y, 'domain': Z}."
                    ),
                },
            )

        targets = config.targets.get("smb") or []
        if not targets:
            return VerifyResult(
                status="inconclusive",
                credential_type=self.credential_type,
                service=self.service,
                metadata={
                    "reason": (
                        "no SMB targets configured; supply via --target-file with "
                        "key 'smb' (list of {host, port?})"
                    ),
                },
            )

        try:
            from impacket.smbconnection import SMBConnection
            from impacket.nmb import NetBIOSError
            from impacket.smb3 import SessionError
        except ImportError as exc:
            return VerifyResult(
                status="inconclusive",
                credential_type=self.credential_type,
                service=self.service,
                error=(
                    f"impacket_not_installed: {exc}. "
                    "Install with `uv sync --group pysnaffler-integration`."
                ),
            )

        t0 = time.perf_counter()
        attempts: list[dict] = []
        for tgt in targets:
            host = tgt.get("host")
            port = int(tgt.get("port", 445))
            try:
                conn = SMBConnection(host, host, sess_port=port, timeout=config.timeout_sec)
                conn.login(username, password, domain)
                conn.close()
                return VerifyResult(
                    status="passed",
                    credential_type=self.credential_type,
                    service=self.service,
                    latency_ms=(time.perf_counter() - t0) * 1000,
                    metadata={
                        "host": host,
                        "port": port,
                        "username": username,
                        "domain": domain,
                    },
                )
            except SessionError as exc:
                attempts.append(
                    {"host": host, "error": f"SessionError: {exc}"}
                )
            except NetBIOSError as exc:
                attempts.append({"host": host, "error": f"NetBIOSError: {exc}"})
            except Exception as exc:
                attempts.append(
                    {"host": host, "error": f"{type(exc).__name__}: {exc}"}
                )

        last = attempts[-1] if attempts else {}
        # If we saw a definitive SessionError on any target, that's "failed".
        # Connection-level errors are inconclusive.
        any_session_err = any("SessionError" in a.get("error", "") for a in attempts)
        return VerifyResult(
            status="failed" if any_session_err else "inconclusive",
            credential_type=self.credential_type,
            service=self.service,
            latency_ms=(time.perf_counter() - t0) * 1000,
            metadata={"attempts": attempts[:10]},
            error=last.get("error"),
        )
