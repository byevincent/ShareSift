"""LDAP credential verifier.

Attempts an LDAP simple bind against each operator-supplied DC URL
with the extracted username + password. Same scaffolded shape as the
SMB verifier — needs ``context["username"]`` + ``context["password"]``
to be provided (parser hookup is v0.17).

``config.targets["ldap"]`` is a list of dicts::

    ldap:
      - url: ldap://dc01.corp.local:389
        base_dn: DC=corp,DC=local
        bind_dn_template: "{username}@corp.local"     # or "cn={username},ou=Users,..."
"""

from __future__ import annotations

import time

from sharesift.verify.base import BaseVerifier, VerifyConfig, VerifyResult


class LDAPVerifier(BaseVerifier):
    service = "ldap"
    credential_type = "ldap_credential"

    def _verify_inner(
        self,
        credential: str,
        config: VerifyConfig,
        context: dict,
    ) -> VerifyResult:
        username = context.get("username")
        password = context.get("password") or credential
        if not username:
            return VerifyResult(
                status="inconclusive",
                credential_type=self.credential_type,
                service=self.service,
                metadata={
                    "reason": (
                        "LDAP verification needs a username; not yet wired from "
                        "structured-parser extraction (v0.17). Pass programmatically "
                        "via context={'username': X, 'password': Y}."
                    ),
                },
            )

        targets = config.targets.get("ldap") or []
        if not targets:
            return VerifyResult(
                status="inconclusive",
                credential_type=self.credential_type,
                service=self.service,
                metadata={
                    "reason": (
                        "no LDAP targets configured; supply via --target-file with "
                        "key 'ldap' (list of {url, bind_dn_template})"
                    ),
                },
            )

        try:
            import ldap3
        except ImportError as exc:
            return VerifyResult(
                status="inconclusive",
                credential_type=self.credential_type,
                service=self.service,
                error=(
                    f"ldap3_not_installed: {exc}. "
                    "Install with `uv sync --group verify`."
                ),
            )

        t0 = time.perf_counter()
        attempts: list[dict] = []
        for tgt in targets:
            url = tgt.get("url")
            template = tgt.get("bind_dn_template", "{username}")
            bind_dn = template.format(username=username)
            try:
                server = ldap3.Server(url, get_info=ldap3.NONE, connect_timeout=int(config.timeout_sec))
                conn = ldap3.Connection(
                    server,
                    user=bind_dn,
                    password=password,
                    auto_bind=False,
                )
                ok = conn.bind()
                if ok:
                    conn.unbind()
                    return VerifyResult(
                        status="passed",
                        credential_type=self.credential_type,
                        service=self.service,
                        latency_ms=(time.perf_counter() - t0) * 1000,
                        metadata={"url": url, "bind_dn": bind_dn},
                    )
                attempts.append(
                    {"url": url, "result": conn.last_error or "bind_returned_false"}
                )
                try:
                    conn.unbind()
                except Exception:
                    pass
            except Exception as exc:
                attempts.append(
                    {"url": url, "error": f"{type(exc).__name__}: {exc}"}
                )

        last = attempts[-1] if attempts else {}
        return VerifyResult(
            status="failed",
            credential_type=self.credential_type,
            service=self.service,
            latency_ms=(time.perf_counter() - t0) * 1000,
            metadata={"attempts": attempts[:10]},
            error=last.get("error") or last.get("result"),
        )
