"""SSH private-key verifier.

Attempts SSH key-based authentication against each operator-supplied
target. ``config.targets["ssh"]`` is a list of dicts::

    ssh:
      - host: build01.corp.local
        port: 22
        usernames: [root, deploy, ubuntu]
      - host: 10.0.0.42
        port: 22
        usernames: [admin]

For each target × username combination, we attempt a non-interactive
``paramiko`` connect using the extracted PEM key. First successful
connection wins; we close immediately (no commands executed).

If no targets are configured, returns ``inconclusive`` with a clear
explanation rather than silently skipping.
"""

from __future__ import annotations

import io
import time

from sharesift.verify.base import BaseVerifier, VerifyConfig, VerifyResult


class SSHVerifier(BaseVerifier):
    service = "ssh"
    credential_type = "ssh_private_key"

    def _verify_inner(
        self,
        credential: str,
        config: VerifyConfig,
        context: dict,
    ) -> VerifyResult:
        targets = config.targets.get("ssh") or []
        if not targets:
            return VerifyResult(
                status="inconclusive",
                credential_type=self.credential_type,
                service=self.service,
                metadata={
                    "reason": (
                        "no SSH targets configured; supply via --target-file with "
                        "key 'ssh' (list of {host, port, usernames})"
                    ),
                },
            )

        try:
            import paramiko
        except ImportError as exc:
            return VerifyResult(
                status="inconclusive",
                credential_type=self.credential_type,
                service=self.service,
                error=(
                    f"paramiko_not_installed: {exc}. "
                    "Install with `uv sync --group verify`."
                ),
            )

        pkey = _load_pkey(paramiko, credential)
        if pkey is None:
            return VerifyResult(
                status="inconclusive",
                credential_type=self.credential_type,
                service=self.service,
                error="unable_to_parse_private_key",
            )

        t0 = time.perf_counter()
        attempts: list[dict] = []
        for tgt in targets:
            host = tgt.get("host")
            port = int(tgt.get("port", 22))
            usernames = tgt.get("usernames") or ["root"]
            for username in usernames:
                client = paramiko.SSHClient()
                client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                try:
                    client.connect(
                        hostname=host,
                        port=port,
                        username=username,
                        pkey=pkey,
                        allow_agent=False,
                        look_for_keys=False,
                        timeout=config.timeout_sec,
                        banner_timeout=config.timeout_sec,
                        auth_timeout=config.timeout_sec,
                    )
                    client.close()
                    return VerifyResult(
                        status="passed",
                        credential_type=self.credential_type,
                        service=self.service,
                        latency_ms=(time.perf_counter() - t0) * 1000,
                        metadata={
                            "host": host,
                            "port": port,
                            "username": username,
                        },
                    )
                except paramiko.AuthenticationException as exc:
                    attempts.append(
                        {"host": host, "username": username, "error": "auth_failed"}
                    )
                except Exception as exc:
                    attempts.append(
                        {
                            "host": host,
                            "username": username,
                            "error": f"{type(exc).__name__}: {exc}",
                        }
                    )
                finally:
                    try:
                        client.close()
                    except Exception:
                        pass

        # All attempts failed
        last = attempts[-1] if attempts else {}
        status = "failed" if any(a.get("error") == "auth_failed" for a in attempts) else "inconclusive"
        return VerifyResult(
            status=status,
            credential_type=self.credential_type,
            service=self.service,
            latency_ms=(time.perf_counter() - t0) * 1000,
            metadata={"attempts": attempts[:10]},
            error=last.get("error"),
        )


def _load_pkey(paramiko_mod, pem: str):
    """Try OPENSSH / RSA / Ed25519 / ECDSA / DSS in order."""
    classes = [
        getattr(paramiko_mod, "Ed25519Key", None),
        getattr(paramiko_mod, "RSAKey", None),
        getattr(paramiko_mod, "ECDSAKey", None),
        getattr(paramiko_mod, "DSSKey", None),
    ]
    for cls in classes:
        if cls is None:
            continue
        try:
            return cls.from_private_key(io.StringIO(pem))
        except Exception:
            continue
    return None
