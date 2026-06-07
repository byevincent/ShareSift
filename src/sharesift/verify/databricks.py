"""Databricks PAT verifier.

GET ``{workspace_url}/api/2.0/clusters/list?max=1`` with
``Authorization: Bearer``. Databricks PATs are workspace-scoped, so
verification needs the workspace URL from
``config.targets["databricks"]`` — a list of base URLs to try.

If no workspace URLs are configured, returns ``inconclusive`` with a
clear explanation so operators don't think the key is invalid when
they just haven't supplied a target.
"""

from __future__ import annotations

from sharesift.verify._http import http_verify
from sharesift.verify.base import BaseVerifier, VerifyConfig, VerifyResult


class DatabricksVerifier(BaseVerifier):
    service = "databricks"
    credential_type = "databricks_pat"

    def _verify_inner(
        self,
        credential: str,
        config: VerifyConfig,
        context: dict,
    ) -> VerifyResult:
        workspaces = config.targets.get("databricks") or []
        cred_type = context.get("credential_type", self.credential_type)
        if not workspaces:
            return VerifyResult(
                status="inconclusive",
                credential_type=cred_type,
                service=self.service,
                metadata={
                    "reason": (
                        "no databricks workspace URL configured; "
                        "supply via --target-file with key 'databricks'"
                    ),
                },
            )
        # Try each workspace; first success wins. On all-failure return
        # the last failure's metadata so the operator can see which
        # workspaces rejected.
        last_result: VerifyResult | None = None
        for base in workspaces:
            url = base.rstrip("/") + "/api/2.0/clusters/list?page_size=1"
            result = http_verify(
                credential_type=cred_type,
                service=self.service,
                method="GET",
                url=url,
                headers={"Authorization": f"Bearer {credential}"},
                config=config,
                extract_metadata=lambda body, base=base: {
                    "workspace": base,
                    "cluster_count": len(body.get("clusters", [])),
                },
            )
            if result.status == "passed":
                return result
            last_result = result
        assert last_result is not None
        return last_result
