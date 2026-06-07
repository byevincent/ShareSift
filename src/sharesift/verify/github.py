"""GitHub PAT / OAuth token verifier.

GET https://api.github.com/user — cheapest authenticated GitHub call.
Accepts every PAT variant (classic ``ghp_``, fine-grained
``github_pat_``, OAuth ``gho_``, app tokens ``ghu_``/``ghs_``).
Response includes login + id so the operator can identify whose
credentials they just verified.
"""

from __future__ import annotations

from sharesift.verify._http import http_verify
from sharesift.verify.base import BaseVerifier, VerifyConfig, VerifyResult


class GitHubVerifier(BaseVerifier):
    service = "github"
    credential_type = "github_pat"

    def _verify_inner(
        self,
        credential: str,
        config: VerifyConfig,
        context: dict,
    ) -> VerifyResult:
        return http_verify(
            credential_type=context.get("credential_type", self.credential_type),
            service=self.service,
            method="GET",
            url="https://api.github.com/user",
            headers={
                "Authorization": f"token {credential}",
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
            },
            config=config,
            extract_metadata=lambda body: {
                "login": body.get("login"),
                "user_id": body.get("id"),
                "type": body.get("type"),
            },
        )
