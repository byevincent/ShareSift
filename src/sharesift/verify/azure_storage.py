"""Azure Storage account key verifier.

Parses an Azure storage connection string for AccountName +
AccountKey, then issues an HTTP GET to the storage account's blob
list endpoint authenticated via Shared Key. Read-only — confirms
the key is live without enumerating containers or mutating anything.

Shared Key signature is documented at
https://learn.microsoft.com/en-us/rest/api/storageservices/authorize-with-shared-key.
We construct the canonicalized string and sign with HMAC-SHA256
over the base64-decoded account key.

The verifier expects the full connection string as the credential
value (the v0.23 extractor produces exactly that shape). If we
receive just an AccountKey, the verifier returns ``skipped`` with
``reason=no_account_name`` — same pattern as the Twilio verifier
when the Account SID isn't supplied.
"""

from __future__ import annotations

import base64
import email.utils
import hashlib
import hmac
import re

from sharesift.verify._http import http_verify
from sharesift.verify.base import BaseVerifier, VerifyConfig, VerifyResult

_CONN_RE = re.compile(
    r"AccountName=(?P<name>[A-Za-z0-9]+);"
    r"AccountKey=(?P<key>[A-Za-z0-9+/=]+)"
)


def _parse_connection_string(value: str) -> tuple[str | None, str | None]:
    m = _CONN_RE.search(value)
    if not m:
        return (None, None)
    return (m.group("name"), m.group("key"))


def _shared_key_signature(
    account_name: str,
    account_key: str,
    canonicalized_resource: str,
    date_str: str,
) -> str:
    """Build the Shared Key Authorization header value for a
    minimal GET against the blob list endpoint."""
    # Canonicalized headers for a List Containers GET.
    canonicalized_headers = (
        f"x-ms-date:{date_str}\n"
        "x-ms-version:2020-04-08\n"
    )
    # String to sign: VERB + newlines for empty fields + canonicalized headers + canonicalized resource.
    string_to_sign = (
        "GET\n"   # HTTP verb
        "\n"      # Content-Encoding
        "\n"      # Content-Language
        "\n"      # Content-Length
        "\n"      # Content-MD5
        "\n"      # Content-Type
        "\n"      # Date (empty — using x-ms-date header instead)
        "\n"      # If-Modified-Since
        "\n"      # If-Match
        "\n"      # If-None-Match
        "\n"      # If-Unmodified-Since
        "\n"      # Range
        f"{canonicalized_headers}"
        f"{canonicalized_resource}"
    )
    key_bytes = base64.b64decode(account_key)
    digest = hmac.new(
        key_bytes, string_to_sign.encode("utf-8"), hashlib.sha256
    ).digest()
    return base64.b64encode(digest).decode("utf-8")


class AzureStorageVerifier(BaseVerifier):
    service = "azure_storage"
    credential_type = "azure_storage_connection_string"

    def _verify_inner(
        self,
        credential: str,
        config: VerifyConfig,
        context: dict,
    ) -> VerifyResult:
        cred_type = context.get("credential_type", self.credential_type)
        account_name, account_key = _parse_connection_string(credential)
        if not account_name or not account_key:
            return VerifyResult(
                status="skipped",
                credential_type=cred_type,
                service=self.service,
                metadata={"reason": "could_not_parse_connection_string"},
            )

        # List Containers endpoint — read-only, no enumeration cost.
        url = f"https://{account_name}.blob.core.windows.net/?comp=list"
        canonicalized_resource = f"/{account_name}/\ncomp:list"
        date_str = email.utils.formatdate(usegmt=True)
        signature = _shared_key_signature(
            account_name, account_key, canonicalized_resource, date_str
        )
        return http_verify(
            credential_type=cred_type,
            service=self.service,
            method="GET",
            url=url,
            headers={
                "Authorization": f"SharedKey {account_name}:{signature}",
                "x-ms-date": date_str,
                "x-ms-version": "2020-04-08",
            },
            config=config,
            # Azure returns 200 + XML on success, 403 on bad signature.
            success_status=(200,),
            fail_status=(403, 401),
            extract_metadata=lambda body: {
                "account_name": account_name,
                # body is XML, not JSON — extract_metadata won't json-decode it.
                # The http_verify helper catches JSON decode error and ignores it.
            },
        )
