"""GCP credential JSON files.

Two flavours live under ``~/.config/gcloud/``:

* **Application Default Credentials** (``application_default_credentials.json``)
  — used by ``gcloud auth application-default login``. Contains a
  user refresh token + client_id / client_secret.
* **Legacy / per-account credentials** (``legacy_credentials/<account>/adc.json``)
  — same shape, scoped to a specific signed-in user.

Schema (both flavours):

    {
      "client_id": "<oauth client id>",
      "client_secret": "<oauth client secret>",
      "refresh_token": "<long-lived refresh token>",
      "type": "authorized_user"
    }

Service-account JSON keys (``"type": "service_account"``) are caught
by the existing v0.23 ``gcp_service_account_email`` extractor — this
parser focuses on user-credential JSONs which have ``refresh_token``
and ``client_secret`` instead.
"""

from __future__ import annotations

import json
from typing import Iterable

from sharesift.parsers.dispatch import ExtractedField


def register(reg) -> None:
    reg(r"^application_default_credentials\.json$", parse_gcloud_creds)
    reg(r"^adc\.json$", parse_gcloud_creds)
    reg(r"^credentials\.db\.json$", parse_gcloud_creds)


def parse_gcloud_creds(content: str) -> Iterable[ExtractedField]:
    try:
        data = json.loads(content)
    except json.JSONDecodeError:
        return
    if not isinstance(data, dict):
        return

    cred_type = data.get("type")
    if cred_type == "service_account":
        # Caught by the gcp_service_account_email extractor + the
        # SSH-key pattern matcher inside verify/extractor.py. Don't
        # double-emit here.
        return

    # User credential flow.
    rt = data.get("refresh_token")
    if rt:
        yield ExtractedField(
            field_name="refresh_token",
            value=str(rt),
            confidence=0.95,
            parser="gcloud_credentials",
        )
    cs = data.get("client_secret")
    if cs:
        yield ExtractedField(
            field_name="client_secret",
            value=str(cs),
            confidence=0.90,
            parser="gcloud_credentials",
        )
    ci = data.get("client_id")
    if ci:
        yield ExtractedField(
            field_name="client_id",
            value=str(ci),
            confidence=0.4,  # public identifier; context only
            parser="gcloud_credentials",
        )
    aid = data.get("account") or data.get("client_email")
    if aid:
        yield ExtractedField(
            field_name="account",
            value=str(aid),
            confidence=0.4,
            parser="gcloud_credentials",
        )
