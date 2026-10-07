"""Manifest + fetcher for the content-classifier LoRA adapter weights.

The content classifier is a Qwen3-1.7B LoRA adapter. The adapter tensor
file (``adapter_model.safetensors``, ~67MB) is **not** tracked in git —
``.gitignore`` excludes ``*.safetensors``/``*.bin`` so the repo stays
lean and clone-fast. Only the small config/metadata files
(``adapter_config.json``, ``chat_template.jinja``, …) are committed.

The weights ship as release assets instead. ``sharesift models pull``
(see ``cli.py``) downloads them into ``models/<version>/`` next to the
committed configs, which is exactly where ``ContentClassifier`` looks.

Path classifiers are sklearn ``.joblib`` files and *are* committed, so
they need no pull — only the content adapters live here.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path

# Weights live next to this package's parent repo root: <repo>/models/.
# __file__ = <repo>/src/sharesift/models_manifest.py → parents[2] = <repo>.
MODELS_DIR = Path(__file__).resolve().parents[2] / "models"

# The single release that carries every published adapter. Assets are
# renamed ``<version-dir>.adapter_model.safetensors`` because GitHub
# release asset names must be unique within a release.
RELEASE_TAG = "weights-v1"
_BASE_URL = (
    "https://github.com/byevincent/ShareSift/releases/download/" + RELEASE_TAG
)

# The adapter tensor file name inside each model dir, as PEFT expects it.
ADAPTER_FILE = "adapter_model.safetensors"


@dataclass(frozen=True)
class AdapterAsset:
    """One downloadable adapter: which dir it belongs in + its checksum."""

    version: str  # model dir name under models/
    sha256: str
    size: int
    default: bool = False

    @property
    def asset_name(self) -> str:
        return f"{self.version}.{ADAPTER_FILE}"

    @property
    def url(self) -> str:
        return f"{_BASE_URL}/{self.asset_name}"

    @property
    def dest(self) -> Path:
        return MODELS_DIR / self.version / ADAPTER_FILE


# Published adapters. v0p6 is the default content model (see content.py).
# v0p7 configs exist in the tree but their weights are not yet released.
MANIFEST: dict[str, AdapterAsset] = {
    a.version: a
    for a in (
        AdapterAsset(
            version="content_classifier_v0p6_docx_salted",
            sha256="b50e9a1bbccedd8ea25617c076ee3357916354f5f24e2d59d2625291e7c606cb",
            size=69782384,
            default=True,
        ),
        AdapterAsset(
            version="content_classifier_v0p5_handlabel",
            sha256="9812c3667883540769fa7f7237639051b4fde227e617e3052a7dcabcc9d4bee3",
            size=69782384,
        ),
        AdapterAsset(
            version="content_classifier_v0p4_creddata",
            sha256="880fe387f28d5b0831aa6632278e09f34fa7e7df4c81c536428297b61d90cc2c",
            size=69782384,
        ),
        AdapterAsset(
            version="content_classifier_v0p3",
            sha256="13bea85c8596ae9d1ef5afbb09e23d755070c724768cc66c1979de83b68642f3",
            size=69782384,
        ),
    )
}

DEFAULT_ASSET = next(a for a in MANIFEST.values() if a.default)


def sha256_file(path: Path, _chunk: int = 1 << 20) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for block in iter(lambda: fh.read(_chunk), b""):
            h.update(block)
    return h.hexdigest()


def is_present(asset: AdapterAsset) -> bool:
    """True if the adapter is already downloaded and checksum-valid."""
    return asset.dest.is_file() and sha256_file(asset.dest) == asset.sha256
