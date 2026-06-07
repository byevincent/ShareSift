"""Compat shim — the package was renamed Truffler → ShareSift on 2026-06-07.

Existing joblib model artifacts (path classifier, ranker) baked
``truffler.*`` module paths into their pickle. This shim makes
``import truffler.X`` resolve to ``sharesift.X`` so old artifacts
still load without forcing a retrain.

Remove after the next model retrain saves with ``sharesift.*`` paths.
"""

from __future__ import annotations

import importlib
import pkgutil
import sys

import sharesift

for _info in pkgutil.walk_packages(sharesift.__path__, prefix="sharesift."):
    if _info.name.endswith(".__main__"):
        continue
    try:
        importlib.import_module(_info.name)
    except Exception:
        pass

sys.modules["truffler"] = sharesift
for _name in list(sys.modules):
    if _name.startswith("sharesift."):
        sys.modules["truffler" + _name[len("sharesift"):]] = sys.modules[_name]
