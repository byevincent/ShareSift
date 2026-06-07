"""Path classifier model code (Phase 2).

Per ``docs/build_plan.md`` §6.2, the v0 baseline is character n-grams +
LightGBM. Only escalate to a transformer encoder (MiniLM-L6 / DistilBERT)
if this misses ≥0.90 PR-AUC on the Snaffler-blind benchmark.

Modules:

* ``train`` — training pipeline (load → featurize → fit → save)
* ``evaluate`` — PR-AUC, precision/recall/F1, per-category breakdown
* ``calibrate`` — isotonic CV calibration wrapper
* ``predict`` — single-path inference for runtime use

The featurization (``features``) and tier-band mapping (``tier``) modules
were moved to the shipped ``sharesift`` package in v0.5 because both the
training pipeline (this directory) and the runtime need them. Import via
``from sharesift.features import ...`` and ``from sharesift.tier import ...``.
"""
