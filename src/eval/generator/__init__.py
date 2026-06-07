"""Synthetic training-data generator package.

Output flows only to ``data/synthetic/``, never ``data/eval/``. The
filesystem boundary is enforced at write time by
``postprocess._validate_output_path``.

See ``docs/generator_spec.md`` for the design discipline.
"""
