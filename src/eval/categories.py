"""Authoritative enum values for eval-set records.

Mirrors the families and severity tiers defined in ``docs/pattern_taxonomy.md``.
A drift test (added in a later step) will compare these constants against
slugs parsed from the taxonomy doc.
"""

CATEGORY_SLUGS: tuple[str, ...] = (
    "private_keys_x509",
    "ssh_credentials",
    "credential_containers",
    "browser_credentials",
    "cloud_credentials",
    "modern_saas_tokens",
    "scm_cicd_tokens",
    "comms_tokens",
    "db_files",
    "embedded_secrets",
    "iac",
    "network_device",
    "windows_credential_artifacts",
    "decoy_docs",
    "benign_noise",
    "high_value_software",
)

MODERN_SAAS_SUBTYPES: tuple[str, ...] = (
    "ai_llm",
    "paas",
    "baas",
    "identity",
    "package_registry",
    "payments",
    "observability",
)

SEVERITY_TIERS: tuple[str, ...] = ("Black", "Red", "Yellow")

LABELS: tuple[str, ...] = ("juicy", "not_juicy")

SOURCES: tuple[str, ...] = (
    "engagement",
    "synthetic",
    "public",
    "seed",
    "github_search",
    "stackexchange",
)

# Labeler-added semantic flags that may appear in ``EvalRecord.validator_warnings``
# alongside (or instead of) names produced by ``negative_validator._HEURISTICS``.
# The ``validator_warnings`` field has two conceptual namespaces:
#
#   * validator namespace: names automatically produced by
#     ``negative_validator.check_path()`` when the labeler overrode a
#     tripwire warning.
#   * labeler namespace (this constant): names added by hand during
#     labeling to flag semantic properties of the record itself —
#     ``uncertainty_prior`` per ``docs/labeling_guidelines.md``,
#     §"Uncertainty Policy".
#
# ``validate.py`` accepts any name from either namespace and flags
# anything else as ``unknown_heuristic_name``.
LABELER_FLAGS: tuple[str, ...] = ("uncertainty_prior",)
