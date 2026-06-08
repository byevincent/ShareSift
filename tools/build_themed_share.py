r"""v0.19: build a themed synthetic share for the iteration benchmark loop.

Reads a theme config YAML (filename tokens, directories, credential
type mix, salt density) and generates a share under
``benchmarks/v0p19/<theme>/share/`` plus a manifest matching the
``constructed_share_manifest.jsonl`` schema. Output is the same shape
the existing audit + scoring tools expect.

Design choices:

* Filename construction draws from per-theme ``juicy_tokens`` and
  ``benign_tokens`` pools. Each file picks a token + extension and
  drops into one of the theme's directories. Salt density determines
  what fraction of files get a salted credential.
* File content is intentionally lightweight — short stub text that
  matches the file extension's expected shape (XLSX → CSV-ish lines,
  YAML config → key:value pairs, etc.). v0.19's measurement target is
  the Stage 1 path classifier, which doesn't read content. Stage 2
  evaluation needs the heavy content classifier weights (not tracked)
  and is deferred.
* Ground-truth labels follow ``constructed_share_manifest.jsonl``:
  ``is_juicy_label`` (from token pool choice), ``salted`` (bool),
  ``tier_label`` (Black/Red/Yellow/Green/Gray inferred from the
  credential type when salted; None otherwise), ``source_box``
  (the theme name).

Schema of the theme config YAML::

    theme: finance
    description: Finance — payroll, treasury, wire transfers
    n_files: 100
    salt_density: 0.10
    seed: 2026
    file_naming:
      juicy_tokens: [payroll, wire_instructions, treasury_creds, ...]
      benign_tokens: [Q4_close, 10K_filing, audit_report, ...]
    extensions:
      documents: [.xlsx, .docx, .pdf, .csv]
      configs: [.yaml, .json, .env, .conf]
    directories:
      - Finance/Payroll
      - Finance/Treasury
      - ...
    credential_types:
      api_key: 0.3
      db_password: 0.4
      swift_iban: 0.2
      cloud_credential: 0.1
"""

from __future__ import annotations

import argparse
import json
import random
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

# Bucketed stub credentials. Each value is realistic SHAPE only — no
# real keys, no patterns that would extract back to a real secret. The
# path classifier doesn't look at content; this is just so the salted
# files contain *something* a future Stage 2 run could try.
_STUB_CREDS = {
    "api_key": "API_KEY=sk-stub-{token}-abcdefghijklmnop",
    "db_password": "DB_PASSWORD={token}_p@ssw0rd_replace_me",
    "swift_iban": "IBAN: GB{token}NWBK60161331926819",
    "cloud_credential": "AWS_SECRET_ACCESS_KEY=stub/{token}/abcdEFGHIJKL",
    "ssh_private_key": (
        "-----BEGIN OPENSSH PRIVATE KEY-----\n"
        "stub_{token}_b3BlbnNzaC1rZXkt\n"
        "-----END OPENSSH PRIVATE KEY-----"
    ),
    "oauth_token": "Bearer ya29.stub-{token}-xyz",
    "vault_token": "hvs.stub-{token}-AAAA",
    "ehr_account": "MRN-{token}-12345 ACCT-67890",
    "saml_assertion": "<saml:Assertion>stub-{token}-base64data</saml:Assertion>",
    "ssn_pattern": "SSN: {token}-45-6789",
    "contract_password": "Password: {token}-ContractAccess",
}

# Tier hint per credential type — what the path classifier *would*
# assign if the filename matched a known token. Used to populate
# ``tier_label`` in the manifest. Themed runs measure recall vs this.
_CRED_TIER = {
    "api_key": "Red",
    "db_password": "Red",
    "swift_iban": "Black",
    "cloud_credential": "Black",
    "ssh_private_key": "Black",
    "oauth_token": "Red",
    "vault_token": "Black",
    "ehr_account": "Yellow",
    "saml_assertion": "Yellow",
    "ssn_pattern": "Yellow",
    "contract_password": "Yellow",
}


def _weighted_choice(rng: random.Random, weights: dict[str, float]) -> str:
    keys = list(weights.keys())
    vals = [weights[k] for k in keys]
    return rng.choices(keys, weights=vals, k=1)[0]


def _stub_content(extension: str, salted: str | None, theme: str, rng: random.Random) -> str:
    """Generate stub content matching the extension's expected shape.

    If ``salted`` is provided, embed the stub credential mid-file.
    """
    lorem = [
        f"# {theme} document — synthetic content for ShareSift v0.19 benchmark",
        f"# Generated for theme={theme}",
        "",
    ]
    if extension in (".yaml", ".yml"):
        body = [
            "service: example",
            "environment: production",
            "owner: ops-team",
        ]
    elif extension == ".json":
        body = ['{', '  "service": "example",', '  "env": "prod"', '}']
    elif extension in (".env", ".conf", ".cfg", ".ini"):
        body = [
            "SERVICE=example",
            "ENV=production",
            "OWNER=ops",
        ]
    elif extension == ".csv":
        body = [
            "name,role,department",
            "Alice,Engineer,Eng",
            "Bob,Analyst,Finance",
        ]
    elif extension in (".docx", ".pdf"):
        # We can't write real docx/pdf binaries with stdlib; just write
        # text content with the extension as a placeholder. v0.19 path
        # classifier doesn't care.
        body = [
            "This is a synthetic placeholder for a binary document.",
            "It exists to populate the share with extension diversity.",
        ]
    elif extension == ".xlsx":
        body = [
            "Sheet1: Q1 Q2 Q3 Q4",
            "Revenue 100 200 300 400",
        ]
    else:
        body = [
            "Synthetic stub content.",
            "This file exists for benchmark generation.",
        ]
    lines = lorem + body
    if salted:
        # Insert the stub credential at a random line, padding with
        # neutral text so it's not always at the same position.
        insert_at = rng.randint(2, len(lines))
        lines.insert(insert_at, salted)
    return "\n".join(lines) + "\n"


def build_share(config: dict, output_root: Path) -> list[dict]:
    """Build the share + manifest. Returns the manifest records list."""
    rng = random.Random(config.get("seed", 2026))
    theme = config["theme"]
    n_files = config["n_files"]
    salt_density = config["salt_density"]
    juicy_tokens = config["file_naming"]["juicy_tokens"]
    benign_tokens = config["file_naming"]["benign_tokens"]
    doc_exts = config["extensions"]["documents"]
    cfg_exts = config["extensions"]["configs"]
    directories = config["directories"]
    cred_weights = config["credential_types"]

    share_root = output_root / "share"
    share_root.mkdir(parents=True, exist_ok=True)

    manifest_records: list[dict] = []
    n_juicy_label_total = max(1, int(n_files * 0.30))  # ~30% juicy by name
    n_juicy_emitted = 0

    for i in range(n_files):
        # Decide juicy-by-name vs benign-by-name.
        is_juicy_by_name = n_juicy_emitted < n_juicy_label_total and rng.random() < 0.6
        if is_juicy_by_name:
            token = rng.choice(juicy_tokens)
            n_juicy_emitted += 1
        else:
            token = rng.choice(benign_tokens)

        # Pick directory + extension.
        directory = rng.choice(directories)
        # Configs tend to live alongside services; documents in doc-heavy dirs.
        use_config_ext = rng.random() < 0.30
        extension = rng.choice(cfg_exts if use_config_ext else doc_exts)

        # Final filename.
        suffix = f"_{i:04d}"
        filename = f"{token}{suffix}{extension}"
        rel_path = Path(directory) / filename
        abs_path = share_root / rel_path

        # Decide salt.
        salted = rng.random() < salt_density
        cred_type: str | None = None
        cred_blob: str | None = None
        if salted:
            cred_type = _weighted_choice(rng, cred_weights)
            cred_blob = _STUB_CREDS.get(cred_type, "STUB={token}").format(
                token=f"{theme}{suffix}"
            )

        abs_path.parent.mkdir(parents=True, exist_ok=True)
        abs_path.write_text(
            _stub_content(extension, cred_blob, theme, rng),
            encoding="utf-8",
        )

        manifest_records.append({
            "local_path": str(abs_path),
            "rel_path": str(rel_path),
            "is_juicy_label": is_juicy_by_name,
            "salted": salted,
            "salted_credential_type": cred_type,
            "tier_label": _CRED_TIER.get(cred_type) if salted else None,
            "source_box": theme,
            "filename_token": token,
            "extension": extension,
        })

    return manifest_records


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--theme", required=True, help="Theme name (also the config file stem).")
    p.add_argument(
        "--config-dir",
        type=Path,
        default=REPO_ROOT / "benchmarks" / "v0p19" / "themes",
        help="Directory containing <theme>.yaml configs.",
    )
    p.add_argument(
        "--output-dir",
        type=Path,
        default=None,
        help="Where to write the share + manifest. Default: benchmarks/v0p19/<theme>/.",
    )
    p.add_argument(
        "--n-files",
        type=int,
        default=None,
        help="Override the config's n_files (for smoke tests).",
    )
    args = p.parse_args(argv)

    try:
        import yaml
    except ImportError as exc:
        raise SystemExit(f"Need PyYAML: uv sync --group verify ({exc})")

    config_path = args.config_dir / f"{args.theme}.yaml"
    if not config_path.exists():
        raise SystemExit(f"Theme config not found: {config_path}")

    config = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    if args.n_files is not None:
        config["n_files"] = args.n_files

    output_dir = args.output_dir or (REPO_ROOT / "benchmarks" / "v0p19" / args.theme)
    output_dir.mkdir(parents=True, exist_ok=True)

    records = build_share(config, output_dir)

    manifest_path = output_dir / "manifest.jsonl"
    with manifest_path.open("w", encoding="utf-8") as f:
        for r in records:
            f.write(json.dumps(r) + "\n")

    paths_list = output_dir / "paths.txt"
    paths_list.write_text(
        "\n".join(r["local_path"] for r in records) + "\n",
        encoding="utf-8",
    )

    n_salted = sum(1 for r in records if r["salted"])
    n_juicy = sum(1 for r in records if r["is_juicy_label"])
    print(
        f"Built {args.theme}: {len(records)} files "
        f"({n_juicy} juicy-by-name, {n_salted} salted) → {output_dir}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
