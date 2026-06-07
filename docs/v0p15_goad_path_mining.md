# v0.15 — mining GOAD share enumerations for path-classifier training

GOAD ([Orange-Cyberdefense/GOAD](https://github.com/Orange-Cyberdefense/GOAD))
is the only publicly available Windows AD lab that approximates real
corporate share structure at meaningful depth. We use it for two
purposes:

1. **Head-to-head eval target** (the v0.14 second-share test, per
   `docs/v0p14_snaffler_beating_stack_spec.md`)
2. **Training data byproduct** — enumerate the share file lists
   during step 1 and feed them into the v0.15 path-classifier corpus

This runbook covers step 2's path-mining workflow. The eval workflow
itself is in the v0.14 spec.

## Prerequisites

- ~16 GB free RAM (GOAD ships 3 VMs by default; lighter variants are
  available — see GOAD-Lite / GOAD-Light)
- ~80 GB free disk
- VirtualBox 7.x or VMware Workstation 17+
- Vagrant + Ansible installed
- Linux host (we're on george-5090 already)
- ~90 min for first-time GOAD build (caches on subsequent runs)

If 16 GB RAM is tight: use the GOAD-Light variant which deploys 2 VMs
in ~6 GB RAM. Trade-off is fewer share structures to enumerate, but
still enough for path mining.

## Step 1 — provision GOAD

```bash
# Pull GOAD
git clone https://github.com/Orange-Cyberdefense/GOAD ~/labs/GOAD
cd ~/labs/GOAD

# Build the lab (this is the long step)
./goad.sh -t install -l GOAD -p virtualbox -m local

# Verify all VMs up
vagrant status
```

Expected output: `DC01`, `DC02`, `SRV02` (and maybe `SRV03`) all
`running`.

## Step 2 — enumerate shares as the standard user

GOAD ships with a few "low-priv" users. Use `jane.ward` or similar
for enumeration (the credentials are in GOAD's docs).

```bash
# Install enumeration tooling if missing
uv add --dev impacket
# or
pipx install impacket

# List shares on each host (-N = no password; substitute creds as needed)
smbclient -L //192.168.56.10 -U jane.ward%Password123!
smbclient -L //192.168.56.11 -U jane.ward%Password123!
smbclient -L //192.168.56.12 -U jane.ward%Password123!

# Better: use smbmap for recursive listing
smbmap -H 192.168.56.10 -u jane.ward -p 'Password123!' -R | tee ~/goad_dc01_paths.txt
smbmap -H 192.168.56.11 -u jane.ward -p 'Password123!' -R | tee ~/goad_dc02_paths.txt
smbmap -H 192.168.56.12 -u jane.ward -p 'Password123!' -R | tee ~/goad_srv02_paths.txt
```

The `smbmap -R` output dumps every readable file path in `\\<host>\<share>\path\to\file.ext` format.

## Step 3 — convert to extracted_paths.jsonl schema

```bash
cd ~/projects/sharesift
uv run python tools/ingest_goad_enumeration.py \
    --inputs ~/goad_*_paths.txt \
    --output data/external/goad/extracted_paths.jsonl
```

(Stub tool — write at ingest time. ~80 lines. Parses smbmap output,
emits records in the schema downstream tools expect:
`{verbatim_path, source: "goad_enumeration", tier, credential_type, ...}`.
Tier + credential_type come from the same `regex_extract_paths_from_articles`
classifier + heuristic pipeline.)

## Step 4 — fold into v0.15 corpus

```bash
uv run python tools/build_v0p15_path_corpus.py \
    --goad data/external/goad/extracted_paths.jsonl \
    --output data/synthetic/training_v0p15_with_goad.jsonl
```

(Extend `build_v0p15_path_corpus.py` to accept `--goad` analogously to
`--peas` / `--kape` / `--hacktricks`. ~5 line change.)

## Step 5 — retrain v0.15 path classifier with the expanded corpus

```bash
uv run python tools/train_path_classifier.py \
    --train-data $PWD/data/synthetic/training_v0p15_with_goad.jsonl \
    --model-dir $PWD/models/path_classifier_v0p15_with_goad
```

Then re-run `tools/calibrate_v0p15_thresholds.py` against the new model
to get updated tier thresholds.

## Step 6 — head-to-head eval on GOAD itself

After retraining, GOAD becomes both the training byproduct AND the
held-out eval target. To prevent test-set contamination, **exclude
GOAD paths from the training run** and use them only as eval:

```bash
# Train v0.15 WITHOUT GOAD (existing corpus)
# Eval on GOAD shares head-to-head Snaffler-vs-ShareSift
uv run python tools/eval_v0p14_vs_snaffler.py \
    --file-list ~/goad_full_paths.txt \
    --ground-truth data/external/goad/ground_truth.jsonl \
    --predictions reports/v0p14_vs_snaffler_goad.jsonl \
    --summary reports/v0p14_vs_snaffler_goad_summary.json
```

(Ground truth comes from manually labeling which paths actually
contain credentials. Use `tools/label_snaffler_hits.py` adapted for
the GOAD records — same cross-check pattern.)

## Expected yield

GOAD-default deploy → 1,000-5,000 enumerable paths across the three
VMs. Most are uninteresting (system files, NETLOGON scripts) — Snaffler
rules will filter to ~50-300 "interesting" paths per host. Of those,
maybe 20-40 are actually credential-bearing in GOAD's default config.

This is similar in scale to what we've already mined from engagement
articles + PEAS + KAPE + HackTricks combined. The qualitative
difference: GOAD paths are **real share enumerations at realistic
depth/structure**, not regex-extracted from prose. Higher quality per
example than any other source we have.

## When NOT to do this

- If v0p7 eval (when it finishes training) shows AUC ≥ 0.85: you don't
  need GOAD for v0.14. Use it only as the head-to-head eval, skip
  retraining.
- If your VM bandwidth is occupied (running other labs): defer until
  the box has the spare cycles.
- If you're going to ship without GOAD because Metasploitable's win
  is already defensible: also fine. GOAD becomes a "publish this if
  someone asks for more eval" reserve.
