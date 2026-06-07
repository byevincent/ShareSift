# v0.12 spec — Metasploitable 3 deployment-realistic test

First measurement of ShareSift on something approximating a real SMB
share rather than synthetic public-corpus benchmarks. The goal is
**one defensible end-to-end number** on VM-realistic data, plus a
small per-stage breakdown.

## Goal

> *What is ShareSift's actual precision/recall on a representative
> "credentialed corp share" when run end-to-end (path triage →
> content scan), and how does that compare to Snaffler running on
> the same share?*

Out of scope:
- Multi-network engagement realism (single-box, single-share)
- Per-credential-type breakdowns (we don't have enough sample)
- Calibration / retraining decisions (those happen after v0.12 lands
  numbers)

In scope:
- A single, measured end-to-end run on Metasploitable 3 Windows
- Ground-truth verified against the published box documentation +
  manual inspection
- Direct head-to-head: Snaffler-alone, ShareSift-alone, Snaffler-then-ShareSift

## Why Metasploitable 3 (not GOAD / HTB)

| | Metasploitable 3 | GOAD | HTB Pro Lab |
|---|---|---|---|
| Disk | ~30 GB | ~80 GB | varies |
| Setup time | ~30 min | ~1 hour | ~15 min (cloud) |
| Cost | Free | Free | Paid sub |
| Realism vs corp | High (Windows 2008 AD-attached, intentional creds) | Higher (multi-machine modern AD) | Highest (designed as engagement clone) |
| First-test value | Best — bounded, well-documented, ground truth public | Better realism, more effort | Best realism, costs $$ |

Metasploitable 3 is the right v0.12. Defer GOAD / HTB to v0.13+ if
the v0.12 number is interesting enough to justify another cycle.

## Phase 0 — Prerequisites

Host requirements:
- Linux/macOS workstation with VirtualBox 7.x or VMware
- ~40 GB free disk (Metasploitable 3 image + manspider corpus)
- 8+ GB RAM (boot the VM with 4 GB allocated)
- Network: NAT or host-only — DO NOT bridge to a real network
- ShareSift installed (v0.11 head)

Tooling:
- `vagrant` (Metasploitable 3 ships as a Vagrant box)
- `manspider` OR `crackmapexec` OR `smbmap` for enumeration
- `python-impacket` (smbclient.py is useful for verification)
- ShareSift CLI (`uv run sharesift`)

## Phase 1 — Acquire + boot the VM

```bash
# Pull the prebuilt Windows 2008 Metasploitable 3 box
git clone https://github.com/rapid7/metasploitable3
cd metasploitable3
./build.sh windows2008
vagrant up win2k8

# Get the VM IP (typically 192.168.56.x on host-only network)
vagrant ssh-config | grep HostName
```

Authentication for SMB:
- Default Metasploitable 3 user: `vagrant` / `vagrant`
- Also has `Administrator` / `vagrant` for AD context

**Sanity check** — confirm SMB is up:

```bash
smbclient -L //<VM_IP> -U vagrant%vagrant
# Expect to see shares like: ADMIN$, C$, IPC$, vagrant
```

## Phase 2 — Enumerate the share

The goal here is to produce a *complete list of paths* that ShareSift
will then triage. Use `manspider` if available (best ShareSift
integration); fall back to `crackmapexec` / `smbmap` if not.

```bash
# manspider — preferred, dumps to JSONL with full paths
manspider <VM_IP> \
    -u vagrant -p vagrant \
    --download-temp /tmp/manspider_msf3 \
    --no-content \
    --max-files-per-share 5000 \
    --json /tmp/msf3_paths.jsonl

# OR crackmapexec — simpler, less structured output
crackmapexec smb <VM_IP> \
    -u vagrant -p vagrant \
    --shares \
    --spider-folder \
    > /tmp/msf3_paths.txt

# OR smbmap — simple recursive listing
smbmap -H <VM_IP> -u vagrant -p vagrant -R \
    > /tmp/msf3_paths.raw.txt
# Then parse to one-path-per-line format
```

Output requirement: a file with **one full UNC path per line**, like:
```
\\<VM_IP>\C$\Users\Administrator\Documents\passwords.txt
\\<VM_IP>\C$\inetpub\wwwroot\config.php
\\<VM_IP>\vagrant\readme.md
...
```

Save to `data/external/metasploitable3/paths_enumerated.txt`.

## Phase 3 — Run ShareSift

Three runs to measure: Snaffler-alone (baseline), ShareSift-alone, Snaffler-then-ShareSift.

### 3.1 Snaffler-alone (baseline)

Run Snaffler against the share directly (it doesn't take a path list
— it does its own enumeration):

```bash
Snaffler.exe -s <VM_IP> -u vagrant -p vagrant \
    -o /tmp/snaffler_msf3.tsv
```

Parse the TSV. Each Snaffler hit has a tier (Black/Red/Yellow/Green)
and a path. Record:
- Total paths Snaffler flagged: N_snaffler
- Per-tier breakdown

### 3.2 ShareSift-alone (Stage 1 path triage)

```bash
cat data/external/metasploitable3/paths_enumerated.txt \
    | uv run sharesift score-paths --stdin \
    > reports/metasploitable3_path_predictions.jsonl
```

Record per-tier breakdown. Snaffler-blind subset = paths Snaffler
didn't flag but ShareSift did.

### 3.3 ShareSift end-to-end on Snaffler-blind tier-flagged paths

For each path ShareSift-Stage-1-flagged but Snaffler missed (this is
where ShareSift adds value), mount the share locally and run
scan-files:

```bash
# Mount the share
mkdir -p /mnt/msf3_c
sudo mount -t cifs //<VM_IP>/C$ /mnt/msf3_c \
    -o username=vagrant,password=vagrant,ro

# For each tier-flagged-by-ShareSift path that's not in Snaffler's
# output, run scan-files. Use tools/scan_share_runner.py (TODO build).
uv run python tools/scan_share_runner.py \
    --predictions reports/metasploitable3_path_predictions.jsonl \
    --snaffler-output /tmp/snaffler_msf3.tsv \
    --mount-prefix /mnt/msf3_c \
    --output reports/metasploitable3_end_to_end.jsonl
```

## Phase 4 — Build ground truth

This is the hardest part. We need to know which paths *actually*
contain credentials so we can compute precision/recall.

### 4.1 From box documentation

Metasploitable 3 publishes a list of intentional vulnerabilities and
credentials at:
- https://github.com/rapid7/metasploitable3/wiki
- README + per-version docs in the repo

Build a `data/external/metasploitable3/ground_truth.jsonl` with one
record per known-credential-bearing file:

```json
{"path": "\\\\<VM_IP>\\C$\\Users\\Administrator\\Documents\\passwords.txt",
 "has_credential": true,
 "credential_type": "plaintext_password",
 "source": "metasploitable3_docs"}
```

### 4.2 From manual inspection

For every file ShareSift OR Snaffler flagged, manually open it and
verify. This is bounded (probably 30-50 files) and gives us:
- TP / FP per tool
- Missed credentials (FN) — these are the ones we open and find
  credentials in despite neither tool flagging

Use:

```bash
# Open files in batch for review
cat reports/metasploitable3_path_predictions.jsonl | \
    jq -r 'select(.path_tier != null) | .path' | \
    head -50 | \
    while read p; do
        local_path="/mnt/msf3_c$(echo $p | sed 's|.*\\C\$||' | tr '\\' '/')"
        echo "=== $p ==="
        head -50 "$local_path" 2>/dev/null
        echo
    done > /tmp/msf3_review.txt
less /tmp/msf3_review.txt
```

### 4.3 The hard part — finding what we *missed*

For False Negatives, manual inspection of the full share for
credential-bearing files ShareSift didn't flag. Bounded by share size
(Metasploitable 3 has maybe ~1000 files total in vagrant share +
public share + writable shares). Spot-check 100-200 random files.

Acceptable FN-estimate methodology:
1. Random sample 100 paths ShareSift flagged None tier
2. Manually inspect each
3. Count credentials found (call this `n_fn_in_sample`)
4. Estimate total FN = `n_fn_in_sample * (total_None_paths / 100)`

This is the standard sampling-based recall estimation used in
information retrieval when full ground-truth is impractical.

## Phase 5 — Compute metrics + write up

`tools/eval_metasploitable3.py` (TODO build) reads:
- `paths_enumerated.txt`
- `path_predictions.jsonl` (ShareSift Stage 1 output)
- `end_to_end.jsonl` (ShareSift Stage 2 output)
- `snaffler_msf3.tsv`
- `ground_truth.jsonl` + manual-inspection records

Outputs `reports/metasploitable3_eval.json` with:

```json
{
  "share": "metasploitable3_windows_2008",
  "enumerated_paths": <N>,
  "snaffler_only": {
    "flagged": <N>,
    "tp": <N>, "fp": <N>, "fn": <N>,
    "precision": <X>, "recall": <X>, "f1": <X>
  },
  "sharesift_stage1_only": {
    "flagged": <N>,
    "tp": <N>, "fp": <N>, "fn": <N>,
    "precision": <X>, "recall": <X>, "f1": <X>
  },
  "sharesift_end_to_end": {
    "flagged_by_stage1": <N>,
    "confirmed_by_stage2": <N>,
    "tp": <N>, "fp": <N>, "fn": <N>,
    "precision": <X>, "recall": <X>, "f1": <X>
  },
  "snaffler_then_sharesift": {
    "union_flagged": <N>,
    "tp": <N>, "fp": <N>, "fn": <N>,
    "precision": <X>, "recall": <X>, "f1": <X>
  },
  "delta_sharesift_over_snaffler": {
    "additional_tp": <N>,
    "additional_fp": <N>,
    "recall_gain_pp": <X>
  }
}
```

Write up at `docs/v0p12_metasploitable_results.md`. Key questions
to answer in the writeup:

1. **What's the end-to-end recall on a real share?** (the headline)
2. **What's the precision delta vs Snaffler at the same operating point?**
3. **Which categories did ShareSift add over Snaffler?** (long-tail recall)
4. **What did ShareSift miss?** (failure mode analysis — file types not seen at training? Idiosyncratic paths?)
5. **Would adding the Snaffler+ShareSift union meaningfully exceed Snaffler-alone in practice?** (the "is ShareSift worth shipping" question)

## Time budget

- Phase 1 (VM setup): 30-60 min
- Phase 2 (enumeration): 15-30 min
- Phase 3 (ShareSift runs): 30-60 min
- Phase 4 (ground truth): 2-4 hours — this is the bottleneck
- Phase 5 (metrics + writeup): 1-2 hours

**Total: half to full day.** Manual ground-truth construction
dominates; everything else is automated.

## Tooling to build before running

In rough order of need:

1. `tools/scan_share_runner.py` — drives `sharesift scan-files` over a
   mounted share, filtering to Snaffler-blind paths
2. `tools/eval_metasploitable3.py` — reads predictions + ground truth,
   emits the metrics JSON
3. `tools/build_msf3_ground_truth.py` — scaffolds the ground-truth
   JSONL from Metasploitable 3 documentation, leaves stubs for manual
   verification

## Risks + how to mitigate

* **Manual ground-truth is the bottleneck.** Mitigation: bound it
  upfront. Pick 100 paths per tier × 3 tiers + 100 random None-tier
  paths = 400 inspections max. ~2 hours at 15 sec/inspection.

* **Metasploitable 3 might be too small a share** to give meaningful
  numbers. Mitigation: if total credential-bearing files < 15, run
  GOAD next as v0.13. Wide confidence intervals are acceptable for a
  first measurement; we're looking for directional signal.

* **VM-realism vs corp-realism gap.** Mitigation: explicitly document
  Metasploitable 3 as "pedagogical share" not "corp share." This v0.12
  is the first deployment-realistic test, not the only one — frame
  as "step 1 toward engagement-realistic measurement."

* **SMB mounting failures on host-only network.** Mitigation: have a
  fallback via `smbclient -c "get <path>"` per file. Slower but
  doesn't require kernel-level CIFS mounting.

## What success looks like

Two satisfactory outcomes:

1. **ShareSift adds measurable recall over Snaffler** (e.g. +10pp on
   Snaffler-blind paths with acceptable precision). v0.12 ships as
   evidence ShareSift is operationally useful as a supplement.

2. **ShareSift doesn't add meaningful recall** (e.g. <3pp gain or
   massive precision drop). Equally valid as a finding — the
   public-corpus engineering hit its limit, real engagement data is
   genuinely the next requirement, and ShareSift is a methodologically
   interesting research artifact but not a deployable tool today.

Either outcome closes the project narrative cleanly. The bad outcome
is doing v0.12 and getting ambiguous numbers (~5pp gain with 20 FPs
per TP) — in that case the spec needs revision before v0.13.

## What this measurement does NOT establish

- Performance on real corporate shares (Metasploitable 3 is pedagogical)
- Generalization across credential types (single-VM corpus is small)
- Multi-machine network performance (single-host test)
- Real-time throughput at large share sizes (~1000-file scale, real
  shares are 100K-files)

Those gaps stay structurally open until engagement data is available.

## References

- Metasploitable 3: https://github.com/rapid7/metasploitable3
- Snaffler: https://github.com/SnaffCon/Snaffler
- manspider: https://github.com/blacklanternsecurity/MANSPIDER
- ShareSift v0.11 final state: `docs/v0p11_linux_path_retrain.md`,
  `docs/v0p10_content_docx_retrain.md`
