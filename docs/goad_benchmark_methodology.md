# GOAD head-to-head benchmark methodology

How to run `sharesift hunt` against `Snaffler.exe` on a GOAD-class
Active Directory lab and produce a defensible scorecard.

## Why GOAD specifically

GOAD ([Game of Active Directory](https://github.com/Orange-
Cyberdefense/GOAD), Orange Cyberdefense) is the standard AD pentest
lab. We pick it because:

- **Pre-seeded credential shapes.** GOAD's vulnerable AD configs
  (Kerberoasting, AS-REP, GPP cpassword, SQL service accounts,
  LAPS edge cases) put real credential-shaped content into the
  shares. This grounds the recall measurement — we know what
  *should* be found.
- **Reproducible.** Vagrantfile + Ansible playbooks build identical
  labs across runs. A scorecard from your GOAD reproduces on
  someone else's GOAD.
- **Documented host/share layout.** Each host's shares are listed
  in the GOAD docs; the benchmark scorecard cross-references
  expected vs found by path.

The full lab is `GOAD-Light` (5 VMs, ~16-20 GB RAM) for the
minimal config or `GOAD-Heavy` (10+ VMs, 32 GB+) for the full
multi-domain forest.

## Lab spec (`GOAD-Light` minimum)

| Host | IP | Role |
|---|---|---|
| sevenkingdoms.local | 192.168.56.10 | DC (forest root) |
| kingslanding.sevenkingdoms.local | 192.168.56.11 | Member server |
| winterfell.north.sevenkingdoms.local | 192.168.56.22 | Subdomain DC |
| meereen.essos.local | 192.168.56.12 | Trusted forest DC |

Seeded creds:

- `khal.drogo / horse` — vanilla domain user
- `arya.stark / Needle` — domain user with extra perms
- `vagrant / vagrant` — local admin everywhere

## Setup

1. **Stand up GOAD-Light** via Vagrant + VirtualBox (or Proxmox):
   ```bash
   git clone https://github.com/Orange-Cyberdefense/GOAD
   cd GOAD
   ./goad.sh -t install -l GOAD-Light -p virtualbox
   ```
   First build takes 1-2 hours. Subsequent up/halt is fast.

2. **Verify network connectivity** from your attacker box:
   ```bash
   nmap -sn 192.168.56.0/24
   nmap -p 389,445 192.168.56.10  # LDAP + SMB on the DC
   ```

3. **Confirm creds work** with `nxc`:
   ```bash
   nxc smb 192.168.56.10 -u khal.drogo -p horse --shares
   ```

## Running the benchmark

### Step 1: ShareSift run (Kali / attacker box)

The harness invokes `sharesift hunt` and captures timings:

```bash
python tools/goad_benchmark.py \
    --ad-domain sevenkingdoms.local \
    --dc 192.168.56.10 \
    -u khal.drogo -p horse \
    --output-dir ./goad_bench_$(date +%Y-%m-%d)
```

Output lands in `./goad_bench_<date>/sharesift/` with one subdir
per discovered share (per `cmd_hunt`'s normal layout).

### Step 2: Snaffler run (Windows host inside lab)

Snaffler is Windows-only. Easiest path: run it from `kingslanding`
(the member server in GOAD) over RDP, or PE-load it via NetExec
from your attacker box.

From `kingslanding` (RDP in as `vagrant`):

```powershell
# Drop Snaffler.exe (download from
#   https://github.com/SnaffCon/Snaffler/releases/latest)
.\Snaffler.exe -s -d sevenkingdoms.local -o C:\snaffler_run.tsv -y tsv
```

Flags:
- `-s` — stdout streaming (see live finds)
- `-d sevenkingdoms.local` — AD domain to enumerate
- `-o ...` — output file
- `-y tsv` — TSV format (what `goad_benchmark.py` ingests)

Copy the TSV back to the attacker box:

```bash
smbget -U vagrant '%vagrant' \
    smb://kingslanding/c\$/snaffler_run.tsv \
    -o ./goad_bench_<date>/snaffler_run.tsv
```

(Or `scp` if you've SSH'd in.)

### Step 3: Score

Re-run the harness with `--skip-sharesift` to score against the
existing ShareSift output:

```bash
python tools/goad_benchmark.py \
    --ad-domain sevenkingdoms.local \
    --output-dir ./goad_bench_<date> \
    --snaffler-tsv ./goad_bench_<date>/snaffler_run.tsv \
    --skip-sharesift
```

This emits:
- `scorecard.md` — markdown for visual review
- `scorecard.json` — machine-readable summary
- `sharesift_hits.jsonl` — normalized ShareSift findings
- `snaffler_hits.tsv` — copy of the Snaffler TSV

## What the scorecard measures

**Overall:**
- Total unique paths each tool found
- Overlap (caught by both)
- Tool-unique finds

**Per category** (19 buckets covering GPP, KeePass, AWS, browser,
SCCM NAA, SQL connection strings, etc.):
- ShareSift count
- Snaffler count
- Overlap
- Tool-unique

**Honest reading:**

- **Recall ratio** (`sharesift_overlap / snaffler_total`) — what
  fraction of Snaffler's finds ShareSift also caught.
- **Expansion ratio** (`sharesift_only / snaffler_total`) — what
  fraction extra ShareSift surfaced beyond Snaffler.
- **Throughput** — wall-clock time per tool. Snaffler's C# +
  threaded enumeration will win on raw speed; ShareSift's
  Python+impacket stack tops out at ~7 MB/s per host. For
  credential hunting on small files this rarely matters; for
  shares with 500 MB SQL dumps it shows.

## What the scorecard does NOT measure

- **Precision** — neither tool has a labeled FP list on GOAD
  shares. Both tools' findings include some FPs; absolute
  precision needs hand-review.
- **Live verification** — ShareSift can run `sharesift verify` on
  the hits.jsonl to check which creds are actually usable; that
  layer isn't in the head-to-head because Snaffler doesn't verify.
- **DFS coverage** — until v0.53 ships, ShareSift skips DFS-shaped
  UNCs (with `--detect-dfs`) or hits `STATUS_PATH_NOT_COVERED` and
  errors. GOAD-Light doesn't use DFS by default; if you enable it
  the comparison changes.

## When to re-run

- After every ShareSift rule generation (v0.53, v0.54, ...)
- After significant model retrains (path classifier / content
  classifier)
- After upstream Snaffler updates (Snaffler's rule set evolves;
  re-run against the latest to keep the comparison fair)

## Pinning the lab

Capture the GOAD commit + the seed-data versions in the
`scorecard.md` header. Different GOAD versions ship different
seeded creds, so a benchmark from `GOAD-Light v3.0` doesn't
compare apples-to-apples with `GOAD-Light v3.1`.

```bash
cd GOAD && git rev-parse HEAD  # paste into scorecard
```
