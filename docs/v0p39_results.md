# v0.39 results — network-wide share discovery

Released 2026-06-09. The headline pitch that's been promised since
the v0.37 results doc — `sharesift //10.10.10.0/24 -u u -p p` —
actually works now. impacket-backed NetrShareEnum behind a new
`discover` subcommand, with CIDR iteration and concurrent TCP
liveness probing.

## Headline

```bash
# Discover shares on one host
sharesift discover //10.10.10.5 -u user -p pass

# Discover shares across an entire subnet
sharesift discover //10.10.10.0/24 -u user -p pass

# Anonymous (null session) discovery
sharesift discover //10.10.10.5 --no-pass

# Compose with batch for end-to-end discovery → scan
sharesift discover //10.10.10.0/24 -u u -p p > targets.txt
sharesift batch --targets targets.txt -u u -p p --output-dir ./out
```

## What shipped

### `sharesift discover` subcommand

Single-host and CIDR both supported via the same target argument.
Live smoke against `dperson/samba` on `127.0.0.0/30`:

```
discover: 2 hosts in 127.0.0.0/30
2/2 hosts have SMB on :24445
//127.0.0.1/public  # disk
//127.0.0.1/Finance  # disk
# //127.0.0.1/IPC$  # special-ipc — IPC Service (Samba Server)
//127.0.0.2/public  # disk
//127.0.0.2/Finance  # disk
# //127.0.0.2/IPC$  # special-ipc — IPC Service (Samba Server)
```

File shares emit uncommented; non-file shares (IPC$, printer
queues, device shares) get a `#` prefix so `batch` (which strips
`#` comments) skips them by default. `--all-types` includes them
uncommented.

### Output formats

| Mode | Use case |
|---|---|
| `--format text` (default) | Compose with `batch` — one UNC per line, comments preserved |
| `--format json` | Tool composition — one record per share with `{host, share, type, comment, unc}` |
| `--all-types` | Include IPC / printer / device shares uncommented |

### CIDR semantics

- `expand_target_to_hosts("10.0.0.0/24")` returns 254 hosts
  (`.hosts()` excludes network + broadcast for IPv4 /24+)
- `expand_target_to_hosts("10.0.0.5/32")` returns the single host
- `expand_target_to_hosts("//10.0.0.0/30")` strips the UNC prefix
  and returns 2 usable hosts
- TCP liveness probe on `:445` filters dead hosts before paying
  impacket's auth cost; uses `ThreadPoolExecutor` with 32 parallel
  sockets

### Per-host fault tolerance (CIDR mode)

Per-host failures (auth fail, RPC error, signing requirement) log
a warning and continue with the next host:

```
discover: 254 hosts in 10.10.10.0/24
12/254 hosts have SMB on :445
  10.10.10.7: SessionError: STATUS_LOGON_FAILURE
  10.10.10.42: SessionError: STATUS_ACCESS_DENIED
//10.10.10.5/Finance  # disk
//10.10.10.5/Public   # disk
...
```

Single-host targets surface the error and exit 1 — operator typed
the host explicitly, so they want to know why it failed.

### Auth dispatch

The same nxc-shaped flag set used by `scan` / `scan-files` /
`batch`:

```bash
sharesift discover //10.0.0.5 -u alice -p pw                # NTLM
sharesift discover //10.0.0.5 -u alice -H 'NT:hash'         # PtH
sharesift discover //10.0.0.5 -u alice -k --use-kcache      # Kerberos
sharesift discover //10.0.0.5 --no-pass                     # null session
```

`enumerate_shares` accepts the existing `Auth` dataclass and
dispatches to the right impacket login method. PtH parses
`LM:NT` or bare NT via the v0.35 `_parse_hash` helper.

### New optional extra: `network-enum`

Adds `impacket>=0.12.0`. Stays separate from the `smb` extra so
operators who only need single-share scanning don't pull in
impacket's larger dep tree:

```bash
pipx install 'sharesift[smb,network-enum]'   # full pentester stack
pipx install 'sharesift[smb]'                # single-share only
```

Missing-extra raises `SystemExit` with the three-line install
guide, matching the v0.37 pattern.

## What didn't ship

**PyInstaller single-file binary** — the v0.38 deferral carries
forward. Initial onefile attempt produced a 1.5 GB intermediate
bundle despite explicit `--exclude-module torch transformers peft
bitsandbytes` flags. Bundle-size investigation needs proper scope
— sklearn submodule trimming, ideally a stage-1-only build mode
that excludes the content-classifier groundwork entirely. v0.40.

**Parallel share enumeration across hosts** — CIDR mode probes
hosts in parallel but enumerates them sequentially. For /24 sized
CIDRs the dead-host probe filters down to a handful of live hosts
(~30s total). Larger subnets would benefit from concurrent
impacket sessions but impacket's thread safety is unverified — and
the credit-flow issue v0.38 lab-tested for smbprotocol applies
here too. Defer.

## Sprint accounting

| Step | Status | Tests added |
|---|---|---|
| 1 — Single-host NetrShareEnum + ShareSummary + CLI subcommand | ✅ | +26 |
| 2 — CIDR expansion + TCP liveness probe + per-host fault tolerance | ✅ | +10 |
| 3 — PyInstaller binary | deferred → v0.40 | — |

**1133 passing total**, 29 skipped (21 SMB-gated + 8 pre-existing),
0 regressions. 21 live SMB integration tests pass.

## Meta

The five-release displacement arc:

| Release | Theme |
|---|---|
| v0.35 | Remote-share addressable (no mount) |
| v0.36 | Finder quality (1.6× rule coverage + smarter triage + correct R/W + ecosystem-compat output) |
| v0.37 | Drop-in workflows (TOML rules + pipx install + batch scans) |
| v0.38 | Parallel reads (1.5× speedup default) |
| v0.39 | Network-wide discovery (`//10.10.10.0/24` → discovered share list → batch scan) |

The end-to-end "drop on Kali, scan a subnet, get verified credentials"
workflow:

```bash
pipx install 'sharesift[smb,network-enum]'
sharesift discover //10.10.10.0/24 -u u -p p > targets.txt
sharesift batch --targets targets.txt -u u -p p --output-dir ./engagement
# ./engagement/<host>-<share>/ for each live host with shares
# ./engagement/<host>-<share>/report.html for each
# ./engagement/<host>-<share>/verified.jsonl — verified-live credentials
```

Three commands. From scratch to credentials.

MIN top-10 = 0.20 / MIN recall = 0.90 chart still flat. Operator
capability matrix moved another major step.
