# v0.17 results — ExtractedField propagation + active learning + 6 new parsers

## Headline

**Closed the two structural gaps from the v0.16 deferral list:**

1. **SMB / LDAP verifiers now dispatch automatically** from
   structured-parser output. Scanner-path hits emit `extracted_fields`;
   the verify runner pairs username/password fields and runs SMB +
   LDAP bind attempts. The "needs username; not yet wired" message
   from v0.16 is gone.
2. **The ranker can learn from real engagements.** The HTML report
   now has per-row TP / FP / Discard buttons + notes, persisted in
   `localStorage`, exportable as `labels.jsonl`. A new
   `sharesift retrain-ranker` subcommand joins labels back to the
   original scan and trains a new LightGBM ranker. Each engagement
   teaches the model.

Plus **six new structured parsers** (13 → 19), and **SVG donut charts**
in the HTML report for the operator's at-a-glance view.

## What shipped

### Phase A — ExtractedField propagation (Scanner path)

`ScanResult` (`src/sharesift/pipeline.py:28-66`) carries a new
`extracted_fields: list[dict]` field. `Scanner.scan_batch` calls the
structured-parser dispatcher (`sharesift.parsers.dispatch.parse_file`)
on every record with content, serializes the resulting `ExtractedField`
records as dicts, and stashes them onto the `ScanResult`. `as_record()`
includes the new field but omits it when empty (so v0.16 consumers
don't see a noisy `[]` per record).

The verify runner now reads `extracted_fields` and:
- Calls `extract_user_password_pairs()` (new in `verify/_pairs.py`) to
  find paired username + password fields within the same parser run.
- Dispatches each pair to BOTH `smb_credential` and `ldap_credential`
  verifiers — they'll try the operator's SMB targets / LDAP DCs from
  the YAML target file.

Pair heuristic: same parser within one source file → almost certainly
the same credential context. Fields with names containing `username` /
`user` / `login` / etc. pair against fields with `password` / `secret`
/ `pwd` etc., positionally.

**Tests:** `test_verify_pairs.py` (7 tests), `test_pipeline_extracted_fields.py` (5 tests).

### Phase B — Six new structured parsers (13 → 19)

| Parser | Filename patterns | Targets |
|---|---|---|
| `terraform_tfstate` | `terraform.tfstate`, `*.tfstate`, `*.tfstate.backup` | Provider secrets (AWS access keys, GCP credentials, Azure client_secret), sensitive outputs |
| `docker_config_json` | `config.json`, `.dockercfg` | base64-decoded `auths.*.auth` → username + password, identitytoken (OAuth refresh) |
| `kube_config` | `kubeconfig`, `config` (sniffed as k8s) | Bearer `token`, `client-certificate-data`, `client-key-data`, basic-auth `username` + `password` |
| `cisco_running_config` | `running-config`, `startup-config`, `*.cfg` (sniffed Cisco), `*.ios` | `enable secret` (type 5/7/9), `username X password Y secret Z`, SNMP community, `crypto isakmp key` |
| `veeam_config_xml` | `veeam*.config`, `veeam*.xml`, `VeeamBackup*.config` | Account names, encrypted password blobs (cracked offline) |
| `ansible_vault` | `*.vault`, `group_vars/*.yml`, `host_vars/*.yml`, any YAML with `$ANSIBLE_VAULT` | Vault header (id + cipher + version), ciphertext blob |

The Cisco and Ansible parsers sniff content before extracting (a `.cfg`
file is only treated as Cisco if it contains enough IOS-shaped lines;
a `.yml` is only treated as vault if it contains `$ANSIBLE_VAULT`).
This keeps false positives down on generic file extensions.

**Tests:** `test_parsers_v0p17.py` (18 tests).

### Phase C — Active learning UI + ranker retrain CLI

The HTML report's expanded row now shows:

- **Three label buttons** (True positive / False positive / Discard) +
  a Clear button to reset
- **Notes field** (free-text, optional)
- **Extracted fields table** (when the record has structured-parser
  output) showing field name / value (truncated) / parser / confidence

Labels persist in `localStorage` keyed `sharesift_labels_v0p17` so the
operator can label iteratively across browser sessions. The **"Export
labels"** button in the controls bar downloads `labels.jsonl`::

```jsonl
{"record_fingerprint": "sha256:abc...", "path": "...", "label": "tp",
 "notes": "real GPP cpassword", "timestamp": "2026-06-05T..."}
```

`record_fingerprint = sha256(path + content_excerpt)[:32]` rejoins
labels to hits across re-scans.

**Retrain CLI** (`sharesift retrain-ranker`, backed by
`tools/retrain_ranker.py`):

```bash
uv run sharesift retrain-ranker \
    --hits hits.jsonl \
    --labels labels.jsonl \
    --base-ranker models/ranker_v0p14_msf3.joblib \
    --output models/ranker_engagement_$(date +%Y%m%d).joblib
```

Builds features from Scanner-path signals (path_tier,
path_probability, content_check, extracted_fields max-confidence),
groups by share (LambdaRank query group), trains LightGBM, saves the
joblib. v0.18 will warm-start from the base ranker's tree ensemble
rather than train from scratch.

**Tests:** `test_retrain_ranker.py` (2 tests — round-trip + discard
filter).

### Phase D — SVG donut charts in HTML report

Two donut charts in the summary banner:

- **Tier distribution** — Black/Red/Yellow/Green/Gray segments
- **Verification status** — passed/failed/inconclusive/skipped
  (shown only when verification ran)

Pure SVG (no Chart.js, no JS framework, no CDN). 90×90px donuts using
`stroke-dasharray` + `stroke-dashoffset` on stacked circles.

## Test summary

| Sprint | New tests | Total after sprint |
|---|---|---|
| 1 | 12 (pairs + pipeline extracted_fields) | 686 |
| 2 | 18 (six new parsers) | 704 |
| 3 | 2 (retrain ranker) | 706 |
| 4 | 2 (SVG donut + active learning UI) | 708 |

**708 tests passing, zero regressions vs v0.16's 674.**

## Files added (v0.17)

```
src/sharesift/parsers/                          # 6 new parsers
  terraform_tfstate.py
  docker_config_json.py
  kube_config.py
  cisco_running_config.py
  veeam_config_xml.py
  ansible_vault.py
src/sharesift/verify/_pairs.py                  # user/password pair extraction
tools/retrain_ranker.py                        # ranker retrain CLI
tests/
  test_pipeline_extracted_fields.py
  test_verify_pairs.py
  test_parsers_v0p17.py
  test_retrain_ranker.py
docs/v0p17_results.md                          # this doc
```

## Files modified

- `src/sharesift/pipeline.py` — `ScanResult.extracted_fields` + `_run_parsers`
- `src/sharesift/verify/runner.py` — `_verify_pairs` integration
- `src/sharesift/parsers/dispatch.py` — register the 6 new parsers
- `src/sharesift/report/html.py` — fingerprint, donut data, extracted_fields prep
- `src/sharesift/report/template.html.j2` — label buttons, donuts, extracted-fields table
- `src/sharesift/cli.py` — `retrain-ranker` subcommand
- `tests/test_report_html.py` — donut + active-learning assertions

## What's still deferred (v0.18 candidates)

- **pysnaffler integration path** for ExtractedField propagation —
  pysnaffler owns its serialization layer; intercepting it is a
  separate concern. Scanner path is enough for the active demo.
- **Azure SP / GCP service-account verifiers** — heavy SDKs;
  prioritize once a real engagement asks.
- **Conformal prediction wrapper** on the path classifier — set-valued
  predictions with calibrated coverage. Pairs with active learning.
- **Warm-start retraining** — start the new ranker from the base
  ranker's tree ensemble instead of from scratch.
- **Per-extension ranker calibration** — different thresholds for
  `.config` vs `.ps1` vs `.env`.
- **Cross-file dedup beyond share clustering** — same secret in 20
  files → one row in the report.

## Verification

End-to-end demo flow (v0.17 includes active learning round-trip):

```bash
# 1. Scan a share — extracted_fields now lands in hits.jsonl
ls /tmp/demo/* | uv run sharesift scan-files --stdin --output hits.jsonl

# 2. Live verify — SMB + LDAP now dispatch from extracted user/password pairs
uv run sharesift verify --input hits.jsonl --output verified.jsonl \
    --target-file targets.yaml --no-banner

# 3. Render the report — donut charts + per-row label buttons
uv run sharesift render-report --input verified.jsonl --output report.html
xdg-open report.html

# 4. Operator labels TP/FP, clicks Export labels → labels.jsonl

# 5. Retrain the ranker on this engagement's labels
uv run sharesift retrain-ranker --hits hits.jsonl --labels labels.jsonl \
    --base-ranker models/ranker_v0p14_msf3.joblib \
    --output models/ranker_acme_q3_2026.joblib

# 6. Next engagement uses the new ranker for top-N triage
```
