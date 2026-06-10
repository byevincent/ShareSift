# The held-out discipline cycle

How ShareSift develops rules without lying to itself.

## The problem rule-based credential hunters have

You write a rule. You test it against a benchmark. It passes. You
ship. Six months later an operator files a bug saying the rule
missed an obvious case — and when you look, the rule was overfit
to the exact examples you used while authoring it.

This is the same problem ML calls "test set contamination," but
rule-based tools rarely talk about it because there's no
explicit training set. The rule author just looks at examples and
writes a regex. The examples ARE the training set, and the
benchmark you validate against is usually drawn from the same
pool. The rule passes the benchmark because it memorizes it.

Snaffler has 198 issues + PRs in its GitHub tracker. Each one
is a real-world false negative an operator filed. They're
ground truth for "what real corporate shares look like" in a way
synthetic benchmarks aren't. But if you use those issue threads
BOTH for rule authoring AND for benchmarking, you've leaked the
test set into training.

## The discipline

For each version `v0.N`, ShareSift does this:

1. **Lock the next generation's held-out set FIRST.** Mine
   sources you haven't read yet — open PRs, deep comment threads,
   issue numbers you haven't touched. Commit them to
   `benchmarks/snaffler_issues/heldout_vN+1.jsonl` BEFORE you
   write a single line of rule code.
2. **Author rules from PRIOR-locked sources only.** Whatever
   failed in `heldout_vN.jsonl` (locked at version N) is now fair
   game for rule authoring. Sources from the just-locked
   `heldout_vN+1.jsonl` are off-limits — you only get to look at
   them at validation time.
3. **Validate.** Re-run everything. The OLD held-out should
   close. The NEW held-out should NOT have been touched by your
   new rules — its score is a snapshot of what your rules
   *generalize to*, not what they were *trained on*.
4. **Ship.** Publish the post-rule scores for ALL prior
   held-outs + the pre-rule baseline for the just-locked one.

If a rule authored from generation N catches probes in
generation N+1 that you never read, that's a **generalization
signal**: the rule's premise is general enough to handle parallel
patterns. If your scores collapse on N+1, your rules overfit N.

## Two generalization signals so far

**v0.48 — browser-creds meta-rule.** Snaffler issue #46 talked
about Firefox `logins.json`. We wrote
`ShareSiftKeepFirefoxSavedCreds` at v0.47 to catch the Firefox
shape. At v0.48 we generalized to a Chromium-base browser
meta-rule:

```
(Chrome|Chromium|Edge|Brave-Browser|Opera Software\Opera)\User Data\<profile>\Login Data
```

Held-out v2 (locked BEFORE the rule was authored) contained
probes for Chrome and Edge `Login Data` paths we never wrote
rules for. Both passed. The premise ("any Chromium-base browser
profile's Login Data SQLite is interesting") generalized from
Firefox to four other browsers.

**v0.50 — SCCMContentLib$ rule.** Snaffler PR #112 (v3-locked)
added a ShareName rule for `\SCCMContentLib$`. We authored
`ShareSiftKeepSccmContentLibShare` as a FilePath approximation
(ShareSift's content engine doesn't have ShareName scope).

Held-out v4 (locked from OPEN PR #186, which adds
DataLib/FileLib/PkgLib/SMSPKG file rules) contained a probe for
`\\sccm01\SCCMContentLib$\PkgLib\PKG00100\settings.reg`. We
never wrote a rule for `.reg` files specifically. The
SCCMContentLib$ rule fired Yellow on the share-name match —
correctly catching the probe via the share-shape rather than the
file-shape. The premise ("any file under SCCMContentLib$ is
worth a Yellow tier because the share is the CMLoot target")
generalized from #112's share-rule framing to #186's
per-extension framing.

## Why v4 matters more than v3

Held-out v3 sits at 90% pre-rule baseline. That sounds great —
until you notice that pysnaffler (the underlying enumeration
library) BUNDLES upstream Snaffler rules. PRs #140 (Kerberos)
and #112 (SCCM) were both merged into upstream Snaffler. Their
rules ship with pysnaffler. So v3's 90% baseline mostly
retests bundled coverage, not ShareSift originals.

Held-out v4 was deliberately built from sources upstream
Snaffler does NOT bundle yet: PRs #192 (unencrypted PPK) and
#186 (broad SCCM coverage) are still **open** as of v0.50. The
60% baseline on v4 is the tighter "without help from bundled
upstream rules" number. The 10-point lift to 70% via the
SCCMContentLib$ generalization is the actual ShareSift signal.

The lesson: even the discipline cycle itself can drift if the
"unread sources" turn out to be already-merged-upstream. Picking
held-out sources should explicitly check upstream merge status.

## What this doesn't claim

The held-out cycle is a methodology for *not overfitting rule
authoring* against operator-grounded ground truth. It doesn't
claim:

- That ShareSift's rule set is exhaustive. It isn't. Real
  corporate shares have shapes nobody has filed a Snaffler issue
  for yet.
- That F1 on these probes generalizes to arbitrary corporate
  shares. The Snaffler-issues set is operator-selected — it's
  weighted toward cases worth filing a bug for, which biases
  toward known-painful patterns.
- That this replaces real-share evaluation. DiskForge Windows
  (forensic disk images) and engagement-derived corpora are
  complementary: they measure recall against actual file
  systems, not against curated bug reports.

What it does claim: when ShareSift adds a rule between version
N and N+1, you can verify whether the rule generalizes by
checking generation N+1's pre-rule baseline against its
post-rule score on probes the author never saw.

## What's actually contributed (and what isn't)

Held-out testing is ML 101 — the cycle borrows nothing from
unique territory. The contribution is the *release discipline*:
publishing the per-version, per-generation scoreboard as a
shippable artifact rather than a one-off audit.

None of the major rule-based credential-hunting tools publish
an equivalent:

- **Snaffler** ([README](https://github.com/SnaffCon/Snaffler))
  is upfront about it: *"like all good 'ML' projects, it just
  uses a shitload of `if` statements and regexen."* No CHANGELOG
  metrics, no held-out set, no contamination discussion.
- **TruffleHog** treats live verification (calling an API to
  confirm a credential works) as the answer to false positives.
  No documented held-out methodology in README, CONTRIBUTING, or
  `docs/`.
- **Gitleaks** ships a `testdata/` directory but no documented
  held-out methodology, no version-over-version recall/precision.
- **Kingfisher** publishes
  [`docs/COMPARISON.md`](https://github.com/mongodb/kingfisher/blob/main/docs/COMPARISON.md)
  comparing tools — by runtime, binary size, HTTP request volume.
  Not by recall, precision, or held-out generalization.
- **detect-secrets** and **MANSPIDER** — generic disclaimers and
  unit tests respectively; nothing analogous.

External benchmarks ([SecretBench, 97k+ candidates from 818
repos](https://github.com/Bill-Jensen/SecretBench);
[CredData](https://github.com/Samsung/CredData)) exist as
shared evaluation datasets, but they're exactly the
shared-training-and-test pool the discipline cycle is designed
to avoid. Academic work on rule evaluation
([arxiv:2509.16749](https://arxiv.org/abs/2509.16749)) uses
held-out methodology, but for LLM-generated rules, not
human-author release discipline.

So: **the held-out concept is not novel; using it as a release
discipline for a rule-based credential hunter, with the
scoreboard published per version, appears to be**. If you find a
prior tool that does this and is publicly documented, the claim
is wrong and the doc should be updated — open an issue with the
link.

## Reproducing the cycle

```bash
# Score yourself against every generation:
uv run python tools/eval_snaffler_issues.py --set all

# Score yourself against the 12-benchmark sweep (the headline
# numbers in the README):
.venv/bin/python tools/run_full_sweep.py
```

The probe sets are versioned in `benchmarks/snaffler_issues/`:

- `corpus.jsonl` — visible during rule authoring (training)
- `heldout.jsonl` — locked at v0.47
- `heldout_v2.jsonl` — locked at v0.48
- `heldout_v3.jsonl` — locked at v0.49
- `heldout_v4.jsonl` — locked at v0.50

Each probe has a `source_issue` URL and a `notes` field with the
operator-grounded justification for the expected tier. If you
disagree with a label, the source URL is the place to argue.
