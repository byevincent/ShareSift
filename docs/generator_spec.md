# Synthetic Training-Data Generator — Design Spec

Status: design, pre-implementation. Derived empirically from a hosted-Qwen
prompt-exploration session, not guessed. This document is the spec for
`src/eval/generator/` when it gets built. Read it before planning that module.

## Scope and the one hard boundary

This generator produces **training data only**. It must never feed the eval set.

The eval set is independent ground truth and must be real (GitHub-sourced paths,
sanitized lab paths, eventually Mandiant-provided engagement paths) and
hand-labeled. Synthetic paths evaluated against a synthetically-trained model is
circular evaluation — the model would be scored on how well it imitates the
generator, not on whether it finds real juicy paths. This is the same
labels-are-sacred / independent-ground-truth discipline enforced everywhere else
in the eval pipeline. The generator is allowed to be wrong in ways the eval set
never is, because dilution in training is survivable and contamination in eval
is fatal.

**Filesystem boundary enforces the rule.** The module lives at
`src/eval/generator/` and writes output only to `data/synthetic/`, never to
`data/eval/`. The directory split is the visible expression of the
training-vs-eval boundary: easy to grep, easy to enforce, hard to violate by
accident. Pin: `test_generator_never_writes_to_eval_dir` that monkeypatches the
output writer to forbid any path under `data/eval/` and runs the generator's
top-level entrypoint. Output-path validation should also reject any path that
isn't under `data/synthetic/` at write time, so a misconfigured CLI flag can't
land synthetic records in the eval set.

## What the prompt exploration established

Three findings, each load-bearing for the generator design:

1. **Capability is not the constraint.** A hosted Qwen on fast mode produced
   adequate output for noise and obvious positives; the local model on
   george-5090 is equally capable for those. Quality is a prompt-engineering
   problem, not a model-size problem. Generate locally for the iteration economics
   (unmetered loop = more iteration = better data); the hard-negative class is
   the one exception where the bigger/thinking-mode model earns its cost (see #3).

2. **The model collapses every under-specified axis to its laziest default.**
   Asked for "a fictional company" it produced `meridian-fs01` and `corp-nas-02`
   for twenty paths — two names, its sticky defaults. Asked for "hard negatives"
   it produced only the *easy* family (documentation-about-security, templates,
   training material) and avoided the genuinely-ambiguous family entirely. The
   rule: **every quality dimension you care about must be named explicitly in the
   prompt, or it collapses to the default.** Mechanism variety, difficulty variety,
   name variety, class ratio — none of these happen on their own.

3. **The hard-negative class is the make-or-break, and it splits into two
   families of very different difficulty.**
   - *Benign-by-context* (easy): the path itself resolves the ambiguity — it's in
     a `Templates/` or `Training/` or `Deprecated/` folder, it's a mockup, a
     blank form, a process doc. The model defaults to this family.
   - *Benign-but-ambiguous-from-path* (hard, valuable): the filename carries a
     genuine sensitivity token AND the surrounding path gives no tell. A careful
     analyst would lean juicy on the path alone and be wrong. Example:
     `\\DC2\common\db\production\backup_20251201.sql` that turns out to be
     DDL-only; `\\WIN-SRV4\users\jthompson\desktop\db_dump.sql` that's
     faker-seeded dev data. These are where the model earns its keep over
     Snaffler and they only appear when explicitly demanded, in thinking mode.

## The five generation rules

These are the spec. Each was derived from a specific failure observed in the
exploration session.

### Rule 1 — Per-class generation with explicit counts (ratio control)
Never ask for "a mix." Generate one class at a time with an explicit count, and
control the dataset ratio by deciding how many of each class to request. Asking
for a mix yields whatever ratio the model feels like (observed: 20% positive,
heavily skewed toward hard negatives) — and ratio/distribution was the single
thing Rafael Benari's replication had to fix across ~10 dataset revisions.
Classes, at minimum:
- obvious positives (real secrets, clear from path)
- realistic noise (the boring 90% of a real share)
- hard negatives — benign-by-context
- hard negatives — benign-but-ambiguous (generate separately, thinking mode)

Target distribution skews toward negatives and noise to reflect real shares
(genuinely-juicy files are 1–5% of a real share, not 20%). Set the ratio
deliberately; do not inherit the model's default.

### Rule 2 — Externally supplied, rotated names (no fingerprint leakage)
Do not let the model invent server/share/company/client names — its defaults are
sticky (Meridian, Acme, Globex, Contoso) and will become a learned constant that
appears across both juicy and non-juicy paths, teaching the model a generator
fingerprint instead of real structure. Supply server/share roots in the prompt.
**Rotate the supplied set across generation runs** (or substitute names
programmatically post-generation), because even a fixed supplied set of eight
roots becomes a constant at volume. The model also leaks defaults at the
*content* level (it produced `Acme_Corp` as a client name inside a path even
when server names were constrained) — constrain or post-process entity names
too, anywhere they appear.

Real shares are messier than the model's default "tidy plausible corporate"
distribution: `\\OLDSERVER\`, `\\srv-fs-03-DONOTUSE\`, half-migrated junk,
inconsistent conventions. Push the generator toward that mess explicitly; its
default is too clean. This cleanliness skew is also a core reason the eval set
must be real, not synthetic.

### Rule 3 — Force mechanism AND difficulty variety (name every axis)
"No two should use the same trick" worked — it produced genuinely varied
hard-negative *mechanisms* (semantic ambiguity, docs-about-secrets, mockups,
training material, coincidence). But difficulty variety did NOT happen until
demanded separately, because the model defaults to the easiest member of any
class. For the ambiguous hard-negative family, explicitly forbid the
disambiguating context that lets the model cheat:

> Do NOT use a folder name that resolves the ambiguity. Forbidden disambiguating
> context: "template", "blank", "training", "sample", "example", "test",
> "fixture", "mock", "deprecated", "old", "archive", "demo", "draft", "policy",
> "guide", "how-to". The file should sit in a plausible real-use location (user
> folder, department working dir, deployment folder, share root). A reasonable
> analyst should be genuinely split. If you can tell it's benign from the path,
> it's the wrong example.

Validation signal when reviewing output: for each path ask "could I know this
from the path alone?" If the `why` field is the only thing revealing benignity,
it's the right kind of example. If the path self-resolves, the model cheated and
the forbidden-words list needs expanding. (Fast mode cheated repeatedly —
"Template document", "fixture", "placeholders" — despite the constraint;
thinking mode obeyed it.)

**Machine-check variety, don't rely on human review.** For a batch of N
hard-negative-ambiguous paths, the generator self-scores by counting how often
each forbidden-context word appears across the `why` rationales of the batch
(separately, across the `path` field, where the same word means a constraint
violation, not just a mechanism reuse). Each word capped at ⌈N/k⌉ occurrences,
with k a target diversity index — concrete first cut: k = 4, so in a batch of
40, no single forbidden word can appear in more than 10 rationales. A batch
that fails the cap is regenerated, not patched. Catches the "model regressed to
one trick" failure mode without human review of every batch, and catches it at
the batch level where the fix is cheap.

### Rule 4 — Thinking mode for the hard-negative-ambiguous class only
Observed gap: fast mode handled noise and obvious positives fine but, on the
ambiguous hard negatives, both took the lazy path (drifting to easy
semantic-ambiguity examples) and violated the forbidden-context constraint.
Thinking mode held the genuinely-split middle and obeyed the constraints.
Strategy: fast/cheap mode for the bulk (noise, obvious positives, easy
negatives), thinking mode reserved for the ambiguous hard-negative class. Don't
pay the reasoning cost on the easy 80%.

### Rule 5 — Regex-tier tokens are EXCLUDED from the hard-negative class (anti-contamination)
This is the most important correctness rule and the easiest to get wrong.

The hard-negative class must draw its sensitivity tokens only from the
**ml_tier / ambiguous** set: `password`, `creds`, `secret`, `backup`, `admin`,
`dump`, `.sql`, `.env`, `.config`, `key` (when ambiguous).

It must NEVER draw from the **regex-tier / near-certain-positive** set:
`.pem`, `.kdbx`, `.kdb`, `.pfx`, `.p12`, `id_rsa`/`id_ed25519`/etc, GPP paths
(SYSVOL/Policies xml), `NTDS.dit`, registry hives, `.kirbi`/`.ccache`.

Why: the regex-tier patterns are near-certain positives by design — that's the
whole basis of `negative_validator.py`'s heuristics and the deterministic
content tier. The exploration session produced `server_key.pem` ("corrupted
garbage") and `ssh/deploy_key` ("only the public half") as not_juicy hard
negatives. Each is individually defensible as a *story*, but as *training data*
they're poison: they teach the model to discount a high-confidence signal
because of a rare benign exception (the 1% case), eroding the exact prior the
regex tier exists to enforce. This is Rafael's contamination lesson in a new
costume — there, real passwords got labeled negative and the model learned to
ignore real passwords; here, regex-tier positives as synthetic negatives would
teach the model to ignore near-certain positives.

**Enforcement: the exclusion gate is the callable `check_path(candidate)`, not
a copied pattern set.** The generator imports `check_path` from
`src.eval.negative_validator` and refuses to emit any hard-negative candidate
for which `check_path(candidate_path) != []`. Using the same callable means the
exclusion list cannot drift from the validator's heuristics by construction —
the same one-function-shared discipline already proven between `build_queue.py`
and `validate.py` for `normalize_for_dedup`. A regex-tier path being generated
as a negative is a generation bug, not a valid sample — drop it and regenerate.
Pin: `test_generator_hard_negative_never_fires_negative_validator` runs
`check_path` over every emitted hard-negative path in a representative batch
and asserts zero firings. Any future drift breaks this test loudly, in the
right place, without the generator needing to know which patterns the validator
currently uses.

## Output format
Generate JSONL with at minimum `path`, the intended `label`, a `category_hint`
mapping to the real `CATEGORY_SLUGS`, and a `why` (the label rationale — useful
for spot-checking and as a future template for the model's own notes-field
explanations). The generator output is training data, so it does NOT go through
`EvalRecord`; it has its own (looser) envelope. Keep it decoupled from the eval
schema the same way `QueueRecord` is.

## Open questions for the implementation plan
- Exact target ratio across the four+ classes (informed by real-share base rates;
  refine once GitHub-sourced real paths reveal the actual noise/signal mix).
- **Name substitution scans the whole `path` field, not just server roots.**
  Lean: post-hoc programmatic substitution. Generate with placeholder roots,
  then run a substitution pass over the full `path` string — server, share,
  intermediate directories, AND filename — because the exploration leaked entity
  names mid-path (`jthompson` in a user folder, `Acme_Corp` embedded inside a
  filename) and not just in server roots. A pass that only touches the leading
  `\\server\share\` portion would leave those leaks in place. Secondary benefit
  of post-hoc over supplied-set rotation: it cleanly separates the "model
  generates structure" job from the "fill in entities" job, and the model is
  empirically bad at the second and good at the first — split jobs along that
  grain. Substitution source: a wide rotating pool of names per run, large
  enough that no individual name appears in more than a small fraction of the
  batch.
- Local-model invocation pattern (llama-server endpoint, same as qwen_cyber) and
  whether thinking-mode is available on the local model or whether the
  hard-negative class needs a different local model / sampling config.
- Dedup of generated paths against each other and against the eval set (must not
  generate a training path that's already a labeled eval path — reuse
  `normalize_for_dedup`).

## What this does not change
The eval set is still the gate and still must be real. This spec makes the
*training-data* half tractable; the *eval-data* half still needs the GitHub
sourcing script (`source_github.py`) for real paths. Do not let good synthetic
output tempt evaluation on synthetic data.
