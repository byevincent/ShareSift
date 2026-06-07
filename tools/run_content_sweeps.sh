#!/usr/bin/env bash
# Runs C5 (data-fraction) and C4 (LoRA-rank) ablation sweeps for the
# content classifier at the v0.3 baseline recipe (7 epochs, full data,
# LoRA rank 16 unless overridden).
#
# Each variant trains then evaluates, appending its result into
# reports/eval_content_classifier.json under a stable label.
#
# Order: C5 first (smaller, faster, more informative), then C4.
# LoRA alpha tracks rank at the canonical 2.0 ratio to keep variants
# comparable.
#
# Expected runtime: ~95 minutes GPU.
set -euo pipefail

cd /home/george-5090/projects/truffler

EPOCHS=7

# --- C5: data fraction sweep (rank 16, alpha 32, all training data scaled) ---
for frac in 0.25 0.50 0.75; do
    label=$(printf "%.0f" $(echo "$frac * 100" | bc))
    outdir="models/content_classifier_c5_f${label}"
    runlabel="c5_data${label}pct_7ep"
    echo
    echo "=== C5 data-fraction ${frac} -> ${outdir} ==="
    uv run python tools/train_content_classifier.py \
        --output-dir "$outdir" \
        --epochs "$EPOCHS" \
        --data-fraction "$frac"
    echo "--- eval ${runlabel} ---"
    uv run python tools/eval_content_classifier.py \
        --model-dir "$outdir" \
        --label "$runlabel"
done

# --- C4: LoRA rank sweep (full data, alpha = 2 * rank) ---
for rank in 8 32 64; do
    alpha=$(( rank * 2 ))
    outdir="models/content_classifier_c4_r${rank}"
    runlabel="c4_rank${rank}_alpha${alpha}_7ep"
    echo
    echo "=== C4 lora-rank ${rank} alpha ${alpha} -> ${outdir} ==="
    uv run python tools/train_content_classifier.py \
        --output-dir "$outdir" \
        --epochs "$EPOCHS" \
        --lora-rank "$rank" \
        --lora-alpha "$alpha"
    echo "--- eval ${runlabel} ---"
    uv run python tools/eval_content_classifier.py \
        --model-dir "$outdir" \
        --label "$runlabel"
done

echo
echo "=== ALL SWEEPS DONE ==="
