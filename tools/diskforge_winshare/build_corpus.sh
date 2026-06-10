#!/usr/bin/env bash
#
# diskforge_winshare_v1 — end-to-end corpus build.
#
# 1. Regenerate the file tree (positives + noise) via generate_files.py
# 2. Regenerate manifest.json from positives_map.json
# 3. Run diskforge in docker → .img output
# 4. Walk the .img with 7z, emit file_list.txt + ground_truth.jsonl
#    into data/external/diskforge_winshare_v1/
#
# Idempotent. Same seed → byte-identical corpus.
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
OUT_DIR="$REPO_ROOT/data/external/diskforge_winshare_v1"
IMG_DIR="$SCRIPT_DIR/output"

echo "[1/4] regenerating file tree..."
python3 "$SCRIPT_DIR/generate_files.py" --clean

echo "[2/4] regenerating manifest..."
python3 "$SCRIPT_DIR/build_manifest.py"

echo "[3/4] running diskforge in docker (this can take a few minutes)..."
mkdir -p "$IMG_DIR"
docker run --rm --privileged \
  -v "$SCRIPT_DIR/manifest.json:/manifests/manifest.json:ro" \
  -v "$SCRIPT_DIR/files:/files:ro" \
  -v "$IMG_DIR:/output" \
  diskforge /manifests/manifest.json

IMG="$IMG_DIR/diskforge_winshare_v1.img"
if [[ ! -f "$IMG" ]]; then
  echo "ERROR: diskforge did not produce $IMG" >&2
  exit 2
fi
echo "[3/4] image: $(ls -lh "$IMG" | awk '{print $5}')"

echo "[4/4] extracting file_list.txt + ground_truth.jsonl..."
mkdir -p "$OUT_DIR"
python3 "$SCRIPT_DIR/extract_corpus.py" \
  --image "$IMG" \
  --mapping "$SCRIPT_DIR/positives_map.json" \
  --output "$OUT_DIR"

echo "[done] corpus written to $OUT_DIR"
echo "       file_list.txt:    $(wc -l < "$OUT_DIR/file_list.txt") paths"
echo "       ground_truth.jsonl: $(wc -l < "$OUT_DIR/ground_truth.jsonl") records"
