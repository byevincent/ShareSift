# v0.29 DiskForge benchmark builder

Stauffer's DiskForge tool (https://github.com/jknyght9/diskforge)
plus a manifest that places 12 credential-bearing files at paths
documented in Snaffler's default rules + MITRE ATT&CK T1552.

## Reproduce

```bash
# 1. Clone + build DiskForge
git clone https://github.com/jknyght9/diskforge.git /tmp/diskforge
cd /tmp/diskforge && docker build -t diskforge .

# 2. Build the v0.29 image
mkdir -p /tmp/msf_diskforge/output
chmod 777 /tmp/msf_diskforge/output
docker run --rm --privileged \
    -v $(pwd)/tools/diskforge_v0p29/manifest.json:/manifest.json \
    -v $(pwd)/tools/diskforge_v0p29/files:/files \
    -v /tmp/msf_diskforge/output:/output \
    diskforge /manifest.json

# 3. Extract the NTFS partition with 7z (no privileged mount needed)
cd /tmp/msf_diskforge && mkdir -p extracted && cd extracted
7z x ../output/sharesift_v0p29_win10.img
7z x primary.img
find . -type f | sort | sed 's|^\./||' > /tmp/msf_diskforge/file_list.txt

# 4. Build the labeled benchmark
uv run python tools/build_diskforge_benchmark.py \
    --manifest tools/diskforge_v0p29/manifest.json \
    --file-list /tmp/msf_diskforge/file_list.txt
```

Outputs:
* `data/external/diskforge_win10/file_list.txt` — 43 paths
* `data/external/diskforge_win10/ground_truth.jsonl` — 12 positive + 31 negative
