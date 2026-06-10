#!/usr/bin/env python3
"""Generate the DiskForge manifest from positives_map.json.

Reads tools/diskforge_winshare/positives_map.json and emits
manifest.json with one add_files entry per source-target pair.
"""
from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent
MAP = ROOT / "positives_map.json"
MANIFEST = ROOT / "manifest.json"

# Target disk size — needs to fit the windows10 template (~50MB of OS
# stubs) + 2500 mostly-empty files (~few MB) + NTFS overhead. 1G is
# safely roomy.
DISK_SIZE = "1G"


def main() -> int:
    mapping = json.loads(MAP.read_text())
    # Build the flat add_files list — every entry is {source, target}.
    # Source paths are relative to /files mount inside docker; target
    # paths are absolute on the NTFS partition.
    # DiskForge's add_files appends source basename to target (target is
    # treated as a parent directory). Our positives_map.json stores the
    # FULL final path under `target`; strip the basename so the manifest's
    # target is just the parent directory.
    add_files = []
    for entry in mapping["positives"]:
        parent_dir = entry["target"].rsplit("/", 1)[0]
        add_files.append({
            "source": f"/files/{entry['source']}",
            "target": parent_dir,
        })
    for entry in mapping["noise"]:
        parent_dir = entry["target"].rsplit("/", 1)[0]
        add_files.append({
            "source": f"/files/{entry['source']}",
            "target": parent_dir,
        })

    manifest = {
        "schema_version": "1.0",
        "disks": [{
            "name": "diskforge_winshare_v1",
            "label": "CorpFS",
            "type": "GPT",
            "size": DISK_SIZE,
            "partitions": [{
                "number": 1,
                "type": "primary",
                "filesystem": "ntfs",
                "label": "CORPFS",
                "size": "1000M",
                "populate": {
                    "template": "windows10",
                    "add_files": add_files,
                },
            }],
        }],
    }

    MANIFEST.write_text(json.dumps(manifest, indent=2))
    print(f"[manifest] wrote {MANIFEST}")
    print(f"  add_files entries: {len(add_files)}")
    print(f"  positives: {len(mapping['positives'])}")
    print(f"  noise:     {len(mapping['noise'])}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
