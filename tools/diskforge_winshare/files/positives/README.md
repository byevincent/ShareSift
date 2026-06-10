# Positives — synthetic credential files

**WARNING — synthetic content only.**

Every file in this tree is fictional. All "passwords", "API keys",
"tokens", and "private keys" are non-functional placeholders
designed to be format-shaped (so ShareSift's regex rules fire on
them) without containing any real credential that could be used
against any real system.

Conventions:

- Passwords / passphrases use the form `FAKE-<descriptor>-2024` or
  the standard AWS docs placeholder `wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY`.
- AWS access keys use the AWS-docs standard fake form
  `AKIAIOSFODNN7EXAMPLE` or other `*EXAMPLE*` markers so secret
  scanners recognize them as fake.
- Private keys are random-shaped base64 placeholders that PARSE as
  the relevant format (PuTTY PPK, OpenSSH) but the key material
  is random and not paired with any real public key.
- KeePass DBs are empty .kdbx (header-only, zero entries).

If you find a real credential here, please open an issue — that's
a bug.

## Layout (per category)

Numbers match the LAYOUT.md spec. Each category dir holds 3–6
synthetic files in numbered subdirs:

```
01_gpp/0/Groups.xml
01_gpp/1/Groups.xml
...
```

The indexed subdir pattern ensures source basename matches target
basename — DiskForge appends source basename to target dir, so the
file lands at the right Windows path with the right name.

The manifest builder (`build_manifest.py`) reads
`../positives_map.json` to map each source file to its final
Windows target path on the generated disk image.
