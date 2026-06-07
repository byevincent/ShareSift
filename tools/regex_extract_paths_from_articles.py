"""v0.15 Phase C-alt — regex + rule-based path extraction.

Hybrid alternative to ``extract_paths_from_articles.py`` (LLM
extraction). Uses regex to identify candidate paths in scraped
articles, then applies the ported Snaffler ruleset + Truffler extras
to assign tier and credential_type. Zero API cost, ~5 min runtime,
no hallucinations (extracted strings are by construction substrings
of source text).

Architectural reasoning: extraction (find path strings) and
classification (assign tier + cred type) are different problems.
Regex is 100% recall on path-shaped strings and free. The ported
Snaffler ruleset already encodes the tier + credential_type judgment
for known credential filenames — those rules were authored by
working pentesters who saw real engagement data. Combining the two
gets us most of v0.15's training corpus without spending API budget
or pasting time.

The LLM-kit flow (``extract_paths_from_articles.py --mode prep-kit``)
remains useful for:
- Cross-check on paths the regex misses (rare — most engagement
  writeups format paths as code or quoted strings)
- Classifying paths whose filenames no rule matches (the "unknown
  tail" — write up to ``--unknown-output`` for optional LLM pass)
- Discovery_type / share_context metadata if you want it (not
  required for the path-classifier retrain target)

Output schema (same as LLM mode for downstream compatibility)::

    {
        "source_url": "...",
        "verbatim_path": "C:\\\\...",
        "context_excerpt": "...",
        "credential_type": "config_secret" | null,
        "share_context": "unknown",
        "discovery_type": "regex_extracted",
        "tier": "Red" | "Yellow" | "Black" | "None",
        "matched_rule": "TrufflerKeepWordPressConfig",
        "verbatim_match_quality": "exact",
        "model": "regex+snaffler_rules",
        "extracted_at": "..."
    }

Usage::

    uv run python tools/regex_extract_paths_from_articles.py \\
        --input data/external/engagement_corpus/articles.jsonl \\
        --output data/external/engagement_corpus/extracted_paths.jsonl \\
        --unknown-output data/external/engagement_corpus/unknown_paths.jsonl
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "references" / "pysnaffler"))
sys.path.insert(0, str(REPO_ROOT / "src"))

DEFAULT_INPUT = REPO_ROOT / "data" / "external" / "engagement_corpus" / "articles.jsonl"
DEFAULT_OUTPUT = REPO_ROOT / "data" / "external" / "engagement_corpus" / "extracted_paths.jsonl"
DEFAULT_UNKNOWN_OUTPUT = REPO_ROOT / "data" / "external" / "engagement_corpus" / "unknown_paths.jsonl"


# ---------------------------------------------------------------------------
# Regex patterns
#
# Tuned conservatively — false positives matter less than missing real paths,
# because the rule-based classifier downstream filters out paths whose
# filenames don't match any credential-relevant rule.
# ---------------------------------------------------------------------------

# UNC: \\host\share\path (no trailing dot or slash; word chars + common path chars)
_UNC_RE = re.compile(
    r"\\\\[\w.-]+\\[\$\w.-]+(?:\\[\w. \-+()&]+)+"
)

# Drive-letter: C:\path or D:\path — word chars + spaces (Windows paths often
# have spaces, e.g. "Program Files\Foo"). Stop at common terminators.
_DRIVE_RE = re.compile(
    r"\b[A-Za-z]:\\(?:[\w. \-+()&]+\\)+[\w. \-+()&]+"
)

# Env-var prefixed Windows: %TEMP%\foo, %APPDATA%\foo, %SYSTEMROOT%\foo
_ENVVAR_RE = re.compile(
    r"%[A-Z_]+%\\(?:[\w. \-+()&]+\\)*[\w. \-+()&]+"
)

# Linux absolute paths under known credential-relevant roots.
# Conservative root list reduces noise (URLs path-segments, code snippets).
_LINUX_RE = re.compile(
    r"(?<![\w./])"
    r"/(?:etc|var|home|root|opt|srv|usr|tmp|mnt|media|run|proc|sys)"
    r"(?:/[\w.+\-:]+)+"
)

# Tilde-home: ~/.ssh/id_rsa, ~/file
_TILDE_RE = re.compile(
    r"(?<![\w.])~/(?:[\w.+\-]+/)*[\w.+\-]+"
)

# Markdown/code-fenced paths — most blog posts wrap paths in backticks.
# This captures "backtick + path-like + backtick" to find paths even when
# the wider regexes would miss them (e.g. relative paths like "config/db.yml").
_BACKTICK_PATH_RE = re.compile(
    r"`([^`]+?\.[a-zA-Z0-9]+)`"
)


def _looks_like_url(s: str) -> bool:
    """Reject path candidates that are obviously URLs."""
    return s.startswith(("http://", "https://", "ftp://", "//")) or "://" in s


def _looks_like_path(s: str) -> bool:
    """Heuristic: must contain a path separator AND look like a real path."""
    if "\\" not in s and "/" not in s:
        return False
    if _looks_like_url(s):
        return False
    # Reject lines that are clearly code snippets / regex / commands
    if any(c in s for c in ("$(", "`", "${", "{{", "<<")):
        return False
    if s.count(" ") > 3:  # too many spaces, probably prose
        return False
    return True


def _extract_paths_from_text(text: str) -> list[tuple[str, int, int]]:
    """Returns list of (path, start_offset, end_offset). Deduplicated."""
    candidates: list[tuple[str, int, int]] = []
    seen: set[tuple[str, int]] = set()
    for rex in (_UNC_RE, _DRIVE_RE, _ENVVAR_RE, _LINUX_RE, _TILDE_RE):
        for m in rex.finditer(text):
            s = m.group(0).rstrip(".,;:'\")")  # strip trailing punctuation
            if not _looks_like_path(s):
                continue
            key = (s, m.start())
            if key in seen:
                continue
            seen.add(key)
            candidates.append((s, m.start(), m.start() + len(s)))
    # Backtick-fenced paths (markdown code spans) — catch paths the above missed
    for m in _BACKTICK_PATH_RE.finditer(text):
        s = m.group(1).strip()
        if not _looks_like_path(s):
            continue
        key = (s, m.start(1))
        if key in seen:
            continue
        seen.add(key)
        candidates.append((s, m.start(1), m.end(1)))
    return candidates


# ---------------------------------------------------------------------------
# Rule-based tier + credential_type classification
# ---------------------------------------------------------------------------

# Map Snaffler rule names to credential_type. Snaffler's rule taxonomy
# encodes tier; this map adds the cred-type axis. Entries not listed get
# credential_type=None and use the rule's tier as-is.
_RULE_TO_CRED_TYPE = {
    # Black-tier credential stores
    "KeepSSHFilesByFileName": "ssh_credentials",
    "KeepSSHFilesByPath": "ssh_credentials",
    "KeepSSHKeysByFileExtension": "private_key",
    "KeepNixLocalHashesByName": "hash",
    "KeepWinHashesByName": "hash",
    "KeepCloudApiKeysByName": "token",
    "KeepCloudApiKeysByPath": "token",
    "KeepPassMgrsByExtension": "encrypted_credential",
    "KeepRemoteAccessConfByName": "config_secret",
    "KeepCyberArkConfigsByName": "config_secret",
    "KeepNetConfigFileByName": "config_secret",
    "KeepMemDumpByName": "hash",
    # Red-tier creds
    "KeepConfigByName": "config_secret",
    "KeepPhpByName": "config_secret",
    "KeepRubyByName": "config_secret",
    "KeepDbMgtConfigByName": "config_secret",
    "KeepGitCredsByName": "token",
    "KeepFtpServerConfigByName": "config_secret",
    "KeepFtpClientByName": "config_secret",
    "KeepPasswordFilesByName": "plaintext_password",
    "KeepJenkinsByName": "encrypted_credential",
    "KeepInfraAsCodeConfigByExtension": "config_secret",
    "KeepMemDumpByExtension": "hash",
    "KeepInlinePrivateKey": "private_key",
    # Truffler extras
    "TrufflerKeepWordPressConfig": "config_secret",
    "TrufflerKeepPhpMyAdminConfig": "config_secret",
    "TrufflerKeepUnattendXmlUpgrade": "plaintext_password",
    "TrufflerKeepLaravelEnv": "config_secret",
    "TrufflerKeepRailsSecrets": "config_secret",
    "TrufflerKeepResetPasswordXml": "encrypted_credential",
    "TrufflerKeepDockerCompose": "config_secret",
    # Snaffler catch-up rules
    "KeepDomainJoinCredsByName": "plaintext_password",
    "KeepDomainJoinCredsByPath": "plaintext_password",
    "KeepKerberosCredentialsByName": "ssh_credentials",
    "KeepKerberosCredentialsByExtension": "key_material",
    "KeepVMDisksByExtension": "encrypted_credential",
    "KeepSCCMBootVarCredsByPath": "config_secret",
    # Yellow tier
    "KeepDatabaseByExtension": "encrypted_credential",
    "KeepDeployImageByExtension": "encrypted_credential",
    "KeepDefenderConfigByName": "config_secret",
    "KeepPcapByExtension": "key_material",
    "KeepRemoteAccessConfByExtension": "config_secret",
    "KeepDbConnStringPw": "config_secret",
}


# ---------------------------------------------------------------------------
# Heuristic tier layer — applied after Snaffler rules miss
#
# Catches credential-relevant paths Snaffler's filename rules don't know
# about (because Snaffler targets specific filenames, but engagement
# writeups describe operational paths beyond those). Each heuristic is a
# (regex, tier, credential_type, label) tuple applied in order; first
# match wins.
# ---------------------------------------------------------------------------

_HEURISTIC_RULES: list[tuple[re.Pattern, str, str | None, str]] = [
    # Private keys + cert-like files (highest confidence)
    (re.compile(r"(?:^|[/\\])id_(rsa|dsa|ecdsa|ed25519)(?:\.pub)?$", re.I),
     "Black", "private_key", "heuristic_id_keyfile"),
    (re.compile(r"\.(pem|pfx|p12|jks|keystore)$", re.I),
     "Black", "private_key", "heuristic_key_extension"),

    # SSH artifacts not in Snaffler's narrow rules
    (re.compile(r"[/\\]\.ssh[/\\][\w.\-]+$", re.I),
     "Black", "ssh_credentials", "heuristic_ssh_path"),
    (re.compile(r"ssh_host_(rsa|dsa|ecdsa|ed25519)_key", re.I),
     "Black", "private_key", "heuristic_ssh_host_key"),
    (re.compile(r"(?:^|[/\\])(authorized_keys|known_hosts)$", re.I),
     "Black", "ssh_credentials", "heuristic_authorized_keys"),

    # Cloud / sync credential dirs
    (re.compile(r"[/\\]\.aws[/\\](credentials|config)", re.I),
     "Black", "token", "heuristic_aws_credentials"),
    (re.compile(r"[/\\]\.kube[/\\]config", re.I),
     "Red", "token", "heuristic_kube_config"),
    (re.compile(r"[/\\]\.azure[/\\]", re.I),
     "Red", "token", "heuristic_azure_dir"),
    (re.compile(r"[/\\]\.gnupg[/\\]", re.I),
     "Black", "key_material", "heuristic_gnupg_dir"),

    # Memory dumps / hive backups
    (re.compile(r"\.(dmp|minidump)$", re.I),
     "Red", "hash", "heuristic_memdump"),
    (re.compile(r"(?:^|[/\\])(SAM|SYSTEM|SECURITY|ntds\.dit)(?:\b|$)", re.I),
     "Black", "hash", "heuristic_hive"),

    # Filenames containing credential keywords (case-insensitive)
    (re.compile(r"(?:^|[/\\])[^/\\]*(creds?|passwords?|passwd|secrets?|"
                r"tokens?|keys?|vault)[^/\\]*\.(txt|csv|json|yaml|yml|"
                r"xml|conf|cfg|ini)$", re.I),
     "Red", "plaintext_password", "heuristic_keyword_filename"),

    # Common attacker-staging output names
    (re.compile(r"(?:^|[/\\])(loot|dump|stolen|exfil|harvest)[^/\\]*\.\w+$", re.I),
     "Red", "encrypted_credential", "heuristic_attacker_staging"),

    # Shell history (Snaffler has KeepShellHistoryByName but Green; per
    # our labeling calibration, fat-fingered creds in history bumps to Red)
    (re.compile(r"(?:^|[/\\])(\.bash_history|\.zsh_history|\.history)$", re.I),
     "Red", "embedded_secrets", "heuristic_shell_history"),

    # Config files containing "credential" or "secret" in their name
    (re.compile(r"(?:^|[/\\])[^/\\]*(credential|secret|vault)[^/\\]*$", re.I),
     "Yellow", "config_secret", "heuristic_credential_named_file"),
]


def _apply_heuristics(path: str) -> tuple[str, str | None, str] | None:
    for rex, tier, cred_type, label in _HEURISTIC_RULES:
        if rex.search(path):
            return (tier, cred_type, label)
    return None


def _build_classifier():
    """Load the ported Snaffler + Truffler ruleset and return a function
    that maps a path → (tier, credential_type, matched_rule_name) or None."""
    from pysnaffler.ruleset import SnafflerRuleSet
    from pysnaffler.rules.constants import MatchAction
    from sharesift.rules import get_extra_rules
    ruleset = SnafflerRuleSet.load_default_ruleset()
    for r in get_extra_rules():
        ruleset.load_rule(r)

    def classify(path: str) -> tuple[str, str | None, str] | None:
        # Normalize separators for pysnaffler (which expects Windows-style)
        norm = path.replace("/", "\\") if path.startswith("\\\\") else path
        # For Unix paths, also try with native separators
        name = norm.replace("\\", "/").split("/")[-1] or norm
        try:
            keep, rules = ruleset.enum_file(None, fullpath=norm, name=name, size=1024)
        except Exception:
            return None
        if not keep or not rules:
            return None
        # Pick the highest-tier Keep rule (Discard wouldn't reach here)
        best = None
        best_tier_ord = -1
        tier_ord = {"Black": 4, "Red": 3, "Yellow": 2, "Green": 1, "Gray": 0}
        for r in rules:
            if r.matchAction == MatchAction.Discard:
                continue
            t = r.triage.name
            if t == "Green":
                # Relay-Green is "look at this", not a triage hit per se;
                # skip unless no better rule fires.
                if best is None:
                    best = r
                    best_tier_ord = tier_ord.get(t, 0)
                continue
            if tier_ord.get(t, 0) > best_tier_ord:
                best = r
                best_tier_ord = tier_ord.get(t, 0)
        if best is None:
            return None
        cred_type = _RULE_TO_CRED_TYPE.get(best.ruleName)
        return (best.triage.name, cred_type, best.ruleName)

    return classify


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def _load_jsonl(path: Path):
    with path.open(encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                yield json.loads(line)
            except json.JSONDecodeError:
                continue


def _context_excerpt(text: str, start: int, end: int, window: int = 150) -> str:
    a = max(0, start - window)
    b = min(len(text), end + window)
    return text[a:b].replace("\n", " ").replace("\r", " ").strip()


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--input", type=Path, default=DEFAULT_INPUT)
    p.add_argument("--output", type=Path, default=DEFAULT_OUTPUT,
                   help="Tiered/classified extracted paths (the main output)")
    p.add_argument("--unknown-output", type=Path, default=DEFAULT_UNKNOWN_OUTPUT,
                   help="Paths regex extracted but no rule matched. Optional "
                        "feed for LLM classification of the unknown tail.")
    p.add_argument("--max-articles", type=int, default=None)
    args = p.parse_args(argv)

    if not args.input.exists():
        print(f"ERROR: --input missing: {args.input}", file=sys.stderr)
        return 2

    print(f"[load-rules] loading ported Snaffler ruleset...", file=sys.stderr)
    classify = _build_classifier()
    print(f"[load-rules] ready", file=sys.stderr)

    args.output.parent.mkdir(parents=True, exist_ok=True)
    out_fh = args.output.open("w", encoding="utf-8")
    unknown_fh = args.unknown_output.open("w", encoding="utf-8")

    n_articles = 0
    n_candidates = 0
    n_classified = 0
    n_unknown = 0
    tier_counts: Counter = Counter()
    rule_counts: Counter = Counter()
    cred_type_counts: Counter = Counter()
    now = datetime.now(timezone.utc).isoformat()

    for article in _load_jsonl(args.input):
        n_articles += 1
        if args.max_articles and n_articles > args.max_articles:
            break
        text = article.get("text", "") or ""
        url = article.get("url", "")
        source = article.get("source", "")
        title = article.get("title", "")
        candidates = _extract_paths_from_text(text)
        # Dedupe by exact path within article — multiple mentions count once
        seen_paths: set[str] = set()
        for path, start, end in candidates:
            n_candidates += 1
            if path in seen_paths:
                continue
            seen_paths.add(path)
            # Snaffler rules first, then heuristic fallback for the long tail
            result = classify(path)
            if result is None:
                result = _apply_heuristics(path)
            base = {
                "source_url": url,
                "source_title": title,
                "source": source,
                "verbatim_path": path,
                "context_excerpt": _context_excerpt(text, start, end),
                "discovery_type": "regex_extracted",
                "share_context": "unknown",
                "verbatim_match_quality": "exact",
                "model": "regex+snaffler_rules",
                "extracted_at": now,
            }
            if result is None:
                base["tier"] = None
                base["credential_type"] = None
                base["matched_rule"] = None
                unknown_fh.write(json.dumps(base) + "\n")
                n_unknown += 1
            else:
                tier, cred_type, rule_name = result
                base["tier"] = tier
                base["credential_type"] = cred_type
                base["matched_rule"] = rule_name
                out_fh.write(json.dumps(base) + "\n")
                n_classified += 1
                tier_counts[tier] += 1
                rule_counts[rule_name] += 1
                if cred_type:
                    cred_type_counts[cred_type] += 1
        if n_articles % 100 == 0:
            print(f"  [progress] {n_articles} articles, "
                  f"{n_classified} classified, {n_unknown} unknown",
                  file=sys.stderr)

    out_fh.close()
    unknown_fh.close()
    print(f"\n[final] {n_articles} articles processed", file=sys.stderr)
    print(f"        {n_candidates} candidate paths extracted", file=sys.stderr)
    print(f"        {n_classified} classified by rules → {args.output}",
          file=sys.stderr)
    print(f"        {n_unknown} unclassified → {args.unknown_output}",
          file=sys.stderr)
    print(f"\n  Tier distribution (classified):", file=sys.stderr)
    for tier, n in tier_counts.most_common():
        print(f"    {tier:8s} {n}", file=sys.stderr)
    print(f"\n  Credential-type distribution:", file=sys.stderr)
    for ct, n in cred_type_counts.most_common(15):
        print(f"    {ct:25s} {n}", file=sys.stderr)
    print(f"\n  Top matched rules:", file=sys.stderr)
    for rule, n in rule_counts.most_common(15):
        print(f"    {rule:35s} {n}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
