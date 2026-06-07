"""Code-corpus file iteration with extension filtering and size bounds.

Walks a directory tree and yields files that are plausible inputs for
the Phase-3 content classifier: source code, config files, env files,
documentation that might carry embedded secrets. Skips binary files,
huge files (training-budget waste), and irrelevant categories (images,
fonts, build artifacts).
"""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

# Extensions worth scanning. Conservative list — content classifier
# inference targets the same shape, so the training corpus should
# represent the same file types.
_CODE_EXTENSIONS = frozenset(
    {
        # General-purpose code
        ".py", ".pyx", ".rb", ".pl", ".php", ".js", ".ts", ".jsx", ".tsx",
        ".go", ".rs", ".java", ".kt", ".swift", ".scala", ".clj", ".ex",
        ".exs", ".erl", ".elm", ".hs", ".ml", ".mli", ".fs", ".fsx",
        ".lua", ".dart", ".sh", ".bash", ".zsh", ".fish", ".ps1", ".bat",
        ".cmd", ".vbs", ".wsf",
        # C-family
        ".c", ".cc", ".cpp", ".cxx", ".h", ".hh", ".hpp", ".hxx", ".m",
        ".mm", ".cs", ".vb",
        # Web / markup
        ".html", ".htm", ".xml", ".vue", ".svelte", ".astro",
        # Configuration
        ".yaml", ".yml", ".toml", ".json", ".ini", ".cfg", ".conf",
        ".properties", ".env", ".tf", ".tfvars", ".hcl",
        # SQL
        ".sql",
        # Notebooks (sometimes carry secrets in outputs)
        ".ipynb",
        # CI / Docker
        ".dockerfile", ".containerfile",
    }
)

# Directories to skip during walks — vendored deps, builds, caches.
_SKIP_DIRS = frozenset(
    {
        ".git", ".svn", ".hg",
        "node_modules", "vendor", "third_party",
        "target", "build", "dist", "out",
        ".venv", "venv", "env", "__pycache__",
        ".cache", ".pytest_cache", ".mypy_cache", ".ruff_cache",
        "site-packages",
    }
)

_DEFAULT_MAX_BYTES = 1_000_000  # 1MB — anything bigger is binary-ish or generated


def walk_code_files(
    root: Path,
    *,
    extensions: frozenset[str] = _CODE_EXTENSIONS,
    skip_dirs: frozenset[str] = _SKIP_DIRS,
    max_bytes: int = _DEFAULT_MAX_BYTES,
) -> Iterator[Path]:
    """Yield code-like files under ``root``, depth-first.

    ``skip_dirs`` matches against directory basename (case-insensitive)
    so e.g. ``.git`` and ``node_modules`` are pruned regardless of
    nesting depth.
    """
    skip_lower = {d.lower() for d in skip_dirs}
    for path in root.rglob("*"):
        if path.is_dir():
            continue
        if any(part.lower() in skip_lower for part in path.parts):
            continue
        if path.suffix.lower() not in extensions and not (
            path.name.lower() in {"dockerfile", "containerfile"}
        ):
            continue
        try:
            size = path.stat().st_size
        except OSError:
            continue
        if size == 0 or size > max_bytes:
            continue
        yield path
