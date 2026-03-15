"""
Payload & Wordlist Manager
Merges built-in defaults with user-supplied custom files.
Users drop files into wordlists/custom/ and they are auto-loaded.
"""
import os
import json
from typing import List, Optional
from pathlib import Path

# ── Paths ─────────────────────────────────────────────────────────────────────

BASE_DIR       = Path(__file__).parent.parent.parent  # project root
WORDLISTS_DIR  = BASE_DIR / "wordlists"
CUSTOM_DIR     = WORDLISTS_DIR / "custom"

# Built-in defaults
DEFAULT_FILES = {
    "subdomains":   WORDLISTS_DIR / "subdomain_wordlist.txt",
    "directories":  WORDLISTS_DIR / "directory_wordlist.txt",
    "xss":          WORDLISTS_DIR / "payloads" / "xss_payloads.txt",
    "ssrf":         WORDLISTS_DIR / "payloads" / "ssrf_payloads.txt",
    "lfi":          WORDLISTS_DIR / "payloads" / "lfi_payloads.txt",
    "sqli":         WORDLISTS_DIR / "payloads" / "sqli_payloads.txt",
    "extensions":   WORDLISTS_DIR / "payloads" / "extensions.txt",
    "headers":      WORDLISTS_DIR / "payloads" / "bypass_headers.txt",
}

# Custom file naming conventions
CUSTOM_PREFIXES = {
    "subdomains":   ["subdomain", "subs", "subdomains"],
    "directories":  ["dir", "dirs", "directory", "paths"],
    "xss":          ["xss", "xss_payloads"],
    "ssrf":         ["ssrf", "ssrf_payloads"],
    "lfi":          ["lfi", "lfi_payloads"],
    "sqli":         ["sqli", "sql", "sqli_payloads"],
    "extensions":   ["ext", "extensions"],
    "headers":      ["headers", "bypass_headers"],
}


def _load_file(path: Path) -> List[str]:
    """Load lines from a text file, ignoring blanks and comments."""
    if not path or not path.exists():
        return []
    with open(path, encoding="utf-8", errors="ignore") as f:
        return [
            line.strip()
            for line in f
            if line.strip() and not line.startswith("#")
        ]


def _find_custom_files(category: str) -> List[Path]:
    """Find any custom files for a category in wordlists/custom/."""
    if not CUSTOM_DIR.exists():
        return []
    prefixes = CUSTOM_PREFIXES.get(category, [category])
    matched = []
    for f in CUSTOM_DIR.iterdir():
        stem = f.stem.lower()
        if f.suffix in [".txt", ".json", ".list"] and any(p in stem for p in prefixes):
            matched.append(f)
    return matched


def load_wordlist(category: str, custom_path: Optional[str] = None) -> List[str]:
    """
    Load a merged wordlist for a given category.

    Priority (all sources are merged + deduplicated):
      1. Built-in default  (wordlists/payloads/*.txt  or wordlists/*.txt)
      2. Custom dir        (wordlists/custom/*<category>*.txt)  — if any exist
      3. Explicit path     (via CLI --wordlist flag or API upload path)

    If the user has NOT uploaded anything, only the built-in default is used.
    This guarantees the tool always works out of the box.
    """
    default_path = DEFAULT_FILES.get(category)
    words = set(_load_file(default_path)) if default_path else set()

    # Log source info (visible with --verbose in CLI)
    sources = []
    if words:
        sources.append(f"default ({len(words)} entries)")

    # Auto-load from custom dir (empty dir = nothing added = uses defaults only)
    custom_files = _find_custom_files(category)
    for cfile in custom_files:
        loaded = _load_file(cfile)
        words.update(loaded)
        sources.append(f"{cfile.name} (+{len(loaded)} entries)")

    # Explicit path override
    if custom_path:
        loaded = _load_file(Path(custom_path))
        words.update(loaded)
        sources.append(f"{custom_path} (+{len(loaded)} entries)")

    # Store source info for verbose logging
    _LOAD_LOG[category] = sources

    return sorted(words)  # Deduplicated + sorted


# Tracks which sources were loaded per category (for --verbose / list command)
_LOAD_LOG: dict = {}


def get_load_log(category: Optional[str] = None) -> dict:
    """Return the load source log, useful for debugging."""
    if category:
        return {category: _LOAD_LOG.get(category, [])}
    return dict(_LOAD_LOG)



def load_payloads(category: str, custom_path: Optional[str] = None) -> List[str]:
    """Alias for load_wordlist, used for payload files."""
    return load_wordlist(category, custom_path)


def list_available(category: Optional[str] = None) -> dict:
    """
    Return info about what wordlists are available.
    Used by the CLI `recon wordlists` command and the API.
    """
    result = {}
    cats = [category] if category else list(DEFAULT_FILES.keys())
    for cat in cats:
        default_path = DEFAULT_FILES.get(cat, Path(""))
        default_count = len(_load_file(default_path))
        custom_files = _find_custom_files(cat)
        custom_counts = {str(f.name): len(_load_file(f)) for f in custom_files}
        result[cat] = {
            "default_file": str(default_path),
            "default_entries": default_count,
            "custom_files": custom_counts,
            "total_entries": default_count + sum(custom_counts.values()),
        }
    return result


def install_custom(src_path: str, category: str) -> str:
    """
    Copy a user-supplied file into wordlists/custom/ with a canonical name.
    Returns the destination path.
    """
    CUSTOM_DIR.mkdir(parents=True, exist_ok=True)
    src = Path(src_path)
    if not src.exists():
        raise FileNotFoundError(f"Source file not found: {src_path}")
    dest = CUSTOM_DIR / f"{category}_custom_{src.name}"
    dest.write_bytes(src.read_bytes())
    return str(dest)
