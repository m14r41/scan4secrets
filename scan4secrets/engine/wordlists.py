"""Load path-guess wordlists for DAST URL seeding."""

from pathlib import Path
from typing import Iterable, List, Set
from urllib.parse import urljoin


CONFIG_DIR = Path(__file__).resolve().parent.parent / "config"
WORDLIST_DIR = CONFIG_DIR / "wordlist"


def load_wordlists(only: Iterable[str] | None = None) -> List[str]:
    """Return non-comment, non-empty entries from every *.txt under config/wordlist/.
    If `only` is provided, restrict to wordlists whose stem is in that set."""
    out: Set[str] = set()
    if not WORDLIST_DIR.is_dir():
        return []
    wanted = {n.lower() for n in only} if only else None
    for p in sorted(WORDLIST_DIR.glob("*.txt")):
        if wanted and p.stem.lower() not in wanted:
            continue
        for line in p.read_text(encoding="utf-8", errors="ignore").splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                out.add(line)
    return sorted(out)


def seed_urls_from_wordlists(base_url: str, only: Iterable[str] | None = None) -> List[str]:
    """Produce candidate URLs by joining each bundled wordlist entry onto base_url."""
    guesses = load_wordlists(only=only)
    return sorted({urljoin(base_url.rstrip("/") + "/", g.lstrip("/")) for g in guesses})


def load_user_wordlist_files(paths: Iterable[str]) -> List[str]:
    """Load entries from one or more user-supplied wordlist files.
    Same rules as bundled: ignore blank lines and lines starting with '#'."""
    out: Set[str] = set()
    for p_str in paths:
        p = Path(p_str)
        if not p.is_file():
            print(f"[WARN] wordlist file not found: {p}")
            continue
        for line in p.read_text(encoding="utf-8", errors="ignore").splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                out.add(line)
    return sorted(out)


def seed_urls_from_files(base_url: str, paths: Iterable[str]) -> List[str]:
    """Produce candidate URLs from user-supplied wordlist file(s)."""
    guesses = load_user_wordlist_files(paths)
    return sorted({urljoin(base_url.rstrip("/") + "/", g.lstrip("/")) for g in guesses})
