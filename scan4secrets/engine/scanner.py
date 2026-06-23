"""SAST scanner: walks a path, applies rules, emits Findings."""

from __future__ import annotations
import os
import logging
from pathlib import Path
from typing import Iterable, List, Optional

from .rules import Rule, KeywordIndex
from .findings import Finding
from .entropy import shannon_entropy

log = logging.getLogger("scan4secrets.scanner")

DEFAULT_SKIP_DIRS = {
    ".git", "node_modules", "vendor", "dist", "build",
    ".venv", "venv", "__pycache__", ".next", ".nuxt",
    ".tox", ".cache", ".mypy_cache", ".pytest_cache",
    "bower_components", "coverage", ".idea", ".vscode",
}
DEFAULT_MAX_BYTES = 10 * 1024 * 1024
DEFAULT_MAX_LINE = 4096


def _is_binary(path: Path) -> bool:
    try:
        with path.open("rb") as f:
            chunk = f.read(4096)
        return b"\x00" in chunk
    except OSError:
        return True


def _walk(path: Path, exclude_dirs: set, exclude_globs: List[str], max_bytes: int) -> Iterable[Path]:
    import fnmatch
    if path.is_file():
        yield path
        return
    for root, dirs, files in os.walk(path):
        dirs[:] = [d for d in dirs if d not in exclude_dirs]
        for fname in files:
            fp = Path(root) / fname
            rel = str(fp.relative_to(path)) if fp.is_relative_to(path) else str(fp)
            if any(fnmatch.fnmatch(rel, g) or fnmatch.fnmatch(fname, g) for g in exclude_globs):
                continue
            try:
                if fp.stat().st_size > max_bytes:
                    continue
            except OSError:
                continue
            yield fp


def scan_text(
    text: str,
    source: str,
    rules: List[Rule],
    index: KeywordIndex,
    *,
    source_kind: str = "sast",
    max_line: int = DEFAULT_MAX_LINE,
) -> List[Finding]:
    out: List[Finding] = []
    seen = set()
    for lineno, line in enumerate(text.splitlines(), start=1):
        if len(line) > max_line:
            line = line[:max_line]
        for rule in index.candidates(line):
            if rule.allowlist.line_allowed(line):
                continue
            if rule.allowlist.path_allowed(source):
                continue
            for m in rule.regex.finditer(line):
                value = m.group(1) if m.groups() else m.group(0)
                if not value:
                    continue
                ent = shannon_entropy(value)
                if ent < rule.entropy_min:
                    continue
                f = Finding(
                    rule_id=rule.id,
                    description=rule.description,
                    severity=rule.severity,
                    file=source,
                    line=lineno,
                    secret=value,
                    line_excerpt=line.strip()[:200],
                    entropy=round(ent, 2),
                    source=source_kind,
                    rule_category=rule.category,
                )
                key = f.dedup_key()
                if key in seen:
                    continue
                seen.add(key)
                out.append(f)
    return out


def scan_path(
    root: Path,
    rules: List[Rule],
    *,
    exclude_dirs: Optional[set] = None,
    exclude_globs: Optional[List[str]] = None,
    max_bytes: int = DEFAULT_MAX_BYTES,
    progress_cb=None,
) -> List[Finding]:
    exclude_dirs = exclude_dirs or DEFAULT_SKIP_DIRS
    exclude_globs = exclude_globs or []
    index = KeywordIndex(rules)
    findings: List[Finding] = []

    files = list(_walk(root, exclude_dirs, exclude_globs, max_bytes))
    for fp in files:
        if progress_cb:
            progress_cb(str(fp))
        if _is_binary(fp):
            continue
        try:
            text = fp.read_text(encoding="utf-8", errors="ignore")
        except OSError as e:
            log.debug("skip %s: %s", fp, e)
            continue
        findings.extend(scan_text(text, str(fp), rules, index))
    return findings
