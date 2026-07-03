"""SAST scanner: walks a path, applies rules, emits Findings."""

from __future__ import annotations
import os
import logging
from pathlib import Path
from typing import Iterable, List, Optional

from .rules import Rule, KeywordIndex
from .findings import Finding
from .entropy import shannon_entropy
from .structural import scan_structural

log = logging.getLogger("scan4secrets.scanner")

DEFAULT_SKIP_DIRS = {
    ".git", "node_modules", "vendor", "dist", "build",
    ".venv", "venv", "__pycache__", ".next", ".nuxt",
    ".tox", ".cache", ".mypy_cache", ".pytest_cache",
    "bower_components", "coverage", ".idea", ".vscode",
}
DEFAULT_MAX_BYTES = 10 * 1024 * 1024
DEFAULT_MAX_LINE = 4096

# categories active by default (secret detection). --misconfig adds "vuln".
SECRET_CATEGORIES = frozenset({None, "secret"})

# file extension -> language tags used to gate vuln rules
_EXT_LANG = {
    ".py": {"python"}, ".pyw": {"python"},
    ".js": {"node", "javascript"}, ".mjs": {"node", "javascript"}, ".cjs": {"node", "javascript"},
    ".jsx": {"react", "javascript", "node"}, ".tsx": {"react", "typescript", "node"},
    ".ts": {"node", "typescript", "javascript"},
    ".sql": {"sql", "psql"}, ".pgsql": {"sql", "psql"},
    ".php": {"php"}, ".php5": {"php"}, ".phtml": {"php"},
    ".rb": {"ruby"}, ".erb": {"ruby", "html"}, ".rake": {"ruby"},
    ".go": {"go"},
    ".java": {"java"}, ".jsp": {"java", "html"},
    ".cs": {"csharp"}, ".csx": {"csharp"}, ".cshtml": {"csharp", "html"}, ".razor": {"csharp", "html"},
    ".asmx": {"csharp", "xml"}, ".svc": {"csharp", "xml"}, ".aspx": {"csharp", "html"}, ".ascx": {"csharp", "html"},
    ".kt": {"kotlin"}, ".kts": {"kotlin"},
    ".jsp": {"java", "html"}, ".jspx": {"java", "html"}, ".tag": {"java", "html"},
    ".tf": {"terraform"}, ".tfvars": {"terraform"}, ".hcl": {"terraform"},
    ".yaml": {"yaml"}, ".yml": {"yaml"},
    ".xml": {"xml"}, ".config": {"xml"}, ".xsd": {"xml"}, ".wsdl": {"xml"},
    ".xsl": {"xml"}, ".xslt": {"xml"}, ".plist": {"xml"}, ".pom": {"xml"},
    ".html": {"html"}, ".htm": {"html"}, ".vue": {"react", "javascript"},
}

# filename (no reliable extension) -> language tags
_NAME_LANG = {
    "dockerfile": {"dockerfile"},
    "containerfile": {"dockerfile"},
}


def lang_of(path: str) -> set:
    base = os.path.basename(path).lower()
    langs = set(_EXT_LANG.get(os.path.splitext(base)[1], set()))
    for stem, tags in _NAME_LANG.items():
        if base == stem or base.startswith(stem + "."):
            langs |= tags
    # GitHub Actions / CI workflow yaml also carries dockerfile-style shell rules
    if base.endswith((".yaml", ".yml")):
        langs |= {"yaml"}
    return langs


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
    enabled_categories: Optional[frozenset] = None,
    language: Optional[set] = None,
) -> List[Finding]:
    enabled_categories = enabled_categories if enabled_categories is not None else SECRET_CATEGORIES
    language = language if language is not None else lang_of(source)
    out: List[Finding] = []
    seen = set()
    for lineno, line in enumerate(text.splitlines(), start=1):
        if len(line) > max_line:
            line = line[:max_line]
        low = line.lower()
        for rule in index.candidates(line):
            if rule.category not in enabled_categories:
                continue
            # vuln rules may be gated to specific languages / file types
            if rule.languages and not (language & set(rule.languages)):
                continue
            # taint gate: for context-sensitive rules, require a dynamic-input hint
            if rule.context_required and not any(h.lower() in low for h in rule.context_required):
                continue
            if rule.allowlist.line_allowed(line):
                continue
            if rule.allowlist.path_allowed(source):
                continue
            for m in rule.regex.finditer(line):
                value = m.group(1) if m.groups() else m.group(0)
                if not value:
                    continue
                is_vuln = rule.category == "vuln"
                if not is_vuln:
                    ent = shannon_entropy(value)
                    if ent < rule.entropy_min:
                        continue
                else:
                    ent = 0.0
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
                    name=rule.name,
                    cwe=rule.cwe,
                    owasp=rule.owasp,
                    remediation=rule.remediation,
                    secure_code=rule.secure_code,
                    vulnerable_code=(line.strip()[:200] if is_vuln else None),
                    technical_impact=rule.technical_impact,
                    business_impact=rule.business_impact,
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
    enabled_categories: Optional[frozenset] = None,
) -> List[Finding]:
    exclude_dirs = exclude_dirs or DEFAULT_SKIP_DIRS
    exclude_globs = exclude_globs or []
    enabled_categories = enabled_categories if enabled_categories is not None else SECRET_CATEGORIES
    secrets_on = bool(enabled_categories & SECRET_CATEGORIES)
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
        line_findings = scan_text(text, str(fp), rules, index,
                                  enabled_categories=enabled_categories)
        # structural pass is secret-only
        struct_findings = scan_structural(text, str(fp)) if secrets_on else []
        # cross-pass de-dup: if the line scanner already caught this value on this
        # line, drop the structural report of it (compare on value+line, not rule).
        seen = {(f.file, f.line, f.secret_sha256) for f in line_findings}
        findings.extend(line_findings)
        for f in struct_findings:
            k = (f.file, f.line, f.secret_sha256)
            if k not in seen:
                seen.add(k)
                findings.append(f)
    return findings
