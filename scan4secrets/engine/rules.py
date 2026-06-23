"""Rule loading + Aho-Corasick keyword pre-filter."""

from __future__ import annotations
import re
import fnmatch
import yaml
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, List, Optional

try:
    import ahocorasick
    _HAS_AHO = True
except ImportError:
    _HAS_AHO = False


DEFAULT_RULES_PATH = Path(__file__).resolve().parent.parent / "config" / "rules.yaml"


@dataclass
class Allowlist:
    regex: List[re.Pattern] = field(default_factory=list)
    paths: List[str] = field(default_factory=list)

    def line_allowed(self, line: str) -> bool:
        return any(p.search(line) for p in self.regex)

    def path_allowed(self, path: str) -> bool:
        return any(fnmatch.fnmatch(path, g) for g in self.paths)


@dataclass
class Verify:
    method: str
    url: str
    header_name: Optional[str] = None
    header_value: Optional[str] = None
    success_status: int = 200
    success_body_contains: Optional[str] = None
    failure_body_contains: Optional[str] = None


@dataclass
class Rule:
    id: str
    description: str
    severity: str
    keywords: List[str]
    regex: re.Pattern
    entropy_min: float = 0.0
    allowlist: Allowlist = field(default_factory=Allowlist)
    verify: Optional[Verify] = None
    category: Optional[str] = None


def _compile_allowlist(d: dict) -> Allowlist:
    d = d or {}
    return Allowlist(
        regex=[re.compile(r) for r in d.get("regex", [])],
        paths=list(d.get("paths", [])),
    )


def _compile_verify(d: Optional[dict]) -> Optional[Verify]:
    if not d:
        return None
    return Verify(
        method=d.get("method", "GET").upper(),
        url=d["url"],
        header_name=d.get("header_name"),
        header_value=d.get("header_value"),
        success_status=int(d.get("success_status", 200)),
        success_body_contains=d.get("success_body_contains"),
        failure_body_contains=d.get("failure_body_contains"),
    )


def load_rules(path: Optional[Path] = None) -> List[Rule]:
    p = Path(path) if path else DEFAULT_RULES_PATH
    raw = yaml.safe_load(p.read_text())
    rules: List[Rule] = []
    for d in raw or []:
        try:
            rules.append(
                Rule(
                    id=d["id"],
                    description=d.get("description", d["id"]),
                    severity=d.get("severity", "medium"),
                    keywords=list(d.get("keywords") or []),
                    regex=re.compile(d["regex"]),
                    entropy_min=float(d.get("entropy_min", 0.0)),
                    allowlist=_compile_allowlist(d.get("allowlist")),
                    verify=_compile_verify(d.get("verify")),
                    category=d.get("category"),
                )
            )
        except (KeyError, re.error) as e:
            print(f"[WARN] Skipping invalid rule {d.get('id', '?')}: {e}")
    return rules


class KeywordIndex:
    """Pre-filter: only run a rule's regex if at least one keyword appears in the line.
    Falls back to a Python set if pyahocorasick isn't installed."""

    def __init__(self, rules: List[Rule]):
        self._rules = rules
        self._aho = None
        self._py = {}
        if _HAS_AHO:
            self._aho = ahocorasick.Automaton()
            kw_to_ids: dict = {}
            for r in rules:
                for kw in r.keywords:
                    kw_to_ids.setdefault(kw.lower(), set()).add(r.id)
            for kw, ids in kw_to_ids.items():
                self._aho.add_word(kw, ids)
            if len(self._aho) > 0:
                self._aho.make_automaton()
        else:
            for r in rules:
                for kw in r.keywords:
                    self._py.setdefault(kw.lower(), set()).add(r.id)

    def candidates(self, line: str) -> Iterable[Rule]:
        """Return rules whose keywords appear in `line` (or which declare no keywords)."""
        lower = line.lower()
        hit_ids = set()
        if self._aho is not None and len(self._aho) > 0:
            for _, ids in self._aho.iter(lower):
                hit_ids |= ids
        else:
            for kw, ids in self._py.items():
                if kw in lower:
                    hit_ids |= ids
        for r in self._rules:
            if not r.keywords or r.id in hit_ids:
                yield r
