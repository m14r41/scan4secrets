"""Output reporters: SARIF, JSON, JSONL, CSV, HTML, Excel, PDF."""

from pathlib import Path
from typing import List

from scan4secrets.engine.findings import Finding

from . import sarif as _sarif
from . import json_ as _json
from . import jsonl as _jsonl
from . import csv_ as _csv
from . import html as _html
from . import excel as _excel
from . import pdf as _pdf


WRITERS = {
    "sarif": _sarif.write,
    "json":  _json.write,
    "jsonl": _jsonl.write,
    "csv":   _csv.write,
    "html":  _html.write,
    "excel": _excel.write,
    "pdf":   _pdf.write,
}

EXTENSIONS = {
    "sarif": ".sarif",
    "json":  ".json",
    "jsonl": ".jsonl",
    "csv":   ".csv",
    "html":  ".html",
    "excel": ".xlsx",
    "pdf":   ".pdf",
}


def write_reports(findings: List[Finding], base: Path, formats: list, *, unsafe_show: bool = False) -> dict:
    out = {}
    for fmt in formats:
        writer = WRITERS.get(fmt)
        if not writer:
            continue
        target = base.with_suffix(EXTENSIONS[fmt])
        writer(findings, target, unsafe_show=unsafe_show)
        out[fmt] = str(target)
    return out
