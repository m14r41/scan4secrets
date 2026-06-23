import csv
from pathlib import Path
from typing import List

from scan4secrets.engine.findings import Finding


FIELDS = ["rule_id", "severity", "verified", "source", "file", "line",
          "entropy", "secret_redacted", "secret_sha256", "description", "line_excerpt"]


def write(findings: List[Finding], path: Path, *, unsafe_show: bool = False):
    fields = list(FIELDS)
    if unsafe_show:
        fields.insert(fields.index("secret_redacted"), "secret")
    with path.open("w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=fields, extrasaction="ignore")
        w.writeheader()
        for f in findings:
            row = f.to_dict(unsafe=unsafe_show)
            w.writerow(row)
