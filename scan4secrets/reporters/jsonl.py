import json
from pathlib import Path
from typing import List

from scan4secrets.engine.findings import Finding


def write(findings: List[Finding], path: Path, *, unsafe_show: bool = False):
    with path.open("w") as f:
        for finding in findings:
            f.write(json.dumps(finding.to_dict(unsafe=unsafe_show), default=str))
            f.write("\n")
