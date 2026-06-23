import json
from pathlib import Path
from typing import List

from scan4secrets.engine.findings import Finding


def write(findings: List[Finding], path: Path, *, unsafe_show: bool = False):
    path.write_text(json.dumps([f.to_dict(unsafe=unsafe_show) for f in findings], indent=2, default=str))
