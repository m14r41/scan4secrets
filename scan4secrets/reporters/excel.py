from pathlib import Path
from typing import List

import pandas as pd

from scan4secrets.engine.findings import Finding
from .csv_ import FIELDS


def write(findings: List[Finding], path: Path, *, unsafe_show: bool = False):
    rows = [f.to_dict(unsafe=unsafe_show) for f in findings]
    cols = list(FIELDS)
    if unsafe_show:
        cols.insert(cols.index("secret_redacted"), "secret")
    df = pd.DataFrame(rows, columns=cols)
    df.to_excel(path, index=False, engine="openpyxl")
