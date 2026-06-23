"""SARIF 2.1.0 output for GitHub Code Scanning, Sonar, Defect Dojo, etc."""

import json
from pathlib import Path
from typing import List

from scan4secrets.engine.findings import Finding
from scan4secrets import __version__


_SEV_TO_LEVEL = {"info": "note", "low": "note", "medium": "warning", "high": "error", "critical": "error"}


def _rules_block(findings: List[Finding]):
    seen = {}
    for f in findings:
        seen.setdefault(f.rule_id, {
            "id": f.rule_id,
            "name": f.rule_id,
            "shortDescription": {"text": f.description},
            "fullDescription": {"text": f.description},
            "defaultConfiguration": {"level": _SEV_TO_LEVEL.get(f.severity, "warning")},
            "properties": {"security-severity": {"critical": "9.5", "high": "7.5", "medium": "5.0", "low": "3.0", "info": "1.0"}.get(f.severity, "5.0")},
        })
    return list(seen.values())


def _results_block(findings: List[Finding], unsafe_show: bool):
    out = []
    for f in findings:
        text = f.description
        if f.verified is True:
            text += " (LIVE — verified against vendor)"
        elif f.verified is False:
            text += " (vendor rejected — likely revoked/format-only)"
        out.append({
            "ruleId": f.rule_id,
            "level": _SEV_TO_LEVEL.get(f.severity, "warning"),
            "message": {"text": text},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": f.file},
                    "region": {"startLine": max(f.line, 1)}
                }
            }],
            "partialFingerprints": {
                "secretHash/v1": f.secret_sha256,
            },
            "properties": {
                "entropy": f.entropy,
                "source": f.source,
                "verified": f.verified,
                "redacted": f.secret_redacted,
                **({"secret": f.secret} if unsafe_show else {}),
            }
        })
    return out


def write(findings: List[Finding], path: Path, *, unsafe_show: bool = False):
    doc = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "scan4secrets",
                "version": __version__,
                "informationUri": "https://github.com/m14r41/scan4secrets",
                "rules": _rules_block(findings),
            }},
            "results": _results_block(findings, unsafe_show),
        }]
    }
    path.write_text(json.dumps(doc, indent=2))
