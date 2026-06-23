"""Live verification of detected secrets against vendor APIs.

Verification is OPT-IN (--verify flag). For each finding whose rule defines a
verify: block, we make ONE HTTP request and set Finding.verified accordingly.

We deliberately use minimal probes (HEAD-like reads) to avoid side effects.
"""

from __future__ import annotations
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List

import requests

from .findings import Finding
from .rules import Rule

log = logging.getLogger("scan4secrets.verifier")


def _verify_one(finding: Finding, rule: Rule, timeout: int) -> bool:
    v = rule.verify
    if not v:
        return False
    headers: Dict[str, str] = {}
    if v.header_name and v.header_value:
        headers[v.header_name] = v.header_value.replace("{{value}}", finding.secret)
    try:
        r = requests.request(v.method, v.url, headers=headers, timeout=timeout, allow_redirects=False)
        if r.status_code != v.success_status:
            return False
        body = r.text or ""
        if v.failure_body_contains and v.failure_body_contains in body:
            return False
        if v.success_body_contains and v.success_body_contains not in body:
            return False
        return True
    except requests.RequestException as e:
        log.debug("verify error %s: %s", finding.rule_id, e)
        return False


def verify_findings(
    findings: List[Finding],
    rules: List[Rule],
    *,
    timeout: int = 5,
    threads: int = 8,
) -> List[Finding]:
    by_id = {r.id: r for r in rules}
    targets = [(i, f, by_id[f.rule_id]) for i, f in enumerate(findings)
               if f.rule_id in by_id and by_id[f.rule_id].verify]
    if not targets:
        return findings
    with ThreadPoolExecutor(max_workers=threads) as ex:
        fut_to_idx = {ex.submit(_verify_one, f, r, timeout): i for i, f, r in targets}
        for fut in as_completed(fut_to_idx):
            idx = fut_to_idx[fut]
            findings[idx].verified = fut.result()
    return findings
