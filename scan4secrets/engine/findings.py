from dataclasses import dataclass, field, asdict
from typing import Optional
import hashlib


SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


@dataclass
class Finding:
    rule_id: str
    description: str
    severity: str
    file: str
    line: int
    secret: str
    line_excerpt: str
    entropy: float
    verified: Optional[bool] = None
    source: str = "sast"
    commit: Optional[str] = None
    rule_category: Optional[str] = None
    # --- vulnerability metadata (populated for category=vuln findings) ---------
    name: Optional[str] = None            # human vulnerability name
    cwe: Optional[str] = None
    owasp: Optional[str] = None
    remediation: Optional[str] = None
    secure_code: Optional[str] = None
    vulnerable_code: Optional[str] = None
    technical_impact: Optional[str] = None
    business_impact: Optional[str] = None
    secret_sha256: str = field(init=False)
    secret_redacted: str = field(init=False)

    def __post_init__(self):
        self.secret_sha256 = hashlib.sha256(self.secret.encode("utf-8", "ignore")).hexdigest()
        # Vulnerability findings carry no secret to hide — show the matched code as-is.
        self.secret_redacted = self.secret if self.rule_category == "vuln" else redact(self.secret)

    def dedup_key(self):
        return (self.file, self.line, self.secret_sha256, self.rule_id)

    def to_dict(self, unsafe=False):
        d = asdict(self)
        if not unsafe:
            d.pop("secret", None)
            # don't let the surrounding line leak the raw secret when masked
            if self.rule_category != "vuln" and self.secret and self.secret in self.line_excerpt:
                d["line_excerpt"] = self.line_excerpt.replace(self.secret, self.secret_redacted)
        return d


def redact(s: str, keep: int = 4) -> str:
    if len(s) <= keep * 2:
        return "*" * len(s)
    return s[:keep] + "*" * (len(s) - keep * 2) + s[-keep:]


def severity_at_least(found_sev: str, threshold_sev: str) -> bool:
    return SEVERITY_RANK.get(found_sev, 0) >= SEVERITY_RANK.get(threshold_sev, 0)


# Rules whose findings should be suppressed if a vendor-specific rule already fired on the same secret value.
GENERIC_RULE_IDS = frozenset({
    "generic-high-entropy-quoted",
    "generic-high-entropy-unquoted",
    "contextual-hex-token",
    "contextual-uuid-secret",
})


def suppress_generic_when_specific(findings: list) -> list:
    """If a vendor-specific rule (non-generic) fired on a given secret value, drop
    generic-rule findings for that same value. Cuts duplicate noise where a key
    triggers both 'stripe-secret-live' and 'generic-high-entropy-unquoted'."""
    specific_hashes = {f.secret_sha256 for f in findings if f.rule_id not in GENERIC_RULE_IDS}
    return [
        f for f in findings
        if not (f.rule_id in GENERIC_RULE_IDS and f.secret_sha256 in specific_hashes)
    ]
