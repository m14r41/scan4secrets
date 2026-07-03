"""Context-aware / structural secret detection.

The line-based scanner (scanner.scan_text) matches one physical line at a time,
so it structurally cannot correlate a credential-named XML tag with a <value>
child on the *next* line, a split <key>/<value> pair, a JSON key/value object,
a multi-line YAML block, or a secret hidden inside a Base64 blob.

This module runs a set of WHOLE-FILE regex passes (some DOTALL) that reconstruct
key -> value relationships across nesting and line breaks, then emits Findings
directly. It reuses the same false-positive guards as the .env rules: URLs,
absolute paths, pure numbers, booleans, templating and placeholders are skipped.
"""

from __future__ import annotations
import re
import base64
import binascii
from typing import List

from .findings import Finding
from .entropy import shannon_entropy

# --- credential-name vocabulary (shared shape with the .env rules) -----------
# An identifier is "credential-named" if it contains one of these tokens.
_CRED = (
    r"(?:CLIENT[_\-.]?SECRET|ACCESS[_\-.]?KEY|PRIVATE[_\-.]?KEY|ENCRYPTION[_\-.]?KEY|"
    r"SECRET[_\-.]?KEY|API[_\-.]?KEY|APIKEY|AUTH[_\-.]?TOKEN|ACCESS[_\-.]?TOKEN|"
    r"REFRESH[_\-.]?TOKEN|BEARER|SECRET|PASSWORD|PASSWD|PASSPHRASE|TOKEN|CREDENTIAL)"
)
# a credential-named identifier: token embedded in a normal name (SMS_API_KEY, db-password, ...)
_NAME = r"[\w.\-]*" + _CRED + r"[\w.\-]*"

# --- value false-positive guards --------------------------------------------
_PLACEHOLDER = re.compile(
    r"(?i)^(?:changeme|change_me|example|placeholder|redacted|dummy|sample|test|"
    r"xxx+|none|null|true|false|undefined|empty|default|enabled|disabled|your[_\-].*)$"
)
_NOT_SECRET_VALUE = re.compile(
    r"(?i)^(?:https?://|/[\w./\-]*$|\d+$|\$\{?[\w]+\}?$|<[^>]*>$|\{\{.*\}\}$)"
)
_MIN_VALUE_LEN = 4


def _looks_like_secret_value(v: str) -> bool:
    v = v.strip().strip("\"'")
    if len(v) < _MIN_VALUE_LEN:
        return False
    if _PLACEHOLDER.match(v):
        return False
    if _NOT_SECRET_VALUE.match(v):
        return False
    return True


def _lineno(text: str, pos: int) -> int:
    return text.count("\n", 0, pos) + 1


def _mk(rule_id: str, sev: str, desc: str, source: str, text: str,
        value: str, value_pos: int) -> Finding:
    line = _lineno(text, value_pos)
    excerpt = text[text.rfind("\n", 0, value_pos) + 1:
                   text.find("\n", value_pos) if text.find("\n", value_pos) != -1 else len(text)]
    return Finding(
        rule_id=rule_id,
        description=desc,
        severity=sev,
        file=source,
        line=line,
        secret=value.strip().strip("\"'"),
        line_excerpt=excerpt.strip()[:200],
        entropy=round(shannon_entropy(value), 2),
        source="sast",
        rule_category="secret",
    )


# --- compiled passes ---------------------------------------------------------
# 1) XML credential-named tag wrapping a <value> child (across lines):
#    <SMS_API_KEY><value>xyz</value></SMS_API_KEY>
_XML_WRAPPED = re.compile(
    r"<(" + _NAME + r")\b[^>]*>\s*<value[^>]*>\s*([^<]+?)\s*</value>\s*</\1>",
    re.I | re.S,
)
# 2) XML credential-named tag holding the value directly (single or multi-line):
#    <SMS_API_KEY>xyz</SMS_API_KEY>
_XML_DIRECT = re.compile(
    r"<(" + _NAME + r")\b[^>]*>\s*([^<>\s][^<>]*?)\s*</\1>",
    re.I | re.S,
)
# 3) Split adjacent key/value tags:
#    <key>SMS_API_KEY</key><value>xyz</value>
_XML_SPLIT = re.compile(
    r"<(?:key|name|n)\b[^>]*>\s*(" + _NAME + r")\s*</(?:key|name|n)>\s*"
    r"<value[^>]*>\s*([^<]+?)\s*</value>",
    re.I | re.S,
)
# 4) JSON split object: {"key":"SMS_API_KEY","value":"xyz"}
_JSON_SPLIT = re.compile(
    r'"(?:key|name)"\s*:\s*"(' + _NAME + r')"\s*,\s*"value"\s*:\s*"([^"]+)"',
    re.I | re.S,
)
# 5) Multi-line YAML / properties: credential key, value on the same or next line
#    SMS_API_KEY:
#      value: xyz          |  sms.api.key:
#                          |    xyz
_MULTILINE = re.compile(
    r"(?m)^[ \t]*(" + _NAME + r")[ \t]*:[ \t]*\n[ \t]+"
    r"(?:value[ \t]*:[ \t]*)?[\"']?([^\s\"'#<][^\s\"'#]*)",
    re.I,
)
# 6) Base64 blob candidates (decoded + inspected for hidden credentials)
_B64 = re.compile(r"(?<![A-Za-z0-9+/])([A-Za-z0-9+/]{20,}={0,2})(?![A-Za-z0-9+/=])")
_DECODED_CRED = re.compile(r"(?i)" + _CRED + r"|[\w.\-]+\s*[=:]\s*\S{4,}")


def _emit_kv(text: str, source: str, rx: re.Pattern, value_group: int,
             rule_id: str, sev: str, desc: str, out: List[Finding]) -> None:
    for m in rx.finditer(text):
        value = m.group(value_group)
        if not _looks_like_secret_value(value):
            continue
        out.append(_mk(rule_id, sev, desc, source, text, value, m.start(value_group)))


def _scan_base64(text: str, source: str, out: List[Finding]) -> None:
    for m in _B64.finditer(text):
        blob = m.group(1)
        if len(blob) % 4 != 0:
            continue
        try:
            decoded = base64.b64decode(blob, validate=True).decode("utf-8", "strict")
        except (binascii.Error, ValueError, UnicodeDecodeError):
            continue
        if not decoded.isprintable() or len(decoded) < 5:
            continue
        if not _DECODED_CRED.search(decoded):
            continue
        f = _mk(
            "structural-base64-secret", "low",
            f"Base64 blob decodes to a credential-looking value: {decoded[:60]!r}",
            source, text, blob, m.start(1),
        )
        out.append(f)


def scan_structural(text: str, source: str) -> List[Finding]:
    out: List[Finding] = []
    _emit_kv(text, source, _XML_WRAPPED, 2, "structural-xml-credential-tag", "medium",
             "Credential-named XML tag wrapping a <value> secret (multi-line)", out)
    _emit_kv(text, source, _XML_DIRECT, 2, "structural-xml-credential-tag", "medium",
             "Credential-named XML tag holding a secret value", out)
    _emit_kv(text, source, _XML_SPLIT, 2, "structural-split-key-value", "medium",
             "Split <key>/<value> pair where key is credential-named", out)
    _emit_kv(text, source, _JSON_SPLIT, 2, "structural-json-key-value", "medium",
             "JSON key/value object where key is credential-named", out)
    _emit_kv(text, source, _MULTILINE, 2, "structural-multiline-credential", "medium",
             "Credential-named key with value on the following line (YAML/properties)", out)
    _scan_base64(text, source, out)

    # de-dup identical (file,line,value,rule)
    seen, deduped = set(), []
    for f in out:
        k = f.dedup_key()
        if k in seen:
            continue
        seen.add(k)
        deduped.append(f)
    return deduped
