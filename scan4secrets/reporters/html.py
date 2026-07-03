"""HTML report v3: collapsible/expandable finding cards.

Each finding renders as a <details> card. The summary line shows severity,
name/rule, location and a short evidence/value. Expanding reveals the full
record — for vulnerabilities the rich schema (description, vulnerable code,
secure code, remediation, technical/business impact, CWE/OWASP); for secrets
the redacted value, entropy, verification and hash. Filter box, severity
sort, and expand/collapse-all controls included. Self-contained, theme-aware.
"""

import html as _h
import json
from pathlib import Path
from typing import List, Optional
from collections import Counter

from scan4secrets.engine.findings import Finding, SEVERITY_RANK


_BADGE = {
    "critical": "#dc2626", "high": "#ea580c", "medium": "#ca8a04",
    "low": "#0891b2", "info": "#475569",
}

_STYLE = """
:root { color-scheme: light dark; --bg:#0b1020; --card:#111827; --card2:#0f172a;
        --line:#1f2937; --fg:#e5e7eb; --muted:#9ca3af; --accent:#38bdf8; }
@media (prefers-color-scheme: light) {
  :root { --bg:#f6f7fb; --card:#ffffff; --card2:#f1f5f9; --line:#e2e8f0; --fg:#0f172a; --muted:#64748b; }
}
* { box-sizing: border-box; }
body { font-family: -apple-system, system-ui, Segoe UI, Roboto, sans-serif;
       margin:0; padding:2rem; background:var(--bg); color:var(--fg); }
h1 { font-size:1.4rem; margin:0 0 .25rem; }
.meta { color:var(--muted); font-size:.85rem; margin-bottom:1rem; }
.summary { display:flex; gap:.5rem; margin:1rem 0; flex-wrap:wrap; }
.pill { padding:.35rem .8rem; border-radius:999px; font-size:.8rem; color:#fff; font-weight:600; }
.controls { display:flex; gap:.5rem; align-items:center; flex-wrap:wrap; margin-bottom:1rem; }
input[type=text], select { background:var(--card); color:var(--fg); border:1px solid var(--line);
       padding:.5rem .6rem; border-radius:6px; font-size:.85rem; }
input[type=text] { min-width:280px; flex:1; }
button { background:var(--card); color:var(--fg); border:1px solid var(--line);
       padding:.5rem .8rem; border-radius:6px; font-size:.8rem; cursor:pointer; }
button:hover { border-color:var(--accent); }
details.f { background:var(--card); border:1px solid var(--line); border-left-width:4px;
       border-radius:8px; margin:.5rem 0; overflow:hidden; }
details.f > summary { list-style:none; cursor:pointer; padding:.7rem .9rem; display:flex;
       gap:.7rem; align-items:center; flex-wrap:wrap; }
details.f > summary::-webkit-details-marker { display:none; }
details.f > summary::before { content:"\\25B6"; color:var(--muted); font-size:.7rem; transition:transform .15s; }
details.f[open] > summary::before { transform:rotate(90deg); }
.sev { display:inline-block; padding:.15rem .55rem; border-radius:4px; color:#fff;
       font-size:.7rem; font-weight:700; text-transform:uppercase; letter-spacing:.03em; }
.name { font-weight:600; }
.loc { color:var(--muted); font-size:.8rem; font-family:ui-monospace,monospace; }
.tag { color:var(--muted); font-size:.72rem; border:1px solid var(--line); padding:.05rem .4rem; border-radius:4px; }
.spacer { flex:1; }
.body { padding:.3rem .9rem 1rem; border-top:1px solid var(--line); }
.field { margin:.7rem 0; }
.field > label { display:block; font-size:.7rem; text-transform:uppercase; letter-spacing:.05em;
       color:var(--muted); margin-bottom:.25rem; }
.field > .val { font-size:.9rem; line-height:1.45; }
pre { background:var(--card2); border:1px solid var(--line); border-radius:6px; padding:.7rem .8rem;
       overflow-x:auto; font-size:.82rem; margin:0; white-space:pre-wrap; word-break:break-word; }
pre.vuln { border-left:3px solid #dc2626; }
pre.safe { border-left:3px solid #16a34a; }
code { background:var(--card2); padding:.1rem .4rem; border-radius:3px; font-size:.82rem; word-break:break-all; }
.metarow { display:flex; gap:.5rem; flex-wrap:wrap; margin-top:.6rem; }
.empty { color:var(--muted); padding:2rem; text-align:center; }
"""

_JS = """
const q = document.getElementById('filter');
const sortSel = document.getElementById('sort');
const list = document.getElementById('list');
function apply() {
  const t = q.value.toLowerCase();
  for (const el of list.querySelectorAll('details.f')) {
    el.style.display = el.dataset.search.includes(t) ? '' : 'none';
  }
}
q.addEventListener('input', apply);
sortSel.addEventListener('change', () => {
  const cards = Array.from(list.querySelectorAll('details.f'));
  const mode = sortSel.value;
  cards.sort((a,b) => {
    if (mode==='severity') return (b.dataset.sevrank-a.dataset.sevrank) || a.dataset.file.localeCompare(b.dataset.file);
    if (mode==='file') return a.dataset.file.localeCompare(b.dataset.file) || (a.dataset.line-b.dataset.line);
    return a.dataset.name.localeCompare(b.dataset.name);
  });
  for (const c of cards) list.appendChild(c);
});
document.getElementById('expand').onclick = () => list.querySelectorAll('details.f').forEach(d=>d.open=true);
document.getElementById('collapse').onclick = () => list.querySelectorAll('details.f').forEach(d=>d.open=false);
"""


def _field(label: str, value: Optional[str], *, pre: str = "") -> str:
    if not value:
        return ""
    inner = f"<pre class='{pre}'>{_h.escape(value)}</pre>" if pre else f"<div class='val'>{_h.escape(value)}</div>"
    return f"<div class='field'><label>{_h.escape(label)}</label>{inner}</div>"


def _card(f: Finding, unsafe_show: bool) -> str:
    color = _BADGE.get(f.severity, "#475569")
    is_vuln = f.rule_category == "vuln"
    title = _h.escape(f.name or f.description or f.rule_id)
    loc = f"{_h.escape(f.file)}:{f.line}"
    value = f.secret if (unsafe_show or is_vuln) else f.secret_redacted

    summary_tags = ""
    if is_vuln and f.cwe:
        summary_tags += f"<span class='tag'>{_h.escape(f.cwe)}</span>"
    if not is_vuln:
        summary_tags += f"<span class='tag'>{_h.escape(f.rule_id)}</span>"

    # body fields
    body = []
    if is_vuln:
        body.append(_field("Description", f.description))
        body.append(_field("Evidence", loc))
        body.append(_field("Vulnerable Code", f.vulnerable_code or f.line_excerpt, pre="vuln"))
        body.append(_field("Secure Code", f.secure_code, pre="safe"))
        body.append(_field("Remediation", f.remediation))
        body.append(_field("Technical Impact", f.technical_impact))
        body.append(_field("Business Impact", f.business_impact))
        metabits = [b for b in (f.cwe, f.owasp, f"rule: {f.rule_id}") if b]
    else:
        body.append(_field("Description", f.description))
        body.append(_field("Location", loc))
        body.append(_field("Value" + ("" if unsafe_show else " (redacted)"), value, pre="vuln"))
        # never leak the raw secret through the surrounding line when masked
        context = f.line_excerpt
        if not unsafe_show and f.secret and f.secret in context:
            context = context.replace(f.secret, f.secret_redacted)
        body.append(_field("Context", context, pre=""))
        ver = "verified" if f.verified is True else "not verified" if f.verified is False else "not checked"
        metabits = [f"rule: {f.rule_id}", f"entropy: {f.entropy}", ver, f"sha256: {f.secret_sha256[:16]}…"]

    meta = "".join(f"<span class='tag'>{_h.escape(m)}</span>" for m in metabits)
    body_html = "".join(b for b in body if b) + f"<div class='metarow'>{meta}</div>"

    search = " ".join([f.severity, f.rule_id, f.file, str(f.line), f.name or "", f.description or "",
                       (f.cwe or ""), (f.owasp or "")]).lower()
    ds = (f"data-search={json.dumps(search)} data-sevrank='{SEVERITY_RANK.get(f.severity,0)}' "
          f"data-file={json.dumps(f.file)} data-line='{f.line}' data-name={json.dumps((f.name or f.rule_id).lower())}")

    return (
        f"<details class='f' style='border-left-color:{color}' {ds}>"
        f"<summary>"
        f"<span class='sev' style='background:{color}'>{_h.escape(f.severity)}</span>"
        f"<span class='name'>{title}</span>"
        f"<span class='loc'>{loc}</span>"
        f"<span class='spacer'></span>{summary_tags}"
        f"</summary>"
        f"<div class='body'>{body_html}</div>"
        f"</details>"
    )


def write(findings: List[Finding], path: Path, *, unsafe_show: bool = False):
    counts = Counter(f.severity for f in findings)
    pills = "".join(
        f"<span class='pill' style='background:{_BADGE.get(s,'#475569')}'>{s}: {counts.get(s,0)}</span>"
        for s in ("critical", "high", "medium", "low", "info") if counts.get(s, 0)
    ) or "<span class='pill' style='background:#16a34a'>no findings</span>"

    ordered = sorted(findings, key=lambda f: (-SEVERITY_RANK.get(f.severity, 0), f.file, f.line))
    cards = "\n".join(_card(f, unsafe_show) for f in ordered) or "<div class='empty'>No findings.</div>"

    html_doc = f"""<!doctype html>
<html lang="en"><head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>scan4secrets report</title>
<style>{_STYLE}</style>
</head><body>
<h1>scan4secrets report</h1>
<div class="meta">{len(findings)} findings &middot; generated by scan4secrets v2</div>
<div class="summary">{pills}</div>
<div class="controls">
  <input type="text" id="filter" placeholder="filter by rule, file, severity, CWE, name…"/>
  <select id="sort">
    <option value="severity">sort: severity</option>
    <option value="file">sort: file</option>
    <option value="name">sort: name</option>
  </select>
  <button id="expand">Expand all</button>
  <button id="collapse">Collapse all</button>
</div>
<div id="list">
{cards}
</div>
<script>{_JS}</script>
</body></html>"""
    path.write_text(html_doc)
