---
id: sample-report
title: Sample Report
sidebar_position: 9
description: A real scan4secrets --misconfig run against the bundled examples/sample-app fixture. Browse or download the exact output in HTML, SARIF, JSON, JSONL, CSV, Excel, and PDF.
keywords: [scan4secrets sample report, secret scan report example, SARIF example, SAST report, vulnerability report, CWE OWASP report, secret scanner demo, misconfig scan]
---

# Sample Report

This is a **real** scan4secrets run you can reproduce in one command. It scans the
[`examples/sample-app`](https://github.com/m14r41/scan4secrets/tree/main/examples/sample-app)
fixture that ships in the repo — a tiny, deliberately-insecure multi-language app —
with **`--misconfig`** so you see both secret detection and the SAST
vulnerability/misconfiguration engine in one report.

:::note Everything here is fake
Every "secret" in the fixture is a generic placeholder — nothing authenticates. The
values are intentionally non-vendor-shaped so the fixture is safe to commit and clone.
:::

```text
$ scan4secrets --version
scan4secrets 2.2.0
```

## Download the report

The same run, in all seven formats:

| Format | Download | Best for |
|---|---|---|
| **HTML** | [sast-sample-app.html](pathname:///reports/sast-sample-app.html) | Collapsible, self-contained — share with anyone |
| **SARIF** | [sast-sample-app.sarif](pathname:///reports/sast-sample-app.sarif) | GitHub Code Scanning, GitLab, Sonar, Defect Dojo |
| **JSON** | [sast-sample-app.json](pathname:///reports/sast-sample-app.json) | Tooling / post-processing |
| **JSONL** | [sast-sample-app.jsonl](pathname:///reports/sast-sample-app.jsonl) | SIEM / SOAR streaming, `jq` |
| **CSV** | [sast-sample-app.csv](pathname:///reports/sast-sample-app.csv) | Spreadsheet triage |
| **Excel** | [sast-sample-app.xlsx](pathname:///reports/sast-sample-app.xlsx) | Pivot tables, exec summaries |
| **PDF** | [sast-sample-app.pdf](pathname:///reports/sast-sample-app.pdf) | Compliance evidence packets |

> 👉 Open the **[HTML report](pathname:///reports/sast-sample-app.html)** for the best
> experience — each finding is an expandable card with the full detail.

## Reproduce it

```bash
git clone https://github.com/m14r41/scan4secrets && cd scan4secrets
pip install -e .

# one command — secrets + vulnerabilities across the fixture
scan4secrets --path examples/sample-app --misconfig \
  --report html sarif json jsonl csv excel pdf \
  --output reports/sast-sample-app
```

That is exactly what the site runs to produce the files above (see
[`examples/generate-sample-reports.sh`](https://github.com/m14r41/scan4secrets/blob/main/examples/generate-sample-reports.sh)).

## What the run finds

**24 findings — 7 secrets + 17 vulnerabilities.**

| Severity | Count |
|---|---|
| critical | 3 |
| high | 9 |
| medium | 10 |
| low | 2 |
| **Total** | **24** |

### Secrets (7)

Detected by name-signal and **context-aware structural** rules — no vendor-shaped
tokens required:

| Rule | File | What it caught |
|---|---|---|
| `env-named-credential-assignment` | `.env` | `AM_CLIENT_SECRET`, `SESSION_SECRET`, `DATABASE_PASSWORD`, `ENCRYPTION_KEY` — flagged on the credential-named key even at low entropy |
| `basic-auth-credential` | `.env` | `basic_auth = "…"` |
| `xml-secret-bearing-tag` | `config/services.xml` | secret inside a nested `<SMS_API_KEY><value>…</value>` tag **and** a split `<key>`/`<value>` pair |

The decoys `AM_REDIRECT_URI` (a URL) and `LOG_LEVEL=debug` are correctly **not** flagged.

### Vulnerabilities (17)

Every vulnerability finding carries a CWE, an OWASP mapping, and paired
vulnerable/secure code plus remediation and impact.

| Severity | Vulnerability | CWE | Language / file |
|---|---|---|---|
| critical | OS Command Injection | CWE-78 | Python `app.py` |
| critical | OS Command Injection | CWE-78 | Node `server.js` |
| critical | Kotlin OS Command Injection | CWE-78 | Kotlin `Main.kt` |
| high | SQL Injection | CWE-89 | Python `app.py` |
| high | SQL Injection | CWE-89 | Node `server.js` |
| high | Server-Side Request Forgery | CWE-918 | Python `app.py` |
| high | Disabled TLS Certificate Verification | CWE-295 | Python `app.py` |
| high | Path Traversal | CWE-22 | Python `app.py` |
| high | Reflected XSS | CWE-79 | Node `server.js` |
| high | XSS via `dangerouslySetInnerHTML` | CWE-79 | React `Widget.jsx` |
| high | Android WebView `addJavascriptInterface` | CWE-749 | Kotlin `Main.kt` |
| high | Remote script piped to shell (`curl \| bash`) | CWE-494 | `Dockerfile` |
| medium | Weak Cryptographic Hash (MD5) | CWE-327 | Python `app.py` |
| medium | Open Redirect | CWE-601 | Node `server.js` |
| medium | ASP.NET debug enabled | CWE-489 | `web.config` |
| medium | ASP.NET `customErrors` off | CWE-209 | `web.config` |
| medium | ASP.NET request validation disabled | CWE-20 | `web.config` |

Note the taint gating in action: `subprocess.run(["ping","-c","1","8.8.8.8"])` and
`requests.get(url, verify=True)` in `app.py` are **not** flagged — only the
dynamically-tainted sinks are.

## How to read each format

### HTML — the collapsible report

Open [sast-sample-app.html](pathname:///reports/sast-sample-app.html) in any browser.
Each finding is an expandable **card**:

- **Summary line** — severity badge, vulnerability/secret name, `file:line`, and (for vulnerabilities) the CWE.
- **Expanded** — description, the vulnerable code, the secure-code fix, remediation, and technical & business impact; secret findings show the redacted value, entropy, and hash.
- Controls: a **filter box**, **severity/file/name sort**, and **expand/collapse-all**. Theme-aware and fully self-contained (one file, no assets).

By default secret values are shown in full (paste-ready for a vendor PoC); add `--mask` to redact them for screenshots.

### SARIF — code-scanning dashboards

Each finding is a `result` with a `ruleId`, `physicalLocation` (file + start line), a
`level` (`error` for critical/high, `warning` for medium, `note` for low), and a
`properties` block. Vulnerability results also carry the CWE and OWASP tags. Upload it:

```yaml
- uses: github/codeql-action/upload-sarif@v3
  with: { sarif_file: reports/sast-sample-app.sarif }
```

### JSONL — grep / SIEM

One finding per line. Fastest to slice with `jq`:

```bash
jq -r 'select(.severity=="critical" or .severity=="high")
  | [.severity, .rule_id, .file, .line] | @tsv' sast-sample-app.jsonl
```

### JSON / CSV / Excel / PDF

`json` is the complete structured feed; `csv` and `xlsx` are spreadsheet-friendly
(Excel adds a pivot summary sheet); `pdf` is a stable, ASCII-safe evidence packet for
auditors. All carry the full vulnerability record (CWE, OWASP, vulnerable/secure code).

## Gate CI on findings

The run above exits `0` regardless of count. Add a gate:

```bash
scan4secrets --path examples/sample-app --misconfig \
  --report sarif --fail-on high --output reports/sast-sample-app
```

`--fail-on high` exits `1` if any finding is `high` or `critical`, while still writing
the SARIF file so the dashboard upload runs.

## Try your own code

Point `--path` at any repo. Secrets-only is the default; add `--misconfig` for the
vulnerability engine, or `--misconfig-only` to scan for vulnerabilities without secrets.
See [Getting Started](./getting-started) and the [CLI Reference](./cli-reference).
