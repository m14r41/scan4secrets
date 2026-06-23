---
id: sample-report
title: Sample Report
sidebar_position: 9
description: A real scan4secrets run against a planted-secret fixture and against this docs site. Download the same scan output in SARIF, JSON, JSONL, CSV, HTML, Excel, and PDF.
keywords: [scan4secrets sample report, secret scan report example, SARIF example, SAST report, DAST report, scan output, secret scanner demo]
---

# Sample Report

A real run of scan4secrets against a planted-secret fixture (SAST) and against the docs site you are reading (DAST). Both runs are reproduced here so you can see exactly what the tool produces before installing it.

Every secret value below is a clearly fake placeholder (AWS documentation example values, or strings stamped with `FAKE`). Nothing in this report authenticates.

## Tool version

```text
$ scan4secrets --version
scan4secrets 2.1.0
```

## Run 1, SAST against a planted fixture

### Target

A small fixture tree representing a typical web application:

```text
sample-app/
├── .env.production                   # cloud, payment, AI, messaging tokens
├── src/config.js                     # Meta access token, OAuth, webhook
├── config/service-account.json       # GCP service-account JSON, PEM block
├── .github/workflows/deploy.yml      # CI log echo with PAT and PyPI token
└── build/bundle.min.js.map           # JS source-map exposing original auth.ts
```

### Command

```bash
scan4secrets --path sample-app \
  --report sarif json jsonl csv html excel pdf \
  --output reports/sast-sample-app
```

### Summary

| Severity | Count |
|---|---|
| critical | 6 |
| high     | 7 |
| medium   | 3 |
| low      | 3 |
| info     | 0 |
| **Total**| **19** |

Per-rule breakdown:

| Rule | Hits |
|---|---|
| `github-pat-classic` | 3 |
| `stripe-secret-live` | 2 |
| `slack-bot-token` | 2 |
| `slack-webhook` | 2 |
| `generic-high-entropy-unquoted` | 2 |
| `anthropic-key` | 1 |
| `meta-access-token` | 1 |
| `private-key-block` | 1 |
| `postgres-connection-uri` | 1 |
| `redis-connection-uri` | 1 |
| `mongodb-connection-uri` | 1 |
| `jwt-token` | 1 |
| `generic-high-entropy-quoted` | 1 |

### Every finding

| Severity | Rule | File | Line | Redacted value |
|---|---|---|---|---|
| `critical` | `github-pat-classic` | `.env.production` | 12 | `ghp_********************************AAAA` |
| `critical` | `github-pat-classic` | `.github/workflows/deploy.yml` | 10 | `ghp_********************************9988` |
| `critical` | `github-pat-classic` | `src/config.js` | 8 | `ghp_********************************0011` |
| `critical` | `private-key-block` | `config/service-account.json` | 5 | `----*******************----` |
| `critical` | `stripe-secret-live` | `.env.production` | 6 | `sk_l********************************FAKE` |
| `critical` | `stripe-secret-live` | `src/config.js` | 15 | `sk_l******************************0000` |
| `high` | `anthropic-key` | `.env.production` | 10 | `sk-a**************************************AAAA` |
| `high` | `meta-access-token` | `src/config.js` | 3 | `EAAB**************************************0099` |
| `high` | `mongodb-connection-uri` | `.env.production` | 28 | `mong***************************.net` |
| `high` | `postgres-connection-uri` | `.env.production` | 26 | `post***************************prod` |
| `high` | `redis-connection-uri` | `.env.production` | 27 | `redi***********6379` |
| `high` | `slack-bot-token` | `.env.production` | 15 | `xoxb******************************FAKE` |
| `high` | `slack-bot-token` | `src/config.js` | 11 | `xoxb******************************FAKE` |
| `medium` | `jwt-token` | `src/config.js` | 26 | `eyJh***********************************************EFAK` |
| `medium` | `slack-webhook` | `.env.production` | 16 | `http*************************************************XXXX` |
| `medium` | `slack-webhook` | `src/config.js` | 12 | `http*************************************************AAAA` |
| `low` | `generic-high-entropy-quoted` | `src/config.js` | 4 | `abcd****************7890` |
| `low` | `generic-high-entropy-unquoted` | `.env.production` | 3 | `wJal********************************EKEY` |
| `low` | `generic-high-entropy-unquoted` | `.github/workflows/deploy.yml` | 9 | `pypi***************************************FAKE` |

### Regenerate the full report locally

The report artifacts are not committed to the repo. GitHub push protection flags the embedded `line_excerpt` lines (planted AWS docs example values, etc.) as real secrets. Reproduce locally to see the exact same output in all seven formats.

```bash
git clone https://github.com/m14r41/scan4secrets
cd scan4secrets
pip install -e .

# Build a fixture (or use yours)
mkdir -p sample-app && cat > sample-app/.env.production <<'EOF'
AWS_ACCESS_KEY_ID=AKIA<...AWS-DOCS-EXAMPLE-VALUE...>
STRIPE_SECRET_KEY=sk_live_FAKE_FAKE_FAKE_FAKE_FAKE
GITHUB_PAT=ghp_FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE00
EOF

# Run the same command this page describes
scan4secrets --path sample-app \
  --report sarif json jsonl csv html excel pdf \
  --output reports/sast-sample-app
```

Each of the seven outputs will land in `reports/`:

| Format | When to use |
|---|---|
| **SARIF** | GitHub Code Scanning, GitLab Security Dashboard, Sonar, Defect Dojo |
| **JSON** | Tooling integration, post-processing |
| **JSONL** | SIEM and SOAR streaming (Splunk, Datadog, Sentinel) |
| **CSV** | Spreadsheet triage |
| **HTML** | Sortable, filterable client view |
| **Excel** | Pivot tables and exec summaries |
| **PDF** | Compliance evidence packets |

## Run 2, DAST against this docs site

### Target

`http://127.0.0.1:3000` (the same Docusaurus site you are reading, run locally).

### Command

```bash
scan4secrets --url http://127.0.0.1:3000 \
  --threads 16 --max-urls 200 --max-depth 2 --timeout 8 \
  --no-wordlist \
  --report sarif json jsonl csv html excel pdf \
  --output reports/dast-localhost
```

`--no-wordlist` disables the bundled 1279-path wordlist seeding for this demo. In a real bug-bounty engagement you would leave wordlist seeding on. `--max-urls 200 --max-depth 2` keeps the run bounded for a demo.

### Summary

| Severity | Count |
|---|---|
| critical | 2 |
| high     | 0 |
| medium   | 0 |
| low      | 0 |
| info     | 0 |
| **Total**| **2** |

### Why this is interesting

Both findings fire on `/docs/targets/github` because that page documents the **shape** of GitHub deploy keys, and the description includes the literal anchor line:

```text
-----BEGIN OPENSSH PRIVATE KEY-----
```

The detection rule `private-key-block` is doing exactly what it is supposed to do, this is a true positive **on the page content**. In a real engagement these would be triaged out as documentation false positives by passing `--exclude '**/docs/targets/**'` or by adding an `allowlist.paths` entry to the rule.

This is the most useful kind of demo finding because it shows two important things in one run:

1. The scanner does fire on a real PEM anchor in any served HTML, not just in source.
2. Documentation pages that explain attack surface need a per-rule allowlist or a `--exclude` path filter, or they will land in every report.

### Regenerate the DAST report locally

```bash
# After installing scan4secrets and running the docs site at localhost:3000
scan4secrets --url http://127.0.0.1:3000 \
  --threads 16 --max-urls 200 --max-depth 2 --timeout 8 \
  --no-wordlist \
  --report sarif json jsonl csv html excel pdf \
  --output reports/dast-localhost
```

## How to read the output

### SARIF

SARIF is the standard for code-scanning dashboards. Each finding becomes a `result` with a `ruleId`, a `physicalLocation` (file plus start line), a `level` (`error` for critical and high, `warning` for medium, `note` for low and info), and a `properties` block carrying the entropy score and the `verified` state.

```json
{
  "ruleId": "github-pat-classic",
  "level": "error",
  "message": { "text": "GitHub Personal Access Token (Classic)" },
  "locations": [{
    "physicalLocation": {
      "artifactLocation": { "uri": "sample-app/.env.production" },
      "region": { "startLine": 12 }
    }
  }],
  "properties": { "entropy": 4.81, "verified": null, "redacted": "ghp_****AAAA" }
}
```

Upload it to GitHub Code Scanning:

```yaml
- uses: github/codeql-action/upload-sarif@v3
  with: { sarif_file: reports/sast-sample-app.sarif }
```

### JSONL

One finding per line, ready to pipe into a SIEM or transform with `jq`. The fastest format to grep against.

```bash
# everything critical and high, file + line + rule
jq -r 'select(.severity=="critical" or .severity=="high")
  | [.severity, .rule_id, .file, .line] | @tsv' sast-sample-app.jsonl
```

```text
critical  github-pat-classic   sample-app/.env.production               12
critical  github-pat-classic   sample-app/.github/workflows/deploy.yml  10
critical  github-pat-classic   sample-app/src/config.js                  8
critical  private-key-block    sample-app/config/service-account.json    5
critical  stripe-secret-live   sample-app/.env.production                6
critical  stripe-secret-live   sample-app/src/config.js                 15
high      anthropic-key        sample-app/.env.production               10
high      meta-access-token    sample-app/src/config.js                  3
...
```

### HTML

Open in any browser. Severity is colored, columns are sortable, the search bar filters live. Best for sharing with a client who does not want to install anything.

### CSV and Excel

Same data shape, optimized for spreadsheet triage. Excel adds a summary sheet with pivot tables (severity by rule, severity by file).

### PDF

Compliance evidence. Stable layout, ASCII-safe encoding. Hands cleanly to an auditor.

### JSON

Full structured output with every finding, every rule, the run metadata, and the tool version. The most precise feed for downstream tooling that wants the complete picture.

## Exit-code semantics

Both runs above did not pass `--fail-on`, so the exit code was `0` regardless of finding count. Add a gate to make CI fail on real incidents.

```bash
scan4secrets --path sample-app --report sarif \
  --fail-on high \
  --output reports/sast-sample-app
```

`--fail-on high` exits `1` if any finding is `high` or `critical`. The SARIF file is still produced so the dashboard upload still runs.

## Reproduce this run

1. Install scan4secrets ([Getting Started](./getting-started)).
2. Pull a copy of the fixture into a temp directory or build your own.
3. Run the two commands from this page.
4. Diff the output against the reports linked above.

The fixture used here is intentionally small, 6 files. Real engagements produce reports with hundreds to thousands of findings. The shape is identical.
