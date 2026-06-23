---
id: getting-started
title: Getting Started
sidebar_position: 2
description: Install scan4secrets via pipx, Docker, prebuilt binary, or pip. Run your first SAST and DAST scans in under two minutes.
keywords: [install scan4secrets, scan4secrets quickstart, pip install scan4secrets, docker scan4secrets, scan4secrets binary]
---

# Getting Started

Install scan4secrets and run your first scan in under two minutes.

## Install

### pipx (recommended)

```bash
pipx install git+https://github.com/m14r41/scan4secrets
```

### pip

```bash
pip install git+https://github.com/m14r41/scan4secrets
# or, when on PyPI:
pip install scan4secrets
```

### From source

```bash
git clone https://github.com/m14r41/scan4secrets
cd scan4secrets
pip install -e .
```

### Docker

```bash
docker run --rm -v $(pwd):/scan ghcr.io/m14r41/scan4secrets:latest --path /scan
```

### Prebuilt binaries

Windows64 and Linux amd64 binaries are published with every release. See [Downloads](./downloads) for direct links and checksums.

After install, the `scan4secrets` command is on your PATH.

```bash
scan4secrets --version
```

## Quick start

### SAST. Scan a local directory

```bash
scan4secrets --path /code
```

### DAST. Crawl a live target

```bash
scan4secrets --url https://staging.example.com --threads 32
```

DAST runs **all 15 bundled wordlists** (1279 unique paths: `/.env`, `/wp-config.php`, `/backup.zip`, source maps, admin panels, API docs, …) by default.

### Use your own wordlist file

```bash
scan4secrets --url https://target.com --wordlist /path/to/my-paths.txt
```

### Combine multiple custom wordlists

```bash
scan4secrets --url https://target.com --wordlist seclists/Common.txt internal-paths.txt
```

### Restrict to specific bundled wordlists by stem

```bash
scan4secrets --url https://wp.example.com --wordlist-only wordpress common env
```

### Turn wordlist seeding off entirely

```bash
scan4secrets --url https://target.com --no-wordlist
```

### Full audit with verification + HTML report

```bash
scan4secrets --path . --url https://app.example.com \
    --verify --report html sarif json \
    --output reports/audit-$(date +%F)
```

### Authenticated DAST with proxy (works with Burp / ZAP)

```bash
scan4secrets --url https://app.example.com \
    --cookie "session=abc123" \
    --header "X-Tenant: acme" \
    --proxy http://127.0.0.1:8080
```

### CI gate. Exit 1 on any high-or-above finding

```bash
scan4secrets --path . --report sarif --fail-on high --output reports/scan
```

## Reports

```bash
scan4secrets --path . --report sarif json jsonl csv html excel pdf --output reports/run
```

| Format | Best for |
|---|---|
| `sarif` | GitHub Code Scanning, GitLab Security Dashboard, Sonar, Defect Dojo |
| `json` | Tooling integrations, post-processing |
| `jsonl` | SIEM/SOAR pipelines (Splunk, Datadog, Sentinel) |
| `csv` | Spreadsheet triage |
| `html` | Sortable / filterable / colored UI for client review |
| `excel` | Pivot tables and exec summaries |
| `pdf` | Compliance evidence packets |

Secrets are **redacted by default** (`abcd****wxyz`). Use `--unsafe-show` only when reports are stored securely.

## Next

- [CLI Reference](./cli-reference). Every flag
- [CI Integration](./ci-integration). GitHub Actions, GitLab CI, pre-commit
- [Verification](./verification). Turn "looks like a token" into "verified live credential"
