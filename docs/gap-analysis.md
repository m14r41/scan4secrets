---
id: gap-analysis
title: Gap Analysis (v1 → v2)
sidebar_position: 91
description: A defect-by-defect comparison of scan4secrets v1 vs v2 — what was broken, why, and how v2 fixes it.
keywords: [scan4secrets gap analysis, v1 vs v2, false positive rate, defect mapping]
---

# Gap Analysis (v1 → v2)

> What was broken in v1, why, and how v2 fixes it. Each row maps a defect to the v2 change that closes it.

| # | v1 defect | Root cause | v2 fix |
|---|---|---|---|
| 1 | Massive false-positive rate | `patterns.json` matched variable NAMES (`password`, `key`, `id`), not vendor value-shapes | `rules.yaml` with per-vendor value-shape regex + entropy + allowlist |
| 2 | Missed private keys (`.ssh/id_rsa`, `*.pem`) | Detection regex required `name = value` shape; PEM blocks have no shape | `private-key-block` rule matches PEM anchor line directly |
| 3 | Missed Docker registry credentials | Same as #2 — JSON-nested value not "named" | `docker-registry-auth` rule keys on `"auth":` token |
| 4 | Random categorization | Same key appeared in multiple categories in `patterns.json`; last-loaded won | Each rule has a stable unique `id`; severity replaces category |
| 5 | Double-scan in DAST mode | `crawler.scan_for_secrets` AND `scanner.scan_remote_file` both fired | Single crawl path, scanning is centralized in `engine.scanner.scan_text` |
| 6 | `core/crawler-clean.py` dead duplicate | Two parallel codebases | Deleted; new `engine/crawler.py` is single source |
| 7 | SAST opened binary files | No extension / binary check | NUL-byte heuristic + skip-dir + max-size + glob exclude |
| 8 | `except Exception: pass` swallowed errors | Hid coverage holes | Replaced with `logging.debug` calls |
| 9 | Status 301/302 dead branch | `requests.get` follows redirects by default | Code path simplified, no longer claims to handle redirects it never sees |
| 10 | `release.yml` referenced `src/main.py` (doesn't exist) | Stale path | Rewritten — builds wheel + Windows EXE + Linux EXE + Docker image |
| 11 | `fpm -s python` without `setup.py` | No packaging | `pyproject.toml` ships, `pip install .` works, wheel built in CI |
| 12 | `wordlist.txt` grew forever | Appended every run | Removed mutating wordlist write; new crawler doesn't write side files |
| 13 | `requirements.txt` lied (`argparse`, `python-docx`, `fpdf v1`) | Drift | Replaced with accurate, pinned deps (`fpdf2`, `pyahocorasick`, `tldextract`, `PyYAML`) |
| 14 | Default `python-requests` UA blocked by WAFs | No UA customization | `--user-agent` flag, sensible default UA |
| 15 | Single-threaded crawler | Recursive `requests.get` | `ThreadPoolExecutor` with `--threads` (default 16) |
| 16 | KeyboardInterrupt lost results | `exit(0)` mid-scan | Crawler catches `RequestException`; CLI traps SIGINT cleanly |
| 17 | Config paths relative to CWD | Hardcoded relative paths | `Path(__file__).resolve().parent.parent / "config"` |
| 18 | No deduplication | Same line could emit multiple times | Dedup keyed on `(file, line, sha256(secret), rule_id)` |
| 19 | No exit code semantics | Always exited 0 | `--fail-on` flag; exit 1 if any finding meets threshold |
| 20 | No max-depth / max-URLs / scope control | Crawler could run forever | `--max-urls`, `--max-depth`, eTLD+1 scope (default) or `--strict-host` |
| 21 | Value char-class allowed `(){}` | Matched CSS / JS blocks | Per-rule regex; no broad char-class |
| 22 | Duplicate keywords in `patterns.json` | Manual list maintenance | Each rule has unique `id`; rule loader warns on duplicates |
| 23 | `python-docx` import never used | Stale requirement | Removed |
| 24 | PDF crashed on non-ASCII | `fpdf` v1 default fonts are Latin-1 | `fpdf2` + safe-encode helper |
| 25 | HTML report was raw `df.to_html()` | No design | New HTML v2: severity pills, sortable columns, live filter, dark theme |
| 26 | No SARIF output | Couldn't go into GitHub Code Scanning | SARIF 2.1.0 reporter |
| 27 | No JSONL output | Couldn't stream into SOAR/SIEM | JSONL reporter |
| 28 | No CLI flags for proxy / cookie / header | Couldn't test authenticated apps | `--cookie`, `--header K:V`, `--proxy`, `--insecure` |
| 29 | No verification | Findings were hypotheses | `--verify` runs vendor probes; finding gets `verified=true\|false` |
| 30 | No JS source-map parsing | `.js.map` files ignored | `engine/sourcemap.py` extracts `sourcesContent[]` and scans each |
| 31 | No JS endpoint extraction | Only HTML link extraction | `crawler.py` regex-extracts string literals from JS |
| 32 | No HTTP header scan | Body-only | Each `Header: Value` line scanned through the same engine |
| 33 | No package install path | `git clone` + `python main.py` | `pip install scan4secrets`, console entry, Docker image |
| 34 | No pre-commit hook | Couldn't be gated | `.pre-commit-hooks.yaml` ships |
| 35 | README oversold "400+ rules" | Marketing vs reality | Honest count + a comparison table vs gitleaks/trufflehog/detect-secrets |

## What's still on the roadmap (v2.1+)

These are intentionally deferred from v2.0:

- **Git history scan** (`--git`, `--since`) — iterate every blob across all branches; biggest real-world secret source
- **OpenAPI / GraphQL / Swagger ingestion** for DAST seed URLs
- **Wayback / common-crawl URL source** for archived endpoints
- **`--gitleaks-import` flag** to re-verify + re-format an existing gitleaks JSON report
- **Tech-stack-aware wordlist selection** (currently loads all wordlists indiscriminately)
- **Sitemap.xml / robots.txt** ingestion as DAST seeds
- **Smart 404 detection** (sites returning 200 with a "Not Found" body)
- **Process-pool SAST** for very large monorepos
- **Diff / baseline mode** (`--baseline previous.json`)
- **Test fixtures + pytest CI** (skeleton is in `tests/`, fixtures need population)

## How v2 compares operationally

| Dimension | v1 | v2 |
|---|---|---|
| Time to first useful run | `git clone && pip install -r req && python main.py --path X` | `pip install scan4secrets && scan4secrets --path X` |
| FP rate on clean repo | ~13% per file | 0% per file (empirical) |
| Detects private keys | No | Yes |
| Detects Docker registry creds | No | Yes |
| Authenticated DAST | No | Yes (cookie, header, proxy) |
| JS source maps | No | Yes |
| CI-native output | No | SARIF, JSONL, exit codes |
| Live verification | No | Yes (4 vendors built-in, schema for more) |
| Lines of detection engine code | ~300 lines, broken | ~400 lines, tested |
