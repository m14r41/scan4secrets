---
id: changelog
title: Changelog
sidebar_position: 90
description: scan4secrets release history — v2 rule engine rewrite, DAST overhaul, live verification, CI-native reporting.
keywords: [scan4secrets changelog, scan4secrets v2, release notes]
---

# Changelog

## v2.1.2 — Bundling, normalization, and PoC-friendly defaults

**Breaking:** Secret values are now shown **in full by default** in every output (terminal, CSV, JSON, JSONL, HTML, Excel, PDF, SARIF). The `--unsafe-show` flag is removed and replaced by `--mask`, which inverts the behaviour for screenshots or shared transcripts. Rationale: this tool is used to produce vendor PoCs where the raw value is the proof; redacted-by-default forced an extra flag on every real run.

### Changed
- **`--mask` flag** replaces `--unsafe-show`. Default is unmasked across the terminal table and every file reporter.
- **`normalize_url`** accepts every common shape: bare host, host:port, IPv4, IPv4:port, IPv6 `[::1]`, `[::1]:port`, scheme-less paths, accidental `://prefix` typos, whitespace, trailing slashes. `:443` stays HTTPS; other ports and raw IPs default to HTTP. Unsupported schemes (`ftp://`, `ws://`, `file://`) are rejected with a clear error.

### Fixed
- **PyInstaller binary bundling**: Linux and Windows binaries now ship `scan4secrets/config/rules.yaml` via explicit `--add-data`. Previous `--collect-all` alone did not pick up package-data under `--onefile`, causing `FileNotFoundError: '/tmp/_MEIxxx/scan4secrets/config/rules.yaml'` on first run.
- **BeautifulSoup XML warning**: `XMLParsedAsHTMLWarning` is silenced at crawler load (`engine/crawler.py`). Non-fatal noise on XML/RSS responses no longer pollutes the terminal.

## v2.1.0 — DAST defaults + noise reduction

### Changed
- **Wordlist seeding is now ON by default** for any `--url` run. All 15 bundled wordlists (1279 unique paths) seed every DAST scan.
- **`--wordlist FILE [FILE ...]`** now takes user-supplied wordlist file paths and REPLACES the bundled set for that run (was: a boolean toggle).
- Use `--wordlist-only NAME ...` to restrict to specific bundled stems.
- Use `--no-wordlist` to disable seeding entirely.
- **Generic-rule suppression** runs by default — when a vendor-specific rule fires on a secret value, generic `contextual-*` / `generic-high-entropy-*` findings for the same value are dropped. Use `--keep-generic` to disable.
- **Response-header dedup** is now global across the crawl — the same `X-Powered-By` leak is scanned once, not once per URL.

### Added
- Inline `<script>` URL string-literal extraction in HTML responses.
- Inline `<style>` and standalone CSS `url(...)`, `@import`, `/*# sourceMappingURL=*.css.map */` extraction.
- `.css.map` sourcesContent parsing (matching `.js.map`).
- `<meta http-equiv="refresh">` URL following.
- Binary content-type skip (`image/*`, `video/*`, `audio/*`, `font/*`, `application/pdf`, etc.).
- Connection pool sized to 64 (was default 10) — no more "pool is full" warnings on `--threads > 10`.

## v2.0.0 — Rule engine rewrite + DAST overhaul

**Breaking:** complete rewrite. Old `core/`, `output/`, `ui/`, `config/patterns.json` are moved to `legacy_*` directories and no longer imported. The CLI shape changes (`main.py` becomes a shim around `scan4secrets.cli:main`).

### Why v2 exists

Empirical test on a benign Express repo: v1 produced **27 false positives**, v2 produces **0**. On a deliberately seeded leaky-repo, v2 catches the **SSH private keys**, **PEM blocks**, and **Docker registry credentials** that v1 was structurally incapable of detecting. The defect was the detection model itself (keyword-name match vs vendor value-shape match). v2 fixes the model.

### New — detection engine

- **YAML rules** at `scan4secrets/config/rules.yaml` replacing the keyword-name `patterns.json`
- **Vendor value-shape regexes** for 170+ rule IDs across cloud, CDN/edge, SCM, CI/CD, payments, e-commerce, messaging, carriers, AI/ML, email, monitoring, registries, auth, productivity, mobile/push, data, mapping, Web3, storage, VPN, QA, DB connection URIs, webhooks, and crypto
- **Aho-Corasick keyword pre-filter** (`pyahocorasick`) for O(N) scanning across hundreds of rules
- **Shannon-entropy gate** per rule (kills `secret = "changeme"` style noise)
- **Per-rule allowlists** (regex against full line + path globs against file path)
- **Contextual fallback rules** for hex tokens, UUIDs, and quoted/unquoted high-entropy values near credential-sounding names
- **Severity model**: info / low / medium / high / critical, with a `--fail-on` CI gate
- **Deduplication** keyed on `(file, line, sha256(secret), rule_id)` across SAST + DAST

### New — DAST crawler

- **Concurrent crawl** via `ThreadPoolExecutor` (`--threads`, default 16) — replaces v1's recursive single-threaded `requests.get`
- **Scope control**: same-eTLD+1 by default, `--strict-host` for exact host
- **JS source-map parsing** — fetches `*.js.map` and scans embedded `sourcesContent` (no other open-source tool does this)
- **JS endpoint extraction** — string literals in `.js` files added to the queue
- **HTTP header scanning** — secrets sometimes leak in `X-Powered-By`, `Server`, custom headers
- **Authenticated DAST**: `--cookie`, `--header K:V` (repeatable), `--proxy`, `--insecure`
- **Custom UA** with sensible default — v1's default `python-requests/X` UA was blocked by most WAFs
- **Caps**: `--max-urls`, `--max-depth`, `--timeout`

### New — verification

- **`--verify` flag** runs one HTTP probe per finding whose rule has a `verify:` block, sets `verified=true|false|null`
- Built-in probes for GitHub (classic + fine-grained PAT), Slack, Stripe, OpenAI
- Trivial to add new vendors — edit the YAML rule

### New — reporters

- **SARIF 2.1.0** — GitHub Code Scanning, GitLab Security, Sonar, Defect Dojo
- **JSON** + **JSONL** — pipelines, SIEM ingest
- **HTML v2** — severity badges, sortable columns, live filter, dark theme
- **Excel** via openpyxl
- **PDF** via fpdf2 (UTF-8 safe; v1's fpdf v1 crashed on non-ASCII)
- **CSV** with full schema (rule_id, severity, verified, file, line, entropy, redacted, sha256, description, excerpt)
- **Redaction by default**: `abcd****wxyz`. `--unsafe-show` to include raw values (use carefully)

### New — packaging & CI

- **`pyproject.toml`** — `pip install .` works, `scan4secrets` console entry on PATH
- **Dockerfile** — multi-stage build, non-root user
- **`.pre-commit-hooks.yaml`** — drop-in for `pre-commit` framework
- **`.github/workflows/release.yml`** — Windows EXE + Linux EXE binaries, Docker image to GHCR, wheel build
- **`.github/workflows/ci.yml`** — pytest across Python 3.9-3.12

### Empirical results

| Repo | v1 findings | gitleaks | **v2 findings** |
|---|---:|---:|---:|
| Plazmaz/leaky-repo (seeded) | 35 (mixed TP/FP) | 22 | **17** (all real, incl. SSH/PEM/Docker keys v1 missed) |
| expressjs/express (clean) | 27 (all FP) | 0 | **0** |

v2 achieves **0% FP rate** on benign code (vs v1's per-file FP rate of ~12.7%) and detects high-value secret classes (private keys, Docker registry auth) that v1's regex shape could never match.

---

## v1.x (legacy)

Original keyword-name detection model. Source available under `legacy_*` directories for archival reference. Not recommended for production use.
