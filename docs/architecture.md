---
id: architecture
title: Architecture
sidebar_position: 4
description: How scan4secrets is organized, how data flows through the engine and crawler, and where to extend it.
keywords: [scan4secrets architecture, scan4secrets internals, secret scanner design, Aho-Corasick keyword index, DAST crawler design]
---

# Architecture

> How scan4secrets is organized, how data flows through it, and where to extend it.

## Package layout

```text
scan4secrets/
├── scan4secrets/                  # the package
│   ├── __init__.py                # version
│   ├── __main__.py                # `python -m scan4secrets`
│   ├── cli.py                     # argparse, orchestration
│   ├── config/
│   │   ├── rules.yaml             # the detection rules (YAML)
│   │   ├── extensions.json        # extensions to gate DAST URL discovery
│   │   └── wordlist/              # path-guess wordlists for DAST
│   ├── engine/
│   │   ├── findings.py            # Finding dataclass, severity, redact
│   │   ├── entropy.py             # Shannon entropy
│   │   ├── rules.py               # Rule loading, Aho-Corasick keyword index
│   │   ├── scanner.py             # SAST: walks filesystem, applies rules
│   │   ├── crawler.py             # DAST: concurrent web crawl, source-maps, JS endpoints
│   │   ├── sourcemap.py           # parses .js.map sourcesContent
│   │   ├── wordlists.py           # load path-guess wordlists for DAST seeding
│   │   └── verifier.py            # live vendor-API verification
│   └── reporters/
│       ├── __init__.py            # writer registry
│       ├── sarif.py               # SARIF 2.1.0
│       ├── json_.py               # pretty JSON
│       ├── jsonl.py               # one finding per line
│       ├── csv_.py                # CSV
│       ├── html.py                # sortable filterable HTML
│       ├── excel.py               # XLSX via openpyxl
│       └── pdf.py                 # PDF via fpdf2 (UTF-8 safe)
├── docs/                          # this directory
├── tests/                         # pytest + planted-secret fixtures
├── pyproject.toml                 # build / install / console entry
├── Dockerfile                     # container image
├── .pre-commit-hooks.yaml         # pre-commit framework integration
├── .github/workflows/             # CI + release pipelines
├── main.py                        # backward-compat shim → cli.main()
└── README.md
```

## Data flow

```text
┌──────────────────────┐                          ┌──────────────────────┐
│ User CLI invocation  │                          │  Custom rules.yaml   │
└──────────┬───────────┘                          └─────────┬────────────┘
           │                                                │
           ▼                                                ▼
     ┌─────────────────────────────────────────────────────────┐
     │ cli.main(): parse args, load_rules(), filter, build CLI │
     └────────────────────┬────────────────────────────────────┘
                          │
            ┌─────────────┼─────────────┐
            │             │             │
            ▼             ▼             ▼
       ┌────────┐    ┌────────┐    ┌──────────┐
       │ stdin  │    │  SAST  │    │   DAST   │
       │ scan   │    │ walk + │    │  crawl + │
       │ text   │    │  scan  │    │  scan    │
       └───┬────┘    └───┬────┘    └────┬─────┘
           │             │              │
           └─────────────┼──────────────┘
                         ▼
              ┌──────────────────────┐
              │ List[Finding] (dedup) │
              └──────────┬───────────┘
                         │
              ┌──────────┴────────────┐
              │ if --verify: verifier  │ ──► live HTTP probes to vendor APIs
              └──────────┬────────────┘     (sets Finding.verified)
                         │
                         ▼
              ┌──────────────────────┐
              │  reporters.write_*   │ ──► sarif / json / jsonl / csv / html / excel / pdf
              └──────────┬───────────┘
                         │
                         ▼
                  exit-code gate
              (0 / 1 based on --fail-on)
```

## Engine model

A rule is `(id, severity, keywords, regex, entropy_min, allowlist, verify)`. The keyword pre-filter (Aho-Corasick) is what makes the engine fast on large repos — for each line we identify only the rules whose keywords appear, then run only those regexes. Without the pre-filter, scanning a large repo with 100+ rules is O(N×R) for every line; with it, ~O(N).

The pipeline per line:

```text
line ──► keyword index ──► candidate rules ──► regex.finditer ──► captured value
                                                                       │
                                                                       ▼
                                                              shannon_entropy
                                                                       │
                                                              ≥ entropy_min ?
                                                                       │
                                                                       ▼
                                                              allowlist.line ?
                                                              allowlist.path ?
                                                                       │
                                                                       ▼
                                                                 emit Finding
```

## Verification model

The `verify:` block on a rule is opt-in (`--verify` flag at runtime). For each finding whose rule has `verify`, the verifier sends one HTTP request:

```python
headers[v.header_name] = v.header_value.replace("{{value}}", finding.secret)
r = requests.request(v.method, v.url, headers=headers, timeout=5, allow_redirects=False)
finding.verified = (r.status_code == v.success_status)
```

Each verification is concurrent (`ThreadPoolExecutor`, default 8 workers). Verification calls are issued AFTER scanning so a non-network scan is unaffected.

A verified finding is incident-grade evidence; an unverified one is a hypothesis. The two are visually distinct in the HTML report and tagged in SARIF properties so downstream triage tools can prioritize.

## Extension points

| Add a... | File to edit |
|---|---|
| New detection rule | `scan4secrets/config/rules.yaml` (append; no code change) |
| New vendor verifier | `verify:` block on the new rule (no code change) |
| New reporter (e.g. Markdown) | `scan4secrets/reporters/<name>.py` + register in `reporters/__init__.py` |
| New CLI flag | `scan4secrets/cli.py` (`_parser()` then `main()`) |
| Custom keyword index backend | `scan4secrets/engine/rules.py` (the `KeywordIndex` class) |
| New URL discovery source (sitemap, openapi) | `scan4secrets/engine/crawler.py` (`extra_seeds` parameter) |
| New path-guess wordlist | drop `*.txt` under `scan4secrets/config/wordlist/` |

## Performance notes

- Aho-Corasick keyword pre-filter: 100+ rules → ~5x faster than naive per-rule regex scanning.
- Binary skip: files with NUL byte in first 4096 bytes skipped (no garbage matches, faster).
- Max file size: 10 MB default (skips minified bundles, build artifacts).
- Max line length: 4096 chars (long minified lines truncated; prevents regex backtracking pathology).
- Crawler concurrency: ThreadPoolExecutor with `--threads` (default 16); use 32-64 for fast targets.
- Verifier concurrency: 8 workers; each probe ≤ 5s timeout.
- Skipped directories by default: `.git`, `node_modules`, `vendor`, `dist`, `build`, `.venv`, `__pycache__`, `.next`, `.nuxt`, `.tox`, `.cache`, `.mypy_cache`, `.pytest_cache`, `bower_components`, `coverage`, `.idea`, `.vscode`.

## Why YAML rules, not TOML or code

- YAML round-trips edits cleanly in PRs.
- Human-readable for non-Python contributors.
- Same shape can be loaded by tests, distributed via package data, or referenced by `--rules custom.yaml` from outside the repo.
