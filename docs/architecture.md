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
│   │   ├── rules.yaml             # 193 secret-detection rules (YAML)
│   │   ├── vulns.yaml             # 223 vuln/misconfig rules (category: vuln)
│   │   ├── extensions.json        # extensions to gate DAST URL discovery
│   │   └── wordlist/              # path-guess wordlists for DAST
│   ├── engine/
│   │   ├── findings.py            # Finding dataclass, severity, redact
│   │   ├── entropy.py             # Shannon entropy
│   │   ├── rules.py               # Rule loading (load_rules merges both YAMLs), keyword index
│   │   ├── scanner.py             # SAST: walks filesystem, ext→lang gating, applies rules
│   │   ├── structural.py          # whole-file structural pass (scan_structural): key→value correlation
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
     │ cli.main(): parse args, load_rules() (rules+vulns), filter │
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

A secret rule is `(id, severity, keywords, regex, entropy_min, allowlist, verify)`. A
vulnerability rule (from `vulns.yaml`, `category: vuln`) adds `name, languages,
context_required, cwe, owasp, remediation, secure_code, technical_impact, business_impact`.
`load_rules()` merges `rules.yaml` + `vulns.yaml` into one active set; secret rules always run,
while `vuln`-category rules are activated by `--misconfig` (secrets + vulns) or `--misconfig-only`
(vulns alone).

The keyword pre-filter (Aho-Corasick) is what makes the engine fast on large repos — for each line we identify only the rules whose keywords appear, then run only those regexes. Without the pre-filter, scanning a large repo with 100+ rules is O(N×R) for every line; with it, ~O(N).

### Extension → language gating

Vulnerability rules are file-type gated. `scanner.py` maps each file's extension to a language
tag via `lang_of` / `_EXT_LANG` (`.py`→python, `.kt`→kotlin, `.cs`→csharp,
`.xml`/`.config`/`.wsdl`→xml, and so on). A vuln rule's `languages` list is matched against that
tag before its regex runs, so python rules never fire on Kotlin files. Secret rules are not
language-gated.

### Detection passes

Two complementary passes run over each file, then de-dup:

1. **Line-based pass** — one rule per physical line, Aho-Corasick pre-filtered (below).
2. **Structural pass** — `structural.py:scan_structural` reads the whole file and correlates
   key→value across lines to catch split secrets the line engine cannot see: nested XML tags,
   split `<key>`/`<value>`, JSON key/value objects, multi-line YAML/`.properties`, and
   Base64-decoded secrets. A cross-pass de-dup step avoids double-reporting.

The line-based pipeline per line:

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
| New secret rule | `scan4secrets/config/rules.yaml` (append; no code change) |
| New vulnerability / misconfig rule | `scan4secrets/config/vulns.yaml` (append with `category: vuln` + `languages`; no code change) |
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
