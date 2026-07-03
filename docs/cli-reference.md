---
id: cli-reference
title: CLI Reference
sidebar_position: 3
description: Every scan4secrets command-line flag. Input targets, scope control, DAST tuning, authentication, output formats, exit-code gates.
keywords: [scan4secrets cli, scan4secrets flags, scan4secrets options, scan4secrets command line, scan4secrets help]
---

# CLI Reference

Every flag, grouped by purpose.

## Synopsis

```text
scan4secrets [INPUT] [SCOPE] [DAST] [AUTH] [OUTPUT] [GATE]
```

## Input targets

| Flag | Default | Description |
|---|---|---|
| `--path PATH ...` |. | One or more local directories or files for SAST. Repeatable. |
| `--url URL ...` |. | One or more URLs for DAST. Repeatable. |
| `--stdin` | off | Read text from stdin and scan as a single buffer. |

## Rule selection

| Flag | Default | Description |
|---|---|---|
| `--rules FILE` | bundled | Override the bundled rule set with a custom YAML file. |
| `--rule-id ID ...` | all | Restrict to specific rule IDs. Repeatable. |
| `--disable-rule ID ...` | none | Disable specific rule IDs while keeping the rest active. Repeatable. |
| `--entropy-min FLOAT` | per-rule | Global Shannon-entropy floor applied to captured values. Overrides each rule's own `entropy_min`. |

## SAST scope control

| Flag | Default | Description |
|---|---|---|
| `--exclude GLOB ...` |. | Skip files matching glob. Repeatable. |
| `--exclude-dir DIR ...` | sensible defaults | Skip directory by name. Repeatable. |
| `--max-size SIZE` | `10M` | Skip files larger than this. Accepts raw bytes or a suffixed size (e.g. `10M`). |

## SAST: misconfiguration / vulnerability scanning

By default scan4secrets only detects secrets. These two flags turn on the source-code
vulnerability rules (SQLi, XSS, RCE, SSRF, path traversal, insecure crypto/TLS, and more).
Vulnerability rules are gated per file type, so they only run against files in a matching
language.

| Flag | Default | Description |
|---|---|---|
| `--misconfig` | off | ALSO scan source for vulnerabilities/misconfigurations alongside secret detection. |
| `--misconfig-only` | off | Scan ONLY for vulnerabilities/misconfigurations; skip secret detection entirely. |

```bash
# Secrets + source vulnerabilities in one pass
scan4secrets --path ./src --misconfig --report html --output reports/audit

# Vulnerability/misconfiguration audit only (no secret detection)
scan4secrets --path ./src --misconfig-only --report sarif --fail-on high --output reports/vulns
```

## DAST tuning

| Flag | Default | Description |
|---|---|---|
| `--threads N` | `16` | Concurrent crawler workers. |
| `--max-urls N` | `2000` | Cap total URLs visited per `--url` target. |
| `--max-depth N` | `3` | Cap crawl depth from each seed. |
| `--timeout SEC` | `15` | Per-request timeout. |
| `--strict-host` | off | Restrict scope to exact hostname (default = eTLD+1). |
| `--user-agent UA` | `scan4secrets/2 (+github.com/m14r41/scan4secrets)` | Override outbound UA. |
| `--no-sourcemaps` | off | Disable `.js.map` sourcesContent extraction during crawl. |
| `--no-js-endpoints` | off | Disable endpoint discovery from JavaScript assets. |
| `--wordlist FILE ...` | bundled | Replace bundled wordlists with custom file(s). |
| `--wordlist-only NAME ...` | all | Restrict to specific bundled stems. |
| `--no-wordlist` | off | Disable wordlist seeding entirely. |

## Authentication / proxy

| Flag | Default | Description |
|---|---|---|
| `--cookie COOKIE` |. | Send cookie header on every DAST request. |
| `--header K:V` |. | Add request header. Repeatable. |
| `--proxy URL` |. | Route DAST through proxy (Burp / ZAP compatible). |
| `--insecure` | off | Disable TLS certificate verification. |

## Verification

| Flag | Default | Description |
|---|---|---|
| `--verify` | off | Run live vendor probes on findings whose rule has a `verify:` block. |
| `--verify-timeout SEC` | `5` | Per-probe timeout. |

## Output

| Flag | Default | Description |
|---|---|---|
| `--output BASE` | `scan` | Output path base name (no extension). |
| `--report FMT ...` | `json` | One or more of: `sarif json jsonl csv html excel pdf`. |
| `--mask` | off | Redact secret values in output. Default: raw values are shown (paste-ready for vendor PoC). |

## Logging / CI

| Flag | Default | Description |
|---|---|---|
| `--quiet` | off | Suppress per-finding console output. |
| `--verbose` | off | Verbose progress logging. |
| `--debug` | off | Emit debug-level diagnostics. |
| `--no-color` | off | Disable ANSI color in console output. |
| `--keep-generic` | off | Keep generic catch-all findings even when a vendor-specific rule matched. |
| `--fail-on LEVEL` | none | Exit `1` if any finding meets or exceeds this severity (info / low / medium / high / critical). |

## Examples

### SAST a monorepo, fail CI on anything high or above

```bash
scan4secrets --path . --report sarif --fail-on high --output reports/scan
```

### Authenticated DAST through Burp, verify live tokens, full report

```bash
scan4secrets --url https://app.example.com \
  --cookie "session=$SESSION" --header "X-Tenant: acme" \
  --proxy http://127.0.0.1:8080 \
  --verify --report html sarif jsonl --output reports/audit
```

### Mixed SAST + DAST, restrict to specific rule IDs

```bash
scan4secrets --path ./src --url https://staging.example.com \
  --rule-id aws-access-key-id stripe-secret-live github-pat-classic \
  --report json --output reports/targeted
```

## Help

```bash
scan4secrets --help
```
