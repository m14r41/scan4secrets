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
| `--rules FILE` | bundled | Override the bundled `rules.yaml` with a custom YAML file. |
| `--rule-id ID ...` | all | Restrict to specific rule IDs. Repeatable. |
| `--severity LEVEL` | `info` | Minimum severity to include (info / low / medium / high / critical). |

## SAST scope control

| Flag | Default | Description |
|---|---|---|
| `--exclude GLOB ...` |. | Skip files matching glob. Repeatable. |
| `--exclude-dir DIR ...` | sensible defaults | Skip directory by name. Repeatable. |
| `--max-size MB` | `10` | Skip files larger than this. |
| `--no-binary-skip` | off | Disable NUL-byte binary skip heuristic. |

## DAST tuning

| Flag | Default | Description |
|---|---|---|
| `--threads N` | `16` | Concurrent crawler workers. |
| `--max-urls N` | `2000` | Cap total URLs visited per `--url` target. |
| `--max-depth N` | `3` | Cap crawl depth from each seed. |
| `--timeout SEC` | `15` | Per-request timeout. |
| `--strict-host` | off | Restrict scope to exact hostname (default = eTLD+1). |
| `--user-agent UA` | `scan4secrets/2 (+github.com/m14r41/scan4secrets)` | Override outbound UA. |
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
| `--verify-workers N` | `8` | Concurrent verifier workers. |

## Output

| Flag | Default | Description |
|---|---|---|
| `--output PREFIX` | `scan` | Output path prefix (no extension). |
| `--report FMT ...` | `json` | One or more of: `sarif json jsonl csv html excel pdf`. |
| `--unsafe-show` | off | Include raw secret values in reports (otherwise redacted). |
| `--keep-generic` | off | Keep generic catch-all findings even when a vendor-specific rule matched. |
| `--quiet` | off | Suppress per-finding console output. |
| `--verbose` | off | Verbose progress logging. |

## Exit-code gate

| Flag | Default | Description |
|---|---|---|
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
