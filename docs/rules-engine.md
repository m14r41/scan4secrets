---
id: rules-engine
title: Rules Engine
sidebar_position: 5
description: scan4secrets rule schema, examples, allowlists, entropy gates, and recipes for writing custom detection rules in YAML.
keywords: [scan4secrets rules, custom rules, YAML rules, regex secret detection, entropy gate, allowlist]
---

# Rules

> Schema, examples, and recipes for writing scan4secrets detection rules.

## Rule files and counts

scan4secrets ships **416 rules total = 193 secret rules + 223 vulnerability/misconfiguration
rules**, split across two YAML files that `load_rules()` auto-merges into a single active set:

| File | Contents | Category |
|---|---|---|
| `scan4secrets/config/rules.yaml` | 193 secret-detection rules | (default) |
| `scan4secrets/config/vulns.yaml` | 223 source-vulnerability / misconfiguration rules | `category: vuln` |

Secret rules run on every scan. Vulnerability rules are opt-in: `--misconfig` adds the `vuln`
category to the active rule set (secrets **and** vulnerabilities), and `--misconfig-only` runs
the vulnerability rules alone. Vulnerability rules also carry a `languages` gate, so they only
execute against files of a matching type (see [Per-language gating](#per-language-gating)).

## Secret rule schema

A secret rule is a YAML mapping with these fields:

```yaml
- id: <unique-slug>            # required, used as the ruleId in SARIF
  description: <human text>    # required
  severity: <level>            # one of: info | low | medium | high | critical
  keywords:                    # list of substrings; if ANY appears in the line, the regex runs
    - kw1
    - kw2
  regex: <python regex>        # required; first capturing group is the secret value
  entropy_min: <float>         # optional, default 0.0 — Shannon entropy floor on the captured value
  allowlist:                   # optional — skip when matched
    regex:                     # regex(es) tested against the FULL line
      - example
      - placeholder
    paths:                     # gitignore-style globs tested against the file path
      - "**/test_*"
      - "**/*.md"
  verify:                      # optional — live verification (see Verification page)
    method: GET
    url: https://api.vendor.com/me
    header_name: Authorization
    header_value: "Bearer {{value}}"
    success_status: 200
```

## Vulnerability rule schema

A vulnerability rule (in `vulns.yaml`) reuses every secret-rule field above (`id`,
`description`, `severity`, `keywords`, `regex`, `entropy_min`, `allowlist`) and adds the
fields below. It is marked with `category: vuln`.

```yaml
- id: <unique-slug>
  category: vuln               # marks this as a vulnerability/misconfig rule
  name: <short vuln name>      # human-facing vulnerability name
  description: <human text>
  severity: <level>
  languages:                   # file-type gate — rule only runs on matching languages
    - python
  context_required:            # taint hints — at least ONE must appear on the line
    - request.                 # keeps false positives low
    - input(
  keywords:
    - execute
  regex: <python regex>
  cwe: CWE-89                  # CWE identifier
  owasp: "A03:2021-Injection"  # OWASP mapping
  remediation: <how to fix>
  secure_code: <safe example>  # rendered as "Secure Code" in reports
  technical_impact: <text>
  business_impact: <text>
```

`languages` values: `python`, `node` / `javascript` / `typescript`, `react`, `php`, `ruby`,
`go`, `java`, `kotlin`, `csharp`, `sql`, `xml` (incl. WSDL), `jsp` (java+html), `terraform`,
`kubernetes` yaml, `dockerfile`. `context_required` is a list of taint hints; at least one
must appear on the line for the rule to fire, which is what keeps vulnerability precision high.

Every vulnerability finding carries: Vulnerability Name, Severity, Description, Evidence
(`file:line`), Vulnerable Code, Secure Code, Remediation, Technical Impact, Business Impact,
CWE, and OWASP mapping.

## Severity guide

| Level | When to use |
|---|---|
| `critical` | Live credential, full account control or PII access (private keys, root tokens, Stripe live secret) |
| `high` | API key with broad scope or write access (GitHub PAT, AWS access key) |
| `medium` | Scoped or limited token (Twilio account SID, Datadog API key, JWT) |
| `low` | Generic high-entropy values, contextual matches that need triage |
| `info` | Public-by-design things you still want to surface (Stripe publishable key, Sentry DSN) |

## How matching works

For each line of input (file or HTTP response):

1. Aho-Corasick matches all rule keywords against the line.
2. For every rule with at least one keyword hit (or no keywords declared), the engine runs `rule.regex.finditer(line)`.
3. For each match, the first capturing group is the candidate secret. Shannon entropy is calculated.
4. If `entropy(value) < entropy_min`, the match is dropped.
5. If any `allowlist.regex` matches the full line, dropped.
6. If the file path matches any `allowlist.paths` glob, dropped.
7. Otherwise the match becomes a `Finding`.

This means **keywords are a fast pre-filter, not the matching logic**. The actual detection is the regex + entropy + allowlist combination.

## Structural pass (whole-file)

The line-based engine above sees one physical line at a time, so it misses secrets that are
split across lines. On top of it, `scan4secrets/engine/structural.py` (function
`scan_structural`) runs a whole-file **structural pass** that correlates key→value across
lines to catch what the line engine cannot:

- nested XML tags,
- split `<key>` / `<value>` pairs,
- JSON key/value objects,
- multi-line YAML / `.properties`,
- Base64-decoded secrets.

A cross-pass de-dup step reconciles the line-based and structural results so the same secret
is never reported twice.

## Per-language gating

Vulnerability rules run only against files of a matching language. `scan4secrets/engine/scanner.py`
maps file extensions to language tags (`lang_of` / `_EXT_LANG`), so python rules only run on
`.py`, kotlin on `.kt`, csharp on `.cs`, xml on `.xml`/`.config`/`.wsdl`, and so on. A rule's
`languages` field is matched against that tag before its regex ever runs. `--misconfig` adds
the `vuln` category to the active set; `--misconfig-only` restricts the run to vulnerability
rules only. Secret rules are not language-gated and always run.

## Recipes

### 1. Vendor token with a fixed prefix

The easiest, highest-precision pattern. Use the prefix as the keyword.

```yaml
- id: stripe-secret-live
  description: Stripe Live Secret Key
  severity: critical
  keywords: ["sk_live_"]
  regex: '\b(sk_live_[A-Za-z0-9]{24,})\b'
```

### 2. Contextual secret (value shape is generic)

Use a keyword that constrains where the regex will fire, then a stricter regex with entropy floor.

```yaml
- id: heroku-api-key
  description: Heroku API Key
  severity: high
  keywords: ["heroku"]
  regex: '(?i)heroku[^A-Za-z0-9]{1,10}([0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12})'
```

### 3. Multi-line / block format

Source maps and PEM blocks are awkward because they span lines. Match a single anchor line:

```yaml
- id: private-key-block
  description: Private key (RSA / EC / OPENSSH / PGP / DSA)
  severity: critical
  keywords: ["BEGIN ", "PRIVATE KEY"]
  regex: '(-----BEGIN ((?:RSA|EC|OPENSSH|PGP|DSA|ENCRYPTED) )?PRIVATE KEY-----)'
```

### 4. Suppressing fixture / docs / test paths

```yaml
allowlist:
  paths:
    - "**/test_*"
    - "**/tests/**"
    - "**/*.example"
    - "**/*.sample"
    - "**/fixtures/**"
    - "**/*.md"
```

### 5. Suppressing common placeholder values

```yaml
allowlist:
  regex:
    - 'changeme'
    - 'example'
    - 'placeholder'
    - 'your[_\-]?(?:api[_\-]?key|token|secret|password)'
    - '<[^>]*>'        # <YOUR-KEY-HERE>
    - '\{\{[^}]*\}\}'  # {{template_var}}
    - '\$\{[^}]+\}'    # ${env_var}
    - 'process\.env\.' # process.env.SECRET
```

### 6. Writing a vulnerability rule

Vulnerability rules live in `vulns.yaml` and add the source-audit fields. Gate the rule to the
languages it applies to and require a taint hint so it only fires on tainted lines.

```yaml
- id: py-sql-injection-fstring
  category: vuln
  name: SQL Injection via f-string
  description: SQL query built with an f-string containing untrusted input
  severity: high
  languages: ["python"]
  context_required: ["request.", "input(", "sys.argv"]
  keywords: ["execute", "executemany"]
  regex: '\.execute(?:many)?\(\s*f["'']'
  cwe: CWE-89
  owasp: "A03:2021-Injection"
  remediation: Use parameterized queries; pass user data as bind parameters, never string-interpolated.
  secure_code: 'cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))'
  technical_impact: Attacker can read, modify, or destroy database contents.
  business_impact: Data breach, data loss, and regulatory exposure.
```

## YAML gotchas

- **Single-quoted strings** only allow `''` as an escape (for a literal `'`). They do NOT honor `\'` or `\n`. If your regex contains a `'`, use a double-quoted YAML string and escape backslashes: `regex: "[^'\\s]+"`.
- **Backslashes**: in single-quoted YAML, `\` is literal. In double-quoted YAML, `\\` is needed for a literal backslash.
- **Anchors with `\b`**: Python regex `\b` is word boundary, fine in both quote styles. Just stay consistent.

## Testing a rule

Drop a file under `tests/fixtures/` containing a planted instance of the secret (use a clearly-fake but realistic value). Then add a pytest case that asserts your rule fires once. Then add a paired negative-fixture asserting the rule does NOT fire on a common look-alike.

```python
def test_my_rule_fires():
    findings = scan_text(open("tests/fixtures/my_secret.txt").read(),
                         "fixture", [my_rule], KeywordIndex([my_rule]))
    assert len(findings) == 1
    assert findings[0].rule_id == "my-rule"

def test_my_rule_no_fp_on_lookalike():
    findings = scan_text(open("tests/fixtures/my_lookalike.txt").read(),
                         "fixture", [my_rule], KeywordIndex([my_rule]))
    assert findings == []
```

## Built-in rule index

The bundled set is **416 rules — 193 secret rules (`rules.yaml`) + 223 vulnerability /
misconfiguration rules (`vulns.yaml`)**. A representative sample of the secret rules:

Cloud: aws-access-key-id, aws-secret-access-key, aws-mws-token, gcp-api-key, gcp-oauth-client, gcp-service-account-json, azure-storage-account-key, azure-sas-token, digitalocean-pat, heroku-api-key.

Source control: github-pat-classic, github-pat-fine-grained, github-oauth, github-app-token, github-refresh-token, gitlab-pat, bitbucket-app-password.

Payments: stripe-secret-live, stripe-restricted-live, stripe-publishable-live, square-token, paypal-braintree-token.

Messaging: slack-bot-token, slack-webhook, discord-bot-token, discord-webhook, telegram-bot-token, twilio-account-sid, twilio-api-key.

AI/ML: openai-key, anthropic-key, huggingface-token, replicate-token.

Email/SaaS: sendgrid-key, mailgun-key, mailchimp-key, postmark-key.

Monitoring: datadog-api-key, sentry-dsn, new-relic-key.

Infra/DevOps: docker-registry-auth, dockerhub-pat, npm-token, pypi-token, terraform-cloud-token, vault-token.

Auth: jwt-token, basic-auth-url.

Crypto: private-key-block, ssh-pub-key-comment, pgp-private-key.

Contextual catch-alls: contextual-hex-token, contextual-uuid-secret, generic-high-entropy-quoted, generic-high-entropy-unquoted.

The 223 vulnerability rules (`--misconfig`) span these languages (approximate rule counts —
a rule may target several languages, so these sum to more than 223): node 62, java 52, php 42,
csharp 38, python 37, html 27, react 14, xml 14, ruby 12, go 11, kotlin 11, yaml 7, terraform 5,
dockerfile 2, sql 1.
