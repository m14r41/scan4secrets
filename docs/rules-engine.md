---
id: rules-engine
title: Rules Engine
sidebar_position: 5
description: scan4secrets rule schema, examples, allowlists, entropy gates, and recipes for writing custom detection rules in YAML.
keywords: [scan4secrets rules, custom rules, YAML rules, regex secret detection, entropy gate, allowlist]
---

# Rules

> Schema, examples, and recipes for writing scan4secrets detection rules.

## Schema

A rule is a YAML mapping with these fields:

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

## Built-in rule index (170+)

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
