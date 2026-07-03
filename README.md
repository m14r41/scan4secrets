# scan4secrets

**DAST + SAST secret scanner with live verification, source-map parsing, and CI-native reporting — plus a SAST vulnerability & misconfiguration engine.**

Find leaked credentials in source trees, running web apps, and CI logs. Verify them live against vendor APIs. Scan the same source trees for code vulnerabilities and misconfigurations. Output SARIF for code-scanning dashboards, JSONL for SOAR pipelines, or Excel/PDF/HTML for client reports.

---

## Why scan4secrets

The crowded landscape (`gitleaks`, `trufflehog`, `detect-secrets`) is great at SAST on git trees but stops there — and they scan for secrets only. **scan4secrets fills the gaps they don't cover**, adding live web DAST, live vendor verification, and a code-vulnerability / misconfiguration engine on top of secret detection:

| Capability | gitleaks | trufflehog | detect-secrets | **scan4secrets** |
|---|:---:|:---:|:---:|:---:|
| SAST secret detection | Y | Y | Y | Y |
| **DAST live web crawl** | - | - | - | Y |
| **JS source-map parsing** | - | - | - | Y |
| **JS endpoint extraction** | - | - | - | Y |
| **HTTP-header secret scan** | - | - | - | Y |
| Live token verification | - | Y | - | Y |
| SARIF output | Y | - | - | Y |
| **Excel / PDF / HTML reports** | - | - | - | Y |
| Entropy gate + allowlist | Y | Y | Y | Y |
| YAML rules schema | - (TOML) | - | - | Y |
| Authenticated DAST (cookie/header/proxy) | n/a | n/a | n/a | Y |
| **SAST vulnerability / misconfiguration detection** | - | - | - | Y |

It is a **complement to gitleaks**, not a replacement. Use both: gitleaks in pre-commit + CI for git-history SAST, scan4secrets for live DAST against staging/production.

---

## Install

```bash
# from source
git clone https://github.com/m14r41/scan4secrets
cd scan4secrets
pip install -e .

# OR via pipx
pipx install git+https://github.com/m14r41/scan4secrets

# OR Docker
docker run --rm -v $(pwd):/scan ghcr.io/m14r41/scan4secrets:latest --path /scan
```

After install, the `scan4secrets` command is on your PATH.

---

## Quick start

```bash
# SAST: scan a local directory
scan4secrets --path /code

# DAST: crawl a live target
scan4secrets --url https://staging.example.com --threads 32

# DAST runs ALL bundled wordlists by default (1279 paths: /.env, /wp-config.php, /backup.zip, ...)
scan4secrets --url https://target.com

# Use YOUR OWN wordlist file (replaces the bundled set)
scan4secrets --url https://target.com --wordlist /path/to/my-paths.txt

# Combine multiple custom wordlist files
scan4secrets --url https://target.com --wordlist seclists/Common.txt internal-paths.txt

# Restrict to specific bundled wordlists by stem
scan4secrets --url https://wp.example.com --wordlist-only wordpress common env

# Turn wordlist seeding off entirely (only follow live links)
scan4secrets --url https://target.com --no-wordlist

# Full audit with verification + HTML report
scan4secrets --path . --url https://app.example.com \
    --verify --report html sarif json \
    --output reports/audit-$(date +%F)

# Authenticated DAST with proxy (works with Burp / ZAP)
scan4secrets --url https://app.example.com \
    --cookie "session=abc123" \
    --header "X-Tenant: acme" \
    --proxy http://127.0.0.1:8080

# CI gate (exit 1 if anything >= high)
scan4secrets --path . --report sarif --fail-on high \
    --output reports/scan

# SAST: secrets + code vulnerabilities / misconfigurations
scan4secrets --path ./src --misconfig

# SAST: vulnerabilities / misconfigurations only (skip secret detection)
scan4secrets --path ./src --misconfig-only
```

---

## Vulnerability & misconfiguration scanning (`--misconfig`)

Beyond secrets, scan4secrets ships a SAST engine for code vulnerabilities and misconfigurations. Add `--misconfig` to scan for both secrets and vulnerabilities, or `--misconfig-only` to scan for vulnerabilities alone:

```bash
scan4secrets --path ./src --misconfig                 # secrets + vulnerabilities
scan4secrets --path ./src --misconfig-only            # vulnerabilities only
scan4secrets --path . --misconfig --report html --output report
```

It detects — with taint/context gating to keep false positives low — SQL injection, NoSQL injection, OS command injection, code injection (eval), SSTI, XXE, insecure deserialization, LFI / path traversal, LDAP & XPath injection, SSRF, open redirect, CORS misconfig, CSRF-disabled, prototype pollution, XSS (reflected/stored/DOM across 11 templating engines: EJS, Handlebars, Pug, Jinja, Thymeleaf, Razor, Blade, ERB, Vue, Angular, React), weak crypto (DES/RC4/ECB/static-IV/weak-RSA), insecure randomness, JWT flaws (alg:none, algorithm confusion, hardcoded signing secret, verification disabled), TLS bypasses, timing-unsafe secret comparisons, SAML signature-not-required, hardcoded credentials, sensitive-data logging, and IaC/config misconfig (Terraform, Kubernetes, Dockerfile, GitHub Actions, ASP.NET web.config, WCF/SOAP).

Languages covered: python, node, javascript, typescript, react, php, ruby, go, java, kotlin, csharp/.NET, sql, plus XML/WSDL, JSP, Terraform/HCL, Kubernetes YAML, and Dockerfile.

Each vulnerability finding carries a rich record: **Vulnerability Name, Severity, Description, Evidence (file:line), Vulnerable Code, Secure Code, Remediation, Technical Impact, Business Impact, and CWE + OWASP Top-10 mapping.**

---

## Context-aware secret detection

Beyond the line-by-line engine, a whole-file pass catches secrets that line-scanners miss: nested XML tags (`<SMS_API_KEY><value>…</value></SMS_API_KEY>`), split `<key>`/`<value>` pairs, JSON key/value objects, multi-line YAML/properties, and Base64-encoded secrets. It also closes an entropy-gate blind spot — credential-named assignments (e.g. `AM_CLIENT_SECRET=…`) are flagged on the **name** signal with no entropy floor, so real low-entropy secrets are no longer silently dropped.

---

## What it detects

**416 rules total** — 193 secret rules + 223 vulnerability / misconfiguration rules.

Secret rules cover:

- **Cloud:** AWS, GCP, Azure, DigitalOcean, Heroku, Linode, Vultr, Hetzner, Alibaba, IBM Cloud, Oracle Cloud, Render, Vercel, Netlify, Fly.io
- **CDN / edge:** Cloudflare (API token + Origin CA), Fastly, Cloudinary, Akamai EdgeGrid, BunnyCDN
- **Source control:** GitHub (classic / fine-grained / OAuth / App / refresh / deploy key), GitLab, Bitbucket
- **CI/CD:** CircleCI, Travis, Buildkite, Jenkins, ArgoCD, Pulumi, Snyk, Doppler
- **Payments:** Stripe, Square, PayPal/Braintree, Razorpay, Plaid, Adyen, Paddle, LemonSqueezy, Coinbase, Binance
- **E-commerce:** Shopify (private app / shared secret / custom app / partner), WooCommerce REST
- **Messaging:** Slack (5 token types + webhook), Discord (bot + webhook), Twilio, Telegram, Microsoft Teams webhook, Zoom JWT, Vonage/Nexmo
- **SMS / carriers:** MessageBird, Plivo
- **AI/ML:** OpenAI, Anthropic, Hugging Face, Replicate, Cohere, Pinecone, Mistral, Groq, Perplexity, DeepL, AssemblyAI, ElevenLabs, Stability AI
- **Email / marketing:** SendGrid, Mailgun, Mailchimp, Postmark, Resend, Mailjet, Klaviyo, ConvertKit, Customer.io
- **Monitoring:** Datadog, Sentry (DSN + org-auth-token), New Relic, Grafana (service-account + Cloud), LaunchDarkly (SDK + mobile), Honeycomb, Rollbar, Bugsnag, Splunk HEC, PagerDuty
- **DevOps / registries:** Docker Hub, Docker registry auth, NPM, PyPI, RubyGems, crates.io, JFrog Artifactory, Terraform Cloud, HashiCorp Vault, HashiCorp Cloud
- **Auth / identity:** Auth0, Okta, Clerk, WorkOS, Stytch, Atlassian / Jira, Frontegg, Keycloak
- **Productivity SaaS:** Notion, Linear, Airtable, Asana, ClickUp, Typeform, Calendly, Zendesk, Intercom
- **Mobile / push:** Firebase Cloud Messaging, Expo, OneSignal, Microsoft AppCenter
- **Data / ML platforms:** Databricks, Snowflake, Algolia
- **Mapping:** Mapbox (pk / sk), HERE Maps
- **Blockchain / Web3:** Infura, Alchemy, Etherscan, WalletConnect, QuickNode
- **Storage:** Backblaze B2 (KeyID + appKey)
- **Networking / VPN:** Tailscale (auth + API)
- **QA / browser testing:** BrowserStack, Sauce Labs, Percy
- **Connection strings:** PostgreSQL, MySQL, MongoDB (incl. srv), Redis, AMQP
- **Webhooks:** Zapier, IFTTT, Meta / Facebook Graph
- **Auth tokens:** JWT, HTTP Basic in URLs
- **Crypto:** RSA / EC / OPENSSH / PGP private keys, SSH public keys, Cloudflare Origin CA, GitHub deploy keys
- **Recently added:** Slack app / user tokens, Dropbox, PlanetScale, PostHog, Supabase, Figma, GitLab runner / pipeline-trigger tokens, Stripe test keys, Google OAuth refresh tokens, Twitch, ngrok
- **Contextual fallbacks:** quoted/unquoted high-entropy strings, hex tokens, UUIDs near credential names

See [docs/rules-engine.md](docs/rules-engine.md) for the full reference and how to add custom rules.

---

## Live verification

With `--verify`, scan4secrets makes one HTTP request per detected token to the vendor API to confirm whether the credential is still **live**:

| Rule | Probe | Success |
|---|---|---|
| `github-pat-classic` / `github-pat-fine-grained` | `GET https://api.github.com/user` | HTTP 200 |
| `stripe-secret-live` | `GET https://api.stripe.com/v1/charges?limit=1` | HTTP 200 |
| `slack-bot-token` | `POST https://slack.com/api/auth.test` | HTTP 200 |
| `openai-key` | `GET https://api.openai.com/v1/models` | HTTP 200 |

Each finding gets `verified=true|false|null` in every output format. A verified token is incident-grade evidence; an unverified one is a hypothesis.

See [docs/verification.md](docs/verification.md) for the full vendor list and how to add probes.

---

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
| `html` | Collapsible, expandable finding cards for client review |
| `excel` | Pivot tables and exec summaries |
| `pdf` | Compliance evidence packets |

The `html` report renders each finding as an expandable card — the summary shows severity + name + file:line + CWE, and expanding reveals the full record including vulnerable/secure code, remediation, and impacts. It ships with a filter box, severity/file/name sort, expand/collapse-all, is theme-aware, and is fully self-contained. JSON/CSV/SARIF/Excel/PDF carry all fields.

Secrets are shown **in full by default** so reports are paste-ready for vendor PoC. Pass `--mask` to redact to `abcd****wxyz` for screenshots or shared transcripts.

---

## DAST details

The crawler:

1. Honors **scope** (same eTLD+1 by default; `--strict-host` for exact host)
2. Runs **concurrently** (`--threads N`, default 16)
3. Sends a custom **User-Agent**, optional **headers**, **cookies**, and routes through your **proxy** (Burp / ZAP friendly)
4. Parses **`.js.map`** files and scans every embedded source (catches secrets hidden inside production source maps that no SAST sees)
5. Extracts **string-literal endpoints** from `.js` files and probes them
6. Scans **response headers** as well as body
7. **Path-guess wordlists are ON by default** — every DAST run seeds 1279 sensitive paths (`.env`, `.git/config`, `wp-config.php`, `phpinfo.php`, `backup.zip`, `composer.json`, source maps, admin panels, API docs, ...). Restrict with `--wordlist-only NAME ...` or disable with `--no-wordlist`.
8. Caps at `--max-urls` and `--max-depth` so you can't accidentally DoS a target

Wordlists are stack-specific: `common`, `env`, `wordpress`, `php-laravel-symfony-drupal`, `Python-Django-Flask`, `Node.js-Express-JS`, `React-Next.js-Vite-Frontend`, `Docker-Compose-Kubernetes`, `CloudProvider-Service`, `Keys-SSH-Certificate`, `OtherConfig-CI-DevOps`, `backup-files`, `admin-panels`, `api-paths`, `database-dumps`. Use `--wordlist-only NAME ...` to restrict to specific stems.

---

## CI / pre-commit

`.pre-commit-hooks.yaml` is shipped:

```yaml
repos:
  - repo: https://github.com/m14r41/scan4secrets
    rev: v2.1.0
    hooks:
      - id: scan4secrets
```

GitHub Actions:

```yaml
- uses: actions/checkout@v4
- run: pip install scan4secrets
- run: scan4secrets --path . --report sarif --output results --fail-on high
- uses: github/codeql-action/upload-sarif@v3
  if: always()
  with: { sarif_file: results.sarif }
```

---

## Documentation

- [docs/architecture.md](docs/architecture.md) — package layout, data flow, extension points
- [docs/rules-engine.md](docs/rules-engine.md) — rule schema, examples, writing custom rules
- [docs/verification.md](docs/verification.md) — how live verification works, adding new vendors
- [docs/changelog.md](docs/changelog.md) — what's new in v2 vs v1
- [docs/gap-analysis.md](docs/gap-analysis.md) — empirical comparison vs v1 and gitleaks

---

## Benchmark

Tested on [Plazmaz/leaky-repo](https://github.com/Plazmaz/leaky-repo) (seeded with real-format secrets) and on [expressjs/express](https://github.com/expressjs/express) (clean OSS code).

| Tool | leaky-repo (TPs found) | benign express (FPs) |
|---|---:|---:|
| scan4secrets v1 | 35 (~22 TPs, ~13 FPs) | **27** |
| gitleaks | 22 | 0 |
| **scan4secrets v2** | **23** (all TPs, incl. SSH/PEM/Docker keys v1 missed) | **0** |

v2 has 0% FP rate on benign code (vs v1's ~13% per-file rate) and captures the high-value secret classes (private keys, Docker registry auth) that v1 was structurally incapable of detecting.

---

## Contributing

- Add a rule: edit `scan4secrets/config/rules.yaml`
- Add a verifier: extend the `verify:` block in the rule
- Add a reporter: drop a module under `scan4secrets/reporters/` and register in `__init__.py`

Run tests: `pytest -q` (planted-secret fixtures under `tests/fixtures/`)

---

## License

MIT — see [LICENSE](LICENSE).

Built by [@M14R41](https://github.com/m14r41).
