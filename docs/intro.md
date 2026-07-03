---
id: intro
title: Introduction
slug: /intro
sidebar_position: 1
description: scan4secrets is a DAST + SAST secret scanner with live verification, source-map parsing, and CI-native reporting, plus a SAST vulnerability and misconfiguration engine. Find leaked credentials and code vulnerabilities in source trees, running web apps, and CI logs.
keywords: [scan4secrets, secret scanner, DAST, SAST, leaked credentials, secrets detection, vulnerability scanner, misconfiguration scanner, gitleaks alternative, trufflehog alternative]
---

# scan4secrets

**DAST + SAST secret scanner with live verification, source-map parsing, and CI-native reporting — plus a SAST vulnerability & misconfiguration engine.**

Find leaked credentials in source trees, running web apps, and CI logs. Verify them live against vendor APIs. Scan the same source trees for code vulnerabilities and misconfigurations. Output SARIF for code-scanning dashboards, JSONL for SOAR pipelines, or Excel/PDF/HTML for client reports.

## Why scan4secrets

The crowded landscape (`gitleaks`, `trufflehog`, `detect-secrets`) is great at SAST on git trees but stops there — and they scan for secrets only. **scan4secrets fills the gaps they don't cover**, adding live web DAST, live vendor verification, and a code-vulnerability / misconfiguration engine on top of secret detection.

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

It is a **complement to gitleaks**, not a replacement. Use both. Gitleaks runs in pre-commit and CI for git-history SAST. Scan4secrets runs as live DAST against staging or production.

## Vulnerabilities & misconfigurations

Beyond secrets, scan4secrets ships a SAST engine for code vulnerabilities and misconfigurations. Add `--misconfig` to scan for both secrets and vulnerabilities, or `--misconfig-only` to scan for vulnerabilities alone:

```bash
scan4secrets --path ./src --misconfig                 # secrets + vulnerabilities
scan4secrets --path ./src --misconfig-only            # vulnerabilities only
```

It detects — with taint/context gating to keep false positives low — SQL/NoSQL/OS-command/code injection, SSTI, XXE, insecure deserialization, LFI / path traversal, LDAP & XPath injection, SSRF, open redirect, CORS misconfig, CSRF-disabled, prototype pollution, XSS (across 11 templating engines), weak crypto, insecure randomness, JWT flaws, TLS bypasses, timing-unsafe comparisons, SAML signature-not-required, hardcoded credentials, sensitive-data logging, and IaC/config misconfig (Terraform, Kubernetes, Dockerfile, GitHub Actions, ASP.NET web.config, WCF/SOAP). Each finding carries a rich record: name, severity, description, evidence (file:line), vulnerable code, secure code, remediation, technical & business impact, and CWE + OWASP Top-10 mapping.

## What it detects

**416 rules total** — 193 secret rules + 223 vulnerability / misconfiguration rules.

Secret rules cover:

- **Cloud:** AWS, GCP, Azure, DigitalOcean, Heroku, Linode, Vultr, Hetzner, Alibaba, IBM Cloud, Oracle Cloud, Render, Vercel, Netlify, Fly.io
- **CDN / edge:** Cloudflare (API token + Origin CA), Fastly, Cloudinary, Akamai EdgeGrid, BunnyCDN
- **Source control:** GitHub (classic / fine-grained / OAuth / App / refresh / deploy key), GitLab, Bitbucket
- **CI/CD:** CircleCI, Travis, Buildkite, Jenkins, ArgoCD, Pulumi, Snyk, Doppler
- **Payments:** Stripe, Square, PayPal/Braintree, Razorpay, Plaid, Adyen, Paddle, LemonSqueezy, Coinbase, Binance
- **Messaging:** Slack (5 token types + webhook), Discord (bot + webhook), Twilio, Telegram, Microsoft Teams webhook, Zoom JWT, Vonage/Nexmo
- **AI/ML:** OpenAI, Anthropic, Hugging Face, Replicate, Cohere, Pinecone, Mistral, Groq, Perplexity, DeepL, AssemblyAI, ElevenLabs, Stability AI
- **Email / marketing:** SendGrid, Mailgun, Mailchimp, Postmark, Resend, Mailjet, Klaviyo, ConvertKit, Customer.io
- **Monitoring:** Datadog, Sentry, New Relic, Grafana, LaunchDarkly, Honeycomb, Rollbar, Bugsnag, Splunk HEC, PagerDuty
- **DevOps / registries:** Docker Hub, Docker registry auth, NPM, PyPI, RubyGems, crates.io, JFrog Artifactory, Terraform Cloud, HashiCorp Vault
- **Crypto:** RSA / EC / OPENSSH / PGP private keys, SSH public keys, Cloudflare Origin CA, GitHub deploy keys
- **Recently added:** Slack app / user tokens, Dropbox, PlanetScale, PostHog, Supabase, Figma, GitLab runner / pipeline-trigger tokens, Stripe test keys, Google OAuth refresh tokens, Twitch, ngrok

Plus context-aware, structural detection — a whole-file pass catches secrets in nested XML tags, split `<key>`/`<value>` pairs, JSON key/value objects, multi-line YAML/properties, and Base64-encoded values, and flags credential-named assignments (e.g. `AM_CLIENT_SECRET=…`) on the name signal with no entropy floor so low-entropy secrets are not silently dropped.

See the [Rules Engine](./rules-engine) page for the full reference and how to add custom rules.

## Next steps

- Install and run your first scan: [Getting Started](./getting-started)
- CLI flags reference: [CLI Reference](./cli-reference)
- Wire into your pipeline: [CI Integration](./ci-integration)
- Live verification probes: [Verification](./verification)
- Architecture deep-dive: [Architecture](./architecture)
