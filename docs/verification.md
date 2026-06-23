---
id: verification
title: Live Verification
sidebar_position: 6
description: Turn "looks like a token" into "verified live credential" by probing the vendor's API. Built-in probes plus a cheat sheet for 20+ vendors.
keywords: [scan4secrets verify, live token verification, secret verification, vendor API probe, github token verify, stripe token verify]
---

# Live verification

> Turn "maybe a secret" into "verified live credential" by probing the vendor's API.

## What it does

When a rule has a `verify:` block AND the user passes `--verify`, scan4secrets sends one HTTP request per finding to confirm whether the captured token is still **live** at the vendor.

Each finding then carries one of three verification states:

| State | Meaning |
|---|---|
| `verified: true` | The vendor accepted the credential — this is a live incident. |
| `verified: false` | The vendor rejected the credential — format-only match, likely revoked or fake. |
| `verified: null` | No `verify:` block on the rule, or `--verify` not passed. Triage manually. |

A verified finding is **incident-grade evidence**. An unverified finding is a hypothesis that still needs human triage.

## Probe schema

```yaml
verify:
  method: GET                                  # GET | POST | HEAD
  url: https://api.vendor.com/check            # the probe endpoint
  header_name: Authorization                   # optional, header to send
  header_value: "Bearer {{value}}"             # optional, {{value}} substitutes the captured secret
  success_status: 200                          # status code that confirms validity
```

The probe should be:

- **Idempotent.** GET requests on read endpoints.
- **Side-effect-free.** Never write/delete data, never charge, never send email.
- **Cheap.** No expensive aggregation queries.
- **Distinct.** Endpoint that returns 200 only with a valid token (not just `/health`).
- **Fast.** Subject to the 5s `--verify-timeout` default.

## Built-in probes

| Rule | Method | Endpoint | Notes |
|---|---|---|---|
| `github-pat-classic`<br/>`github-pat-fine-grained` | GET | `https://api.github.com/user` | Returns 200 with `X-OAuth-Scopes` revealing scope |
| `slack-bot-token` | POST | `https://slack.com/api/auth.test` | Slack auth.test returns 200 on valid bot/user token |
| `stripe-secret-live` | GET | `https://api.stripe.com/v1/charges?limit=1` | List endpoint; cheap, no side effects |
| `openai-key` | GET | `https://api.openai.com/v1/models` | Returns 200 + model list on valid key |

## Adding a new vendor

Edit the rule in `scan4secrets/config/rules.yaml` and add a `verify:` block. For example, to verify Discord bot tokens:

```yaml
- id: discord-bot-token
  description: Discord Bot Token
  severity: high
  keywords: ["MT", "Nz", "Bot "]
  regex: '\b([MN][A-Za-z\d]{23}\.[\w\-]{6}\.[\w\-]{27})\b'
  verify:
    method: GET
    url: https://discord.com/api/v10/users/@me
    header_name: Authorization
    header_value: "Bot {{value}}"
    success_status: 200
```

Reload by re-running. No code change needed.

## Cheap probe cheatsheet

| Vendor | Probe |
|---|---|
| AWS | `sts:GetCallerIdentity` via SigV4 signing (requires `boto3`, not in default rule set) |
| GitHub | `GET https://api.github.com/user` + `Authorization: token X` |
| GitLab | `GET https://gitlab.com/api/v4/user` + `Authorization: Bearer X` |
| Bitbucket | `GET https://api.bitbucket.org/2.0/user` + `Authorization: Bearer X` |
| Slack | `POST https://slack.com/api/auth.test` + `Authorization: Bearer X` |
| Stripe | `GET https://api.stripe.com/v1/charges?limit=1` + `Authorization: Bearer X` |
| Twilio | `GET https://api.twilio.com/2010-04-01/Accounts.json` + Basic auth |
| SendGrid | `GET https://api.sendgrid.com/v3/scopes` + `Authorization: Bearer X` |
| Mailgun | `GET https://api.mailgun.net/v3/domains` + Basic auth |
| OpenAI | `GET https://api.openai.com/v1/models` + `Authorization: Bearer X` |
| Anthropic | `POST https://api.anthropic.com/v1/messages` (minimal payload) + `x-api-key: X` |
| Heroku | `GET https://api.heroku.com/account` + `Authorization: Bearer X` + Accept header |
| Datadog | `GET https://api.datadoghq.com/api/v1/validate` + `DD-API-KEY: X` |
| Cloudflare | `GET https://api.cloudflare.com/client/v4/user/tokens/verify` + `Authorization: Bearer X` |
| Discord (bot) | `GET https://discord.com/api/v10/users/@me` + `Authorization: Bot X` |
| Telegram (bot) | `GET https://api.telegram.org/bot{value}/getMe` (the token is in the URL itself) |
| DigitalOcean | `GET https://api.digitalocean.com/v2/account` + `Authorization: Bearer X` |
| NPM | `GET https://registry.npmjs.org/-/whoami` + `Authorization: Bearer X` |
| Docker Hub | `GET https://hub.docker.com/v2/user/` + `Authorization: Bearer X` |
| PyPI | (no read endpoint; cannot verify cheaply) |
| Linode | `GET https://api.linode.com/v4/profile` + `Authorization: Bearer X` |

## Operational notes

- **Rate limiting**: scan4secrets verifies up to 8 findings in parallel by default. If you're verifying hundreds of GitHub tokens in one run, GitHub will start returning 429. Lower with `--verify-timeout` adjustments or `--rule-id` filtering.
- **Outbound network policy**: verification makes outbound HTTPS calls to vendor APIs. In air-gapped CI, run without `--verify` and gate on findings count alone.
- **Don't verify against production tenants you don't own**. Verification is fine on your own credentials or in an authorized bug-bounty scope; verifying a leaked third-party credential without authorization may itself be unauthorized access.
- **Pre-revocation**: once a token verifies live, rotate it. Then revoke. Then push the fix.

## Why verification matters

In bug-bounty triage, "I found a string that looks like a token" is N/A-rate fuel. "I found a token, here's the HTTP response from the vendor confirming it grants `repo,user,workflow` scope" is a Critical with payout. The `--verify` flag is the difference between those two reports.
