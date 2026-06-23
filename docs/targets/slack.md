---
id: slack
title: Slack
sidebar_label: Slack
description: scan4secrets coverage for Slack. Bot, user, app, configuration, and legacy tokens, plus incoming webhooks.
keywords: [slack secret scanner, slack token leak, slack webhook leak, xoxb token, scan4secrets slack]
---

# Slack

scan4secrets detects leaked **Slack tokens** of all five common types, plus **incoming webhooks** and **signing secrets**.

## Token formats

| Type | Prefix | Notes |
|---|---|---|
| **Bot token** | `xoxb-` | The most common production credential. Full bot scope. |
| **User token** | `xoxp-` | Impersonates the user; broadest power. |
| **App token** | `xapp-` | Socket-mode app-level token. |
| **Configuration token** | `xoxe.xoxp-` | Used for app manifest deploy. |
| **Legacy token** | `xoxs-` | Older workspace/admin tokens. |
| **Webhook URL** | `https://hooks.slack.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]{24}` | Posts as the integration. |
| **Signing secret** | hex 32 | Used to verify Slack-signed requests. |

## Detection rules

```yaml
- id: slack-bot-token
  description: Slack Bot Token (xoxb)
  severity: high
  keywords: ["xoxb-"]
  regex: '\b(xoxb-[0-9]{10,}-[0-9]{10,}-[A-Za-z0-9]{20,})\b'
  verify:
    method: POST
    url: https://slack.com/api/auth.test
    header_name: Authorization
    header_value: "Bearer {{value}}"
    success_status: 200

- id: slack-user-token
  description: Slack User Token (xoxp)
  severity: critical
  keywords: ["xoxp-"]
  regex: '\b(xoxp-[0-9]{10,}-[0-9]{10,}-[0-9]{10,}-[A-Za-z0-9]{20,})\b'

- id: slack-app-token
  description: Slack App-Level Token (xapp)
  severity: high
  keywords: ["xapp-"]
  regex: '\b(xapp-[0-9]+-[A-Z0-9]+-[0-9]+-[a-f0-9]+)\b'

- id: slack-webhook
  description: Slack Incoming Webhook URL
  severity: medium
  keywords: ["hooks.slack.com/services"]
  regex: '\b(https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]{20,})\b'

- id: slack-signing-secret
  description: Slack Signing Secret
  severity: high
  keywords: ["slack_signing_secret", "SLACK_SIGNING_SECRET"]
  regex: '(?i)slack[_\-]?signing[_\-]?secret[^A-Za-z0-9]{1,10}([a-f0-9]{32})\b'
```

## Live verification

Built-in for `xoxb`:

```http
POST /api/auth.test HTTP/1.1
Host: slack.com
Authorization: Bearer xoxb-...
```

The 200-body JSON reveals `team`, `user`, and `bot_id`. Capture for evidence. Slack's `auth.test` is the canonical idempotent probe; never use `chat.postMessage` for verification (writes to a channel).

## Impact when verified live

| Token | Worst-case impact |
|---|---|
| `xoxb-` | Read messages on channels bot is in, post as bot, list users/channels |
| `xoxp-` | Full user impersonation (read DMs, post anywhere, change settings) |
| `xapp-` | Socket-mode subscription, events delivery |
| Webhook | Post arbitrary content to one channel (phishing pretext) |
| Signing secret | Forge events the app trusts. Pivot to internal automation |

## Revocation

| Token | Action |
|---|---|
| Bot / user / app token | Slack admin → Apps → Manage → Revoke |
| Webhook URL | Slack admin → Apps → Incoming Webhooks → Delete configuration |
| Signing secret | App settings → Basic Information → Regenerate signing secret. Re-deploy verifiers. |

## Common leak surfaces scan4secrets catches

1. Frontend bundle `const SLACK_WEBHOOK = "https://hooks.slack.com/services/..."` (DAST + JS string-literal).
2. CI log echoing `xoxb-...` from `printenv` (JSONL pipeline → SIEM).
3. Mobile app `assets/config.json` shipping `xoxp-` token (SAST on apktool output).
4. `.env.production` in a public S3 bucket discovered via wordlist seeding (`/.env.production`).
5. Source map exposing pre-build `slack-config.ts` (only scan4secrets parses `.js.map`).
6. Misconfigured Notion / status page leaking the webhook URL in HTML (DAST body scan).

## References

- [Slack API · Tokens](https://api.slack.com/concepts/token-types)
- [Verifying requests · signing secret](https://api.slack.com/authentication/verifying-requests-from-slack)
