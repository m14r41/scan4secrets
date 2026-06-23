---
id: facebook
title: Meta / Facebook
sidebar_label: Meta / Facebook
description: scan4secrets coverage for Meta / Facebook Graph API tokens. Formats, detection rule, live-verification probe, revocation guide.
keywords: [facebook secret scanner, meta graph api token, facebook app secret leak, facebook access token detection, scan4secrets facebook]
---

# Meta / Facebook

scan4secrets detects leaked Meta / Facebook **Graph API access tokens**, **app secrets**, and **OAuth client credentials**.

## Token formats

| Token | Shape | Length | Where it leaks |
|---|---|---|---|
| **User / page / app access token (v1)** | `[A-Za-z0-9]+\|[A-Za-z0-9_-]+` | ~150 chars | Mobile SDK, frontend bundles, server logs |
| **App access token (v2 short)** | `[0-9]+\|[A-Za-z0-9_-]+` | ~50–80 chars | Server config, env vars |
| **EAAB / EAAG long-lived** | `EAA[A-Za-z0-9_-]{20,}` | 80–250 chars | JS bundles, source maps, mobile apps |
| **App secret** | `[a-f0-9]{32}` | 32 chars | Backend config, env vars |
| **Facebook Graph webhook URL** | `https://graph.facebook.com/.../?access_token=...` | n/a | JS, mobile apk strings |

## Detection rule

```yaml
- id: facebook-access-token
  description: Meta / Facebook Graph API access token
  severity: high
  keywords: ["EAA", "facebook", "graph.facebook.com"]
  regex: '\b(EAA[A-Za-z0-9_-]{20,})\b'
  entropy_min: 3.5
```

```yaml
- id: facebook-app-secret
  description: Facebook App Secret (server-side only)
  severity: critical
  keywords: ["facebook", "app_secret", "FB_APP_SECRET", "client_secret"]
  regex: '(?i)(?:facebook|fb)[_\-]?(?:app[_\-]?)?secret[^A-Za-z0-9]{1,10}([a-f0-9]{32})\b'
  allowlist:
    regex:
      - 'example'
      - 'changeme'
      - '<.+>'
```

## Live verification

Facebook's Graph API exposes a debug-token endpoint that returns `200` with metadata on a valid token:

```yaml
verify:
  method: GET
  url: https://graph.facebook.com/debug_token?input_token={{value}}&access_token={{value}}
  success_status: 200
```

Caveat: `debug_token` echoes the token to the network. It's fine on tokens you own; **do not run** `--verify` against third-party tokens without explicit authorization.

## Impact when verified live

| Token type | Worst-case impact |
|---|---|
| User access token | Read user profile, friends, posts; act on behalf of user (scope-dependent) |
| Page access token | Post / delete on the page, read DMs, access page insights |
| App access token | Manage subscriptions, read aggregated app data |
| App secret | Forge user access tokens, sign API calls server-side, exchange short for long-lived |
| Long-lived EAA token | All of user/page access for ~60 days, often without re-prompt |

## Revocation

| If leaked | Action |
|---|---|
| Access token | Rotate the user/page session; revoke via `DELETE /me/permissions` on Graph |
| App secret | **Reset immediately** in [App Dashboard → Settings → Basic → App Secret](https://developers.facebook.com/apps/). Re-deploy all backends that use it. |
| Webhook with embedded token | Rotate webhook secret in App Dashboard → Webhooks |

## Common leak surfaces scan4secrets catches

1. JS bundle: `const FB_TOKEN = "EAAB..."`. Picked up by DAST crawler + SAST.
2. Source map: a `.js.map` `sourcesContent` exposing the original `const FB_APP_SECRET = "..."`. Only scan4secrets parses source maps.
3. Mobile bundle decompile (`apktool`): `strings/strings.xml` containing a hard-coded EAA token.
4. Public S3 bucket: `.env.production` with `FB_APP_SECRET=...`.
5. HTTP header: `X-FB-Access-Token: EAAB...` on a misconfigured proxy. Only scan4secrets reads response headers.

## Related rules

- [`oauth2-client-secret`](../rules-engine). Generic OAuth 2.0 client secret detection
- [`jwt-token`](../rules-engine). Meta-issued JWTs in OAuth flows

## References

- [Meta Graph API · Debug Token](https://developers.facebook.com/docs/graph-api/securing-requests)
- [App Secret · best practices](https://developers.facebook.com/docs/facebook-login/security)
