---
id: google-cloud
title: Google Cloud (GCP)
sidebar_label: Google Cloud
description: scan4secrets coverage for Google Cloud. API keys, OAuth client secrets, service-account JSON, gcloud credentials.
keywords: [gcp secret scanner, google cloud api key leak, gcp service account json, oauth client secret, scan4secrets gcp]
---

# Google Cloud (GCP)

scan4secrets detects leaked **GCP API keys**, **OAuth 2.0 client credentials**, and **service-account JSON** keys.

## Token formats

| Credential | Shape | Notes |
|---|---|---|
| **API key** | `AIza[A-Za-z0-9_-]{35}` | 39 chars total. Used for Maps, Translate, YouTube, Firebase, …. |
| **OAuth 2.0 client ID** | `[0-9]+-[a-z0-9]{32}\.apps\.googleusercontent\.com` | Public by design. Only flagged as `info`. |
| **OAuth 2.0 client secret** | `GOCSPX-[A-Za-z0-9_-]{28}` | NEVER public. Critical. |
| **Service-account JSON** | `"type":\s*"service_account"` + `"private_key":\s*"-----BEGIN ` | Full PEM block. Critical. |
| **gcloud access token** | `ya29.[A-Za-z0-9_-]{60,}` | Short-lived; still high if active. |
| **Refresh token** | `1//[A-Za-z0-9_-]{40,}` | Long-lived. Critical. |

## Detection rules

```yaml
- id: gcp-api-key
  description: Google Cloud API Key (AIza prefix)
  severity: high
  keywords: ["AIza"]
  regex: '\b(AIza[A-Za-z0-9_-]{35})\b'

- id: gcp-oauth-client-secret
  description: Google OAuth 2.0 Client Secret (GOCSPX prefix)
  severity: critical
  keywords: ["GOCSPX-"]
  regex: '\b(GOCSPX-[A-Za-z0-9_-]{28})\b'

- id: gcp-service-account-json
  description: GCP Service Account JSON private key block
  severity: critical
  keywords: ['"type": "service_account"', '"private_key"']
  regex: '("private_key":\s*"-----BEGIN [A-Z ]+PRIVATE KEY-----[^"]+-----END [A-Z ]+PRIVATE KEY-----[\\n]?")'
```

## Live verification

```yaml
# API key
verify:
  method: GET
  url: https://www.googleapis.com/discovery/v1/apis?key={{value}}
  success_status: 200

# OAuth client secret (no cheap probe. must perform full OAuth dance)
# Service-account JSON: parse → sign JWT → POST to oauth2/v4/token
# (see verifier.py extensions for vendor-specific helpers)
```

## Impact when verified live

| Credential | Worst-case impact |
|---|---|
| **API key** (Maps / Translate / YouTube) | Quota abuse, billing run-up; some APIs allow read of project metadata |
| **API key** (Firebase) | Read/write to Realtime Database / Firestore if rules are permissive |
| **OAuth client secret** | Mint user tokens via PKCE bypass on misconfigured apps |
| **Service-account JSON** | Full IAM-scoped access to the project. Usually game over |
| **Refresh token** | Mint new access tokens until revoked |

## Revocation

| Credential | Action |
|---|---|
| API key | Console → APIs & Services → Credentials → Delete / regenerate. Restrict by referrer/IP next time. |
| OAuth client secret | Console → Credentials → OAuth 2.0 → Reset Secret. |
| Service-account JSON | Console → IAM & Admin → Service Accounts → Keys → Delete. Then revoke any caches. |
| Refresh token | Revoke via `https://oauth2.googleapis.com/revoke?token={value}` |

## Common leak surfaces scan4secrets catches

1. Frontend bundle: `const MAPS_KEY = "AIza..."`. Caught by DAST crawler + JS parser.
2. Source map: original `firebase.config.ts` with both API key and DB URL exposed in `.js.map` sourcesContent.
3. Public GitHub repo with `service-account.json` committed → SAST + entropy gate catches.
4. CI logs accidentally echoing `$GCP_SA_KEY` → JSONL output to SIEM.
5. Misconfigured S3/GCS bucket serving `.env.production` over HTTP → DAST wordlist seeding (`/.env`).

## References

- [Google Cloud · API key restrictions](https://cloud.google.com/docs/authentication/api-keys)
- [Service account credential best practices](https://cloud.google.com/iam/docs/best-practices-for-managing-service-account-keys)
