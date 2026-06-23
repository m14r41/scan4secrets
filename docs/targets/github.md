---
id: github
title: GitHub
sidebar_label: GitHub
description: scan4secrets coverage for GitHub. Classic and fine-grained PATs, OAuth tokens, App tokens, refresh tokens, deploy keys.
keywords: [github secret scanner, github pat leak, github oauth token, github app token, github fine-grained pat, scan4secrets github]
---

# GitHub

scan4secrets detects leaked **GitHub PATs (classic and fine-grained)**, **OAuth tokens**, **App installation tokens**, **refresh tokens**, and **deploy keys**.

## Token formats

| Token type | Prefix | Shape |
|---|---|---|
| **Classic PAT** | `ghp_` | `ghp_[A-Za-z0-9]{36}` |
| **Fine-grained PAT** | `github_pat_` | `github_pat_[A-Za-z0-9_]{82}` |
| **OAuth token** | `gho_` | `gho_[A-Za-z0-9]{36}` |
| **App installation token** | `ghs_` | `ghs_[A-Za-z0-9]{36}` |
| **App user-to-server token** | `ghu_` | `ghu_[A-Za-z0-9]{36}` |
| **Refresh token** | `ghr_` | `ghr_[A-Za-z0-9]{36}` |
| **Deploy key (private)** | n/a | `-----BEGIN OPENSSH PRIVATE KEY-----` block |

## Detection rules

```yaml
- id: github-pat-classic
  description: GitHub Personal Access Token (Classic)
  severity: critical
  keywords: ["ghp_"]
  regex: '\b(ghp_[A-Za-z0-9]{36})\b'
  verify:
    method: GET
    url: https://api.github.com/user
    header_name: Authorization
    header_value: "token {{value}}"
    success_status: 200

- id: github-pat-fine-grained
  description: GitHub Fine-Grained Personal Access Token
  severity: critical
  keywords: ["github_pat_"]
  regex: '\b(github_pat_[A-Za-z0-9_]{82})\b'
  verify:
    method: GET
    url: https://api.github.com/user
    header_name: Authorization
    header_value: "Bearer {{value}}"
    success_status: 200

- id: github-oauth
  description: GitHub OAuth Token
  severity: high
  keywords: ["gho_"]
  regex: '\b(gho_[A-Za-z0-9]{36})\b'

- id: github-app-token
  description: GitHub App Installation Token (server-to-server)
  severity: high
  keywords: ["ghs_"]
  regex: '\b(ghs_[A-Za-z0-9]{36})\b'

- id: github-refresh-token
  description: GitHub OAuth Refresh Token
  severity: high
  keywords: ["ghr_"]
  regex: '\b(ghr_[A-Za-z0-9]{36})\b'
```

## Live verification

Built-in. `--verify` issues:

```http
GET /user HTTP/1.1
Host: api.github.com
Authorization: token ghp_xxx
```

The response `X-OAuth-Scopes` header reveals exactly what the token grants. Capture this and quote it verbatim in any bug-bounty report. Example: `X-OAuth-Scopes: repo, workflow, admin:org` = full RCE on hosted runners.

## Impact when verified live

| Token + scopes | Worst-case impact |
|---|---|
| `ghp_…` + `repo` | Read/write all private repos the user can see |
| `ghp_…` + `repo, workflow` | Trigger / inject malicious workflows → secret exfil, RCE on runners |
| `ghp_…` + `admin:org` | Add/remove org members, settings, transfer repos |
| `github_pat_…` (FGPAT) | Limited to declared repos and resources. Still high if it touches secrets |
| `ghs_…` (App install) | Whatever the App's permission set allows |
| Deploy key (write) | Push to one repo without going through CI |

## Revocation

| Token | Action |
|---|---|
| Classic PAT | Settings → Developer settings → Personal access tokens (classic) → Delete |
| Fine-grained PAT | Settings → Developer settings → Personal access tokens → Fine-grained → Revoke |
| OAuth | Settings → Applications → Authorized OAuth Apps → Revoke |
| App installation | Org / repo Settings → Installations → Suspend |

After revocation, audit the org **Audit Log** and any affected repos' Actions runs for use between issue and revocation.

## Common leak surfaces scan4secrets catches

1. `.env`, `.env.local`, `.env.production` committed (SAST).
2. `package.json`'s `scripts` calling `curl -H "Authorization: token ${TOKEN}"` with the token inline (SAST).
3. `~/.gitconfig`, `~/.config/gh/hosts.yml` mistakenly bundled into a Docker image.
4. Public Gist with a forgotten PAT (DAST against a Gist URL).
5. CI log echo: `echo "Token: $TOKEN"` (JSONL into SIEM).
6. Source-map of internal admin SPA leaking a build-time GitHub access token (only scan4secrets parses `.js.map`).

## References

- [GitHub token formats](https://github.blog/2021-04-05-behind-githubs-new-authentication-token-formats/)
- [Fine-grained PAT scopes](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/managing-your-personal-access-tokens)
