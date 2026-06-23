---
id: aws
title: Amazon Web Services (AWS)
sidebar_label: AWS
description: scan4secrets coverage for AWS. IAM access keys, session tokens, MWS tokens, STS credentials. Detection rules, verification probe, revocation.
keywords: [aws secret scanner, aws access key leak, aws iam credentials, sts session token, scan4secrets aws]
---

# Amazon Web Services (AWS)

scan4secrets detects leaked **AWS IAM access keys**, **secret access keys**, **STS session tokens**, and **MWS tokens**.

## Token formats

| Credential | Shape | Length |
|---|---|---|
| **Access key ID** | `AKIA[0-9A-Z]{16}` (long-term) · `ASIA[0-9A-Z]{16}` (STS) | 20 chars |
| **Secret access key** | `[A-Za-z0-9/+=]{40}` | 40 chars |
| **Session token** | base64-like, `~300+` chars | Variable |
| **MWS auth token** | `amzn\.mws\.[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}` | 47 chars |

## Detection rules

```yaml
- id: aws-access-key-id
  description: AWS IAM Access Key ID
  severity: high
  keywords: ["AKIA", "ASIA"]
  regex: '\b((?:AKIA|ASIA)[0-9A-Z]{16})\b'

- id: aws-secret-access-key
  description: AWS Secret Access Key (contextual. paired with access key or AWS_SECRET name)
  severity: critical
  keywords: ["aws_secret_access_key", "AWS_SECRET_ACCESS_KEY"]
  regex: '(?i)aws[_\-]?secret[_\-]?access[_\-]?key[^A-Za-z0-9]{1,10}([A-Za-z0-9/+=]{40})'
  entropy_min: 4.5

- id: aws-mws-token
  description: Amazon MWS Auth Token
  severity: high
  keywords: ["amzn.mws"]
  regex: '\b(amzn\.mws\.[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})\b'
```

## Live verification

AWS requires SigV4 signing for any call. There's no static "Bearer" probe. The recommended verifier:

```python
import boto3
sts = boto3.client(
    'sts',
    aws_access_key_id=finding.secret,           # if AKIA finding
    aws_secret_access_key=paired_secret_or_None,
)
identity = sts.get_caller_identity()            # 200 = valid, ClientError = invalid
```

Run only when authorized. STS `GetCallerIdentity` is the standard idempotent probe.

## Impact when verified live

| Credential pair | Worst-case impact |
|---|---|
| AKIA + secret key | Whatever IAM policy that user/role has. Often broad |
| ASIA + secret + session | Same as the assumed role |
| MWS token | Amazon Marketplace seller actions (refunds, order data, listings) |

A single `AKIA` access key with `*:*` IAM policy = full account takeover.

## Revocation

| Credential | Action |
|---|---|
| Access key | IAM Console → Users → Security Credentials → **Delete access key** (immediately) |
| Session token | Cannot be revoked. Expires when the original role's session ends. Revoke the parent role. |
| MWS token | Seller Central → User Permissions → Revoke MWS access |

After revocation, audit CloudTrail for use of the leaked credential between `KeyCreate` and `KeyDelete` events.

## Common leak surfaces scan4secrets catches

1. `.env` file in repo: `AWS_ACCESS_KEY_ID=AKIA...` (SAST).
2. CI log echoing access key (JSONL → SIEM).
3. Mobile app `strings.xml` (mobile reverse engineering output → SAST).
4. JS bundle with hard-coded `AWS.config.update({accessKeyId: ...})` (DAST + JS parser).
5. Source map exposing pre-build `aws-config.ts` (`.js.map` sourcesContent. Unique to scan4secrets).
6. Server header `Server: AmazonS3` paired with a `X-Amz-...` debug header leak (response-header scan).

## References

- [IAM access key best practices](https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html#use-temp-creds)
- [Audit access keys with CloudTrail](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference.html)
