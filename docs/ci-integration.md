---
id: ci-integration
title: CI Integration
sidebar_position: 7
description: Wire scan4secrets into GitHub Actions, GitLab CI, Jenkins, and the pre-commit framework. SARIF upload, fail-on gates, scheduled scans.
keywords: [scan4secrets github actions, scan4secrets gitlab ci, scan4secrets pre-commit, SARIF GitHub code scanning, CI secret scanner]
---

# CI Integration

Wire scan4secrets into your pipeline. Three patterns: pre-commit, on-PR scan, scheduled DAST.

## pre-commit

`.pre-commit-hooks.yaml` ships in the repo. Add to your project:

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/m14r41/scan4secrets
    rev: v2.1.0
    hooks:
      - id: scan4secrets
```

Then:

```bash
pre-commit install
pre-commit run --all-files
```

## GitHub Actions. SAST + SARIF upload

```yaml
# .github/workflows/secrets.yml
name: Secret scan
on:
  push:
  pull_request:

jobs:
  scan:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with: { python-version: '3.12' }
      - run: pip install git+https://github.com/m14r41/scan4secrets
      - name: scan4secrets
        run: |
          scan4secrets --path . \
            --report sarif json \
            --fail-on high \
            --output reports/scan
      - name: Upload SARIF
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: reports/scan.sarif
      - name: Archive JSON
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: scan4secrets-report
          path: reports/
```

## GitHub Actions. Scheduled DAST on staging

```yaml
# .github/workflows/dast.yml
name: DAST secret sweep
on:
  schedule: [{ cron: '0 6 * * *' }]   # daily 06:00 UTC
  workflow_dispatch:

jobs:
  dast:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with: { python-version: '3.12' }
      - run: pip install git+https://github.com/m14r41/scan4secrets
      - name: Scan staging
        env:
          STAGING_COOKIE: ${{ secrets.STAGING_COOKIE }}
        run: |
          scan4secrets --url https://staging.example.com \
            --cookie "$STAGING_COOKIE" \
            --verify \
            --report html sarif jsonl \
            --fail-on medium \
            --output reports/dast
      - uses: actions/upload-artifact@v4
        if: always()
        with: { name: dast-report, path: reports/ }
```

## GitLab CI

```yaml
# .gitlab-ci.yml
secret-scan:
  image: python:3.12-slim
  stage: test
  script:
    - pip install git+https://github.com/m14r41/scan4secrets
    - scan4secrets --path . --report sarif json --fail-on high --output reports/scan
  artifacts:
    when: always
    paths: [ reports/ ]
    reports:
      sast: reports/scan.sarif
```

## Jenkins (declarative)

```groovy
pipeline {
  agent { docker { image 'python:3.12-slim' } }
  stages {
    stage('Scan') {
      steps {
        sh 'pip install git+https://github.com/m14r41/scan4secrets'
        sh 'scan4secrets --path . --report sarif json --fail-on high --output reports/scan'
      }
    }
  }
  post {
    always { archiveArtifacts artifacts: 'reports/**', allowEmptyArchive: true }
  }
}
```

## Docker in CI

```bash
docker run --rm -v "$PWD:/scan" ghcr.io/m14r41/scan4secrets:latest \
  --path /scan --report sarif --fail-on high --output /scan/reports/scan
```

## Exit-code semantics

| Flag | Exit `0` | Exit `1` |
|---|---|---|
| _none_ | Always | Never |
| `--fail-on info` | No findings | Any finding |
| `--fail-on low` | All findings < low | At least one ≥ low |
| `--fail-on medium` | All findings < medium | At least one ≥ medium |
| `--fail-on high` | All findings < high | At least one ≥ high (recommended for PR gates) |
| `--fail-on critical` | All findings < critical | At least one critical |

## Tips

- **Cache** the install: `pip install scan4secrets` is < 2s after first run on a warm runner.
- **Restrict on PR**: scan only the diff for speed. `git diff --name-only main...HEAD | xargs -I{} scan4secrets --path {} --report json`.
- **Don't `--verify` on third-party tokens you don't own**. See [Verification › Operational notes](./verification#operational-notes).
- **Redaction** is on by default. Reports are safe to upload to artifact stores. Use `--unsafe-show` only behind access control.
