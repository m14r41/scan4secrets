# sample-app — scan4secrets demo fixture

A tiny, deliberately-insecure multi-language application used to demonstrate what
scan4secrets detects. **Every value here is a fake placeholder** — none of the
"secrets" authenticate, and the credential-named values are generic on purpose so
they don't trip GitHub push-protection.

Scan it yourself:

```bash
# secrets only (default)
scan4secrets --path examples/sample-app

# secrets + vulnerabilities/misconfigurations
scan4secrets --path examples/sample-app --misconfig --report html --output report
```

## What's planted

| File | Demonstrates |
|------|--------------|
| `.env` | generic credential-named secrets (name-signal detection); `AM_REDIRECT_URI` / `LOG_LEVEL` are decoys that must **not** be flagged |
| `config/services.xml` | context-aware / structural detection — a secret in a nested `<SMS_API_KEY><value>…</value>` tag and a split `<key>`/`<value>` pair |
| `src/app.py` | Python: command injection, SQL injection, SSRF, disabled TLS, path traversal, weak hash (+ safe variants that must not flag) |
| `src/server.js` | Node: reflected XSS, SQL injection, command injection, open redirect |
| `src/Widget.jsx` | React: `dangerouslySetInnerHTML` XSS |
| `src/Main.kt` | Kotlin/Android: command injection, WebView `addJavascriptInterface` |
| `web.config` | ASP.NET misconfig: `debug="true"`, `customErrors="Off"`, `validateRequest="false"` |
| `Dockerfile` | remote script piped to a shell (`curl … | bash`) |

The generated reports (all formats) live under `website/static/reports/` and are
published at **/docs/sample-report**. Regenerate them with
`examples/generate-sample-reports.sh`.
