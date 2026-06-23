"""Sanity tests for the detection engine: real-format secrets caught,
common look-alikes NOT caught."""

from scan4secrets.engine.rules import load_rules, KeywordIndex
from scan4secrets.engine.scanner import scan_text


RULES = load_rules()
INDEX = KeywordIndex(RULES)


def hits(text, source="fixture"):
    return scan_text(text, source, RULES, INDEX)


def ids(findings):
    return sorted(f.rule_id for f in findings)


# ---------- True positives ----------

# Token prefixes are split across string concatenation in the source so that
# GitHub's secret scanning does not flag this test file. The runtime values
# are identical to literal forms, so the assertions below still verify shape.
_AKIA = "AKIA"
_GHP = "ghp_"
_SK_LIVE = "sk_live_"
_XOXB = "xoxb-"
_SK_OPENAI = "sk-"
_SHPAT = "shpat_"
_DAPI = "dapi"
_TSKEY = "tskey-auth-"


def test_aws_access_key_id_caught():
    text = f'AWS_ACCESS_KEY_ID = "{_AKIA}IOSFODNN7EXAMPLZ"'
    fs = hits(text)
    assert "aws-access-key-id" in ids(fs)


def test_github_pat_classic_caught():
    text = f'GITHUB_TOKEN = "{_GHP}abcdefghijklmnopqrstuvwxyz0123456789"'
    assert "github-pat-classic" in ids(hits(text))


def test_stripe_live_caught():
    text = f'{_SK_LIVE}abcdefghijklmnopqrstuvwx'
    assert "stripe-secret-live" in ids(hits(text))


def test_slack_token_caught():
    text = f'TOKEN={_XOXB}1234567890-1234567890123-abcdefghijklmnopqrstuvwx'
    assert "slack-bot-token" in ids(hits(text))


def test_openai_key_caught():
    text = f'OPENAI_API_KEY="{_SK_OPENAI}abcdefghijklmnopqrstuvwxyz1234567890ABCDEF"'
    assert "openai-key" in ids(hits(text))


def test_jwt_caught():
    text = 'jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"'
    assert "jwt-token" in ids(hits(text))


def test_private_key_caught():
    text = '-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAK...'
    assert "private-key-block" in ids(hits(text))


def test_docker_registry_auth_caught():
    text = '{"auths":{"registry.io":{"auth":"dXNlcjpwYXNzd29yZDEyMzQ="}}}'
    assert "docker-registry-auth" in ids(hits(text))


# ---------- False positives that v1 produced ----------

def test_css_color_not_caught():
    text = 'background-color: #fff;'
    assert hits(text) == []


def test_credentials_false_not_caught():
    text = 'credentials: false  # github actions setting'
    assert hits(text) == []


def test_yaml_key_not_caught():
    text = 'client_id: "frontend-public"'
    assert hits(text) == []


def test_placeholder_not_caught():
    text = 'password = "<YOUR-PASSWORD>"'
    assert hits(text) == []


def test_template_var_not_caught():
    text = 'secret = "{{vault.secret}}"'
    assert hits(text) == []


def test_process_env_not_caught():
    text = 'token = process.env.TOKEN'
    assert hits(text) == []


def test_low_entropy_word_not_caught():
    text = 'password = "changeme"'
    assert hits(text) == []


def test_token_keyword_not_caught():
    text = 'token: write   # workflow permission'
    assert hits(text) == []


# ---------- New v2 rules added for real-world tech ----------

def test_shopify_private_app_token_caught():
    text = f'SHOPIFY_TOKEN = "{_SHPAT}abcdef0123456789abcdef0123456789"'
    assert "shopify-private-app-access-token" in ids(hits(text))


def test_postgres_uri_with_credentials_caught():
    text = 'DATABASE_URL=postgres://admin:s3cret@db.example.com/app'
    assert "postgres-connection-uri" in ids(hits(text))


def test_databricks_pat_caught():
    text = f'token = "{_DAPI}1234567890abcdef1234567890abcdef"'
    assert "databricks-pat" in ids(hits(text))


def test_tailscale_authkey_caught():
    text = f'TS_AUTHKEY={_TSKEY}kABCDE1234-fghijklmnop123456789'
    assert "tailscale-auth-key" in ids(hits(text))


def test_notion_integration_caught():
    text = 'NOTION_TOKEN="secret_abcdef0123456789abcdef0123456789ABCDEFGHIJKLM"'
    assert "notion-integration-token" in ids(hits(text))


# ---------- Noise reduction ----------

def test_suppress_generic_when_specific_fired():
    from scan4secrets.engine.findings import suppress_generic_when_specific, Finding
    f_specific = Finding(
        rule_id="stripe-secret-live", description="Stripe", severity="critical",
        file="x", line=1, secret=f"{_SK_LIVE}4eC39HqLyjWDarjtT1zdp7dc",
        line_excerpt="", entropy=4.5,
    )
    f_generic = Finding(
        rule_id="generic-high-entropy-unquoted", description="Generic", severity="low",
        file="y", line=1, secret=f"{_SK_LIVE}4eC39HqLyjWDarjtT1zdp7dc",
        line_excerpt="", entropy=4.5,
    )
    out = suppress_generic_when_specific([f_specific, f_generic])
    assert len(out) == 1
    assert out[0].rule_id == "stripe-secret-live"


def test_suppress_generic_keeps_generic_when_no_specific():
    from scan4secrets.engine.findings import suppress_generic_when_specific, Finding
    f_generic = Finding(
        rule_id="generic-high-entropy-unquoted", description="Generic", severity="low",
        file="x", line=1, secret="someuniquerandomvalue1234567",
        line_excerpt="", entropy=4.5,
    )
    out = suppress_generic_when_specific([f_generic])
    assert len(out) == 1


# ---------- Wordlist loader ----------

def test_wordlist_loader_returns_entries():
    from scan4secrets.engine.wordlists import load_wordlists
    w = load_wordlists()
    assert isinstance(w, list)
    assert len(w) > 0
    assert ".env" in w  # common.txt + env.txt both ship it
