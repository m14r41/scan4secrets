"""Context-aware / structural secret detection: multi-line, nested XML,
split key/value, JSON, YAML, and Base64-encoded secrets."""

from scan4secrets.engine.structural import scan_structural


def ids(findings):
    return sorted(f.rule_id for f in findings)


def values(findings):
    return sorted(f.secret for f in findings)


# ---------- True positives ----------

def test_xml_nested_value_tag_caught():
    text = "<SMS_API_KEY>\n    <value>xyz23kdt3uij3430x</value>\n</SMS_API_KEY>"
    f = scan_structural(text, "config.xml")
    assert "structural-xml-credential-tag" in ids(f)
    assert "xyz23kdt3uij3430x" in values(f)


def test_xml_split_key_value_caught():
    text = "<key>SMS_API_KEY</key>\n<value>abc99zzt3uij3430q</value>"
    f = scan_structural(text, "config.xml")
    assert "structural-split-key-value" in ids(f)
    assert "abc99zzt3uij3430q" in values(f)


def test_xml_direct_credential_tag_caught():
    text = "<DB_PASSWORD>Sup3rP@ssw0rdDB</DB_PASSWORD>"
    f = scan_structural(text, "config.xml")
    assert "Sup3rP@ssw0rdDB" in values(f)


def test_json_split_key_value_caught():
    text = '{ "key": "STRIPE_SECRET_KEY", "value": "9x7Qe0veryrealtoken123" }'
    f = scan_structural(text, "config.json")
    assert "structural-json-key-value" in ids(f)


def test_yaml_multiline_credential_caught():
    text = "sms.api.key:\n  value: xyz23kdt3uij3430x\n"
    f = scan_structural(text, "app.yaml")
    assert "structural-multiline-credential" in ids(f)


def test_base64_encoded_secret_caught():
    # base64 of "password=Sup3rS3cret123"
    text = 'config_blob = "cGFzc3dvcmQ9U3VwM3JTM2NyZXQxMjM="'
    f = scan_structural(text, "blob.conf")
    assert "structural-base64-secret" in ids(f)


# ---------- False positives ----------

def test_email_in_attributevalue_not_caught():
    text = "<AttributeValue>john.doe@example.com</AttributeValue>"
    assert scan_structural(text, "saml.xml") == []


def test_url_value_not_caught():
    text = "<endpoint_url>https://api.example.com/sms</endpoint_url>"
    assert scan_structural(text, "config.xml") == []


def test_plain_base64_word_not_caught():
    # base64 of "helloworldfoobar" — no credential signal
    text = 'random_id = "aGVsbG93b3JsZGZvb2Jhcg=="'
    assert scan_structural(text, "app.conf") == []


def test_non_credential_tag_not_caught():
    text = "<timeout>30</timeout>\n<log_level>debug</log_level>"
    assert scan_structural(text, "config.xml") == []
