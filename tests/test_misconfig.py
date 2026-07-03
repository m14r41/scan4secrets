"""SAST vulnerability / misconfiguration engine (--misconfig): category gating,
language gating, taint-context gating, and rich metadata population."""

from scan4secrets.engine.rules import load_rules, KeywordIndex
from scan4secrets.engine.scanner import scan_text, SECRET_CATEGORIES

RULES = load_rules()
INDEX = KeywordIndex(RULES)
ALL = frozenset({None, "secret", "vuln"})
VULN_ONLY = frozenset({"vuln"})


def vuln_hits(text, source):
    return scan_text(text, source, RULES, INDEX, enabled_categories=ALL)


def ids(findings):
    return sorted(f.rule_id for f in findings)


# ---------- category gating ----------

def test_vuln_silent_without_flag():
    text = 'os.system("ping " + request.args.get("h"))'
    assert scan_text(text, "app.py", RULES, INDEX,
                     enabled_categories=SECRET_CATEGORIES) == []


def test_vuln_fires_with_flag():
    text = 'os.system("ping " + request.args.get("h"))'
    assert "py-command-injection" in ids(vuln_hits(text, "app.py"))


# ---------- true positives across languages ----------

def test_python_command_injection():
    text = 'subprocess.run("ls " + request.args.get("d"), shell=True)'
    assert "py-command-injection" in ids(vuln_hits(text, "app.py"))


def test_python_sql_injection():
    text = 'cursor.execute("SELECT * FROM u WHERE n = \'%s\'" % name)'
    assert "py-sql-injection" in ids(vuln_hits(text, "app.py"))


def test_node_command_injection():
    text = "cp.exec('cat ' + req.query.file);"
    assert "node-command-injection" in ids(vuln_hits(text, "server.js"))


def test_react_dangerous_innerhtml():
    text = "<div dangerouslySetInnerHTML={{ __html: html }} />"
    assert "react-dangerous-innerhtml" in ids(vuln_hits(text, "W.jsx"))


# ---------- language gating ----------

def test_python_rule_does_not_fire_on_js_file():
    text = 'os.system("ping " + request.args.get("h"))'
    assert "py-command-injection" not in ids(vuln_hits(text, "server.js"))


# ---------- taint-context gating (false positives) ----------

def test_command_with_literal_not_flagged():
    text = 'subprocess.run(["ping", "-c", "1", "8.8.8.8"])'
    assert "py-command-injection" not in ids(vuln_hits(text, "app.py"))


def test_requests_literal_url_not_ssrf():
    # "requests.get" must not trip the SSRF taint hint "request."
    text = 'requests.get("https://api.example.com", verify=True)'
    assert "py-ssrf" not in ids(vuln_hits(text, "app.py"))


def test_safe_yaml_load_not_flagged():
    text = "data = yaml.safe_load(stream)"
    assert "py-deserialization" not in ids(vuln_hits(text, "app.py"))


# ---------- rich metadata ----------

def test_finding_carries_report_metadata():
    text = "cp.exec('cat ' + req.query.file);"
    f = [x for x in vuln_hits(text, "server.js") if x.rule_id == "node-command-injection"][0]
    assert f.name and f.cwe and f.owasp and f.remediation
    assert f.secure_code and f.technical_impact and f.business_impact
    assert f.vulnerable_code


# ---------- extended multi-language coverage (mined from bughunting skills) ----------

def test_php_command_injection():
    text = 'system("ping " . $_GET["host"]);'
    assert "php-command-injection-shell" in ids(vuln_hits(text, "app.php"))


def test_php_lfi_include():
    text = 'include($_GET["page"] . ".php");'
    assert "php-lfi-dynamic-include" in ids(vuln_hits(text, "app.php"))


def test_ruby_marshal_deserialization():
    text = "data = Marshal.load(request.body.read)"
    assert "ruby-deserialization-marshal" in ids(vuln_hits(text, "app.rb"))


def test_java_objectinputstream_deserialization():
    text = "Object o = ois.readObject();"
    assert "java-deserialization-objectinputstream" in ids(vuln_hits(text, "App.java"))


def test_go_insecure_skip_verify():
    text = "tr := &tls.Config{InsecureSkipVerify: true}"
    assert "tls-go-insecure-skip-verify" in ids(vuln_hits(text, "main.go"))


def test_csharp_binaryformatter():
    text = "var bf = new BinaryFormatter();"
    assert "csharp-deserialization-binaryformatter" in ids(vuln_hits(text, "Api.cs"))


def test_terraform_public_s3():
    text = 'acl = "public-read"'
    assert "iac-tf-s3-public-acl" in ids(vuln_hits(text, "main.tf"))


def test_k8s_privileged_container():
    text = "        privileged: true"
    assert "iac-k8s-privileged-container" in ids(vuln_hits(text, "pod.yaml"))


def test_dockerfile_curl_pipe_shell():
    text = "RUN curl -fsSL https://x/i.sh | bash"
    assert "iac-docker-curl-pipe-shell" in ids(vuln_hits(text, "Dockerfile"))


def test_jwt_alg_none():
    text = 'const opts = { "alg": "none" };'
    assert "jwt-alg-none" in ids(vuln_hits(text, "auth.js"))


# ---------- FP regression: re.compile must not trip the eval rule ----------

def test_re_compile_not_flagged_as_eval():
    text = 'PATTERN = re.compile(r"<(" + name + r")>")'
    assert "py-code-injection-eval" not in ids(vuln_hits(text, "engine.py"))


def test_literal_eval_not_flagged():
    text = "value = ast.literal_eval(user_supplied)"
    assert "py-code-injection-eval" not in ids(vuln_hits(text, "app.py"))


# ---------- gap-fill: .NET / JSP / Kotlin / XML / WSDL ----------

def test_dotnet_request_validation_disabled():
    text = '<pages validateRequest="false"/>'
    assert "dotnet-request-validation-disabled" in ids(vuln_hits(text, "web.config"))


def test_dotnet_viewstate_mac_disabled():
    text = '<machineKey enableViewStateMac="false"/>'
    assert "dotnet-viewstate-mac-disabled" in ids(vuln_hits(text, "web.config"))


def test_wcf_security_mode_none():
    text = '<security mode="None"/>'
    assert "xml-wcf-security-mode-none" in ids(vuln_hits(text, "svc.config"))


def test_xml_inline_doctype_system_entity():
    text = '<!DOCTYPE foo SYSTEM "file:///etc/passwd">'
    assert "xml-inline-doctype-system-entity" in ids(vuln_hits(text, "data.xml"))


def test_jsp_scriptlet_xss():
    text = '<%= request.getParameter("q") %>'
    assert "jsp-xss-scriptlet-request" in ids(vuln_hits(text, "page.jsp"))


def test_kotlin_command_injection():
    text = 'Runtime.getRuntime().exec("sh -c " + intent.getStringExtra("cmd"))'
    assert "kotlin-command-injection-exec" in ids(vuln_hits(text, "Main.kt"))


def test_kotlin_android_webview_js_interface():
    text = 'webView.addJavascriptInterface(JsBridge(), "android")'
    assert "kotlin-android-webview-javascript-interface" in ids(vuln_hits(text, "Main.kt"))


def test_php_procedural_2arg_sqli():
    text = 'mysqli_query($conn, "SELECT * FROM u WHERE n=\'" . $_GET["n"] . "\'");'
    assert "php-sqli-procedural-2arg" in ids(vuln_hits(text, "legacy.php"))


def test_csharp_xmldocument_xxe():
    text = 'doc.LoadXml(Request.Form["xml"]);'
    assert "csharp-xxe-xmldocument-load" in ids(vuln_hits(text, "Svc.cs"))
