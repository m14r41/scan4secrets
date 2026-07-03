fun setup(intent: Intent, webView: WebView) {
    Runtime.getRuntime().exec("sh -c " + intent.getStringExtra("cmd"))  // cmd injection (CWE-78)
    webView.addJavascriptInterface(JsBridge(), "android")               // Android JS bridge (CWE-749)
    webView.settings.javaScriptEnabled = true
}
