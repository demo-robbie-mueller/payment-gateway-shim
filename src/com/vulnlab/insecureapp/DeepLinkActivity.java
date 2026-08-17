package com.vulnlab.insecureapp;

import android.app.Activity;
import android.content.Intent;
import android.net.Uri;
import android.os.Bundle;
import android.util.Log;
import android.webkit.WebView;
import android.webkit.WebViewClient;
import android.widget.LinearLayout;
import android.widget.TextView;
import android.widget.Toast;

/**
 * VULNERABILITY 11.4 — Deep Link & URL Scheme Attacks
 *
 * This Activity handles three deep-link patterns, all vulnerable:
 *
 * 1. Open redirect — redirect param passed directly to WebView.loadUrl()
 * 2. OAuth token theft — auth code logged and passed unsanitized
 * 3. Parameter injection — token used without validation
 *
 * Tests:
 *   # Open redirect + XSS via redirect param
 *   adb shell am start -a android.intent.action.VIEW \
 *       -d "vulnlab://app/reset?token=STOLEN&redirect=javascript:alert(1)"
 *
 *   # Trigger OAuth callback deep link (simulates attacker app stealing code)
 *   adb shell am start -a android.intent.action.VIEW \
 *       -d "vulnlab://oauth/callback?code=STOLEN_AUTH_CODE&state=xyz"
 *
 *   # App Link without autoVerify — any app can intercept
 *   adb shell am start -a android.intent.action.VIEW \
 *       -d "https://vulnlab.example.com/reset?token=EVIL_TOKEN"
 */
public class DeepLinkActivity extends Activity {

    private static final String TAG = "VulnLab:DeepLink";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        LinearLayout ll = new LinearLayout(this);
        ll.setOrientation(LinearLayout.VERTICAL);
        ll.setPadding(32, 32, 32, 32);

        Intent intent = getIntent();
        Uri data = intent.getData();

        TextView tv = new TextView(this);
        tv.setText("DeepLinkActivity\n\nVulnerability: Deep Link Parameter Injection\n\n");
        ll.addView(tv);

        if (data != null) {
            handleDeepLink(ll, data);
        } else {
            TextView info = new TextView(this);
            info.setText("No deep link received.\n\nTest via adb:\n" +
                    "adb shell am start -a android.intent.action.VIEW \\\n" +
                    "  -d 'vulnlab://app/reset?token=STOLEN&redirect=javascript:alert(1)'");
            ll.addView(info);
        }

        setContentView(ll);
    }

    private void handleDeepLink(LinearLayout ll, Uri data) {
        String host = data.getHost();
        String path = data.getPath();
        Log.d(TAG, "Deep link received: " + data.toString());

        TextView info = new TextView(this);
        info.setText("Received deep link:\n" + data.toString() + "\n\nHost: " + host + "\nPath: " + path + "\n\n");
        ll.addView(info);

        // OAuth callback path
        if ("oauth".equals(host) && "/callback".equals(path)) {
            handleOAuthCallback(ll, data);
            return;
        }

        // Password reset or generic deep link
        String token = data.getQueryParameter("token");
        String redirect = data.getQueryParameter("redirect");

        // VULNERABLE: token logged in plaintext
        Log.w(TAG, "Reset token from deep link: " + token);

        if (token != null) {
            // VULNERABLE: token used without validation (length, format, binding to session)
            processPasswordReset(ll, token);
        }

        if (redirect != null) {
            // VULNERABLE: attacker-controlled URL loaded directly into WebView
            // Allows open redirect and JavaScript injection (javascript: URI)
            Log.w(TAG, "Loading redirect URL from deep link parameter: " + redirect);
            loadInWebView(ll, redirect);
        }
    }

    private void handleOAuthCallback(LinearLayout ll, Uri data) {
        // VULNERABLE: OAuth authorization code logged and processed without state validation
        String code = data.getQueryParameter("code");
        String state = data.getQueryParameter("state");

        // Token logging vulnerability
        Log.w(TAG, "OAuth callback — code=" + code + " state=" + state);
        Toast.makeText(this, "OAuth code received: " + code, Toast.LENGTH_LONG).show();

        // No state parameter validation — CSRF possible
        // No app link verification — any app with vulnlab:// scheme intercepts this

        TextView tv = new TextView(this);
        tv.setText("OAuth Callback received!\n" +
                "code=" + code + "\n" +
                "state=" + state + "\n\n" +
                "Vulnerability: No state validation, no App Link verification.\n" +
                "Any app declaring vulnlab://oauth/callback intercepts the code.");
        ll.addView(tv);
    }

    private void processPasswordReset(LinearLayout ll, String token) {
        // VULNERABLE: token used without expiry, binding, or format validation
        Log.w(TAG, "Processing password reset with token: " + token);
        TextView tv = new TextView(this);
        tv.setText("Processing reset for token: " + token + "\n(No validation performed)");
        ll.addView(tv);
    }

    private void loadInWebView(LinearLayout ll, String url) {
        WebView wv = new WebView(this);
        wv.getSettings().setJavaScriptEnabled(true);
        wv.setWebViewClient(new WebViewClient());
        // VULNERABLE: attacker-controlled URL, no whitelist check
        wv.loadUrl(url);
        ll.addView(wv);
    }
}
