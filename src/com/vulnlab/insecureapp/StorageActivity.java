package com.vulnlab.insecureapp;

import android.app.Activity;
import android.content.Context;
import android.content.SharedPreferences;
import android.os.Bundle;
import android.os.Environment;
import android.util.Log;
import android.widget.LinearLayout;
import android.widget.TextView;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;

/**
 * VULNERABILITY 11.6 — Insecure Data Storage
 *
 * Demonstrates several insecure storage patterns:
 *   1. Plaintext credentials in SharedPreferences
 *   2. Session token in SharedPreferences (world-readable on old APIs)
 *   3. Sensitive JSON written to external storage (readable by any app pre-API29)
 *   4. Private key material stored in plain files
 *   5. Sensitive data logged to Logcat
 *
 * Test:
 *   # Dump SharedPreferences (rooted device)
 *   adb shell su -c "cat /data/data/com.vulnlab.insecureapp/shared_prefs/vulnlab_prefs.xml"
 *
 *   # ADB backup (if app doesn't set allowBackup=false)
 *   adb backup -noapk -f vulnlab_backup.ab com.vulnlab.insecureapp
 *
 *   # Read external storage file (accessible pre-API 29 without root)
 *   adb shell cat /sdcard/Android/data/com.vulnlab.insecureapp/files/session.json
 */
public class StorageActivity extends Activity {

    private static final String TAG = "VulnLab:Storage";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        LinearLayout ll = new LinearLayout(this);
        ll.setOrientation(LinearLayout.VERTICAL);
        ll.setPadding(32, 32, 32, 32);

        StringBuilder report = new StringBuilder();
        report.append("StorageActivity\n\nVulnerability: Insecure Data Storage\n\n");

        // ── 1. SharedPreferences — plaintext credentials ──────────────────
        storeInSharedPreferences(report);

        // ── 2. External storage — world-readable JSON ─────────────────────
        storeOnExternalStorage(report);

        // ── 3. Internal file — private key stored in plaintext ────────────
        storePrivateKeyInFiles(report);

        // ── 4. Logcat leak ───────────────────────────────────────────────
        logSensitiveData(report);

        report.append("\nTest commands:\n" +
                "adb shell su -c \"cat /data/data/com.vulnlab.insecureapp/shared_prefs/vulnlab_prefs.xml\"\n" +
                "adb shell cat /sdcard/Android/data/com.vulnlab.insecureapp/files/session.json\n" +
                "adb logcat -s VulnLab:Storage\n" +
                "adb backup -noapk -f backup.ab com.vulnlab.insecureapp");

        TextView tv = new TextView(this);
        tv.setTextSize(11);
        tv.setText(report.toString());
        ll.addView(tv);
        setContentView(ll);
    }

    private void storeInSharedPreferences(StringBuilder report) {
        SharedPreferences prefs = getSharedPreferences(ConfigReceiver.PREFS_NAME, MODE_PRIVATE);
        SharedPreferences.Editor ed = prefs.edit();

        // VULNERABLE: plaintext credentials in SharedPreferences
        ed.putString("username", "admin");
        ed.putString("password", "Admin@123!");                        // plaintext password
        ed.putString("session_token", "eyJhbGciOiJIUzI1NiJ9.secret"); // JWT in plain prefs
        ed.putString("api_key", "sk-prod-HARDCODED-API-KEY-1234567890");
        ed.putString("api_server_url", "https://api.vulnlab.example.com");
        ed.apply();

        String path = getApplicationInfo().dataDir + "/shared_prefs/" + ConfigReceiver.PREFS_NAME + ".xml";
        report.append("[1] SharedPreferences (plaintext):\n    ").append(path).append("\n\n");
        Log.w(TAG, "Stored plaintext password in SharedPreferences");
    }

    private void storeOnExternalStorage(StringBuilder report) {
        // VULNERABLE: external storage readable by other apps (pre-Android 10)
        File extDir = getExternalFilesDir(null);
        if (extDir == null) {
            report.append("[2] External storage not available\n\n");
            return;
        }

        File sessionFile = new File(extDir, "session.json");
        try (FileWriter fw = new FileWriter(sessionFile)) {
            fw.write("{\n" +
                    "  \"username\": \"admin\",\n" +
                    "  \"session_token\": \"eyJhbGciOiJIUzI1NiJ9.secret\",\n" +
                    "  \"role\": \"admin\",\n" +
                    "  \"api_key\": \"sk-prod-HARDCODED-API-KEY-1234567890\"\n" +
                    "}");
            report.append("[2] External storage (world-readable pre-API29):\n    ")
                  .append(sessionFile.getAbsolutePath()).append("\n\n");
            Log.w(TAG, "Stored session JSON on external storage: " + sessionFile.getPath());
        } catch (IOException e) {
            report.append("[2] External storage write failed: ").append(e.getMessage()).append("\n\n");
        }
    }

    private void storePrivateKeyInFiles(StringBuilder report) {
        // VULNERABLE: private key stored as plaintext in internal files
        File keyFile = new File(getFilesDir(), "private_key.pem");
        try (FileWriter fw = new FileWriter(keyFile)) {
            fw.write("-----BEGIN PRIVATE KEY-----\n" +
                    "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7\n" +
                    "FAKE_PRIVATE_KEY_FOR_LAB_DO_NOT_USE_IN_PRODUCTION\n" +
                    "-----END PRIVATE KEY-----\n");
            report.append("[3] Internal files (private key in plaintext):\n    ")
                  .append(keyFile.getAbsolutePath()).append("\n\n");
            Log.w(TAG, "Stored private key in plaintext at: " + keyFile.getPath());
        } catch (IOException e) {
            report.append("[3] Internal files write failed: ").append(e.getMessage()).append("\n\n");
        }
    }

    private void logSensitiveData(StringBuilder report) {
        // VULNERABLE: sensitive data logged to Logcat (any app with READ_LOGS can read on old APIs)
        String password = "Admin@123!";
        String token = "eyJhbGciOiJIUzI1NiJ9.secret";

        Log.d(TAG, "User login: username=admin password=" + password);   // credential leak to logs
        Log.v(TAG, "Session established: token=" + token);               // token leak to logs
        Log.i(TAG, "API key loaded: sk-prod-HARDCODED-API-KEY-1234567890");

        report.append("[4] Logcat leak:\n    adb logcat -s VulnLab:Storage\n\n");
    }
}
