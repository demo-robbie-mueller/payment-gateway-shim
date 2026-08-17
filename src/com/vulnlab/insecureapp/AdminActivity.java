package com.vulnlab.insecureapp;

import android.app.Activity;
import android.content.Intent;
import android.os.Bundle;
import android.util.Log;
import android.widget.LinearLayout;
import android.widget.TextView;

/**
 * VULNERABILITY 11.1 — Component Exposure & Insecure IPC
 *
 * This Activity is exported with no permission check.
 * Any app or adb command can invoke it and trigger admin actions.
 *
 * Test:
 *   adb shell am start -n com.vulnlab.insecureapp/.AdminActivity \
 *       --ez isAdmin true --es action deleteAll
 *
 * Drozer:
 *   dz> run app.activity.start --component com.vulnlab.insecureapp \
 *           com.vulnlab.insecureapp.AdminActivity \
 *           --extra boolean isAdmin true --extra string action deleteAll
 */
public class AdminActivity extends Activity {

    private static final String TAG = "VulnLab:AdminActivity";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        LinearLayout ll = new LinearLayout(this);
        ll.setOrientation(LinearLayout.VERTICAL);
        ll.setPadding(32, 32, 32, 32);

        Intent intent = getIntent();

        // VULNERABLE: No authorization check — any caller can trigger admin actions
        boolean isAdmin = intent.getBooleanExtra("isAdmin", false);
        String action = intent.getStringExtra("action");

        String result = performAdminAction(isAdmin, action);

        TextView tv = new TextView(this);
        tv.setText("AdminActivity\n\nVulnerability: No auth check on exported component\n\n" +
                "isAdmin extra: " + isAdmin + "\n" +
                "action extra: " + action + "\n\n" +
                "Result: " + result + "\n\n" +
                "Attack: Any app can call this Activity without permission.\n" +
                "The isAdmin flag is trusted blindly from the Intent.\n\n" +
                "Test:\nadb shell am start -n com.vulnlab.insecureapp/.AdminActivity \\\n" +
                "  --ez isAdmin true --es action deleteAll");
        ll.addView(tv);
        setContentView(ll);
    }

    // VULNERABLE: Accepts attacker-controlled input with no validation
    private String performAdminAction(boolean isAdmin, String action) {
        if (action == null) {
            Log.d(TAG, "Admin panel opened, no action specified");
            return "Admin panel opened (no action)";
        }

        // Log sensitive info to logcat (also a vulnerability — info disclosure via logs)
        Log.d(TAG, "Admin action triggered: isAdmin=" + isAdmin + " action=" + action);

        switch (action) {
            case "deleteAll":
                Log.w(TAG, "EXECUTED: deleteAll — all user data would be wiped");
                return "EXECUTED: deleteAll";
            case "resetPasswords":
                Log.w(TAG, "EXECUTED: resetPasswords — all passwords reset");
                return "EXECUTED: resetPasswords";
            case "exportUsers":
                Log.w(TAG, "EXECUTED: exportUsers — user database dumped");
                return "EXECUTED: exportUsers — check /sdcard/users_export.json";
            default:
                return "Unknown action: " + action;
        }
    }
}
