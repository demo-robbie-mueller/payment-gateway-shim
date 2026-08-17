package com.vulnlab.insecureapp;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.util.Log;

/**
 * VULNERABILITY 11.2 — Intent Redirection
 *
 * This exported BroadcastReceiver extracts a nested Intent from the
 * broadcast extras and calls startActivity() on it, using THIS app's
 * privileges. An attacker can craft a broadcast that causes VulnLab to
 * start any activity — including unexported ones in other apps — on
 * the attacker's behalf.
 *
 * Test:
 *   adb shell am broadcast \
 *       -a com.vulnlab.insecureapp.RELAY_ACTION \
 *       --ep next_intent \
 *           "{ component: 'com.vulnlab.insecureapp/.AdminActivity', \
 *              extras: { isAdmin: true, action: deleteAll } }"
 *
 * Real-world impact: Can bypass android:exported="false" on target activities
 * because the call is made by the victim app which has the required permissions.
 */
public class IntentRedirectReceiver extends BroadcastReceiver {

    private static final String TAG = "VulnLab:IntentRedirect";

    @Override
    public void onReceive(Context context, Intent intent) {
        Log.d(TAG, "RELAY_ACTION received");

        // VULNERABLE: directly starts attacker-controlled Intent
        Intent nextIntent = intent.getParcelableExtra("next_intent");
        if (nextIntent != null) {
            nextIntent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
            Log.w(TAG, "Relaying intent to: " + nextIntent.getComponent());
            // This call runs with VulnLab's identity — bypasses access controls
            context.startActivity(nextIntent);
        } else {
            Log.d(TAG, "No next_intent extra found");
        }
    }
}
