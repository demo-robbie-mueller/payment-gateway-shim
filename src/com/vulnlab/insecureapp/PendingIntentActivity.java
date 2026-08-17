package com.vulnlab.insecureapp;

import android.app.Activity;
import android.app.PendingIntent;
import android.content.Intent;
import android.os.Bundle;
import android.util.Log;
import android.widget.LinearLayout;
import android.widget.TextView;

/**
 * VULNERABILITY 11.2 — PendingIntent Misuse
 *
 * Creates a MUTABLE PendingIntent wrapping an empty (implicit) Intent.
 * When passed to a third-party component (e.g. notification service,
 * partner SDK), the recipient can fill in the action/component, then
 * fire it under VulnLab's identity.
 *
 * CVE pattern: GHSL-2021-1061, StrandHogg variants.
 *
 * Contrast:
 *   VULNERABLE: PendingIntent.FLAG_MUTABLE + empty Intent
 *   SAFE:       PendingIntent.FLAG_IMMUTABLE + explicit Intent
 *
 * Test (requires an attacker app that receives and modifies the PI):
 *   The PI is broadcast via ACTION_VULN_PI — any receiver gets it
 *   and can fire it targeting any component in VulnLab.
 */
public class PendingIntentActivity extends Activity {

    private static final String TAG = "VulnLab:PendingIntent";

    // FLAG_MUTABLE value (API 31+) = 0x04000000; pre-31 all PIs were mutable
    private static final int FLAG_MUTABLE = 0x04000000;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        LinearLayout ll = new LinearLayout(this);
        ll.setOrientation(LinearLayout.VERTICAL);
        ll.setPadding(32, 32, 32, 32);

        // VULNERABLE: empty Intent — attacker can fill in component/action
        Intent emptyIntent = new Intent();
        PendingIntent vulnerablePi = PendingIntent.getActivity(
                this,
                0,
                emptyIntent,
                FLAG_MUTABLE   // DANGEROUS on API 31+
        );
        Log.w(TAG, "Created MUTABLE PendingIntent (empty base Intent)");

        // Simulate "sending" the PI to a third-party (e.g. a partner notification SDK)
        sendVulnerablePendingIntent(vulnerablePi);

        // SAFE example for comparison
        Intent explicitIntent = new Intent(this, AdminActivity.class);
        PendingIntent safePi = PendingIntent.getActivity(
                this, 1, explicitIntent,
                PendingIntent.FLAG_IMMUTABLE
        );
        Log.d(TAG, "Created IMMUTABLE PendingIntent (explicit Intent) — safe");

        TextView tv = new TextView(this);
        tv.setText("PendingIntentActivity\n\n" +
                "Vulnerability: MUTABLE PendingIntent with empty base Intent\n\n" +
                "A vulnerable PendingIntent has been created and broadcast.\n" +
                "Any app receiving it can fill in the target component\n" +
                "and fire it under VulnLab's identity.\n\n" +
                "See logcat tag VulnLab:PendingIntent for details.\n\n" +
                "Mitigation:\n" +
                "  Use FLAG_IMMUTABLE (API 23+)\n" +
                "  Always use explicit Intents in PendingIntents");
        ll.addView(tv);
        setContentView(ll);
    }

    private void sendVulnerablePendingIntent(PendingIntent pi) {
        // Simulate broadcasting the PI to a third party
        Intent delivery = new Intent("com.vulnlab.insecureapp.VULN_PI_DELIVERY");
        delivery.putExtra("pending_intent", pi);
        Log.w(TAG, "Broadcasting vulnerable PendingIntent to any receiver");
        sendBroadcast(delivery);
    }
}
