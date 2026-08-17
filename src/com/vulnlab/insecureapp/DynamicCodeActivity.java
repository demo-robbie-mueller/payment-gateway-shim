package com.vulnlab.insecureapp;

import android.app.Activity;
import android.os.Bundle;
import android.os.Environment;
import android.util.Log;
import android.widget.LinearLayout;
import android.widget.TextView;

import dalvik.system.DexClassLoader;
import dalvik.system.PathClassLoader;

import java.io.File;
import java.lang.reflect.Method;

/**
 * VULNERABILITY 11.9 — Dynamic Code Loading
 *
 * Loads a DEX file from external (world-writable) storage.
 * An attacker who can write to /sdcard/vulnlab_plugins/update.dex
 * can inject arbitrary code that runs with VulnLab's privileges.
 *
 * Attack steps:
 *   1. Create a malicious DEX with a class implementing IVulnPlugin
 *   2. Push it to the target path:
 *      adb push malicious.dex /sdcard/vulnlab_plugins/update.dex
 *   3. Trigger this Activity — malicious code executes
 *
 * Test (benign, verify the load path):
 *   adb shell ls -la /sdcard/vulnlab_plugins/
 *   adb shell am start -n com.vulnlab.insecureapp/.DynamicCodeActivity
 *
 * See also: integrity not checked — no signature verification on loaded DEX.
 */
public class DynamicCodeActivity extends Activity {

    private static final String TAG = "VulnLab:DynamicCode";

    // VULNERABLE: world-writable external storage path
    private static final String PLUGIN_PATH =
            Environment.getExternalStorageDirectory() + "/vulnlab_plugins/update.dex";

    private static final String PLUGIN_CLASS = "com.vulnlab.plugin.UpdatePlugin";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        LinearLayout ll = new LinearLayout(this);
        ll.setOrientation(LinearLayout.VERTICAL);
        ll.setPadding(32, 32, 32, 32);

        StringBuilder report = new StringBuilder();
        report.append("DynamicCodeActivity\n\nVulnerability: Dynamic Code Loading from External Storage\n\n");
        report.append("Plugin path: ").append(PLUGIN_PATH).append("\n\n");

        File pluginFile = new File(PLUGIN_PATH);
        if (pluginFile.exists()) {
            report.append("Plugin file found! Attempting to load...\n");
            String result = loadAndRunPlugin(pluginFile);
            report.append("Load result: ").append(result).append("\n\n");
        } else {
            report.append("Plugin file NOT found at expected path.\n\n");
            report.append("To exploit:\n" +
                    "1. Build malicious DEX with class com.vulnlab.plugin.UpdatePlugin\n" +
                    "2. Push: adb push malicious.dex /sdcard/vulnlab_plugins/update.dex\n" +
                    "3. Launch this Activity\n\n");
        }

        report.append("Vulnerability details:\n" +
                "  - DEX loaded from world-writable /sdcard path\n" +
                "  - No signature or integrity verification\n" +
                "  - Loaded code runs under VulnLab's UID\n" +
                "  - Can access all VulnLab's private data and permissions\n\n");

        report.append("Source pattern:\n" +
                "  new DexClassLoader(\n" +
                "    \"/sdcard/vulnlab_plugins/update.dex\",  // attacker-controlled\n" +
                "    optimizedDir, null, getClassLoader()\n" +
                "  );\n");

        TextView tv = new TextView(this);
        tv.setTextSize(10);
        tv.setText(report.toString());
        ll.addView(tv);
        setContentView(ll);
    }

    private String loadAndRunPlugin(File pluginFile) {
        try {
            // VULNERABLE: loading DEX from world-writable path, no integrity check
            File optimizedDir = getDir("dex", MODE_PRIVATE);
            DexClassLoader loader = new DexClassLoader(
                    pluginFile.getAbsolutePath(),       // DANGEROUS: external storage
                    optimizedDir.getAbsolutePath(),
                    null,
                    getClassLoader()
            );
            Log.w(TAG, "DexClassLoader created for: " + pluginFile.getAbsolutePath());

            Class<?> pluginClass = loader.loadClass(PLUGIN_CLASS);
            Log.w(TAG, "Loaded class: " + pluginClass.getName());

            // Try calling execute() if it exists
            try {
                Method exec = pluginClass.getMethod("execute", android.content.Context.class);
                Object instance = pluginClass.newInstance();
                Object result = exec.invoke(instance, this);
                Log.w(TAG, "Plugin executed, result: " + result);
                return "Plugin executed successfully: " + result;
            } catch (NoSuchMethodException e) {
                return "Class loaded but no execute() method found";
            }

        } catch (ClassNotFoundException e) {
            Log.e(TAG, "Plugin class not found: " + e.getMessage());
            return "ClassNotFoundException: " + e.getMessage();
        } catch (Exception e) {
            Log.e(TAG, "Plugin load failed: " + e.getMessage());
            return "Error: " + e.getMessage();
        }
    }
}
