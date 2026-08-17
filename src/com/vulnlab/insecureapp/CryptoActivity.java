package com.vulnlab.insecureapp;

import android.app.Activity;
import android.os.Bundle;
import android.util.Base64;
import android.util.Log;
import android.widget.LinearLayout;
import android.widget.TextView;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Random;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLSession;

/**
 * VULNERABILITY 11.7 — Cryptography Failures
 *
 * Demonstrates multiple cryptographic anti-patterns:
 *   1. Hardcoded AES key
 *   2. AES/ECB mode (no IV, deterministic, pattern-preserving)
 *   3. Static zero IV in AES/CBC
 *   4. MD5 for password hashing (broken, rainbow-table vulnerable)
 *   5. Weak PRNG (java.util.Random seeded with time)
 *   6. Disabled hostname verification (accepts any certificate for any host)
 *
 * Frida hook to extract keys at runtime:
 *   Java.use("javax.crypto.spec.SecretKeySpec")
 *     .$init.overload('[B','java.lang.String')
 *     .implementation = function(key,algo) {
 *       console.log("Key: " + bytesToHex(key) + " algo=" + algo);
 *       return this.$init(key,algo);
 *     };
 */
public class CryptoActivity extends Activity {

    private static final String TAG = "VulnLab:Crypto";

    // VULNERABLE 1: Hardcoded AES-128 key in source
    private static final byte[] HARDCODED_KEY = "hardcoded1234567".getBytes();

    // VULNERABLE 3: Static zero IV — defeats CBC mode randomness
    private static final byte[] STATIC_IV = new byte[16]; // all zeros

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        LinearLayout ll = new LinearLayout(this);
        ll.setOrientation(LinearLayout.VERTICAL);
        ll.setPadding(32, 32, 32, 32);

        StringBuilder report = new StringBuilder();
        report.append("CryptoActivity\n\nVulnerability: Cryptography Failures\n\n");

        // Run all demos
        report.append(demoEcbMode());
        report.append(demoCbcStaticIv());
        report.append(demoMd5Password());
        report.append(demoWeakRandom());
        report.append(demoDisabledHostnameVerifier());

        TextView tv = new TextView(this);
        tv.setTextSize(10);
        tv.setText(report.toString());
        ll.addView(tv);
        setContentView(ll);
    }

    /**
     * VULNERABLE 2: AES/ECB — identical plaintext blocks produce identical ciphertext blocks.
     * Patterns in plaintext are visible in ciphertext (penguin effect).
     */
    private String demoEcbMode() {
        try {
            SecretKeySpec keySpec = new SecretKeySpec(HARDCODED_KEY, "AES");
            // VULNERABLE: ECB mode
            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, keySpec);

            String plaintext = "secret_data_AAAAAAAAAAAAAAAAAAAAAAAA"; // repeated pattern
            byte[] encrypted = cipher.doFinal(plaintext.getBytes());
            String encoded = Base64.encodeToString(encrypted, Base64.NO_WRAP);

            Log.w(TAG, "[ECB] key='" + new String(HARDCODED_KEY) + "' encrypted=" + encoded);
            return "[1] AES/ECB (hardcoded key):\n" +
                    "    Key: " + new String(HARDCODED_KEY) + "\n" +
                    "    Plain: " + plaintext + "\n" +
                    "    Cipher (b64): " + encoded + "\n\n";
        } catch (Exception e) {
            return "[1] ECB demo failed: " + e.getMessage() + "\n\n";
        }
    }

    /**
     * VULNERABLE 3: AES/CBC with static zero IV — first block is always the same
     * for a given key, making it non-semantically secure.
     */
    private String demoCbcStaticIv() {
        try {
            SecretKeySpec keySpec = new SecretKeySpec(HARDCODED_KEY, "AES");
            IvParameterSpec ivSpec = new IvParameterSpec(STATIC_IV); // all zeros
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);

            byte[] encrypted = cipher.doFinal("password123".getBytes());
            String encoded = Base64.encodeToString(encrypted, Base64.NO_WRAP);

            Log.w(TAG, "[CBC-StaticIV] iv=zeros encrypted=" + encoded);
            return "[2] AES/CBC (static zero IV):\n" +
                    "    IV: 0000000000000000 (16 zero bytes)\n" +
                    "    Cipher (b64): " + encoded + "\n\n";
        } catch (Exception e) {
            return "[2] CBC demo failed: " + e.getMessage() + "\n\n";
        }
    }

    /**
     * VULNERABLE 4: MD5 password hashing — collision-prone, rainbow-table crackable.
     * No salt used.
     */
    private String demoMd5Password() {
        try {
            MessageDigest md = MessageDigest.getInstance("MD5");
            byte[] hash = md.digest("Admin@123!".getBytes());
            StringBuilder sb = new StringBuilder();
            for (byte b : hash) sb.append(String.format("%02x", b));
            String md5hex = sb.toString();

            Log.w(TAG, "[MD5] password hash=" + md5hex);
            return "[3] MD5 password hash (no salt):\n" +
                    "    Input: Admin@123!\n" +
                    "    MD5:   " + md5hex + "\n" +
                    "    Crack: https://crackstation.net → instant\n\n";
        } catch (NoSuchAlgorithmException e) {
            return "[3] MD5 not available: " + e.getMessage() + "\n\n";
        }
    }

    /**
     * VULNERABLE 5: java.util.Random with time seed — predictable output.
     * An attacker who knows approximate token generation time can brute force.
     */
    private String demoWeakRandom() {
        Random weakRng = new Random(System.currentTimeMillis()); // predictable seed
        StringBuilder token = new StringBuilder();
        for (int i = 0; i < 16; i++) {
            token.append((char) ('a' + weakRng.nextInt(26)));
        }
        String generated = token.toString();

        Log.w(TAG, "[WeakRandom] generated token=" + generated);
        return "[4] Weak PRNG token:\n" +
                "    Seed: System.currentTimeMillis()\n" +
                "    Token: " + generated + "\n" +
                "    Predictable if generation time is known\n\n";
    }

    /**
     * VULNERABLE 6: Disabled hostname verification — accepts any cert for any hostname.
     * Classic SSL MitM enabler.
     */
    private String demoDisabledHostnameVerifier() {
        // VULNERABLE: blindly returns true for ALL hostnames
        HttpsURLConnection.setDefaultHostnameVerifier(new AllowAllHostnameVerifier());
        return "[5] Hostname verification disabled:\n" +
                "    Any certificate accepted for any hostname.\n" +
                "    Enables SSL MitM without cert pinning bypass.\n\n";
    }

    /** Named static class — avoids d8 bug with anonymous interface implementations. */
    static class AllowAllHostnameVerifier implements HostnameVerifier {
        @Override
        public boolean verify(String hostname, SSLSession session) {
            Log.w("VulnLab:Crypto", "[HostnameVerifier] Allowing: " + hostname);
            return true; // accepts MITM cert for any host
        }
    }
}
