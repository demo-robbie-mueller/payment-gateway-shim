from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def read(path):
    return (ROOT / path).read_text()


def test_manifest_keeps_intentional_lab_flags():
    manifest = read("AndroidManifest.xml")

    assert 'package="com.vulnlab.insecureapp"' in manifest
    assert 'android:debuggable="true"' in manifest
    assert 'android:allowBackup="true"' in manifest
    assert 'android:usesCleartextTraffic="true"' in manifest
    assert 'android:networkSecurityConfig="@xml/network_security_config"' in manifest


def test_documented_components_have_source_files():
    expected_sources = [
        "AdminActivity.java",
        "IntentRedirectReceiver.java",
        "PendingIntentActivity.java",
        "VulnContentProvider.java",
        "FileVulnProvider.java",
        "DeepLinkActivity.java",
        "ConfigReceiver.java",
        "StorageActivity.java",
        "CryptoActivity.java",
        "WebViewActivity.java",
        "DynamicCodeActivity.java",
    ]

    source_files = {path.name for path in (ROOT / "src/com/vulnlab/insecureapp").glob("*.java")}

    for filename in expected_sources:
        assert filename in source_files


def test_vulnerability_reference_includes_exploit_and_fix_sections():
    reference = read("docs/VULNERABILITIES.md")

    for section in ["11.1", "11.2", "11.3", "11.4", "11.5", "11.6", "11.7", "11.8", "11.9"]:
        assert section in reference
    assert reference.count("### Exploit") >= 6
    assert reference.count("### Fix") >= 6


def test_build_script_uses_expected_android_sdk_tools():
    build_script = read("build.sh")

    for tool in ["aapt", "javac", "d8", "zipalign", "apksigner"]:
        assert tool in build_script
