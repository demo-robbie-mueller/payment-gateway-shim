# Validation Plan

Validation should prove that the lab is reproducible and intentionally scoped.

## Repository Checks

- Manifest contains expected dangerous flags.
- Manifest package remains `com.vulnlab.insecureapp`.
- Every documented vulnerability maps to a source component.
- The vulnerability reference includes exploit and fix guidance.
- The build script uses Android SDK tooling directly.

## Emulator Checks

For release validation, run on an Android emulator:

- install the APK
- open every activity from the launcher
- run one command per vulnerability class
- capture expected logcat or UI evidence
- uninstall the app and wipe the emulator

## Release Evidence

Each release should include:

- APK artifact
- SHA256 hash
- source tag
- build environment notes
- known limitations
