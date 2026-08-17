# Roadmap

VulnLab APK should mature as a safe, reproducible Android security training lab.

## 1.1: Reproducible Build And Test Baseline

- Add a GitHub Actions workflow for repository checks.
- Add optional Android SDK build verification where runners support it.
- Publish expected APK metadata for release builds.
- Add checks that every documented vulnerability has a matching source file.

## 1.2: Lab Quality

- Add per-vulnerability test notes for emulator validation.
- Add safer teardown instructions for lab devices.
- Add mapping from each vulnerability to OWASP MASVS and MASTG references.
- Add expected logcat snippets for every exercise.

## 1.3: Release Evidence

- Attach signed lab APKs to GitHub Releases.
- Document SHA256 hashes for release artifacts.
- Add screenshots or short GIFs for the full lab workflow.
- Collect external usage feedback before curated-list resubmission.

## Curated-List Readiness

Before resubmitting to strict curated lists, collect:

- tagged releases with APK hashes
- visible CI/check history
- complete safety and lab reset instructions
- third-party feedback or independent usage
- clear maintainer and security policy files
