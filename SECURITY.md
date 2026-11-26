# Security Policy

## Reporting a Vulnerability

If you discover a security issue in the FWT Reborn Patch tooling, APK/ELF/DEX handling, or GitHub Actions workflows, please report it privately via GitHub Security Advisories instead of opening a public issue.

## Scope & Hygiene Policy

- Never include copyrighted game binaries (`.apk`, `.so`, `.dex`, `.dat`, `.unity3d`), signing keystores (`.jks`, `.keystore`), savegame backups, or extracted `.env` cipher keys in issues, pull requests, or advisories.
- All external toolchain artifacts (`apktool.jar`, Android command-line tools, JDK downloads) must be verified by SHA-256 checksum before execution.
