---
name: fwt-pre-release-audit
description: >-
  Pre-release and publication audit runbook for FWT Reborn Patch covering
  version consistency, English-only compliance, secrets/PII/copyright hygiene,
  GitHub governance workflows, release build isolation, and full verification gates.
---

# FWT Pre-Release & Publication Audit

Run this checklist before tagging a release, building distribution archives, or pushing public repository updates.

## 1. Version & Metadata Parity

1. Confirm `APP_VERSION` and `APP_RELEASE_DATE` in `core/version.py` match:
   - `[project].version` in `pyproject.toml`
   - `README.md` header and versioned filename examples
   - `docs/FEATURE_CATALOG.md` header
   - Top released section in `CHANGELOG.md` (with `## [Unreleased]` present above it)
2. Run `pytest -q tests/test_version.py tests/test_suite_health.py`.

## 2. English-Only, PII, Secrets & Copyright Hygiene

1. Verify all tracked files, scripts, docs, comments, tests, workflows, and harness files use **English** exclusively (ignoring intentional localized game strings such as Korean `BOOTSTRAP_TEXT` keys in `core/dex_smali.py`).
2. Scan the working tree and staged diff for:
   - Personal names, workstation hostnames/paths, real private LAN IPs (use RFC 5737 `192.0.2.x` in examples)
   - Hardcoded AES/DES/handshake secrets (verify `.env` keys come solely from user extraction via `tools/extract_env_keys.py`)
   - Copyrighted binaries (`*.apk`, `*.so`, `*.dex`, `*.dat`, `source/`), user saves (`backups/`), keystores (`keystore/`, `*.jks`), `.coverage`, or downloaded jars
   - Unsafe subprocess usage (`shell=True`)
3. Confirm all relative markdown links and documented repository paths exist on disk.

## 3. GitHub Authorial Governance & CI Integrity

1. Verify `.github/CODEOWNERS`, `.github/workflows/ci.yml`, `.github/workflows/release.yml`, `.github/workflows/pr-policy.yml`, `.github/workflows/pr-policy-comment.yml`, `.github/workflows/issue-triage.yml`, issue/PR templates, and `CONTRIBUTING.md` stay synchronized.
2. Run `pytest -q tests/test_github_workflows.py` to enforce fork-safety invariants (no `actions/checkout` on `pull_request_target`/`issues`, env-var input passing, no job-level `if:` on `PR Policy (Approved Issue)`).
3. Never commit or modify Spec Kit manifest-tracked files under `.specify/scripts/`, `.specify/templates/`, or `.agents/skills/speckit-*`.

## 4. Release Packaging & Verification Gates

1. Run release packaging only from verified release APKs (`tools/create_distribution_zip.py`, `tools/register_release.py`); both must reject `--dev` or non-reference builds (`assets/fwt_re_patched_build_type.txt`).
2. Run all verification gates after the final edit:
   - `python -m compileall -q core gui tools tests fwt_patcher.py`
   - `ruff check .`
   - `mypy core gui fwt_patcher.py tools tests`
   - `pytest -q -m "not integration and not slow" --cov=core` (and `pytest -q` when `source/` reference APK is available)
   - Ensure `git status --short` contains no `.coverage` or temporary artifacts before committing.
