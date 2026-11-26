# FWT Re-Patched Constitution

## Core Principles

### I. Deterministic Binary Patching & Dual Verification

Every patch targeting `libfwt_local_server.so`, `libil2cpp.so`, `classes8.dex`, XML/AXML, or external datatables MUST be deterministic, idempotent-safe, and verified before and after mutation against expected original byte sequences, literals, or SHA-256 checksums. Native address translation MUST resolve ELF `PT_LOAD` segment mappings dynamically rather than assuming a single fixed file bias. Every user-facing option on `PatchOptions` in `core/core_patches.py` MUST have an independent verification check in `core/patch_inspector.py` so build output inspection cannot report false passes.

### II. Core-First & CLI/GUI Parity

All patching, ELF/DEX manipulation, APK alignment/signing, and inspection logic MUST reside in `core/` so both the CLI (`fwt_patcher.py`) and desktop GUI (`gui/main_window.py`) remain thin interfaces over one shared engine. Option constraints, defaults, and mutually exclusive flag pairs MUST be validated centrally via `validate_patch_options()` in `core/core_patches.py`, and GUI option collection (`_collect_patch_options()`) MUST remain in parity with CLI behavior as enforced by `tests/test_gui_feature_parity.py` and `tests/test_suite_health.py`.

### III. Verification Gates & Emulation Evidence

Changes to ARM64 patches or code caves MUST carry reproducible automated evidence (Keystone/Capstone instruction checks, Unicorn emulation where applicable, and inspector assertions) plus device validation before claiming runtime behavior. Every change set MUST pass `compileall`, `ruff check .`, `mypy core gui fwt_patcher.py tools tests`, non-integration tests (`pytest -q -m "not integration and not slow" --cov=core` meeting the configured coverage floor), and integration tests when the proprietary reference APK is present in `source/`.

### IV. Release Isolation & Zero Copyrighted Assets

Proprietary APKs, game binaries (`.so`, `.dex`, `.dat`), savegame backups (`backups/`), signing keys (`keystore/`), local secrets (`.env`, `*.local.json`), and build outputs (`output/`) MUST remain gitignored and MUST NEVER be committed. Development instrumentation (`--dev*` flags) MUST remain strictly isolated from release builds: `--dev` alone MUST leave `.so` and `.dex` byte-identical to a release build, and `--dev*` builds MUST never be packaged into release distribution archives (`tools/create_distribution_zip.py`, `tools/register_release.py`).

### V. Android 16 Page Alignment & Toolchain Determinism

Patched APKs MUST store native `.so` libraries uncompressed, enforce `PT_LOAD p_align >= 16384` (16 KB), and pass `zipalign -f 16384` alignment. External toolchain artifacts (`APKTOOL_VERSION` and `APKTOOL_SHA256` in `core/dex_smali.py`), subprocess invocations (never `shell=True`), and cipher environment overrides MUST fail closed on integrity or key mismatches rather than falling back silently.

## Technical & Environment Constraints

- **Python & Host Matrix**: Target Python `>=3.12` across Linux build hosts and Windows mirrors as validated in `.github/workflows/ci.yml`.
- **Hardware & Upstream Caps**: Keep `duckdb>=1.5.6,<2` in `pyproject.toml` and `requirements.txt` because `duckdb 2.x` requires AVX2 (`x86-64-v3`) instructions unavailable on legacy x86-64 build hosts lacking AVX2; keep `websockets` on `13.x` (`<14`) as constrained by `frida-tools==14.13.1`.
- **Java & DEX Tooling**: Use `find_java_executable()` (`PATH` and `JAVA_HOME`) for JVM discovery; tests requiring JDK/APK tools MUST skip cleanly when absent rather than failing erroneously.
- **Persistent Technical Documentation & Language**: Long-lived feature catalogs, reverse-engineering addresses, code-cave layouts, and guides live in `docs/FEATURE_CATALOG.md`, `docs/PATCH_SPEC.md`, `docs/CODE_CAVES.md`, `docs/DEV_BUILD.md`, `docs/AUTO_MODE_AI_GUIDE.md`, `docs/GUILD_RAID_SELF_MERCENARY.md`, `docs/HEROS_MARK_GUIDE.md`, `docs/HERO_AWAKENING_GUIDE.md`, `docs/KNOWN_BUGS.md`, `docs/SKILL_REBALANCE_GUIDE.md`, and `docs/SERVER_ARCHITECTURE_AND_REVERSE_ENGINEERING.md`. Tracked code, comments, scripts, workflows, and documentation MUST be written in English.

## Specification & Development Workflow

- **Spec-Driven Development (Spec Kit)**: New features, new binary/datatable patches, or architectural changes SHOULD progress through `/speckit-specify` → `/speckit-clarify` (when ambiguous) → `/speckit-plan` → `/speckit-tasks` → `/speckit-analyze` → `/speckit-implement`.
- **Artifact Lifecycle**: Feature specs, plans, and task lists live under `specs/<NNN-short-name>/` while active. Enduring technical contracts, offsets, and usage notes MUST be consolidated into `docs/` and `README.md` before retiring completed spec artifacts.
- **Change Discipline**: Keep each logical fix or feature focused and reviewable; do not invent unverified offsets, hardware claims, or test results.

## Governance

This constitution supersedes ad-hoc conventions for all human and AI-agent contributions. Amendments follow semantic versioning (`MAJOR` for breaking principle removals/redefinitions, `MINOR` for new principles or expanded gates, `PATCH` for clarifications) and SHOULD be performed via `/speckit-constitution`. Any intentional deviation from a principle or complexity exception MUST be justified in writing in `docs/` or the active feature `plan.md` Complexity Tracking table. Runtime agent guidance lives in `AGENTS.md`.

**Version**: 1.0.2 | **Ratified**: 2026-11-13 | **Last Amended**: 2026-11-26
