---
name: fwt-add-patch
description: >-
  Step-by-step runbook for adding or modifying a binary, DEX, or UnityFS
  datatable patch in FWT Reborn Patch while maintaining ELF PT_LOAD safety,
  code-cave disjointness, inspector verification, and CLI/GUI/catalog parity.
---

# Add or Modify a Patch

Follow this workflow whenever implementing or changing a gameplay feature or bug fix in `core/`.

## Before Editing

1. Read `docs/PATCH_SPEC.md`, `docs/CODE_CAVES.md`, and `docs/FEATURE_CATALOG.md`.
2. Inspect `core/` to verify whether an existing entry point (`core/core_patches.py`, `core/apk_tooling.py`, `core/dex_smali.py`, `core/axml.py`, `core/elf_mapping.py`, `core/patch_inspector.py`) or a dedicated feature module under `core/` already owns the feature.

## Implementation Checklist

1. **ELF Address Translation (`core/elf_mapping.py`)**:
   - Resolve ELF virtual addresses dynamically via `PT_LOAD` segments (`read_load_segments()` / `translate_vaddr()`). Never hardcode a binary-wide bias.
   - Validate original bytes, instruction semantics, or table SHA-256 hashes before mutating; keep every `apply_*` routine idempotent and fail closed on mismatch.
2. **Code Caves (`docs/CODE_CAVES.md`)**:
   - Allocate new native trampolines only from audited dead ranges (for example, remaining headroom or `tools/dead_code_map.py` candidates verified with `tools/lab_trap_apk.py`).
   - Register every new cave or scratch interval in `validate_cave_layout()` in `core/core_patches.py`.
3. **Options & Conflict Validation (`core/core_patches.py`)**:
   - Add or update the field on `PatchOptions` (and update `EXPECTED_PATCH_COUNTS` when the patch has a deterministic occurrence count).
   - For non-boolean `PatchOptions` fields, register the field in `_INTEGER_FEATURE_SCALES` or `_NON_FEATURE_FIELDS` in `tests/test_suite_health.py`.
   - Update `validate_patch_options()` for mutual exclusions, `--force` incompatibilities, or numeric bounds.
   - Never let `--all` or release patches leak into `DevOptions`.
4. **Independent Verification (`core/patch_inspector.py`)**:
   - Add an independent check in `inspect_native_so()` / asset inspection and map it in `expected_feature_keys()`.
   - Confirm client datatable + server `.so` consistency via `verify_report()` where both sides must match.
5. **CLI, GUI & Permanent Feature Catalog**:
   - Wire CLI flags in `fwt_patcher.py` (`build_parser()`, `run_cli()`).
   - Add the GUI variable and control in `gui/main_window.py` (`_init_option_vars()`, `_collect_patch_options()`, widget layout).
   - Assign a **brand-new permanent ID** in `gui/feature_catalog.py` and `docs/FEATURE_CATALOG.md` (never renumber or reuse an existing or retired ID).
6. **Android 16 Alignment**:
   - Keep `.so` entries uncompressed, `PT_LOAD p_align >= 16384`, and `zipalign -f 16384`.
7. **Tests & Docs**:
   - Add unit tests (Capstone disassembly / Unicorn emulation where native code is emitted) under `tests/`.
   - Update `docs/PATCH_SPEC.md`, `docs/CODE_CAVES.md` (if cave/scratch changed), `README.md` (if user-facing), and `CHANGELOG.md` under `## [Unreleased]`.

## Verification Gates

Run using the project virtualenv (`.\.venv\Scripts\python.exe` or `.venv/bin/python`, or native Windows Python 3.12+ when `.venv` is Linux-hosted):

1. `python -m compileall -q core gui tools tests fwt_patcher.py`
2. `ruff check .`
3. `mypy core gui fwt_patcher.py tools tests`
4. `pytest -q tests/test_gui_feature_parity.py tests/test_suite_health.py`
5. `pytest -q -m "not integration and not slow" --cov=core` (and `pytest -q` when the reference APK is available under `source/`)
