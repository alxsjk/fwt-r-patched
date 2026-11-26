---

description: "Project-specific task list template for FWT Reborn Patch (Constitution-aligned)"
---

# Tasks: [FEATURE NAME]

**Input**: Design documents from `specs/[###-feature-name]/`

**Prerequisites**: `plan.md` (required), `spec.md` (required for user stories), `research.md`, `data-model.md`, `contracts/`

**Tests**: Tests are **MANDATORY** under Constitution Principle III (Keystone/Capstone checks, Unicorn emulation for native ARM64 code caves, inspector assertions, CLI/GUI parity, and full verification gates).

**Organization**: Tasks are grouped by user story to enable independent implementation and verification of each story.

## Format: `[ID] [P?] [Story] Description`

- **[P]**: Can run in parallel (different files, no dependencies)
- **[Story]**: Which user story this task belongs to (e.g., US1, US2, US3)
- Include exact repository file paths in descriptions

## Path Conventions (FWT Reborn Patch)

- **Core engine & feature modules**: `core/` (`core_patches.py`, `apk_tooling.py`, `dex_smali.py`, `axml.py`, `elf_mapping.py`, `patch_inspector.py`, and per-feature modules)
- **CLI entry point**: `fwt_patcher.py`
- **Desktop GUI & feature catalog**: `gui/` (`main_window.py`, `feature_catalog.py`)
- **Tooling & code-cave generators**: `tools/`
- **Automated tests**: `tests/` (`test_gui_feature_parity.py`, `test_suite_health.py`, `test_principle_v_invariants.py`, and feature-specific tests)
- **Reference documentation**: `docs/` (`FEATURE_CATALOG.md`, `PATCH_SPEC.md`, `CODE_CAVES.md`, `DEV_BUILD.md`, guides) and `CHANGELOG.md`

<!--
  ============================================================================
  IMPORTANT: Replace the sample tasks below with real tasks derived from
  spec.md, plan.md, data-model.md, and contracts/. Do NOT keep sample tasks
  in the generated tasks.md file.
  ============================================================================
-->

## Phase 1: Setup & Pre-Implementation Audit

**Purpose**: Verify baseline invariants, ELF/cave availability, and catalog IDs before editing code

- [ ] T001 Review `docs/PATCH_SPEC.md`, `docs/CODE_CAVES.md`, and `docs/FEATURE_CATALOG.md` for affected hooks, caves, and permanent feature IDs
- [ ] T002 [P] Audit target addresses / datatable structures and confirm cave headroom (or `tools/lab_trap_apk.py` verification if allocating new cave space)

---

## Phase 2: Foundational (Blocking Prerequisites)

**Purpose**: Shared options, layout registration, and core helpers required before user story work

- [ ] T003 Add or update `PatchOptions`, `validate_patch_options()`, and `validate_cave_layout()` in `core/core_patches.py`
- [ ] T004 [P] Register any non-boolean `PatchOptions` fields in `tests/test_suite_health.py`

**Checkpoint**: Core option validation and cave-layout invariants ready

---

## Phase 3: User Story 1 - [Title] (Priority: P1) 🎯 MVP

**Goal**: [Brief description of what this story delivers]

**Independent Test**: [Automated unit/emulation/inspector verification for this story]

### Tests for User Story 1 (MANDATORY — Constitution Principle III)

- [ ] T005 [P] [US1] Add unit / Capstone / Unicorn emulation tests in `tests/test_[feature].py`
- [ ] T006 [P] [US1] Add independent inspector assertions in `core/patch_inspector.py` and `tests/test_[feature].py`

### Implementation for User Story 1

- [ ] T007 [P] [US1] Implement deterministic patch / generator logic in `core/[feature].py` (and `tools/gen_[feature].py` if emitting ARM64 caves)
- [ ] T008 [US1] Wire patch application and independent inspection into `core/core_patches.py` and `core/patch_inspector.py`
- [ ] T009 [US1] Wire CLI flags in `fwt_patcher.py`, GUI controls in `gui/main_window.py`, and permanent ID in `gui/feature_catalog.py`

**Checkpoint**: User Story 1 passes unit, emulation, inspector, and CLI/GUI parity tests independently

---

## Phase N: Documentation, Parity & Verification Gates

**Purpose**: Keep documentation, feature catalog, and full verification gates green

- [ ] TXXX [P] Update `docs/FEATURE_CATALOG.md`, `docs/PATCH_SPEC.md`, `docs/CODE_CAVES.md` (if changed), `README.md` (if user-facing), and `CHANGELOG.md` (`## [Unreleased]`)
- [ ] TXXX Run `python -m compileall -q core gui tools tests fwt_patcher.py`, `ruff check .`, and `mypy core gui fwt_patcher.py tools tests`
- [ ] TXXX Run `pytest -q -m "not integration and not slow" --cov=core` (and `pytest -q` when the reference APK is available under `source/`)
- [ ] TXXX Remove `.coverage` before staging commits and record device validation evidence if native/client behavior changed

---

## Notes

- [P] tasks = different files, no dependencies
- [Story] label maps task to specific user story for traceability
- Never edit Spec Kit manifest-tracked files under `.specify/scripts/`, `.specify/templates/*.md`, or `.agents/skills/speckit-*`
- Follow `.agents/skills/fwt-add-patch/SKILL.md` for binary, DEX, or UnityFS datatable patches
