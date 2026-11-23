# AGENTS.md

## Project Scope & Context

FWT Reborn is a game-preservation project for personal offline play. Fantasy
War Tactics is a discontinued title: official service has ended, and client
0.682 runs entirely offline against an embedded local server
(`libfwt_local_server.so`). This repository patches a locally owned copy of
that client for single-player use — no online service, multiplayer opponent,
or third party is involved. Reverse engineering here serves interoperability
and preservation of abandoned software, the same category as offline game
modding.

## Governance & Constitution

This repository uses **GitHub Spec Kit** for Spec-Driven Development (SDD) and agent governance.
Read [`.specify/memory/constitution.md`](.specify/memory/constitution.md) before proposing architectural changes, adding patch options, or planning new features — its principles are non-negotiable project law.

## Spec Kit Workflow & Skills

Project skills live under [`.agents/skills/`](.agents/skills/), alongside optional local **GitHub Spec Kit** scaffolding (`.specify/` and `speckit-*` skills, ignored in git when installed locally):

- `/speckit-constitution` — Establish or amend [`.specify/memory/constitution.md`](.specify/memory/constitution.md).
- `/speckit-specify` — Create a feature specification under `specs/<NNN-short-name>/spec.md`.
- `/speckit-clarify` — Resolve underspecified requirements (max 5 targeted questions) before planning.
- `/speckit-plan` — Generate `plan.md`, research notes, contracts, and Constitution Checks.
- `/speckit-checklist` — Generate requirements-quality review checklists.
- `/speckit-tasks` — Break the plan into dependency-ordered executable tasks in `tasks.md`.
- `/speckit-analyze` — Read-only cross-artifact consistency check across `spec.md`, `plan.md`, and `tasks.md`.
- `/speckit-implement` — Execute `tasks.md` phase by phase against verification gates.
- `/speckit-converge` — Reconcile code against `spec.md`, `plan.md`, and `tasks.md` and append remaining work.

Use the Spec Kit pipeline for new features, new patches, or multi-file design work. For small, unambiguous bug fixes or documentation updates, inspect the relevant code/docs and apply tests directly.

### Project Skills (`.agents/skills/fwt-*`)

Project-specific skills complement Spec Kit (keep all edits outside the Spec Kit manifest-tracked `.agents/skills/speckit-*` files):

- `fwt-add-patch`: End-to-end procedure for adding or modifying a binary, DEX, or UnityFS datatable patch (ELF `PT_LOAD` mapping, cave reservation, `PatchOptions`, `patch_inspector.py`, `FEATURE_CATALOG`, CLI/GUI parity, alignment, tests).
- `fwt-reverse-engineering`: Safe reverse-engineering workflow for `libfwt_local_server.so`, `libil2cpp.so`, and UnityFS datatables (RE output hygiene, dead-code traps, `patch_audit.py`, key extraction without echoing secrets, `float32` quantization).
- `fwt-pre-release-audit`: Pre-release and GitHub publication verification (version parity, English-only sweep, secrets/PII/copyright hygiene, `.github/` governance checks, release build guards, verification gates).

> **Cross-platform note on `.specify/scripts/python/*.py`**: Upstream skill prompts invoke `python3 .specify/scripts/python/<script>.py`. On Windows, if `python3` is unavailable or resolves to the Store alias, run the script using `.\.venv\Scripts\python.exe .specify/scripts/python/<script>.py` (on Linux, `.venv/bin/python`). If `.venv/` on a shared drive is a Linux virtualenv (`bin/`), invoke the native Windows Python 3.12+ interpreter instead.

## Repository Layout

- `core/`: Deterministic patch engine (`core_patches.py`), APK/zipalign/signing (`apk_tooling.py`), DEX/smali & `apktool` (`dex_smali.py`), feature detector (`patch_inspector.py`), ELF segment mapping (`elf_mapping.py`), manifest AXML (`axml.py`), release metadata (`version.py`), and modular feature patches (`alex_awakening*.py`, `alex_rebalance.py`, `costume_package*.py`, `equipment_tier_upgrades.py`, `guild_raid_*.py`, `hero_shop_offers.py`, `mythical_shop.py`).
- `gui/`: Desktop interface (`main_window.py`, `components.py`, `theme.py`) and stable feature grouping/IDs (`feature_catalog.py`).
- `fwt_patcher.py`: CLI entry point (`fwt-patcher`).
- `tools/`: Reverse-engineering helpers, ELF/code-cave generators, `.env` cipher extractor (`extract_env_keys.py`), ADB probes, and release packagers (`create_distribution_zip.py`, `register_release.py`).
- `tests/`: Unit, Keystone/Capstone/Unicorn emulation, GUI parity, inspector, GitHub workflow policy (`test_github_workflows.py`), and APK-backed `integration` tests.
- `docs/`: Feature index (`FEATURE_CATALOG.md`) and technical reference docs (`PATCH_SPEC.md`, `CODE_CAVES.md`, `DEV_BUILD.md`, `AUTO_MODE_AI_GUIDE.md`, `GUILD_RAID_SELF_MERCENARY.md`, `HERO_AWAKENING_GUIDE.md`, `SKILL_REBALANCE_GUIDE.md`, `SERVER_ARCHITECTURE_AND_REVERSE_ENGINEERING.md`).
- `scripts/`: Toolchain setup (`setup-linux-toolchain.sh`).
- `.github/`: CI matrix workflow (`ci.yml`), `CODEOWNERS`, issue/PR templates, and authorial PR/issue governance workflows (`pr-policy.yml`, `pr-policy-comment.yml`, `issue-triage.yml`).

## Agent Conduct: RE Output Hygiene & Provider Blocks

LLM providers occasionally block requests whose context carries large volumes
of native disassembly, raw machine-code bytes, or hook/patch dumps, even for
legitimate preservation work like this project.
The transcript is re-sent with every model call, so keep it lean:

- Run verbose native output (disassembly, hex dumps, byte blobs, symbol
  tables) with stdout redirected to a file under `output/`, and print only a
  short conclusion to the transcript: addresses verified, counts, pass/fail,
  and the decision it supports.
- Read files with targeted line ranges and filtered views rather than whole
  dumps. Do not paste multi-hundred-line disassembly excerpts into replies,
  plans, or docs — reference the file path and the one relevant line.
- Keep RE-heavy sessions short: start a fresh conversation per large
  investigation instead of accumulating megabytes of binary context in one
  transcript.
- If a provider-side block occurs ("This request was blocked by ..."), stop
  retrying — the blocked request includes the whole session context, so
  rephrasing rarely helps. Write the current state (findings, open questions,
  next steps) to a dated handoff file under `output/` (or the active spec's
  directory), and tell the user to continue in a fresh session bootstrapped
  from that file.

## Area-Specific Rules

### Feature Catalog & Stable IDs

For every feature added, modified, moved, disabled, or removed, update
[`docs/FEATURE_CATALOG.md`](docs/FEATURE_CATALOG.md) in the same change. Keep
its group, behavior/name, CLI flag, option field, GUI variable, `--all` or
development status, and availability accurate. Update `gui/feature_catalog.py`
and the GUI when their mappings or controls change, and update `README.md`,
`docs/PATCH_SPEC.md`, `docs/DEV_BUILD.md`, and `CHANGELOG.md` as applicable.

Feature IDs are permanent: never renumber or reuse an ID, even when a feature
moves or is removed. Preserve a moved feature's existing ID and record retired
IDs as historical rather than reassigning them. Assign new features a new ID,
including features without a selectable GUI control, and identify their status.
Run `tests/test_gui_feature_parity.py` and update relevant parity tests whenever
catalog entries or feature mappings change.

### Binary, DEX & Datatable Patches

Before adding or editing patches or `PatchOptions` flags:
1. Read [`docs/PATCH_SPEC.md`](docs/PATCH_SPEC.md) and [`docs/CODE_CAVES.md`](docs/CODE_CAVES.md).
2. Translate ELF virtual addresses to file offsets dynamically per `PT_LOAD` segment; never assume one fixed binary-wide bias.
3. Update `core/patch_inspector.py` detection, `validate_patch_options()` in `core/core_patches.py`, GUI parity in `gui/main_window.py` (`_collect_patch_options()`), and [`tests/test_suite_health.py`](tests/test_suite_health.py) / [`tests/test_gui_feature_parity.py`](tests/test_gui_feature_parity.py).
4. Ensure Android 16 alignment (`.so` stored uncompressed, `PT_LOAD p_align >= 16384`, `zipalign -f 16384`) remains satisfied.

### Dev Instrumentation (`--dev*`)

Before changing development build instrumentation:
1. Read [`docs/DEV_BUILD.md`](docs/DEV_BUILD.md).
2. Keep `--dev` byte-identical on `.so` and `.dex` to release builds when no instrumentation flags are enabled.
3. Never allow dev builds in release packaging (`tools/create_distribution_zip.py`, `tools/register_release.py`).

### English-Only & Documentation Hygiene

- All tracked code, comments, docstrings, CLI output, tests, scripts, GitHub workflows, and docs MUST be written in English.
- Never commit personal names, local LAN IPs, workstation paths, or email addresses; use generic placeholders (such as RFC 5737 `192.0.2.x` addresses) in docs and examples.

### GitHub Governance Workflows (`.github/`)

- Preserve the fork-safety and maintainer-gate invariants in `.github/workflows/pr-policy.yml`, `.github/workflows/pr-policy-comment.yml`, and `.github/workflows/issue-triage.yml`:
  - Never use `actions/checkout` in workflows triggered by `pull_request_target` or `issues`.
  - Pass untrusted event fields (titles, bodies, authors, comments) through environment variables rather than inline `${{ ... }}` script interpolation.
  - Keep `PR Policy (Approved Issue)` without a job-level `if:` so required branch-protection / ruleset checks never remain stuck waiting on maintainer PRs.
- Run `tests/test_github_workflows.py` whenever editing `.github/` workflows, `CODEOWNERS`, issue/PR templates, or `CONTRIBUTING.md`.

### Dependencies & Security

- Keep `requirements.txt`, `requirements-dev.txt`, and `pyproject.toml` synchronized (including the `[assets]` runtime extra: `UnityPy`, `cryptography`, `Pillow`, `pyelftools`, `capstone`, `keystone-engine`).
- Preserve `duckdb>=1.5.6,<2` (legacy x86-64 build hosts lacking AVX2) and `websockets` `<14` (`frida-tools` constraint).
- Keep `APKTOOL_VERSION` and `APKTOOL_SHA256` pinned in `core/dex_smali.py`; verify downloads against SHA-256 and never bypass signature/key validation.
- Keep `tools/extract_env_keys.py` printing only variable names and character lengths — never echo extracted `.env` cipher secrets.
- Never pass `shell=True` when invoking external binaries (`nm`, `adb`, `java`, `apksigner`, `zipalign`).

### Git Hygiene & Sensitive Files

- Never commit copyrighted binaries (`source/`, `*.apk`, `*.so`, `*.dex`, `*.dat`), user saves (`backups/`), signing keystores (`keystore/`), secrets (`.env`, `*.local.json`), build outputs (`output/`), coverage files (`.coverage`), or local editor/harness directories (`.commandcode/`).
- Do not manually edit generated files under `.specify/scripts/`, `.specify/templates/`, or `.agents/skills/speckit-*` unless overriding intentionally via Spec Kit presets/extensions (checksums are tracked in `.specify/integrations/*.manifest.json`).

## Release Builds & Documentation

- Always pass `--all` when generating APK builds for the user so each build
  includes the full default feature set.
- For every new release build (both the patched APK and the distribution patch
  ZIP produced via `tools/create_distribution_zip.py`), update `CHANGELOG.md`
  (plus `core/version.py` / `pyproject.toml` / `README.md` version references
  when bumping the version), all affected reference docs
  (`docs/FEATURE_CATALOG.md`, `docs/PATCH_SPEC.md`, `docs/CODE_CAVES.md`, etc.),
  and register the release APK in `output/releases.json` / `output/RELEASES.md`
  via `tools/register_release.py`. Clean temporary RE dumps (`output/*.asm`,
  `output/*.txt`, unpacked temp directories) and superseded build artifacts
  from `output/` once packaging finishes.
- Document novel reverse-engineering discoveries and unprecedented patch
  mechanisms (such as `docs/HERO_AWAKENING_GUIDE.md`,
  `docs/SKILL_REBALANCE_GUIDE.md`, `docs/GUILD_RAID_SELF_MERCENARY.md`, or
  `docs/AUTO_MODE_AI_GUIDE.md`) in a dedicated specification/guide under `docs/`
  for future reference before or alongside releasing them.
- After completing a new release build, optionally generate (or offer to draft)
  a concise release summary post in English for community announcements,
  listing only features verified as working in that build.

## Verification Gates

Run checks inside the project virtualenv rather than a bare system Python:

**Linux (`.venv/bin/`)**:
```bash
.venv/bin/python -m compileall -q core gui tools tests fwt_patcher.py
.venv/bin/ruff check .
.venv/bin/mypy core gui fwt_patcher.py tools tests
JAVA_HOME=/path/to/jdk21 .venv/bin/python -m pytest -q -m "not integration" --cov=core
# Full non-slow suite when source/ reference APK is present:
JAVA_HOME=/path/to/jdk21 .venv/bin/python -m pytest -q
```

**Windows (`.\.venv\Scripts\`)**:
```powershell
.\.venv\Scripts\python.exe -m compileall -q core gui tools tests fwt_patcher.py
.\.venv\Scripts\ruff.exe check .
.\.venv\Scripts\mypy.exe core gui fwt_patcher.py tools tests
.\.venv\Scripts\pytest.exe -q -m "not integration"
```

*(If `.venv/` on a shared drive is a Linux virtualenv (`bin/`), run the checks above with the native Windows Python 3.12+ interpreter instead of `.\.venv\Scripts\python.exe`.)*

Remove `.coverage` after local coverage runs before staging commits.
