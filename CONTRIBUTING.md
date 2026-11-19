# Contributing to FWT Reborn Patch

Thank you for your interest in **FWT Reborn Patch**.

This repository is strictly maintainer-controlled (**authorial / BDFL model**): **`@alxsjk`** is the sole code owner and final reviewer for all changes. Direct pushes to `main` are disabled, and all Pull Requests require explicit approval from `@alxsjk` plus passing CI checks before merging.

---

## Contribution Rules

1. **Open an issue first and wait for `approved`**
   Every external Pull Request must reference an **open issue** carrying the maintainer-only **`approved`** label (`Closes #<number>`). Opening an issue automatically adds **`needs-triage`** and posts workflow guidance; please wait for `@alxsjk` to review the design and apply the `approved` label before opening a PR. External PRs without an approved open issue fail the required **`PR Policy (Approved Issue)`** status check (with an explanatory comment) and cannot be merged.

2. **Fork & branch off `main`**
   Keep every PR focused on a single logical change. One feature or fix per PR.

3. **Follow project architecture & technical rules**
   Review [`docs/PATCH_SPEC.md`](docs/PATCH_SPEC.md), [`docs/CODE_CAVES.md`](docs/CODE_CAVES.md), and [`docs/DEV_BUILD.md`](docs/DEV_BUILD.md) before proposing changes:
   - Never renumber or reuse Feature IDs in [`docs/FEATURE_CATALOG.md`](docs/FEATURE_CATALOG.md) or [`gui/feature_catalog.py`](gui/feature_catalog.py), and keep GUI/CLI/`validate_patch_options()`/`core/patch_inspector.py` parity synchronized.
   - Always translate ELF virtual addresses dynamically per `PT_LOAD` segment (`core/elf_mapping.py`).
   - Preserve Android 16 alignment (`.so` stored uncompressed, `PT_LOAD p_align >= 16384`, `zipalign -f 16384`).
   - Keep `--dev` builds strictly separated from release packaging (`tools/create_distribution_zip.py`, `tools/register_release.py`).
   - Never pass `shell=True` when invoking external binaries.

4. **Strict copyright, secrets & privacy hygiene**
   - **Never commit or attach** original game binaries (`*.apk`, `*.so`, `*.dex`, `*.dat`, `source/`), signing keystores (`keystore/`, `*.jks`), save files (`backups/`), `.env`, AES cipher keys, downloaded jars (`tools/*.jar`), or personal emails/paths/IPs.
   - Use only generic placeholders in examples and docs.

5. **English-only repository**
   - All Issues, Pull Requests, tracked code, comments, docstrings, CLI messages, tests, scripts, GitHub workflows, and documentation MUST be written in **English**.

6. **AI coding assistants**
   - If you use an AI coding agent, follow [`AGENTS.md`](AGENTS.md), [`.specify/memory/constitution.md`](.specify/memory/constitution.md), and the project skills under `.agents/skills/fwt-*`.

---

## Local Development Setup

```bash
python -m venv .venv
# Activate .venv, then:
python -m pip install --upgrade pip setuptools wheel
python -m pip install -r requirements-dev.txt
cp .env.example .env
```

Set your local `ANDROID_HOME`, `JAVA_HOME`, and required `FWT_DATATABLE_CRYPT_KEY` / `FWT_DATATABLE_CRYPT_IV` values inside `.env` (`.env` is gitignored).

---

## Required Verification Before Opening a PR

Run all checks inside `.venv` after your final edit:

```bash
python -m compileall -q core gui tools tests fwt_patcher.py
ruff check .
mypy core gui fwt_patcher.py tools tests
pytest -q -m "not integration"
```

*(Integration tests marked `@pytest.mark.integration` require a locally supplied authorized reference APK under `source/` and datatable credentials in `.env`; CI skips them automatically when `source/` is absent.)*

---

## Pull Request Process

1. Confirm your linked issue is **open** and carries the **`approved`** label from `@alxsjk`.
2. Ensure all local checks pass cleanly.
3. Fill out the entire [`.github/PULL_REQUEST_TEMPLATE.md`](.github/PULL_REQUEST_TEMPLATE.md), including the linked approved issue (`Closes #<number>`).
4. Wait for **`PR Policy (Approved Issue)`**, CI checks, and `@alxsjk`'s Code Owner approval.
5. Keep commits clean and focused; do not commit `.coverage` or temporary outputs.
