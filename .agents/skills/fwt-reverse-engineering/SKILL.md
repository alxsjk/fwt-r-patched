---
name: fwt-reverse-engineering
description: >-
  Safe reverse-engineering workflow for libfwt_local_server.so, libil2cpp.so,
  and UnityFS datatables in FWT Reborn Patch, enforcing output hygiene, cave trap
  validation, secret protection, and float32 serialization rules.
---

# FWT Reverse-Engineering Workflow

Use this skill when inspecting `libfwt_local_server.so`, `libil2cpp.so` RVAs, local HTTP wire payloads, or encrypted `.unity3d` datatables.

## Strict Context & Provider Hygiene

1. Redirect verbose native output (disassembly, hex dumps, symbol tables, raw byte blobs) to files under `output/`.
2. Print only compact conclusions to stdout / the conversation transcript: verified addresses, byte counts, pass/fail verdicts, and decisions.
3. Never paste multi-hundred-line disassembly dumps into docs, plans, or messages.
4. If a provider block occurs, stop retrying in the blocked thread, write findings/next steps to a dated handoff file under `output/`, and resume in a fresh session.

## Toolchain & Scripts

- **Dead-code cave discovery**: `tools/dead_code_map.py` (prefer `demangler-only` `*itanium_demangle*` candidates; treat static unreachable `offline_convenience` functions as false positives until proven otherwise).
- **On-device cave trap verification**: `tools/lab_trap_apk.py` builds `--dev` `brk #0` trap APKs before allocating new cave space.
- **Function / string inspection**: `tools/dump_fn.py`, `tools/find_string_refs.py`, and `tools/patch_audit.py` (per-`PT_LOAD` diff summary against reference `.so`).
- **Cave assembly & probes**: `tools/asm_cave.py` (`keystone` ARM64 little-endian) and `tools/probe_local_server.py`.
- **Cipher credentials**: `tools/extract_env_keys.py` extracts `.env` AES/DES/network keys from the local `source/` APK — never print, log, or commit the extracted values.

## UnityFS Datatable & Dev Build Rules

1. **Float32 quantization**: Unity serializes `MonoBehaviour` floats as IEEE-754 float32. Quantize modified floats with `struct.unpack("<f", struct.pack("<f", val))[0]` before saving so round-trip checks pass deterministically.
2. **Preserve bundle compression**: Save modified `UnityPy` assets with `packer="original"`, re-encrypt with `_encrypt_datatable`, and reload to assert round-trip equality.
3. **DEX resource contract**: Whenever assets inside `assets/fwt_resources_v1.zip` change, ensure `ResourceContract` / `HASHED_CRITICAL_FILES` in `classes8.dex` is updated in lockstep.
4. **Dev isolation**: Use `--dev` telemetry flags (`docs/DEV_BUILD.md`, parsed by `tools/dev_log_parse.py`) for device debugging; never enable `--dev-debuggable` alongside gameplay patches on production installs, and never allow dev builds in release archives.
5. **No proprietary binaries in git**: Keep `source/`, `output/`, `backups/`, `keystore/`, and `.env` strictly untracked.
