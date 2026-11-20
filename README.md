# FWT Reborn - Offline Client Patcher & Modding Suite

**Version 2.5.53** · [Changelog](CHANGELOG.md) · [Technical documentation](docs/SERVER_ARCHITECTURE_AND_REVERSE_ENGINEERING.md) · [Contributing](CONTRIBUTING.md)

Cross-platform desktop application (**Windows & Linux**) in Python for applying deterministic patches directly to the offline Korean APK of Fantasy War Tactics (**0.682 v1574**), eliminating the need to compile a separate server when playing 100% offline on a phone or emulator with all quality-of-life enhancements enabled.

The desktop app shows the current patch version in the window header and includes an **About** menu with build, repository, changelog and disclaimer information.

---

## ⚠️ Legal Notice & Copyright

This repository contains **exclusively open-source tooling, deterministic patching scripts, and reverse-engineering technical documentation**.
- **No copyrighted binary files** (such as the original `fwt_0.682_offline_v1574.apk`, proprietary compiled `.so` libraries, `.dex` files, or `.dat` assets from the original developer) are included in this repository.
- To use the patcher, you must supply your own legitimate copy of the offline Korean APK and place it in the `source/` directory named `fwt_0.682_offline_v1574.apk`.
- Directories such as `source/`, `output/`, `backups/`, and signing certificates under `keystore/` are strictly ignored by Git (`.gitignore`).

---

## 📚 In-Depth Technical Documentation

For developers and modders who want to understand network packets, AES/zlib encryption, the savegame state JSON, ARM64 assembly shims, and how to author new patches:
- 👉 **[Complete Server Architecture & Reverse-Engineering Guide](docs/SERVER_ARCHITECTURE_AND_REVERSE_ENGINEERING.md)**
- 👉 **[Awakening and original hero skills guide](docs/HERO_AWAKENING_GUIDE.md)** — research, implementation and validation workflow behind shipped feature `12.01` (`--alex-awakening`) and its lab workflow.
- 👉 **[Skill rebalance guide](docs/SKILL_REBALANCE_GUIDE.md)** — native datatable effect & geometry rebalancing methodology, verified enums, and the Alex `12.02` benchmark.
- 👉 **[Known bugs](docs/KNOWN_BUGS.md)** — unresolved issues with evidence and workarounds (currently KB-001: Mythical Stone display resets after a game restart).
  - Network protocol, 43-byte startup probe handshake, and TCP framing.
  - Complete packet and command table (`req_login`, `req_attendance`, `req_hero_*`, `req_equip_*`, `req_gacha`, etc.).
  - Detailed Save State schema (`fwt_server_state_v1.json`).
  - Reverse engineering of `libfwt_local_server.so` (offsets, ARM64 disassembly, gacha pools, code caves).
  - Step-by-step tutorial for creating new trampolines and binary patches.

---

## ✨ Key Features

### Build and sideload
   - Generate the patched APK directly into `output/` to copy manually to your device or sideload.
   - Or perform a **1-click install** via ADB (Wi-Fi or USB).

### Grouped and numbered patch features

The interface and the [complete feature catalog](docs/FEATURE_CATALOG.md) share permanent IDs. Use these numbers to identify the option to change:

01. **Campaign, expeditions and modes** — 01.01–01.10
02. **Summons and shops** — 02.01–02.10
03. **Equipment and soulgear** — 03.01–03.11
04. **Runes** — 04.01–04.05
05. **Gems** — 05.01–05.05
06. **Resources and upgrade costs** — 06.01–06.10
07. **Battle Arena and Guild Raid** — 07.01–07.08
08. **Language, network and build** — 08.01–08.06
09. **Development: telemetry and controls** — 09.01–09.06
10. **Development: tools** — 10.01–10.05
11. **Development: experimental** — 11.01–11.02
12. **Original hero modifications** — 12.01–12.02

The catalog lists each CLI flag, GUI variable and `PatchOptions` or `DevOptions` field, including summon alternatives, LAN mode, alignment, the always-on Coocoo fix and separate development controls. Feature 02.08 makes costume packages 3 and 4 award one copy of each eligible owned costume, collectable from shop mail, up to 10 purchases per package per day. Feature 03.11 makes one appropriate hammer finish the current equipment tier (+10 → +15, +15 → +20, +20 → +26), with the confirmation and stat preview showing the target. Descriptions, addresses and historical evidence remain in [PATCH_SPEC.md](docs/PATCH_SPEC.md).

### Original hero modifications (12.01–12.02)

Feature 12.01 adds Alex's original 5★→6★ Awakening and Destiny Lance as an independent option in the **Original hero modifications** section and via `--alex-awakening` (also included in `--all`, incompatible with `--force`). See the [guide](docs/HERO_AWAKENING_GUIDE.md) for implementation details and validation notes.

Feature 12.02 (`--alex-rebalance`, also included in `--all`) rebalances Alex's Skills 1–3, *Knighthood* passive, and (when combined with 12.01) *Destiny Lance* terrain conversion using native game effect types and skill geometries across all 8 localized Unity asset tables. *Giga-break* uses the cast range of Jakyak's *Do not Chase me* and retains Alex's area of effect. See the [skill rebalance guide](docs/SKILL_REBALANCE_GUIDE.md) for the complete effect specification and rebalancing workflow.

### Removed experimental paths

The former Stamina Cashback companion script and the `--recycle-tickets` path
were removed in 2.5.35. See
[docs/FEATURE_CATALOG.md](docs/FEATURE_CATALOG.md) and
[docs/PATCH_SPEC.md](docs/PATCH_SPEC.md) for the current feature catalog.

### Savegame backup and restore
   - Automatic backup prior to installation, aborting the install if the backup fails (unless `--no-backup` is passed).
   - Reads the private save at `/data/data/com.nexon.fwar/files/fwt/fwt_server_state_v1.json` when root/emulator access is available.
   - Rootless fallback: copies the backup that the local server itself writes to `/sdcard/Download/fwt/fwt_server_state_v1.json`.
   - Restore via ADB (`--restore`) on rooted devices; on unrooted physical devices, the file can still be preserved manually.

### Verification and inspection
   - Analyzes a full APK (`--inspect`) or a standalone `libfwt_local_server.so` (`--inspect-so`), checking opcodes, pools, tables, hashes, and code-cave overlap.

### Integrity and safety
   - The engine only accepts the reference SO/DEX (pinned SHA-256); any other build is rejected unless `--force` is explicitly supplied.
   - All patch counts are verified (e.g., 381 campaign stages, 122 event shop items) and the final APK is re-verified before installation.

### Log console
   - Live progress for every step (unpacking, opcode patching, 16 KB zipalign, apksigner signing, and ADB deployment).

---

## ⚠️ Signing, Updates & Keystore

The original APK and the patched APK are signed with different keys. Consequently, `adb install -r` **cannot** overwrite an existing official installation: Android returns `INSTALL_FAILED_UPDATE_INCOMPATIBLE`.

Safe workflow for first-time installation or key migration:

1. Back up your save (the GUI/CLI attempts this automatically; on rooted devices/emulators private backup also works).
2. Uninstall `com.nexon.fwar` (this wipes app data).
3. Install the patched APK.
4. Restore your save with `--restore backup.json` on a rooted environment, or manually according to your device setup.

**Preserve `keystore/fwt_reborn_lan.jks`.** If it is deleted, the patcher generates a new key and the next update will require uninstalling and reinstalling again. The default development keystore password is `android`; for production/shared use, set `FWT_KEYSTORE_PASS` / `FWT_KEY_ALIAS` (and generate the keystore with that password) and keep the keystore file backed up safely. You can override the keystore path via `--keystore`.

The MuMu Player environment tested with this project runs with root `adbd`, so private backup and restore work without `su`. On an unrooted physical phone, use the `Download/fwt` fallback for backup; private restore is not possible without root.

---

## 🌐 How to Use LAN Server Mode (Online / Shared LAN Server)

If you prefer playing connected to a dedicated server on your local network (allowing multiple devices to share the same world, database, and account portal):

1. **Start the LAN Server**:
   On the host computer, start a compatible FWT LAN server listening on TCP port `8010`.
   *Make sure TCP port 8010 is allowed through your operating system firewall.*

2. **Find the Host Computer's Local IP**:
   - Windows: `ipconfig` (look for the IPv4 Address, e.g., `192.0.2.20`).
   - Linux: `ip addr` or `hostname -I`.

3. **Apply the LAN Redirect Patch**:
   - Via the **Desktop GUI**:
     - Select **Redirect to LAN Server**.
     - Enter your computer's IP and port (e.g., `192.0.2.20:8010`).
   - Via the **Command Line**:
     ```bash
     python fwt_patcher.py --lan 192.0.2.20:8010 --all --install
     ```

4. The generated APK disables the embedded local server and routes all Unity traffic directly to the configured IP.

---

## 🚀 How to Use the Patcher

### Step 0: Preparation

1. Install **Python 3.12+** and the runtime dependencies (lightweight option matching `run_gui.bat`, or full RE/analysis stack):

   ```bash
   # Lightweight runtime install (GUI, CLI, datatable assets, ELF/ARM64 patching):
   python -m pip install -e ".[assets]"

   # Or install the full dependency set (adds analysis/RE and data libraries):
   python -m pip install -r requirements.txt
   ```

2. Place `fwt_0.682_offline_v1574.apk` (~1 GB) inside the `source/` folder:

   ```text
   fwt-r-patched/
   └── source/
       └── fwt_0.682_offline_v1574.apk
   ```

   **Base APK requirement:** you must supply your own legitimate offline Korean build
   (`fwt_0.682_offline_v1574.apk`). This repository does not host, mirror, link to, or
   auto-download copyrighted game binaries.

3. Extract the cipher keys (optional; required by the datatable-editing features):

   ```bash
   python tools/extract_env_keys.py
   ```

   The keys are read from the APK you just placed — see the cipher keys note in the
   Development Environment section below. Without them, patches that edit encrypted datatables
   stop with `Missing datatable AES credentials`, while the remaining patches work normally.

### Graphical User Interface (Desktop GUI)

On Windows, double-click **`run_gui.bat`**: it creates a `.venv`, installs the dependencies and
launches the GUI. On any platform you can also start it manually:

```bash
python fwt_patcher.py
```

The window title and header show the current patch version. Use **About -> About FWT Reborn Patch** for version, target build, repository and disclaimer information, and **About -> Open Changelog** to read the version history.

In the window:
1. Confirm the base APK is selected under **Base Offline APK** (`source/fwt_0.682_offline_v1574.apk`).
2. Click **Inspect / Verify APK** to check the file status.
3. Toggle the desired options under **Custom Patch Features**.
4. Connect your ADB device (Wi-Fi or USB):
   - For a Wi-Fi emulator (e.g., MEmu/MuMu at `192.0.2.10:5555`), click **Connect IP** and enter `IP:Port`.
5. Click:
   - **Generate Patched APK Only**: Builds `output/FWT-Reborn-Patched-<version>-release.apk` (for example `FWT-Reborn-Patched-2.5.53-release.apk`) for manual sideloading. No ZIP wrapper is generated.
   - **Generate & Install via ADB**: Backs up the save, builds the 16 KB-aligned signed APK, verifies the output, and installs it onto the device.
   - **Restore Save JSON...**: Restores a save backup (requires root).
   - **Uninstall App (wipes data)**: Removes the installed package to resolve signature conflicts; back up your save first.

---

### Versioning & Changelog

The patch version is defined once in [`core/version.py`](core/version.py) and is
also reflected in `pyproject.toml`, the GUI title/header, the About dialog and
`python fwt_patcher.py --version`. Release history lives in
[`CHANGELOG.md`](CHANGELOG.md) and follows the Keep a Changelog format.

---

### Command Line Interface (CLI / Automation)

The patcher provides a complete headless CLI:

```bash
python fwt_patcher.py --version
```

#### 0. Check the toolchain (do this first):
```bash
python fwt_patcher.py --check-tools
```
This prints the detected `zipalign`, `apksigner`, `keytool` and `adb` paths plus
the runtime Python modules (`dotenv`, `UnityPy`, `cryptography`, `elftools`,
`capstone`, `keystone`). It exits with code `1` and an actionable message when a
packaging tool is missing.

APK inspection verifies signatures with `apksigner`; without it, the signature
is reported as unverified. Release packaging and registration require a valid
signature, 16 KB alignment, verified features and a signed internal release
identity. Older APKs without that identity and builds based on unknown input
are not accepted as releases; rebuild from the supported reference APK.
Development builds retain their internal identity even when renamed.

Save backup validates the same basic structure required for restore; an invalid
backup aborts the automatic pre-install path. If ADB times out during installation,
the result is unknown: check the device before retrying.

#### 1. Inspect an APK:
```bash
python fwt_patcher.py --inspect source/fwt_0.682_offline_v1574.apk
python fwt_patcher.py --inspect output/FWT-Reborn-Patched-2.5.53-release.apk
```

#### 2. Inspect a standalone `.so`:
```bash
python fwt_patcher.py --inspect-so /path/to/libfwt_local_server.so
```

#### 3. Back up the savegame from a device:
```bash
python fwt_patcher.py --backup --device 192.0.2.10:5555
```

#### 4. Restore a savegame (requires root):
```bash
python fwt_patcher.py --restore backups/fwt_server_state_v1_20261106_120000.json --device 192.0.2.10:5555
```

#### 5. Build APK with all enhancements and install:
```bash
python fwt_patcher.py --all --install --device 192.0.2.10:5555
```

If the currently installed signature differs, the command fails with guidance. For a full migration workflow:
```bash
python fwt_patcher.py --backup --device 192.0.2.10:5555
python fwt_patcher.py --uninstall --device 192.0.2.10:5555
python fwt_patcher.py --all --install --device 192.0.2.10:5555
python fwt_patcher.py --restore backups/YOUR_BACKUP.json --device 192.0.2.10:5555
```

#### 6. Build a custom APK (only XP and 70/20/10 Summon Rates):
```bash
python fwt_patcher.py --campaign-xp --summon-rates --output output/FWT_Custom.apk
```

#### 7. Build a LAN-redirected APK with IP/port validation:
```bash
python fwt_patcher.py --all --lan 192.0.2.20:8010 --output output/FWT_LAN.apk
```

#### 8. Generate the patcher distribution ZIP:
```bash
python tools/create_distribution_zip.py
```
The archive is written as `output/FWT-Reborn-Patcher-Suite-<version>.zip`
(for example `FWT-Reborn-Patcher-Suite-2.5.53.zip`). Custom `--output` names
without the current version receive it automatically. No APK-only ZIP is
generated; use `--apk-only` to stage/copy the versioned APK instead.

#### 9. Force patching a non-reference build (advanced):
```bash
python fwt_patcher.py --all --force --input other.apk --output output/Experimental.apk
```

> `--force` does not make an incompatible binary safe: it only downgrades the
> initial SHA-256 mismatch to a warning. Every patch site still validates its
> expected original bytes and counts; use only for development.

---

## 📁 Project Structure

```text
fwt-r-patched/
├── fwt_patcher.py          # Entry point (Desktop GUI and headless CLI)
├── source/                 # [NOT IN REPO] Place fwt_0.682_offline_v1574.apk here
├── output/                 # [GIT IGNORED] Built and signed APKs
├── backups/                # [GIT IGNORED] Savegame backups (.json)
├── keystore/               # [GIT IGNORED] Auto-generated signing keystore
├── .github/                # CI matrix, CODEOWNERS, templates & PR/issue workflows
├── docs/                   # Detailed documentation and technical guides
│   ├── CODE_CAVES.md
│   ├── DEV_BUILD.md
│   ├── FEATURE_CATALOG.md
│   ├── HERO_AWAKENING_GUIDE.md
│   ├── GUILD_RAID_SELF_MERCENARY.md
│   ├── PATCH_SPEC.md
│   ├── SERVER_ARCHITECTURE_AND_REVERSE_ENGINEERING.md
│   └── SKILL_REBALANCE_GUIDE.md
├── core/
│   ├── core_patches.py     # Binary ARM64, DEX, and asset patch engine
│   ├── patch_inspector.py  # Signature, hash, ELF, and feature verification
│   ├── apk_tooling.py      # 16 KB zipalign, apksigner, ADB, backup/restore
│   ├── dex_smali.py        # apktool smali/DEX rebuild & resource contract updates
│   ├── axml.py             # Binary AndroidManifest.xml rewriter (--dev flags)
│   ├── elf_mapping.py      # Dynamic ELF PT_LOAD vaddr <-> offset translation
│   ├── version.py          # Single source of truth for version & metadata
│   └── ...                 # Modular patches (alex_*, costume_*, equipment_tier_*,
│                           #   guild_raid_*, hero_shop_offers.py, mythical_shop.py)
├── gui/
│   ├── main_window.py      # Thread-safe Tkinter main window
│   ├── feature_catalog.py  # Stable feature IDs, groups & CLI/GUI parity mapping
│   ├── components.py       # Custom widgets (LogViewer, FilePathPicker, StatusBadge)
│   └── theme.py            # Modern dark theme palette
├── scripts/
│   └── setup-linux-toolchain.sh  # Rootless Temurin JDK 21 & Android SDK setup
├── tools/                  # Inspection, cave analysis, key extraction & packagers
├── tests/                  # Unit, emulation, workflow policy & integration tests
├── CONTRIBUTING.md         # Maintainer workflow and contribution rules
├── pyproject.toml          # Package metadata, dependencies, and linter/typecheck config
├── requirements.txt        # Pinned runtime and analysis dependencies
├── requirements-dev.txt    # Pinned development dependencies
├── .env.example            # Local configuration template
└── LICENSE                 # MIT License
```

---

## 🛠️ System Requirements

- **Python**: 3.12 or newer.
- **Tkinter**: bundled with standard Python installers on Windows; on Linux install `python3-tk`.
- **Android SDK Tools** (auto-discovered via `PATH`, `ANDROID_HOME`, `ANDROID_SDK_ROOT`, `~/Android/Sdk`, etc.):
  - `zipalign` (build-tools 33+ recommended)
  - `apksigner`
  - `keytool` (Java JDK 17+ recommended)
  - `adb` (platform-tools)
- **Java 17+** for `apksigner`/`keytool` and the bootstrap smali pass.

> **Important:** the Python requirements (`requirements.txt` / `pip install -e .`)
> do **not** install `zipalign`, `apksigner` or `keytool`. These are external
> Android SDK Build-Tools/JDK binaries. If the build stops with
> `Missing required packaging tools`, install the Android SDK Build-Tools and a
> JDK 17+, then run:
>
> ```bash
> python fwt_patcher.py --check-tools
> ```
>
> Add the tools to `PATH` or set `ANDROID_HOME`/`ANDROID_SDK_ROOT` and
> `JAVA_HOME` (including in `.env`). On Linux the helper script
> `scripts/setup-linux-toolchain.sh` installs both without `sudo`.

- **apktool 3.0.3**: downloaded once to the user cache and verified against its
  SHA-256. Set `FWT_APKTOOL_JAR` to use a local jar or a different release.
- **Disk Space**: ~4× the input APK size for temporary files (~3.6 GB for the ~0.9 GB APK); the nested resource archive is streamed through temporary files to keep RAM usage low.

### Note on 16 KB / Android 16

The base APK uses `extractNativeLibs=true`; in that mode, Android extracts native
libraries at install time and the governing alignment is the ELF `p_align`
(already 16 KB / 64 KB in this APK), not just ZIP alignment. The patcher enforces
both: uncompressed `.so` entries + 16 KB ZIP data offsets + `PT_LOAD p_align >= 16 KB`.
Loading libraries directly from the APK without extraction would also require
modifying `AndroidManifest.xml` to set `extractNativeLibs=false`; release builds
do not alter the manifest. Only `--dev` builds modify `AndroidManifest.xml`
(appending `-dev` to `android:versionName` unless `--dev-keep-version` is set,
or setting `android:debuggable=true` with `--dev-debuggable`).

---

## ⚙️ Development Environment (`.venv` and `.env`)

Use a local `.venv` to isolate dependencies. On Windows:

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip setuptools wheel
python -m pip install -r requirements-dev.txt
Copy-Item .env.example .env
```

On Linux/macOS:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip setuptools wheel
python -m pip install -r requirements-dev.txt
cp .env.example .env
```

For a lightweight install of just the patcher and test suite (without the heavy
reverse-engineering and data-science packages):

```bash
python -m pip install -e ".[dev]"
```

`.env` is local and ignored by Git. It holds the default ADB target, Android SDK
paths, keystore settings, and the client datatable cipher keys required when
patching or inspecting encrypted UnityFS bundles. See `.env.example` for all
supported variables.

> **Cipher keys are not distributed — extract them from your own APK.** The game keeps its
> secret strings inside the APK itself, in a Unity TextAsset (`DefineResources/Assembly`) whose
> blob embeds its own DES key, so the project ships no secret values. Run
> `python tools/extract_env_keys.py`: it reads the base APK from `source/` (override with
> `--apk`), extracts the secrets from your own copy and writes all cipher variables
> (`FWT_CACHE_CRYPT_*`, `FWT_DATATABLE_CRYPT_*` including the `_REVERSED` forms,
> `FWT_NETWORK_CRYPT_*`, `FWT_ID_KEY_*`) into `.env`. Without these values, features that edit
> encrypted datatables stop with `Missing datatable AES credentials`, while the remaining
> patches work normally.

### Rootless Android Toolchain Setup (Linux)

On Linux servers without `sudo`, the helper script below installs Temurin JDK 21
under `~/tools/jdk` and the Android SDK (`platform-tools` + `build-tools`) under
`~/Android/Sdk`:

```bash
bash scripts/setup-linux-toolchain.sh
```

Then point `.env` to the installed toolchain:

```env
ANDROID_HOME=/home/YOUR_USER/Android/Sdk
JAVA_HOME=/home/YOUR_USER/tools/jdk
```

The patcher automatically prepends `$JAVA_HOME/bin` to subprocess `PATH`s so
`apksigner` locates `java` even in non-interactive shells.

### CPUs Without AVX2 (Legacy x86-64)

`polars` uses the `rtcompat` runtime, which works on CPUs without AVX2 (e.g.,
older x86-64 CPUs). `duckdb` 2.x requires x86-64-v3 (AVX2/BMI2/FMA), so
`requirements.txt` pins the AVX2-free `duckdb==1.5.6` line. Upgrading DuckDB to
2.x is optional and only recommended on modern CPUs.

Building, signing, inspecting, and testing the patcher do not depend on DuckDB.

Main dependencies:
- Runtime & assets (`[assets]`): `UnityPy`, `cryptography`, `Pillow`, `pyelftools`, `capstone`, `keystone-engine`
- Binary analysis (`[analysis]`): `pyelftools`, `capstone`, `keystone-engine`, `unicorn`, `lief`
- Runtime/IL2CPP (`[analysis]`): `frida-tools`
- Data exploration (`[analysis]`): `polars[rtcompat]`, `pandas`, `duckdb`, `orjson`, `ijson`, `jmespath`
- CLI/config: `python-dotenv`, `rich`, `typer`, `pydantic-settings`, `adbutils`
- Quality (`[dev]`): `pytest`, `pytest-cov`, `pytest-timeout`, `hypothesis`, `ruff`, `mypy`, `pre-commit`, `pip-audit`

Dependency vulnerability audit:

```bash
python -m pip_audit
```

## 🧪 Testing

With `.venv` active:

```bash
# Run the unit test suite (works without the proprietary APK):
pytest -q -m "not integration"

# Or run the full suite (unit + integration when source/fwt_0.682_offline_v1574.apk is present):
pytest
```

Unit tests run without the proprietary APK. Integration tests run automatically
when `source/fwt_0.682_offline_v1574.apk` is present; they apply all patches,
validate change counts, hashes, DEX checksums, code-cave layout, idempotency,
and inspector reports.

Runtime validation performed in this project: MuMu Player (Android 15, x86_64
with ARM64 translation, package `com.nexon.fwar`), APK built with all offline
features enabled. The game launched, passed the Hive Terms screen and server
selection, and reached the lobby with the embedded local server responding on
`127.0.0.1:8010`.

---

## 🩺 Troubleshooting

| Symptom | Probable Cause | Solution |
|---|---|---|
| `Missing required packaging tools: zipalign, apksigner, keytool` | Python requirements are installed, but Android SDK Build-Tools/JDK are absent from `PATH` | Install Android SDK Build-Tools 33+ and JDK 17+, set `ANDROID_HOME`/`JAVA_HOME` (or edit `.env`), then run `python fwt_patcher.py --check-tools`. `pip install` does **not** install these binaries. |
| `INSTALL_FAILED_UPDATE_INCOMPATIBLE` | Installed APK is signed with a different key | Back up save, uninstall `com.nexon.fwar`, install the patched APK, and restore save |
| Backup fails on physical phone | App is not debuggable and device is not rooted | Use the `Download/fwt` fallback copy or a rooted device/emulator |
| `Restore requires root` | Writing to `/data/data` requires root | Use an emulator with root `adbd` or restore manually |
| Garbled characters in `--help`/`--inspect` | Legacy `cp1252` console | The CLI replaces unencodable characters automatically; use Windows Terminal / UTF-8 for best output |
| `Input ... is not the supported reference build` | Different APK or version | Supply the 0.682 v1574 reference APK or pass `--force` deliberately |
| `Code cave overlap` | Invalid internal cave layout | Do not edit cave constants without running the layout tests |
| Build fails due to disk space | Temporary files require ~4× the APK size | Free disk space on the volume hosting `output/` |
| `Could not download apktool` | First build has no network and no local jar | Install apktool 3.0.3 and set `FWT_APKTOOL_JAR`, or allow access to the pinned GitHub release |
| Bootstrap says *Resource installation verification failed* | The patched `equipselectlist.unity3d` hash in `classes8.dex` does not match the extracted file | Rebuild with 2.3.0+; the build rewrites the `HASHED_CRITICAL_FILES` constant (17 contract edits) and the resource contract together |
| Bootstrap says *Resource size exceeds the expected limit* | APK has a patched `fwt_resources_v1.zip` but an old resource contract | Rebuild with 2.0.1+; do not mix a patched archive with a 2.0.0 `classes8.dex` |
| Bootstrap UI is Korean | Old build or `--english` not enabled | Rebuild with `--all`/`--english`; 2.0.1 translates all bootstrap strings |

---

## 🤝 Contributing

This repository uses a maintainer-controlled (**authorial / issue-first**) workflow:
open an Issue first, wait for review and the `approved` label before opening a
Pull Request, and keep all contributions in **English**. See
[`CONTRIBUTING.md`](CONTRIBUTING.md) for the full rules and verification steps,
and [`AGENTS.md`](AGENTS.md) if you work with AI coding assistants.

---

## 📄 License

MIT — see [`LICENSE`](LICENSE). The original APK, proprietary game assets, and
player save files are not distributed with this repository.
