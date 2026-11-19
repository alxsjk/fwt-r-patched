# Dev build (development instrumentation)

The GUI's stable IDs for these options are listed in groups 09–11 of the
[Grouped Feature Catalog](FEATURE_CATALOG.md). Pending controls remain marked
as pending and are not enabled by `--all`.

> **Status · Phases 0–8 implemented (Phases 1–6 & 8 device-validated)** · the dev
> *scaffolding* exists (options, CLI, GUI card, naming guard, distribution guard) and
> the binary carries real instrumentation: manifest (`0.682-dev`, `debuggable`),
> dead-code trap map, dispatch log cave, per-patch hit counter, build marker, handler
> timing, log parser / response capture, and the `DEV_DUMP` endpoint — validated with
> unicorn emulation, capstone decoding, and real-device runs (Phase 7 `state_snapshots`
> and Phase 9 `lab_traps` / AppSealing experiments remain pending/experimental). With
> `--dev` alone (no instrumentation flag) `.so` and `.dex` remain byte-identical to a
> release build — asserted by tests, not assumed.

The dev build exists so reverse engineering of the patched client can be done on a
real phone instead of an emulator: the game talks to its embedded server over
`127.0.0.1:8010` inside its own sandbox, so no external sniffer can see it without
root. Instrumentation has to live *inside* the APK.

## Invariants (enforced in code and tests)

1. **`--all` never enables anything dev.** `DevOptions` is a separate dataclass;
   the gameplay flags map to `PatchOptions` only.
2. **Every instrumentation needs the master switch.** `--dev-log` without `--dev`
   is an error (`DevOptions.validate()`); the GUI disables the toggles until the
   master checkbox is ticked.
3. **A dev build is always written to a `*-dev.apk` name.** The CLI and the GUI
   refuse any other name, and the header of the GUI shows `● DEV BUILD`.
   A signed internal `assets/fwt_re_patched_build_type.txt` entry records the
   build identity and selected options independently of its filename. Release packaging and
   registration reject dev or unknown identities and verify the APK. Legacy
   builds without the entry must be rebuilt from the supported reference to be
   distributed as releases.
4. **Release output is provably untouched.** With every dev field at its default,
   `apply_all_patches` returns the same `so_sha256`/`dex_sha256` as before
   (`tests/test_dev_options.py::test_dev_build_is_byte_identical_to_release`).

## CLI

```bash
# release build (writes output/FWT-Reborn-Patched-<version>-release.apk)
python fwt_patcher.py --all -o output/FWT-Reborn-Patched.apk

# dev build: master switch + chosen instrumentation
# (writes output/FWT-Reborn-Patched-<version>-dev.apk)
python fwt_patcher.py --all --dev --dev-debuggable --dev-log \
    -o output/FWT-Reborn-Patched.apk
```

| Flag | Purpose |
| --- | --- |
| `--dev` | master switch; forces a `*-dev.apk` output |
| `--dev-keep-version` | leave `android:versionName` untouched (do not append `-dev`) |
| `--dev-debuggable` | `android:debuggable=true` → `run-as`, JDWP, `log.redirect-stdio` without root |
| `--dev-log` | log embedded-server request JSON to logcat (tag `FWTR-DEV-v<ver>`) |
| `--dev-log-limit BYTES` | max bytes per logged message (`0` = whole body, default 1024) |
| `--dev-log-commands CSV` | command whitelist option (not yet filtered in-cave; logs all commands and warns at build time — filter captures offline with `tools/dev_log_parse.py`) |
| `--dev-counters` | per-request execution counter (used alone or paired with request/response/timing logs) |
| `--dev-marker` | `FWTR-DEV v<ver> ...` logged once at first dispatch (`FWTR-DEV-BUILD`) |
| `--dev-log-response` | log the response body at dispatcher exit (`FWTR-DEV-R-v<ver>`) |
| `--dev-timing` | `cntvct_el0` timing around the JSON dispatcher (`FWTR-DEV-T-v<ver>`) |
| `--dev-snapshots` | numbered state snapshots for diffing *(pending — emits build warning)* |
| `--dev-endpoint` | `DEV_DUMP` command served by the embedded server |
| `--lab-traps` | laboratory: `brk #0` dead-code traps *(pending in main patcher — emits build warning; use `tools/lab_trap_apk.py`)* |

A dev flag whose feature is not implemented yet is reported as a **warning** in
the build log (`apply_all_patches` → `PatchResult.warnings`) and leaves the binary
untouched, so a dev build can never pretend to instrument something it does not.

## GUI

`gui/main_window.py` card **"3. Development — dev build (never distribute)"**:
master checkbox, three groups (*Telemetry*, *Tools*, *Laboratory*), the log limit
and command whitelist fields, and an amber `● DEV BUILD` badge in the header.
Enabling the master switch rewrites the output path to `*-dev.apk` automatically.

## Measured facts that drive the phases (2026-11-11)

Measured on `source/fwt_0.682_offline_v1574.apk`:

- `libfwt_local_server.so` = sha256 `03ec76a1…` = `REFERENCE_SO_SHA256` (matches).
- Library is **unstripped**, 145 `fwt::` symbols; JSON entry point
  **`fwt_stub_handle_json` @ `0x7e3bd8`**; `liblog.so` is already `NEEDED` and
  **`__android_log_print` is already imported** (GOT `0xbdd810`) — a code cave can
  call its PLT. Only **one** call site exists today (`0x7ee0c0`), so there is no
  existing per-request log to piggyback on.
- **Code-cave space is the scarce resource**: no zeroed or NOP-filled region
  ≥ 96 B in `.text` (`0x7DAC80–0xB48DF0`); the ~20 existing caves (from
  `0xb33314`, plus the `FLAN` shim at `0xAB6858`) were carved over existing code.
  `validate_cave_layout()` only detects overlap, never reachability — hence the
  dead-code map (phase 2) before any new cave.
- Manifest: `debuggable=false`, `allowBackup=false`, `targetSdk 34`,
  `zygotePreloadName="com.inka.appsealing.AppSealingZygote"`. Turning
  `debuggable` on (phase 1) unlocks the `run-as` fallback in
  `core/apk_tooling.py` for `--backup` (`--restore` still requires root via `adb root` or `su -c`).
- AppSealing is fully present (`libcovault-appsec.so` 1.53 MB,
  `libPglmetasec_ov.so` 1.04 MB, `assets/AppSealing/` 22 files, Java layer
  **static in `classes.dex`**) and the `il2cpp` section is **still encrypted**
  (entropy 7.994), with the original author's two patches in place
  (`0x1b184f8` = `B #0x7b0`; `0x27e7378` = `MOVZ W0,#1; RET`). Removing
  AppSealing is therefore *not* a shortcut to readable code: it is the decryptor.

## Phase status

| Phase | Feature | Status |
| --- | --- | --- |
| 0 | scaffolding, CLI, GUI card, guards | **done** |
| 1 | manifest: `versionName=-dev`, `debuggable=true` | **done — device-validated** (keep `debuggable` off) |
| 2 | dead-code map for code caves | **done — device-validated** (trap never fired) |
| 3 | dispatch log cave | **done — device-validated** |
| 4 | per-patch hit counters | **done — device-validated** |
| 5 | build marker | **done — device-validated** |
| 6 | handler timing | **done — device-validated** |
| 7 | log parser + response capture | **done** (parser done; `state_snapshots` pending) |
| 8 | `DEV_DUMP` endpoint | **done — device-validated** |
| 9 | laboratory: AppSealing experiments | experimental (`lab_traps`) |

## Phase 1 — the manifest patch (`core/axml.py`)

`core/axml.py` reads and rewrites the binary `AndroidManifest.xml` directly, so a
dev build does not need apktool to decode ~900 MiB of APK. Two edits:

- **`android:versionName`** gets the `-dev` suffix on a dev build (`0.682` →
  `0.682-dev`), unless `--dev-keep-version` asks for it to stay identical. The value is a literal string, so a new entry is
  appended to the manifest string pool: every following chunk shifts by four
  bytes, the pool/Xml chunk sizes are rewritten and the appended string is padded
  so the file stays 4-byte aligned (aapt rejects misaligned XML).
- **`android:debuggable`** (`--dev-debuggable`) flips the boolean typed value in
  place — no size change at all.

Both are strict: a non-boolean `debuggable`, or a `versionName` that is not a
literal string, raises instead of guessing. `tests/test_axml.py` verifies the
result with **`aapt2 dump badging`/`xmltree`**, the same tool the Android build
system uses — a self-consistent parser would only prove it agrees with itself.

What `debuggable=true` unlocks on the device (no root required):

```bash
adb shell run-as com.nexon.fwar ls files/     # read the save and app files
python fwt_patcher.py --backup                # run-as fallback already implemented
python fwt_patcher.py --restore <json>        # requires root (adb root or su -c)
adb shell setprop log.redirect-stdio true     # stdout/stderr of the app -> logcat
```

### Device result: `debuggable=true` breaks the patched build

Measured on the real phone with the 2.5.26 build:

| build | patches | `-dev` name | debuggable | result |
|---|---|---|---|---|
| release | yes | no | no | **works**, save loads |
| lab (phase 2) | no | yes | yes | **works** (Korean, no localization patch) |
| `--dev` + `--dev-debuggable` | yes | yes | yes | **hangs at the sponsor screen** (valofe/vfun) |
| `--dev` (no debuggable) | yes | yes | no | **works**, save loads |

So the `-dev` version string is harmless and `debuggable=true` is the trigger — but
only *together with* the gameplay patches: the lab build has debuggable and runs,
because it never reaches the patched server flow where the check bites.

Consequences: **never ship a device build with `--dev-debuggable`**. The patcher now
prints a loud warning when it is enabled. Without it, `run-as` (and therefore the
`--backup` fallback) is unavailable — use `adb backup`/root (`adb root` or `su -c`) or the save
fixture instead. (`--restore` always requires root via `adb root` or `su -c`.)


## Phase 3 — the dispatch log (`--dev-log`)

`fwt_stub_handle_json(config, json)` at `0x7e3bd8` is the embedded server's JSON entry
point (extern "C", unstripped). Its first instruction is `sub sp, sp, #0x90` and **x1
holds the NUL-terminated JSON payload**, so the hook needs no buffer copy and no length
computation: `%.*s` truncates at `--dev-log-limit` bytes (default 1024), or `%s` logs the
whole body when the limit is 0.

Cave at `0xb29ebc` (inside `itanium_demangle::AbstractManglingParser`, 4,572 B of
assumed-dead code — same family the shipped campaign caves overwrite), 0x120 bytes
budget, ends with the `FDVL` magic. The hook is a single `b` at the function entry; the
cave saves x0–x5/x8/x9/x30, calls `__android_log_print` through its PLT stub
(`0xb464b0`, GOT `0xbdd810`), restores everything, replays the displaced
`sub sp, sp, #0x90` and branches back to `0x7e3bdc`.

Logcat tag: `FWTR-DEV-v<version>` (e.g. `FWTR-DEV-v2.5.50`).

Proof without a phone (`tests/test_dev_dispatch_log.py`, 13 tests): the cave is executed
under **unicorn** — hook branch, saved registers, the `bl` into an instrumented PLT stub,
the truncation argument, the replayed instruction and the branch back — and every encoder
is disassembled with capstone so a wrong opcode cannot pass. A surgical-diff test asserts
the dev build changes **only** the hook word and the cave, and that the DEX stays
byte-identical.

```bash
adb logcat -c && adb logcat -s FWTR-DEV-v2.5.50:V > /tmp/fwtr-log.jsonl
# or, after a session, dump the ring:
adb logcat -d -s FWTR-DEV-v2.5.50:V | tail -50
```



## Phase 4 — the hit counter (`--dev-counters`)

The counter needed writable memory, and a measurement killed the obvious plan:

- `.bss` has **no free tail** (the last `STT_OBJECT` ends exactly at the section
  end) and zero gaps ≥ 64 B; `.data` (696 B) is fully covered by symbols;
- the `.data.rel.ro` "gaps" are relocation tables (684/214/47 relocations inside
  them), i.e. live data;
- the 622 `STT_OBJECT`s that no *relocation* points at are the game's data tables
  (`kFwtInfinityDataRows`, `fwt_pvp_opponents::rows`, …), referenced through
  `adrp`+`add` instead — exactly the false positive the code map already warns
  about.

So the cave makes **its own pages** writable, once per process, through the
library's imported `mprotect` (PLT `0xb476d0`, GOT `0xbde120`) — the same trick the
offline APK author's own framework uses. A magic byte gates the syscall:
`ldrb` → `cbnz` over the call → `mprotect(align16k(base), 0x4000, 7)` → `strb` the
magic.

Two details cost a device crash before they were right:

- the cave base (`0xb29ebc`) and its state block (`+0x280`) land in **different
  pages**, so the range has to cover both — and it must be 16 KB aligned, because
  Android 15 can run 16 KB pages where `mprotect` rejects a 4 KB-aligned address.
  The symptom of getting this wrong is `SIGSEGV / SEGV_ACCERR` at exactly
  `cave + 0x280`;
- if `mprotect` refuses anyway, the cave points its state register at scratch space
  inside its own frame instead of faulting: counters and the marker then mean
  nothing, but the game survives.

The state base lives in **x19** (callee-saved). Every `x0`-`x18` is caller-saved and
`__android_log_print` is free to clobber them — a marker latch that used `x12`
after the call re-logged the marker on every dispatch until this was fixed. The counter lives at
`base+0x1a4` and is printed at the head of every log line:

```
FWTR-DEV-v2.5.50: 1234 {"cmd":"GET_MY_INFO","user_index":993838}
```

Consequences worth knowing:

- the cave page (inside `itanium_demangle`) becomes RWX for the dev build only —
  `--dev-log` alone does **not** do that (test asserts `mprotect` is never called);
- the counter is per **process**, so it resets when the game restarts; it counts
  dispatch calls (one per command), not per gameplay patch;
- counting lines offline (`tools/dev_log_parse.py`, phase 7) is the lossless
  alternative when the logcat ring drops older entries.



## Phase 5 — the build marker (`--dev-marker`)

A dev build announces itself once per process, on its own logcat tag, so any
capture says which build produced it:

```
adb logcat -s FWTR-DEV-BUILD
FWTR-DEV-BUILD: FWTR-DEV v2.5.50 fp=3f9c1a04 n=39 flags=build_marker,dev[...]
```

- `fp` is a fingerprint of the **recipe** — version, number of applied patches and
  the sorted list of enabled instrumentation — so two APKs built differently never
  share a marker and rebuilding the same way reproduces it byte for byte;
- `n` counts the patch groups applied (not the individual sites);
- the line is latched by its own magic byte (`base+0x288`), *before* the log call,
  so three dispatches still print it once;
- with `--dev-marker` alone (no `--dev-log`) the cave logs **nothing per
  dispatch** — only the marker, at the first dispatch;
- the marker is also detected by `fwt_patcher.py --inspect <apk>` and
  `--inspect-so <so>` ("Dev Build Marker"), so a release and a dev APK can be told
  apart without running the game.



## Phase 6 — handler timing (`--dev-timing`)

Two pieces, both emulation-proven:

1. the **entry cave** samples the virtual counter (`mrs x11, cntvct_el0`) and stores
   it in the state block at `base+0x290`;
2. the single `ret` of `dispatch_json_impl` — `0x7ecd68`, the function's only exit —
   branches to a second cave at `0xb2a1bc`, which computes

   ```
   us = (cntvct_el0 - start) * 1_000_000 / cntfrq_el0
   ```

   logs it (`FWTR-DEV-T-v2.5.50: 842 us`) and then replays the displaced `ret`.

Measured on the emulator (Android 15, x86_64 running the arm64 APK through
translation, so the absolute numbers are not meaningful): 5 requests, 5 dispatch
lines, 5 timing lines, one marker, zero crashes — the mechanism works. Real
microsecond values have to come from the phone.

Why hook the returns instead of wrapping the call: a detour (`blr` trampoline) would
put the cave in the middle of the unwind chain, and a C++ exception thrown by a
handler would unwind past a frame with no CFI — a crash. Hooking `ret` needs no frame
juggling and cannot affect unwinding; a handler that throws simply logs no timing.

Caveats worth knowing before reading the numbers:

- the duration covers the whole handler call, including any blocking I/O it does;
- the start tick lives in a **single** slot, so two dispatches overlapping on
  different threads make one of them report a too-large duration;
- `udiv` by zero yields zero on ARM, so a device reporting `cntfrq_el0 == 0` logs
  `0 us` instead of trapping;
- only `x0`/`x1` (the return value) and `x30` must survive the exit cave, so its frame
  is 0x40 bytes and the return value is preserved (asserted by test).


## Phase 7 — turning a capture into data (`tools/dev_log_parse.py`)

The cave family is now four tags, and every one of them is parsed:

| tag | when | body |
| --- | --- | --- |
| `FWTR-DEV-v<ver>` | dispatch entry, every request | `<counter> <request JSON>` |
| `FWTR-DEV-R-v<ver>` | dispatcher exit (`--dev-log-response`) | `<counter> <response JSON>` |
| `FWTR-DEV-T-v<ver>` | dispatcher exit (`--dev-timing`) | `<microseconds> us` |
| `FWTR-DEV-BUILD` | first dispatch of the process | `FWTR-DEV v<ver> fp=<8 hex> n=<patches> flags=<csv>` |

The response comes from the exit hook, but **not** from `x0`: `dispatch_json_impl`
returns its `std::string` by value (the caller sets `x8` to the destination at
`0x7daec4`), and this binary's epilogue never touches `x0` — the sret convention says
the callee should hand the pointer back in `x0`, and here it does not. Trusting `x0`
crashed the process on the first request (the register held leftovers, and reading the
"string" from it faulted). So the **entry** cave stores the incoming `x8` in the state
block (`base+0x298`) and the exit cave reads that slot instead; the pointer is then a
`std::string*` with the same libc++ layout the entry cave reads. The cave logs it with
the counter taken from the state block, so request and response pair by number.

    adb logcat -v time -s FWTR-DEV-v2.5.50:V FWTR-DEV-R-v2.5.50:V \
        FWTR-DEV-T-v2.5.50:V FWTR-DEV-BUILD:V > capture.log
    python tools/dev_log_parse.py capture.log --jsonl records.jsonl --md report.md

The parser accepts both logcat layouts — `-v threadtime` carries pid **and** tid,
`-v time` only pid, so timing pairing falls back to ordering when there is no tid —
flags payloads cut by `--dev-log-limit`, and reports counter gaps (logd's ring
dropping lines) so a truncated capture can never be mistaken for a complete one.

### First real numbers (physical arm64 device, Android 15, 4 KB pages)

69 requests in one lobby session. Almost every command lands in a **46-55 ms band**,
which looks like a deliberate delay rather than real work; the heavy ones stand out:

| command | p50 | max |
| --- | --- | --- |
| `GET_MY_INFO` | 3.64 s | 3.64 s |
| `GET_MAIL_INFO` | 1.36 s | 1.36 s |
| `GET_MY_GUILD_INFO` | 1.08 s | 1.08 s |
| `HIVE_LOGIN` | 547 ms | 547 ms |
| `REQ_ACHIEVE_EVENT_LIST` | 482 ms | 482 ms |
| `GET_SHOP_LIST` | 192 ms | 3.22 s (cold) |

Cross-check: the game's own `LOG_LATENCY` command measured 52 ms, matching our
independent measurement of the same round trip.

## Testing a dev build (no emulator)

The APK targets arm64 only, so the phone is the test device. Over Wi-Fi ADB:

```bash
adb connect <phone-ip>:<port>
adb install -r output/FWT-Reborn-Patched-2.5.50-dev.apk
# phase 1+: read the save without root
adb shell run-as com.nexon.fwar ls files/
# phase 3+: capture the instrumentation
adb logcat -d -s FWTR-DEV:V > /tmp/fwtr-dev-$(date +%F).jsonl
```

Captures are ring-buffered by `logd` (a few MB, oldest entries dropped): nothing
accumulates on the device. Keep a PC attached (`adb logcat ... > file`) for
lossless sessions.

Installing the dev build over the release build is safe while both use the same
`applicationId` and keystore — the savegame survives. Do **not** rename the
package to keep both installed side by side: the 43-byte startup probe carries
`com.nexon.fwar` and the save path is tied to it.

## Phase 8 — `DEV_DUMP`: a command the server answers

`--dev-endpoint` makes the instrumentation cave recognise a request whose body starts
with `{"CMD":"DEV_DUMP"` and **replace the response** the dispatcher produced with a
fixed payload. Nothing else about the request changes: the counter, the timing and the
response log all still fire.

    {"CMD":"DEV_DUMP","x":1}  ->  {"ERROR":0,"DUMP":1}

### How it works

* **Entry cave**: after resolving the `std::string*` in `x1`, the cave compares the two
  leading qwords against `{"CMD":"` and `DEV_DUMP`, then checks that the next byte is the
  closing quote — so `DEV_DUMPX` does not match. A hit stores a byte flag in the cave
  state at `base+0x2A0`.
* **Exit cave**: if the flag is set it is cleared (one rewrite per request), the `sret`
  slot at `base+0x298` gives the destination `std::string`, and the payload is written
  straight into it: short (`SSO`) mode gets the characters at `+1` and `len<<1` in byte 0,
  long mode writes into the heap buffer at `+0x10` and stores the size at `+8`. A NUL
  goes right after, so the `%.s` log line does not print whatever the original body left
  behind.

The rewrite happens before the HTTP layer serialises the response, so `Content-Length`
matches the injected payload — the client sees a clean, well-formed answer.

### Driving it from the bench

The embedded server lives on `127.0.0.1:8010` inside the app sandbox. With root, the adb
shell can talk to it directly — no UI navigation needed:

    adb shell "printf 'POST / HTTP/1.1\r\nHost: 127.0.0.1:8010\r\nContent-Length: 24\r\n\r\n{\"CMD\":\"DEV_DUMP\",\"x\":1}' | nc 127.0.0.1 8010"

This is the tool to reach any game command for diagnosis, DEV_DUMP or not.

### Device results

| check | result |
| --- | --- |
| `DEV_DUMP` answered with the injected body | ✅ `{"ERROR":0,"DUMP":1}`, `Content-Length: 20` |
| flag cleared between requests | ✅ two dumps in a row, counters 6 and 7 |
| response log line clean after the NUL fix | ✅ `... 6 {"ERROR":0,"DUMP":1}` |
| crashes | none |

### Bugs this phase produced (and taught)

* The string-mode branch was inverted (`b.eq` after `tst #1` sent short strings down the
  long path). Caught by disassembling the cave before it reached the device.
* The rewritten body was not NUL terminated, so the `%.s` response log printed the tail of
  the original payload after our bytes. The HTTP client was never affected — only the log.
