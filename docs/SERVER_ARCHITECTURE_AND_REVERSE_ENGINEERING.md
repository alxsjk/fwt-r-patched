# FWT Reborn Server Architecture & Reverse-Engineering Guide

This document provides an exhaustive technical breakdown of the **Fantasy War Tactics (0.682 v1574)** server architecture, covering both the embedded offline APK server and compatible external LAN server implementations. Its goal is to equip developers and modders to host a LAN server and author new deterministic binary patches and extensions independently.

---

## 📑 Table of Contents
1. [Architecture Overview](#1-architecture-overview)
2. [How to Host a LAN Server](#2-how-to-host-a-lan-server)
3. [Protocol, Packet Framing & Cryptography Specification](#3-protocol-packet-framing--cryptography-specification)
4. [Server Modules & Game API Command Breakdown](#4-server-modules--game-api-command-breakdown)
5. [Save State Structure (`fwt_server_state_v1.json`)](#5-save-state-structure-fwt_server_state_v1json)
6. [Reverse-Engineering the Native Binary (`libfwt_local_server.so`)](#6-reverse-engineering-the-native-binary-libfwt_local_serverso)
7. [Step-by-Step Guide to Creating New Binary Patches](#7-step-by-step-guide-to-creating-new-binary-patches)

---

## 1. Architecture Overview

The offline Korean FWT client (`0.682 v1574`) uses a decoupled client-server architecture that runs entirely on the Android device or emulator:

```text
┌────────────────────────────────────────────────────────┐
│                    Android Client                      │
│                                                        │
│   ┌────────────────────────┐  TCP Socket 127.0.0.1     │
│   │    Unity 3D / C#       │◄───────────────────────┐  │
│   │   (UI & Battle Logic)  │  (Loopback Port 8010)  │  │
│   └───────────┬────────────┘                        │  │
│               │                                     │  │
│               ▼                                     ▼  │
│   ┌────────────────────────┐  fork/execve   ┌───────┴────────────────┐
│   │   classes8.dex Java    │───────────────►│ libfwt_local_server.so │
│   │   (Process Bootstrap)  │                │  (Local ELF Server)    │
│   └────────────────────────┘                └────────────────────────┘
└────────────────────────────────────────────────────────┘
```

### Connection Modes Supported by the Patcher

1. **Offline Standalone (Default)**:
   - The game spawns `libfwt_local_server.so` on the device.
   - Unity connects to `127.0.0.1:8010`.
   - All gameplay modifications (10x gold, 10x XP, 70/20/10 or 50/30/20 summon rates, 10x event coins, 90% event shop discount, etc.) run **directly inside the native binary** without any external server.

2. **LAN Server Redirect (`--lan IP:PORT`)**:
   - An **ARM64 Assembly shim** (`0xAB6858`, magic `FLAN`) intercepts `connect()` calls targeting `127.0.0.1:8010` and redirects them to the configured LAN IP and port (e.g., `192.0.2.20:8010`).
   - On-device native server spawning is neutralized (`NOP`s at the spawn `BL` sites `0xAADF34 .. 0xAAE07C`).
   - Enables multiple phones and emulators to play on the same server, share a database, and use the web account portal.

---

## 2. How to Host a LAN Server

To run a dedicated server on a machine on your local network (Windows or Linux), configure a compatible FWT LAN server implementation listening on port `8010`.

### 2.1 Requirements
- **Python 3.10+** (64-bit)
- Operating System: Windows 10/11 or Linux (Ubuntu 22.04+, Debian 12+)
- Phone or emulator connected to the same Wi-Fi / LAN as the server PC.

### 2.2 Step-by-Step Setup

1. **Find Your Host Machine's LAN IP**:
   - **Windows**: Run `ipconfig` in PowerShell and look for your adapter's *IPv4 Address* (e.g., `192.0.2.20`).
   - **Linux**: Run `ip addr` or `hostname -I`.

2. **Configure Environment Variables (Optional)**:
   Create or edit `.env` in your LAN server root:
   ```ini
   FWT_HOST=0.0.0.0
   FWT_PORT=8010
   FWT_DEFAULT_LANGUAGE=en
   FWT_ID_KEY_START=
   ```

3. **Install Server Dependencies**:
   ```bash
   pip install aiohttp cryptography pydantic
   ```

4. **Open the Firewall Port**:
   - **Windows Defender Firewall**:
     ```powershell
     New-NetFirewallRule -DisplayName "FWT Reborn Server" -Direction Inbound -LocalPort 8010 -Protocol TCP -Action Allow
     ```
   - **Linux (ufw)**:
     ```bash
     sudo ufw allow 8010/tcp
     ```

5. **Start the Server**:
   Launch your compatible LAN server bound to `0.0.0.0:8010`:
   ```text
   [LAN Server] Listening on 0.0.0.0:8010
   ```

6. **Build an APK Pointing to the LAN Server**:
   In the patcher GUI (`fwt_patcher.py`):
   - Select **Redirect to LAN Server**.
   - Enter your host IP (e.g., `192.0.2.20`) and port (`8010`).
   - Click **Generate Patched APK Only** or **Generate & Install via ADB**.

---

## 3. Protocol, Packet Framing & Cryptography Specification

Communication between the Unity client and the local/LAN server runs over TCP port 8010.

### 3.1 Packet Framing
Every network message uses a 4-byte length prefix:
```text
┌─────────────────────────┬──────────────────────────────────────────┐
│   Payload Length (4B)   │              Message Body                │
│    uint32 Big-Endian    │  (43-byte probe OR encrypted JSON body)  │
└─────────────────────────┴──────────────────────────────────────────┘
```

### 3.2 Initial Handshake (Startup Probe)
Immediately upon connecting, the client sends a 43-byte startup probe:
- **Length**: `0x00000027` (39 bytes following the 4-byte header)
- **Signature**: Begins with the client connection identifier and package name (`com.nexon.fwar`).
- **Expected Response**: The server replies with an HTTP/200 handshake confirmation or binary session ACK packet to unlock the Unity loading screen.

### 3.3 Packet Cryptography & Codec (`codec.py`)
1. **Compression**:
   - JSON payloads are compressed with raw DEFLATE / `zlib`.
2. **Symmetric Encryption (AES-128-CBC / AES-256-CBC)**:
   - **Key**: Derived from the session token / handshake cipher material.
   - **IV (Initialization Vector)**: 16-byte initialization vector.
3. **Packet Signature**:
   - To prevent spoofing or corruption, packets carry a token computed as:
     $$\text{Token} = \text{MD5}(\text{id\_start} + \text{login\_code} + \text{id\_end})$$

### 3.4 Embedded Offline Server (`libfwt_local_server.so`) — Measured Wire Format

The shipped offline build does **not** use the framed/AES codec above. Traffic to
`127.0.0.1:8010` is plain HTTP/1.1 with a raw-DEFLATE JSON body:

```text
POST / HTTP/1.1
Host: [::1]:8010
User-Agent: UnityPlayer/2019.4.40f1 (UnityWebRequest/1.0, libcurl/7.80.0-DEV)
accept: application/json
accept-charset: utf-8
accept-encoding: deflate
user_index: <lord_idx>
Content-Type: application/x-www-form-urlencoded
X-Unity-Version: 2019.4.40f1
Content-Length: <n>

<raw DEFLATE (RFC 1951) of the JSON request>
```

The response is uncompressed JSON: `{"CMD":..,"packet_no":..,"ERROR":0,"msg":"",..}`.
`ERROR` is `0` on success and negative on failure; `-101` is the generic
"handler refused" code that the client renders as a message box.

A request body is a flat object; handlers validate an exact field list through the
server's `ExactJsonAccess` helper, so extra or missing keys are rejected before
any work happens. Example (`RIDDLE_START`, the VIP ticket dungeon entry):

```json
{"CMD":"RIDDLE_START","packet_no":72,"lord_idx":993838,"access_code":"local-access-code",
 "req_recommend_friend":true,"dg_code":"950233","combat_power":0,"num_hero":0,"mail_idx":1484}
```

Reproducing traffic: `strace -f -e trace=read,recvfrom -s 600 -p <pid> -o <file>`
on the app process shows both request and response bodies in clear text, and
`adb forward tcp:18010 tcp:8010` lets a host script talk to the server directly
(`tools/probe_local_server.py`).

The binary keeps a full `.symtab`, which resolves the riddle path without a
disassembler: `riddle_stamina_cost_for_dungeon_id` (`0x8D6DC0`, cost
`(dg_code & 0xf) * 2 + 8`, `-1` when the low nibble is above 3 or the base is not
an approved ticket base), `riddle_base_dungeon_id_for_ticket_id` (`0x8DC6EC`),
`is_approved_riddle_ticket_product_shop_code` (`0x87F74C`, only `70132`, `70133`
and `70134`) and the `RiddleTicketIdentityStateAccess` ticket migrations. Inside
`dispatch_json_impl`, the `RIDDLE_START` branch at `0x803C2C`-`0x803C78` has four
refusal exits (`0x804B9C`/`0x80B750`): exact-field validation, mail lookup,
`dg_code` parse and the stamina-cost check.

---

## 4. Server Modules & Game API Command Breakdown

### 4.1 Typical External LAN Server Components
- `server`: Async TCP and HTTP (`aiohttp`) server managing client sockets, handshakes, and static endpoints.
- `router.py`: Route dispatcher. Receives decoded messages, validates sessions, and dispatches requests to the rules engine or native Core Host.
- `codec.py`: Serialization, 4-byte framing, zlib compression, and AES encryption.
- `rules.py`: **Reborn Standard Rules Engine**. Intercepts gacha rolls, equipment enchantments, progression, and cash shop gates.
- `rebalance.py`: Rebalances the event shop and campaign map multipliers.
- `accounts.py`: Multi-user account database with PBKDF2-SHA256 password hashing.
- `portal.py`: Embedded web interface accessible via the in-game *News* button in the lobby for account switching and save backups.
- `localization.py`: Strips forced Korean strings and injects the English language pack.

### 4.2 Game API Command Reference

| Command | Description & Server Action |
|---|---|
| `req_login` | Initial Lord authentication. Validates credentials and returns player profile, gold, crystals, and stamina. |
| `req_attendance` | Processes daily check-in and grants attendance calendar rewards. |
| `req_get_server_time` | Returns synchronized Unix timestamp for events and laboratory timers. |
| `req_notice` | Loads lobby banners and news (redirected to the account portal in LAN mode). |
| `req_mail_receive` | Claims items from the mailbox and credits them to inventory (`equipments`, `items`). |
| `req_hero_info` | Returns stats, genes, equipped gear, and skill levels for all unlocked heroes. |
| `req_hero_level_up` | Consumes EXP materials and gold to level up a hero. |
| `req_hero_grade_up` | Promotes a hero to the next star rank (up to 6★). |
| `req_hero_skill_level_up` | Upgrades active/passive hero skills using genes. |
| `req_hero_potential` | Rerolls hero potential slots using essences. |
| `req_get_my_equipment_info` | Returns all equipment pieces in the player's inventory (weapons, armor, accessories). |
| `req_equip_enchant` | Equipment enhancement (`+1` to `+26`). |
| `req_equip_transcend` | Transcends SS/Set equipment to raise its maximum enhancement cap. |
| `req_equip_disassemble` | Disassembles equipment into fragments and alchemy powder. |
| `req_equip_transform` | Reforges equipment type or secondary stats. |
| `req_get_equipment_hole` | Unlocks equipment gem slots using *Dragon Fangs*. |
| `req_gacha` / `req_shop_purchase` | Equipment summons. Applies the configured **70/20/10** or **50/30/20** distribution (0% 1★–3★). |
| `req_shop_list` | Returns the gem and gold shop catalog. |
| `req_event_shop` | Special event shop catalog and purchases. |
| `req_stage_start` | Validates stamina consumption and initiates a campaign or island battle. |
| `req_stage_clear` | Validates stage completion and computes 10x Gold, 10x XP, and 10x Event Coin rewards. |
| `req_expedition_start` | Dispatches heroes to explore one of the 19 expedition regions. |
| `req_expedition_complete` | Completes an expedition and grants multiplied rewards (**10x XP, crystals, mana, coins, genes, and items**). |
| `req_guild_info` | Returns guild data, member list, and raid scores. |
| `req_guild_raid_clear` | Settles a Guild Raid attack. Storage and settlement already use 64-bit integers; `guild_raid_score_fix` fixes the signed 32-bit `bonus_limit` in the start response. |
| `req_lab_tool_info` | Queries laboratory tool timers (Gold Cylinder, Mana Stone Compactor, Energy Flask, Genetic Analyzer). |
| `req_lab_tool_craft` | Collects/uses a laboratory tool charge; `energy_flask_x10`, `gold_cylinder_x10`, and `mana_cylinder_x10` multiply yields by 10x (legacy `flask_3h` was removed in 2.5.35). |

---

## 5. Save State Structure (`fwt_server_state_v1.json`)

The complete player state is persisted as JSON at `/data/data/com.nexon.fwar/files/fwt/fwt_server_state_v1.json`.

### Primary Root Keys
- `"lord"`: Player profile (`lord_id`, level, Lord XP, current stamina, gold, crystals/gems).
- `"heroes"`: Dictionary or list of unlocked heroes, each containing:
  - `"crs_idx"`: Numeric hero ID (e.g., `10010` for Lord, `10020` for Chris).
  - `"grade"`: Star rating (1 to 6).
  - `"crs_level"`: Current level (1 to 120).
  - `"experience"`: Accumulated EXP.
  - `"skills"`: Skill levels for each of the character's 3–5 skills.
  - `"equip_slots"`: Item IDs equipped in weapon, armor, and accessory slots.
- `"equipments"`: List of all equipment pieces owned by the player:
  - `"idx"`: Unique inventory instance ID.
  - `"equip_code"`: Equipment template code (e.g., `"01011520"`).
  - `"enchant_cnt"`: Current enhancement level (`+0` to `+26`).
  - `"star"` / `"grade"`: Equipment grade (4★, 5★, 6★).
  - `"options"`: Rolled bonus stats and magical properties.
- `"items"`: Materials, consumables, essences, and genes (stored as `item_code` and `count`).
- `"stage_clear_info"`: Cleared stages, SSS ratings, and map achievements.
- `"laboratory"`: Recharge timers for laboratory tools (including the Mana Stone Compactor) and alchemy slots.

---

## 6. Reverse-Engineering the Native Binary (`libfwt_local_server.so`)

`libfwt_local_server.so` is a **64-bit ARMv8-A (AArch64) ELF shared library** compiled with Clang/LLVM against Android Bionic.

### 6.1 Virtual Memory Mapping & Section Deltas
When patching raw file buffers, virtual addresses map to file offsets via fixed section deltas:
- **Executable Code (`.text`)**:
  $$\text{File Offset} = \text{Virtual Address (vaddr)} - 0x4000$$
  *Example: Virtual `0xAA6BFC` $\rightarrow$ File offset `0xAA2BFC`.*
- **Relocatable Read-Only Data (`.data.rel.ro`)**:
  $$\text{File Offset} = \text{Virtual Address (vaddr)} - 0x8000$$
  *Example: Virtual `0xB9DFD0` $\rightarrow$ File offset `0xB95FD0`.*
- **Read-Only Data & Strings (`.rodata`)**:
  $$\text{File Offset} = \text{Virtual Address (vaddr)}$$

### 6.2 Resolving Symbols Without Ghidra / IDA
The original binary retains its full symbol tables (`.symtab` and `.dynsym`). You can inspect any function directly from Python:
```python
import struct

# Each ELF64 .symtab entry is 24 bytes:
# uint32 st_name, uint8 st_info, uint8 st_other, uint16 st_shndx, uint64 st_value, uint64 st_size
```

### 6.3 The Code Cave (`0xB33314 .. 0xB3384C`)

> ⚠️ **Important:** `0xAA6BFC` is **not free space**. It is the entry point of
> the exported `fwt_egl_swap_buffers_clear_compat` function called by Unity
> during startup. Legacy patcher versions overwrote this range and caused a
> startup `SIGSEGV` at `0xAA6BFC`. Runtime testing on MuMu (Android 15)
> reproduced the crash and the cave was relocated.

The current code cave resides at `0xB33314`, inside an unreferenced libc++
Itanium demangler function (`...itanium_demangle7NewExpr9printLeft...`, size
`0x538`). Static analysis confirmed zero direct branches, `ADRP+ADD`
references, pointers in `.data.rel.ro`/`.rodata`/`.got`, vtable entries, or
`.init_array`/`.fini_array` pointers targeting this function. The reference
SHA-256 check continues to guard against binary version drift.

| Virtual Address Range | Size | Current Patcher Usage |
|---|---|---|
| `0xB33314 .. 0xB33348` | 52 bytes | Campaign Gold Multiplier (10x; stack flag at `[sp]` + roll multiplication) |
| `0xB33348 .. 0xB3336C` | 36 bytes | Gene Drop Quantity Multiplier (10x) |
| `0xB3336C .. 0xB333A0` | 52 bytes | Mana / Potion Quantity Multiplier (10x) |
| `0xB333A0 .. 0xB333DC` | 60 bytes | Unused (legacy item cave slot; moved to `0xB33734`) |
| `0xB333DC .. 0xB333EC` | 16 bytes | Campaign Event Coin Multiplier (10x) |
| `0xB333EC .. 0xB33408` | 28 bytes | Expedition Rewards Multiplier (10x) |
| `0xB33408 .. 0xB33414` | 12 bytes | Dimension Breakthrough Drop Multiplier (10x) |
| `0xB33424 .. 0xB33534` | 272 bytes | Client installer + runtime hook for 64-bit Guild Raid scores |
| `0xB335C4 .. 0xB33610` | 76 bytes | Guild Raid `bonus_limit` (-1) server sentinel cave |
| `0xB33634 .. 0xB3367C` | 72 bytes | Battle Arena Save client hook (post-covault) |
| `0xB3367C .. 0xB336C8` | 76 bytes | Single Dragon Fang client gate hook (RVA `0x1DCACEC`) |
| `0xB336D8 .. 0xB33724` | 76 bytes | Guild Raid self-mercenary client filter hook |
| `0xB33724 .. 0xB33734` | 16 bytes | Unknown Paradise World Boss Settlement Manastone (10x) |
| `0xB33734 .. 0xB337A4` | 112 bytes | Item Drop Multiplier (10x; campaign + Nephthys + Lost Island) |
| `0xB337A4 .. 0xB337B0` | 12 bytes | Dimension Breakthrough gene count multiplier (10x) |
| `0xB337B4 .. 0xB33800` | 76 bytes | One Modification Stone client hook (RVA `0x1CF069C`) |
| `0xB33800 .. 0xB33820` | 32 bytes | Free (Select All 4★/5★ was removed in 2.5.35) |
| `0xB33820 .. 0xB3384C` | 44 bytes | **Free Space for Future Patches** |

The campaign gold trampoline uses two segments: the first stores a campaign
stage flag in a free stack slot (`[sp]`) and the second multiplies the rolled
gold value by 10. (The legacy implementation used bit 32 of `x21`, which was
clobbered by intermediate function calls between the two hook sites.) The item
trampoline uses the same stack flag with values 0/1/2: 0 = no multiplier,
1 = campaign (category-2 items only), 2 = Nephthys/Lost Island item rewards.
It recognizes stage prefixes `0x10-0x12`, `0x70-0x71` and `0x80-0x81`; the
Nephthys/Lost Island item multiplier requires `campaign_gold` (enabled by
`--all`) because the trampoline is installed by that patch.

The event-coin hook is placed at `0x8D05C0` (`mov x0, x19`), the common return
path of `battle_event_coin_reward`, rather than `0x8D05B8` (which only ran on
the string-cleanup path), ensuring the 10x multiplier applies unconditionally.

Internal branches within trampoline blobs are PC-relative and remain valid when
relocated; branches exiting the cave are encoded with
`core/core_patches.py::encode_arm64_branch`. Cave disjointness is enforced at
runtime by `validate_cave_layout()` and tested in `tests/test_core_patches.py`.

### 6.3.1 Guild Raid 64-bit Score Fix

The `bonus_limit` field in `REQ_START_GAME_GUILD` is declared as a signed
32-bit `int` in the client. Once the stored daily record exceeds
`2,147,483,647`, the client's JSON parser throws a `NullReferenceException` in
`ParseRecievePacket`/`OnStartGuildRaid` before the battle starts. While the
native server already stores and settles scores in 64-bit integers, the start
response transport overflows.

`guild_raid_score_fix` (CLI `--guild-raid-score-fix`, GUI
**Guild Raid 64-bit Scores (>2.5B)**) installs two components:

1. **Server sentinel** (`0x831CE4` → cave `0xB335C4`): preserves the clamp of
   negative values to zero, and for values above `INT32_MAX` emits `-1` only if
   the client hook trampoline is confirmed present in memory; otherwise emits
   `0` (safe fallback for unpatched clients).
2. **Client runtime hook** (installer at `0xAB00D8`, trampolines at client RVAs
   `0x158C744` and `0x158CF94`): when `bonus_limit == -1`, reads the real
   64-bit score from `rank_list[0].rank_score` and passes it to
   `BattleGuildRaidScore.set_scoreLimit`.

Runtime validation on MuMu (Android 15, ARM64):
- Synthetic save with `guild_raid_score=3000000000`.
- `REQ_START_GAME_GUILD` returned `bonus_limit=-1` and
  `rank_list[0].rank_score=3000000000`.
- Client logged `FWTGuildRaid: scoreLimit=3000000000`.
- Battle started and `REQ_RESULT_GAME_GUILD` completed with `ERROR=0`.

### 6.3.2 Single-Material Upgrades (Black Hammer & Dragon Fang)

Two independent patches reduce upgrade material consumption to 1 unit:

- **`single_black_hammer`** (`0x8A7404` in
  `EquipmentTranscendStateAccess::transcend`): replaces `sub x22, x8, #0xe`
  (`level - 14` black hammers for levels 15..19, item `130006`) with
  `mov w22, #1`. Levels 20..25 already consume 1 unit of item `130027`.
- **`upgrade_no_fail_above_20`**: sets the six entries of
  `equipment_infinite_transcend_success_percent` (`0x6BAE64`) from
  `100/90/80/70/60/50` to `100`, so the +21..+26 failure and insurance paths
  are never taken.
- **`single_gem_fang`** (`0x7F5148` in `REQ_EQUIPMENT_SET_HOLE`): replaces
  `csinc x24, x9, xzr, ne` (which derived Dragon Fang count from the slot
  number for item `2060051`) with `mov x24, #1`.

### 6.3.3 Laboratory Timers (Gold Cylinder vs. Mana Stone Compactor)

The laboratory has four tools; the two timer-driven production tools are:

- **Tool Type 1 (Gold Cylinder)**: single 21,600s (6h) production cycle. Sites:
  `0xA63708` (refresh) and `0xA6517C`, `0xA651E8`, `0xA653DC` (use).
- **Tool Type 2 (Mana Stone Compactor)**: accumulates up to 5 charges at
  7,200s (2h) per charge in the reference build. Sites: `0xA63904`, `0xA6390C`
  (refresh) and `0xA6649C` (use).

- **`flask_3h`** *(removed in 2.5.35; superseded by `energy_flask_x10`, `gold_cylinder_x10`, and `mana_cylinder_x10`)*: previously updated only the three tool type 2 sites from 7,200s to 10,800s (3h per charge), paired with `tools/patch_labcount_datatable.py` for the external `laboratorycount.unity3d` datatable.
- **`gold_cylinder_fix`** *(historical, superseded in 2.5.35 by `gold_cylinder_x10`)*: previously verified and restored all four tool type 1 sites to 21,600s.

### 6.3.4 Daily Event Shop Gene Limit

The Event Shop catalog is an embedded JSON table inside `.so`. Hero gene rows
have `"item_category":18` and `"limit_max":100`. **`event_gene_unlimited`**
replaces the `limit_type=1/limit_max=100` fragment with
`"limit_type":255,"limit_max":9` across all 33 Event Shop gene rows,
preserving byte length so all `.rodata` offsets stay intact while leaving the
5 non-gene rows untouched. `limit_type=255` is the catalog's no-limit sentinel
(the same value used by existing unlimited products); the previous `-1/-1`
replacement could leave a gene item blocked after a large first purchase.

**`event_limits_daily`** converts every `"limit_type":3` row (the client's
"Lifely"/event period, which never resets) to `"limit_type":1` (daily) while
keeping `limit_max`. **Every** `"limit_type":4` row (event/Honor period) is
converted too, so those purchases no longer stay blocked on the event cycle.
Gem-upgrade materials limited to 3 per event therefore become 3 per day and
can be purchased again after the daily reset. The replacement is
byte-length preserving; monthly rows outside the Event Shop are untouched.
Reference total: 1,423 matches (1,224 `limit_type=3` + 199 `limit_type=4`).

### 6.3.5 Kraken Scale World Boss Event Reward

The offline server's fixed World Boss rotation exposes events `10001`–`10003`.
The event reward table at `0x75F6A8` has 24-byte rows `(event_code, reward_type,
resource_type, resource_id, min, max)`. Event `10002` holds stock
`(65538, 2, 255, -1, -1, -1)` (`row_type == 2`, the Mobile Repair Shop trigger
in `WORLDBOSS_RESULT_EVENT` at `0x849328` that opens `worldboss_travel_repair_offer`),
so `mode_drops_x10` keeps `0x75F6C0` intact (and repairs older builds back to
stock) instead of overwriting it, granting daily Kraken Scales cleanly via
`WORLDBOSS_DAILY_KRAKEN_SITE` (`0x8E69F4` -> `0xB2AB00`, 500 + 500/day).

### 6.3.6 Sacred Lands Set Restoration

The support-only slot-IV set `4028` ("Sacred Lands") is present in
`setitemtableenglish.unity3d` with `_itemGrade: 1`, while all of its
`equiptable.json` pieces are `_equipGrade: 4`. Grade-based client filters hid
it from the grade-4 rotation and ticket lists. `sacred_lands_restore`:

- rewrites both 4028 rows to `_itemGrade: 4` in the base/Chinese/English/
  Japanese `setitemtable*.unity3d` bundles (other locales contain no 4028 row);
- adds `(10001, 4028)` and `(10004, 4028)` to `equipselectlist.unity3d`;
- recomputes the bootstrap's hardcoded `equipselectlist` hash
  (`A6AE3829…`) in `FwtResourceBootstrapActivity.smali`, because the
  `HASHED_CRITICAL_FILES` table verifies that file after extraction.

The rotation pair table `(4028, 4101)` already exists in
`fwt_six_star_rotation_pairs`; no rotation data change is required.

### 6.3.7 Coocoo Garden Level x2

The 30 coocoo reward stage rows start at file offset `0x735488`, 140 bytes
each, and store the exp-creature level at row offsets `+68`/`+72`. Levels are
`2,4,8,20,60,100,130,150,185,220` for the Rock (700010–700100), Scissors
(701010–701100) and Pit of Nephthys (702010–702100) tiers. `coocoo_level_x2`
doubles both fields, producing four level-440 coocoos on the final stages. The
patch is idempotent and reports 30 rows. Runtime validation on Rock Coocoo's
Garden 10 (2.5.0) shows four level-440 coocoos on the result screen and four
new `00210841` monsters at level 440 in the save; 2.5.5 adds the 702 tier,
which is the table used after a Pit of Nephthys reset.

### 6.3.8 Guild Raid Self-Mercenary

`guild_battle_hired_projection` (`0x930034`) first rejects selecting the
player's own lord (`0x930100`). A bare NOP of that check fails because the
function then computes a row index as `lord_idx - 9900001` and bounds it to
999 (`0x930118`/`0x930138`) before reading the 1,000-entry offline PVP
opponent table at `0xBA8BE8`. The player's own lord ID (for example `993838`)
is outside that range, so `x21` becomes null and the projection returns empty.
The shipped self-mercenary patch solves this by branching into a save-reading
code cave at `0xB34860` (`tools/gen_merc_cave.py`); see
[GUILD_RAID_SELF_MERCENARY.md](GUILD_RAID_SELF_MERCENARY.md) for the complete
slot map and implementation.

### 6.3.9 50/30/20 Summon Profile

Alongside the classic 70/20/10 profile (`summon_rates`), the patcher supports
**`summon_rates_50_30_20`** (50% 4★, 30% 5★, 20% 6★). Both profiles reuse
`apply_summon_rates()` with distinct target weight dictionaries and are
mutually exclusive. `--all` defaults to the 50/30/20 profile; pass
`--summon-rates` to select 70/20/10 instead.

### 6.3.10 Multi-Extraction "Select All" Includes 4★/5★ (removed in 2.5.35)

The `select_all_4_5` client hook was demoted in 2.5.35 because it caused
game crashes. Its 108-byte grade stub previously occupied `0xB337B4`; that
space now holds the One Modification Stone client hook (`0xB337B4..0xB33800`).

### 6.3.11 Limit Break Gold Cost, Coocoo EXP Bonus & Stamina

- **`limit_break_gold_half`** *(historical legacy)*: halved the `gold_cost` field (`+20`)
  across all 45 rows of `kFwtCreatureLimitBreakCosts` (`0x756CF0`), leaving
  material item codes and counts untouched (superseded by `limit_break_cost_tenth` / `limit_break_cost_fixed`).
- **`limit_break_cost_half`** *(removed in 2.5.35; superseded by `limit_break_cost_tenth` and `limit_break_cost_fixed`)*: previously halved both the material count (`+16`) and the
  gold cost (`+20`) for all 45 rows.
- **`no_equip_drops`**: clears `_rewardEquipChance` (stage row index 10) on all
  431 stages that had equipment drops and apportions its weight across the
  remaining eligible categories in the same row.
- **`recycle_hammer_rewards`** *(removed in 2.5.35; superseded by `recycle_six_star`)*: previously replaced the equipment grant in
  `EquipmentDisassembleStateAccess::disassemble` with item tickets. A selector
  trampoline at `0x89CEF8` saved the native table selector in `[sp+0x2F8]`;
  the completion trampoline at `0x89D150` granted `130001`–`130005` (class I–V
  equipment transcendence tickets) for normal completions and `130006`
  (Ultimate Transcendence Ticket, the black +16..+20 hammer) for the final
  full-bar step. In `2.5.50`, `recycle_six_star` fills the 873 rows in `kFwtEquipRewardRows`
  tables 102–111 with balanced 6★ set equipment pieces (matched in client `equipreward*.unity3d`). Alchemy points
  (`110001`–`110005`) are unchanged.
- **`coocoo_exp_x2`**: replaces `cset w8, eq` at `0x7FCF30` in
  `SUMEXP_CREATURE` with `mov w8, #1` so the 2x EXP bonus applies to every
  level-up material.
- **`devil_boost_x10`**: changes the Devil's Soul EXP-synthesis multiplier at
  `0x6C49D8` from `2.0` to `20.0`. The `SUMEXP_CREATURE` handler detects a
  Devil's Soul ingredient and multiplies the summed ingredient EXP by this
  float.
- **`mode_drops_x10`**: the Battle of Honor result immediate at `0x83FCF0`
  grants 60 coins instead of 6; Dimension Breakthrough's gene chance gate is
  bypassed (`0x83C1E4` NOP) and the rolled gene count is multiplied by 10
  (`0x83C25C` -> cave `0xB337A4`).
- **`stamina_cost_half` (default in `--all`)**: patches
  `BattleSecondStartStateAccess::charge` (`0x8D744C`) from
  `sub x0, x27, x28` to `sub x0, x27, x28, lsr #1`, halving server-side stamina
  deduction across World Conquest, Tower of Dawn, Sky Library, Lost Island, and
  Tower of Mirage.
- **`stamina_potion_1000`**: replaces `csinc x21, x0, xzr, gt` at `0x8EC1E8` in
  `StaminaItemStateAccess::use_potion` with `mov x21, #1000`, making normal
  Stamina Potions restore 1,000 stamina points.

### 6.3.12 Unknown Paradise Battleship Part Discount

`worldboss_ship_part_gold_cost` (`0x977FB8`) returns an int64 gold cost from
three `.rodata` arrays: common costs at `0x75F790` (30 values), part-5 costs at
`0x75F880` (10 values), and part-7 costs at `0x75F950` (4 values). Parts 1–4
and 6 share the common array; part-level caps are at `0x75F768`
(`30,30,30,30,10,30,4`). `ship_parts_90_off` (originally `ship_parts_half` at 50% in
2.5.4) applies a 90% discount (`ceil(cost / 10)`) to all 41 non-zero entries, so
`WORLDBOSS_SHIP_PART_LEVELUP` charges 10% of the original gold. The client does
not embed these values; the discount is entirely server-side. Runtime check:
part 1 level 1→2 charged 500 gold (raised from 2,500 in 2.5.4; original 5,000).

### 6.3.13 Unknown Paradise Core Crystal Discount

`WORLDBOSS_SHIP_SKILL_LEVELUP` upgrades the three crystal skills
(Banishing/Calming/Circulating Light). The handler at `0x84A2C0` spends a
hard-coded 50 Kraken Scales (`280001`) per level before calling
`worldboss_set_ship_skill_level`. `crystal_skill_90_off` changes that immediate
to 5 (`42068052` -> `a2008052`). The client `crystalskillcost.unity3d` table has
29 levels × 3 skills, all 50; the build rewrites all 87 fields to 5 so the Core
Processing Plant UI and the client pre-check show the discounted price. The
resource archive hash is recomputed and written into the bootstrap DEX. Runtime
check: skill 1 level 1→2 deducted 5 Kraken Scales (590 → 585).

---

## 7. Step-by-Step Guide to Creating New Binary Patches

To create a new deterministic binary modification:

### Step 1: Locate the Target Site
1. Inspect `libfwt_local_server.so` using Python (`pyelftools` / `capstone`) or Ghidra by symbol name.
2. Record the virtual address (`vaddr`) and original 4-byte ARM64 instruction.

### Step 2: Encode ARM64 Instructions in Little-Endian Hex
Every ARM64 instruction is a 32-bit little-endian word:
- 64-bit register multiply (`mul x19, x19, x8`):
  `0x9B087E73` $\rightarrow$ `bytes.fromhex("737e089b")`
- Load immediate (`mov w8, #10`):
  `0x52800148` $\rightarrow$ `bytes.fromhex("48018052")`
- Logical shift left to double a register (`lsl x2, x2, #1`):
  `0xD37FF802` $\rightarrow$ `bytes.fromhex("02f87fd3")`

### Step 3: Build a Code Cave Trampoline (If Needed)
Use `encode_arm64_branch` from [`core/core_patches.py`](../core/core_patches.py):
```python
def encode_arm64_branch(src_vaddr: int, dst_vaddr: int, *, link: bool = False) -> bytes:
    delta = dst_vaddr - src_vaddr
    imm26 = (delta // 4) & 0x03FFFFFF
    opcode = (0x94000000 if link else 0x14000000) | imm26
    return struct.pack("<I", opcode)
```

1. **At the hook site**: Replace the original instruction with an unconditional branch `b cave_vaddr`.
2. **Inside the Code Cave** (see [`docs/CODE_CAVES.md`](CODE_CAVES.md) for current remaining headroom such as `0xB2AE18..0xB2B098` or `tools/dead_code_map.py` `demangler-only` candidates, registered in `validate_cave_layout()`):
   - Execute the displaced original instruction.
   - Apply your custom register manipulation.
   - Jump back to the instruction following the hook: `b (src_vaddr + 4)`.

> Never use `0xAA6BFC..0xAA6D2C` (`fwt_egl_swap_buffers_clear_compat`). Always
> allocate from audited headroom in [`docs/CODE_CAVES.md`](CODE_CAVES.md) and
> register the range in `validate_cave_layout()`.

### Step 4: Register the Feature in the Patcher
1. [`core/core_patches.py`](../core/core_patches.py): Add the boolean field to `PatchOptions`, add the expected count to `EXPECTED_PATCH_COUNTS`, and implement `apply_your_feature(so_buf)` (or place multi-asset modules alongside it in `core/`).
2. [`core/patch_inspector.py`](../core/patch_inspector.py): Add detection in `inspect_native_so()` and map the option in `expected_feature_keys()`.
3. [`gui/feature_catalog.py`](../gui/feature_catalog.py) and [`docs/FEATURE_CATALOG.md`](FEATURE_CATALOG.md): Assign a new permanent Feature ID (never renumber or reuse retired IDs).
4. [`gui/main_window.py`](../gui/main_window.py): Add the option variable and checkbox/control row and collect it in `_collect_patch_options()`.
5. [`fwt_patcher.py`](../fwt_patcher.py): Add the CLI flag in `build_parser()` and wire it into `PatchOptions` in `run_cli()`.
6. [`tests/`](../tests/): Add unit and integration tests verifying byte modifications, idempotency, inspector detection, and GUI/catalog parity (`tests/test_gui_feature_parity.py`, `tests/test_suite_health.py`).
