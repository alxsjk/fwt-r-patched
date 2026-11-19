# Guild Raid self-mercenary: how the projection really works

Reverse-engineering notes for `guild_raid_mercenary`, measured on the v2.5.26 build.
Every address below was read from `libfwt_local_server.so` of the reference APK; re-verify
before reuse.

## The original flow

`guild_battle_hired_projection` (`0x930034`) is one of the builders reached only through a
function-pointer table in `.data.rel.ro` — there is **no** `bl` and no `adrp`+`add` that
materialises its address, so a pointer scan is the only way to find it and its siblings:

| table slot | function | role |
| --- | --- | --- |
| `0xbdb838` | `guild_battle_hired_projection` (`0x930034`) | identity projection |
| `0xbdb880` | `make_guild_hired_soldier_deck_snapshot` (`0x933034`) | equipment decks |
| `0xbdb8c8` | `guild_hired_soldier_info_json` (`0x932664`) | per-weekday hire record |
| `0xbdb8e0` | `guild_hired_decks_json` (`0x932998`) | deck JSON |

Inside the function:

```
0x9300f8  ldr  x8,[x0,#0x20]         ; state.self_lord
0x9300fc  cmp  x8, x23               ; selected lord == self?
0x930100  b.eq 0x9302c4              ; yes -> empty projection   <- the patch site
0x93010c  bl   selected_lord_is_current_guild_member_json
0x930110  tbz  w0,#0 -> empty        ; not a guild member -> empty
0x930114  ldr  x9,[0xbdc000+0xca8]   ; global roster base
0x930118  sub  x8,x23,#0x970,lsl#12  ; x8 = lord - 990001
0x930124  cmp  x8,#0x3e7             ; index must be < 999
0x930130  madd x9,x8,#0x60,x9        ; row = base + index*0x60
0x930144  madd x8,x23,#0xa,#2        ; expected crs = lord*10 + 2
0x930148  cmp  x8,x22 ; b.ne -> empty
0x930150  valid = 1
0x930160  bl   friend_hired_soldier_json(row)        -> hired_info
0x930174  bl   hired_info_with_transport_identity(…, 2)
0x9301b4  bl   friend_hired_costume_json(row, 2)     -> hired_costume
0x9301e4  bl   friend_hired_equipments_json(row, 2)  -> hired_equips
```

Projection struct layout: `+0x00` valid byte, `+0x08` info, `+0x20` costume, `+0x38` equips
(each a 24-byte `std::string`).

**Why the player is refused**: the player's lord id (measured: `993838`) gives
`993838 - 990001 = 3838`, past the 999 rows, so the index guard rejects it and the function
returns an empty projection. The code was written so that a lord can never hire himself.

## The self mirror row

`infinity_local_hired_soldier_json` (`0xa6af78`) hits the same problem and has a fallback at
`0xa6b11c`:

```
0xa6b11c  ldr  x8,[0xbdc000+0xca8]   ; same roster base
0xa6b124  add  x8,x8,#0x17,lsl#12    ; + 0x17000
0xa6b128  add  x0,x8,#0x6a0          ; row = base + 0x176a0
0xa6b130  bl   friend_hired_soldier_json(row)
```

That fixed row is a **shipped mirror of the player**, and it is what the new cave points the
four builders at.

## The cave

`_build_guild_raid_self_mercenary_cave()` in `core/core_patches.py`, placed at `0xb34860`
(44 instructions / 176 bytes inside a dead demangler function with 1816 bytes of room; the
previous site at `0xcampaign+0x368` only had 92 bytes).

Steps: read the roster through the GOT slot, compute `row = base + 0x176a0`, mark the
projection valid, then call `friend_hired_soldier_json` →
`hired_info_with_transport_identity(row->lord, 2)` → `friend_hired_costume_json` →
`friend_hired_equipments_json`, copying each result to its offset (`+0x08`, `+0x20`,
`+0x38`) and jumping to the epilogue at `0x9302c4`.

## Measured result (device, MuMu)

`REQ_START_GAME_GUILD` replayed straight into the embedded server over `nc`:

| field | before the rewrite | after |
| --- | --- | --- |
| `hired_info` | `crs_idx 9938382` — a bare team slot, no stats | `crs_idx 99010002`, `crs_code 00120646`, level 120, grade 6, potentials |
| `hired_equips` | `[]` | full list, with `equip_code`, `enchant_cnt`, `options`, `crs_code` |
| `hired_costume` | `null` | still `null` |
| `hired_runes` | `[]` | still `[]` |

## Open issues

1. **`hired_costume` and `hired_runes` are still empty.** The costume builder is called and
   its result is copied to `+0x20`, so either the row carries no costume/rune data, or those
   two JSON fields are serialised from another source. Next step: find what produces
   `"hired_costume"` / `"hired_runes"` in the response (string addresses `0x175cf6`,
   `0x1b9e41`) and compare with the guild-member path.
2. **The unit may not be the player's own hired mercenary.** The row at `+0x176a0` is a
   shipped mirror (level 120, grade 6), while the player's hired soldier index is `49`.
   Decide whether the goal is the mirror row or the mercenary from the save; if the latter,
   the row has to be synthesised from the state instead.
3. **Leak**: the temporary `std::string`s built inside the cave are copied out and never
   destroyed, so each projection leaks its heap buffers. Same as the previous cave; harmless
   per call, worth fixing if the list refresh is frequent.
4. **The substitution is unconditional**: the site instruction is replaced by a plain branch,
   so every selection (guild member or self) produces the self projection. If the intent is
   to substitute only the self slot, the cave needs a guard on `x23 == state.self_lord`.

## How to test without the game UI

The embedded server listens on `127.0.0.1:8010` inside the app sandbox. With root:

```bash
adb shell "printf 'POST / HTTP/1.1\r\nHost: 127.0.0.1:8010\r\nContent-Length: 246\r\n\r\n{\"res_type\":-1,\"friend_crs_idx\":99000062,\"friend_idx\":9900006,\"dg_code\":\"400040\",\"dg_key\":0,\"combat_force\":253289,\"buff_event_no\":null,\"attack_team\":[99,54,19,70,49],\"num_hero\":0,\"lord_idx\":993838,\"access_code\":\"local-access-code\",\"CMD\":\"REQ_START_GAME_GUILD\",\"packet_no\":95}' | nc 127.0.0.1 8010 | tail -1"
```

This starts a raid battle server-side and returns the projection, so the mercenary payload can
be inspected without touching the UI.

## Routing fix (2026-11-12, v2.5.31)

The first cave replaced the branch at `0x930100` with an unconditional jump into the builder,
so **every** hire -- a real guild member included -- came back as the self mirror. The cave
now starts with `cmp x8, x23 ; b.ne <stub>` and the stub jumps back to `0x930104`. `x8`
already holds `state.self_lord` (loaded at `0x9300f8`) and `x23` the selected lord; the
comparison is explicit instead of leaning on the caller's flags, and the conditional branch
only reaches a local stub because a `b.cond` cannot span the distance to `0x930104`.

Layout: `[cmp x8, x23][b.ne -> stub][projection body][b 0x930104]` — 188 bytes.
`tests/test_self_merc_cave.py` drives both paths with unicorn.

## Projection struct: seven slots, three filled

`guild_battle_hired_projection` receives the output struct in `x8` and primes **seven**
libc++ strings before it looks at anything (`0x930074`..`0x9300dc`):

| slot | default | written by the stock path |
| --- | --- | --- |
| `+0x08` | `null` | `hired_info` (soldier row + transport identity) |
| `+0x20` | `null` | `hired_costume` |
| `+0x38` | `[]` | `hired_equips` |
| `+0x50` | `[]` | **never** |
| `+0x68` | `[]` | **never** |
| `+0x80` | `[]` | **never** |
| `+0x98` | `[]` | **never** |

The response templates in `.rodata` list the fields in order:
`"hired_costume":null,"hired_equips":[],"hired_runes":[],"hired_soulgears":[],"all_soulgears":[]`
(`0x1b9e1b`, `0x1b9e30`, `0x1b9e42`, `0x1b9f1f`). So the four untouched slots correspond to
runes, soulgears and the two `hired_soldier_*` blocks.

**Consequence:** `hired_runes` and `hired_soulgears` are empty for *every* mercenary in this
stub, not only for the self case. That is an author limitation, not a save problem, and it
needs its own patch.

## What the save already has (measured on the phone state, 2026-11-12)

| state key | value |
| --- | --- |
| `guild_hired_soldier_info` | `{mon_crs_idx: 49, ..., sun_crs_idx: 49, update_date: 2026-10-31}` |
| `hired_soldier_idx` | `49` |
| `guild_hired_soldier_decks` | `[{deck_no: 0, slot_no: 0, equip_idx: 4331}, ...]` |
| `hired_soldier_deck` | `[{deck_no: 1, slot_no: 1, equip_idx: 4331}, ...]` |

So the player's own mercenary is creature instance **49**, with a deck that maps
`(deck_no, slot_no) -> equip_idx`.

## Path to the player's own creature

`StateSnapshot` layout, measured: `+0x00` valid byte, **`+0x08` the state JSON `std::string`**
(`0x930104` does `add x0, x0, #8` and calls `selected_lord_is_current_guild_member_json`), and
`+0x20` `self_lord`.

Builders that read the save:

| function | address | role |
| --- | --- | --- |
| `hired_soldier_fields(std::string const&)` | `0x9401d8` | reads `hired_soldier_idx` (int) and `hired_soldier_deck` (array) out of the state JSON |
| `make_hired_soldier_deck_snapshot(std::string const&, long long)` | `0x940580` | builds the deck snapshot for one creature code; its only caller (`0x836f2c`) stores it as `hired_soldier_deck` |
| `select_rows_by_requested_ids_json(json, list_field, key, ids)` | `0x911f50` | what `GET_MY_CREATURE_INFO` (`0x826108`) uses with `crs_idx_list` / `crs_idx` |
| `equipment_holes_list_json(std::string const&)` | `0x8a9624` | the player's equipment |
| `find_equipment_json(std::string const&, long long)` | `0x897d14` | one equipment by index (matches the deck's `equip_idx`) |

Plan for the next iteration:

1. read `hired_soldier_idx` from the save (call `hired_soldier_fields` on `state+8`);
2. build `hired_info` for that id with `select_rows_by_requested_ids_json(state, "crs_idx_list",
   "crs_idx", "[<id>]")` and unwrap the single-element array into an object;
3. build `hired_equips` from the deck: `find_equipment_json` per `equip_idx`, joined into an
   array;
4. fill the runes / soulgears slots (separate patch, and it applies to guild members too).

Steps 2 and 3 need constant `std::string`s on the stack, an integer-to-decimal formatter and an
array join, which is why the cave has to be written as assembly rather than encoder calls:
`tools/asm_cave.py` assembles AArch64 text with symbolic branch targets (keystone 0.9.2 is
already in the project venv, and `KS_MODE_LITTLE_ENDIAN` is the right mode for ARM64).

## Measured payloads (device, 2026-11-12)

`tools/probe_guild_hire.py` asks the embedded server for a hire projection and always restores
the state, because `REQ_START_GAME_GUILD` is **not** read-only: the state file went from
773.708 to 774.163 bytes on the first probe. The body has to cross the nested adb shells
base64-encoded, otherwise the JSON quotes are eaten and the server answers `400 bad request`.

| field | guild member (baseline) | self with the cave |
| --- | --- | --- |
| `hired_info` | `crs_idx 99000062`, code `00120756`, level 114, grade 6, 5 potentials | `crs_idx 99010002`, code `00120646`, **level 120**, grade 6, 5 potentials |
| `hired_equips` | 15 items (`equip_idx 9900006001`…) | 15 items (`equip_idx 9901000001`…) |
| `hired_costume` | `null` | `null` |
| `hired_runes` / `hired_soulgears` | `[]` / `[]` | `[]` / `[]` |
| `all_soulgears` / `all_costumes` | `[]` / `[]` | `[]` / `[]` |
| `is_win_box` | `false` | `false` |

Measured conclusions:

1. **The cave delivers a complete unit** (info + 15 equipment items), so the payload is not
   "bare" — but it is the **built-in mirror**, not the player's hero. His configured mercenary
   is creature **49**: code `00130816`, **level 74**, grade 6, passive 8, with potentials in
   the save. The mirror is level 120, code `00120646` — a different hero.
2. **`hired_costume`, `hired_runes`, `hired_soulgears` and `all_*` are empty for EVERYONE** in
   this stub, including a real guild member's mercenary. It is not a patch regression: it is a
   limitation of the author's server (the projection has 7 slots and he fills 3).
3. `is_win_box` always comes out `false` — a bug fix embedded since 2.5.35 (no flag).

## Next step, now with a defined target

Swap the mirror for creature 49 from the save. The target payload is the one in the table
above, with `hired_info` coming from `creatures[crs_idx=49]` and `hired_equips` from the
creature's deck. The pieces:

- `hired_soldier_fields(state)` returns `{int hired_soldier_idx; std::string hired_soldier_deck}`
  (sret in `x8`, like every builder in this binary);
- `select_rows_by_requested_ids_json(x0, x1, x2, x3, x8=out)` is the filter that
  `GET_MY_CREATURE_INFO` uses with the names `crs_idx_list` / `crs_idx`, and it returns an
  **array**; `hired_info` expects an **object**, so the cave has to unwrap `[{...}]`;
- `find_equipment_json(state, equip_idx)` returns one equipment item by index, which is how the
  deck (`guild_hired_soldier_decks`) points at the gear.

The resulting cave has to assemble a `{"crs_idx_list":[<idx>]}` JSON on the stack (itoa), call
the filter, unwrap and join the equipment items — which is why `tools/asm_cave.py` (keystone)
exists.

## Slot map of the projection (measured 2026-11-12)

The serialiser cannot be found by xref, so the map was measured: `tools/mark_projection_slots.py`
redirects the cave's final branch into a block that stamps `SL50` / `SL68` / `SL80` / `SL98` into
the four unknown slots, and the probe then shows where each marker surfaces. The response came
back with invalid JSON right after the first marker, which is itself the answer: **the slots hold
JSON fragments, not plain strings** (the stock defaults are `null` and `[]`), so a marker without
quotes breaks the payload and its position names the field.

| slot | field in the response | filled by the stock path |
| --- | --- | --- |
| `+0x08` | `hired_info` | yes |
| `+0x20` | `hired_costume` | yes (always `null` so far) |
| `+0x38` | `hired_equips` | yes |
| `+0x50` | **`hired_runes`** | no |
| `+0x68` | **`all_costumes`** | no |
| `+0x80` | **`hired_soulgears`** | no |
| `+0x98` | **`all_soulgears`** | no |

Consequences for the feature ("full equips / costume / soul gear"):

- every slot must be written with **valid JSON text**: `[]` for an empty array, `null`, or the
  real fragment (`[{...}]`). A raw string breaks the whole response;
- `hired_runes`, `hired_soulgears` and the two `all_*` slots are exactly the author's four gaps,
  so filling them is the whole "soul gear" part of the request;
- `all_costumes` and `all_soulgears` are list-shaped: the client is told which costumes and
  soulgears exist, while `hired_*` carries the ones worn by the hired unit.

## Substitution is unconditional by design (2026-11-12)

In the guild raid a mercenary that already fought one stage cannot be hired again, so the feature
works the other way round: the player picks **any** name from the member list and gets his own
mercenary. The replaced branch (`0x930100`, stock `b.eq 0x9302c4`) is therefore a plain branch
into the cave, and the cave always builds the self projection. A guard on
`x23 == state.self_lord` was tried and reverted — it defeats the purpose.

## The cave that reads the save (2026-11-12)

The projection is now built from the player's own state instead of a shipped mirror row.
`tools/gen_merc_cave.py` holds the assembly (AArch64, assembled with keystone by
`tools/asm_cave.py`); `core/core_patches.py` carries the resulting 876 bytes and
`tests/test_self_merc_cave.py` re-emulates them under unicorn with the helpers stubbed.

What it does, in order:

1. `id = int_field(state + 8, "hired_soldier_idx", -1)` — nothing configured bails out and the
   stock `null`/`[]` priming stands.
2. builds `{"crs_idx_list":[<id>]}` on the stack (immediates for the prefix, an itoa loop for the
   digits) and constructs the request `std::string` from it.
3. fills the seven slots from the state, every ownership list filtered by `crs_idx`:

| slot | call |
|---|---|
| `+0x08 hired_info` | `find_object_by_int_field_json(state, "creatures", "crs_idx", id)` |
| `+0x20 hired_costume` | `find_object_by_int_field_json(state, "costumes", "crs_idx", id)` |
| `+0x38 hired_equips` | `select_rows_by_requested_ids_json(raw_array_field(state, "equipments"), request, "crs_idx_list", "crs_idx")` |
| `+0x50 hired_runes` | same over `"runes"` |
| `+0x80 hired_soulgears` | same over `"soulgears"` |
| `+0x68 all_costumes` | `raw_array_field(state, "costumes")` |
| `+0x98 all_soulgears` | `raw_array_field(state, "soulgears")` |

Every builder writes through `x8` (hidden return pointer) and takes `std::string const&`
arguments; each temporary is released with `~basic_string()` (`0xAD913C`) and each result is
moved into its slot with `operator=` (`0xADABB0`).

### Two traps that cost a probe each

**The jump target is `0x9302BC`, not the epilogue.** The stock function marks the projection valid
two instructions before its epilogue: `0x9302BC mov w8,#1 ; 0x9302C0 strb w8,[x19]`, and `0x9302C4`
is the bare register-restore + `ret`. Jumping to `0x9302C4` leaves `+0x00 valid == 0` and the
dispatcher answers `{"ERROR":-101,"msg":""}` — the cave's work is silently discarded.

**`0xB45FB0` is not a `std::string` constructor.** The constructor the binary uses with literals is
`0x7DBFB0` (`basic_string(char const*)^{abi:v170000}`). `0xB45FB0` is the *assignment* from a
`char const*`; calling it on an uninitialised stack buffer is what produced the first `-101`.

### Measured payload (physical Android device, `REQ_START_GAME_GUILD`, member hire)

```
hired_info    : crs_idx=49 code=00130816 level=74 grade=6 potentials=5
hired_equips  : 15 items (first equip_idx=1382)
hired_costume : {costume_idx:77, crs_idx:49, costume_code:'3126', ...}
hired_runes   : 3 | hired_soulgears: 3
```

`tools/probe_merc_variant.py` builds a library with only some of the slots filled, straight from the
pristine `.so`, so a failing builder can be bisected without touching `core_patches` or the recorded
cave digest. `tools/probe_guild_hire.py` backs the state up, sends the request and restores the save
(`REQ_START_GAME_GUILD` does mutate it: `522d51a8…` → `333d28d7…` → restored).
