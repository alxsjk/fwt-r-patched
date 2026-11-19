# Hero Awakening and Custom Skills Guide

This guide collects the investigated process for granting Awakening to a hero who never received it and creating a custom skill for that hero. The example is **Destiny Lance** for Alex, developed against the reference build (`feature 008-alex-awakening`): Features `12.01` (`--alex-awakening`, shipped in `2.5.45` via `core/alex_awakening*.py`) and `12.02` (`--alex-rebalance`, shipped in `2.5.49` via `core/alex_rebalance.py`) are now production features included in `--all`, while the standalone `tools/lab_alex_*` scripts referenced here remain research/lab prototyping tools (not a generic generator and not meant to be distributed as standalone patches).

Production integration and validation status: Features `12.01` and `12.02` passed device/emulator validation for Awakening evolution up to level 70, Limit Break to 72, persistence, Pit boss selection/position swap, Guild Raid Auto and manual boss targeting (including post-swap Thornbush terrain conversion in `12.02`), and unavailability when no living boss is present. Exact damage, immunities, timing across all equipment sets, and long-tail error/unwind paths in the reused demangler code caves remain outside the tested lab matrix. Historical lab telemetry earlier encountered AppSealing `[90002]` on an initialization run before hooks stabilized; a clean startup on one device does not establish general stability across untested builds.

Detailed sources: the [patch specification](PATCH_SPEC.md), [code caves](CODE_CAVES.md) and [development builds](DEV_BUILD.md). Some historical notes mention selecting the nearest boss; the most recent decision is to select a single boss automatically and allow manual choice when several are present.

## 1. Define the behavior before touching data

For each hero, record the identification and original form; Awakening cost and requirements; the identity, equipment and progression that must be preserved; name and description; target, range, selection, exceptions and immunities; damage and progression per level; effects and their order; animation, audio and visual effects; cooldown and interaction with equipment sets. Specify the behavior with no valid target and on special maps. Costs copied from another hero serve only as test data until balance approval.

Alex: a global-range skill against a living boss, intended base damage of 200% of Attack at level 1, and a position swap. A single boss must be selected automatically; with several, the player chooses. With no living boss, the skill must be unavailable. The intended cooldown is one turn, reducible to zero by the corresponding equipment-set effect. The attack reuses the Giga-break jump; no new animation was created for this Awakening.

## 2. Inventory the hero and the build

1. Pin the version and the hashes of the reference APK and libraries. Inspect the localized tables, the local server and the character assets. Do not assume that another package, version, costume or model has the same layout.
2. Locate the IDs of each grade in `creaturedata*`, the existing skills, the model and the `creaturerebirth` records. A 6★ record may exist without the transition or a working skill.
3. Audit candidate IDs across **every** relevant table, including localized variants, effects, levels, FX and server structures. Searching only a few tables does not prove the global absence of collisions. Do not assume rows are ordered or that all languages have the same row count.
4. Identify a compatible donor for the record format, but confirm semantics, economy and in-game behavior separately.

For Alex, `0x130185` is the 5★ form, `0x130186` is the existing 6★ row, and the 5★→6★ transition was missing. His 6★ row had `_skill4=-1`. The skill candidate is `0x100185` (`1048965`) and the candidate damage effect is `0x10018501`; these numbers are not templates to reuse for other heroes. `python -m tools.analyze_alex_awake --help` describes the specific audit; `--resources <zip>` and `--probe-roundtrip` run the documented checks. The existing audit is not global.

## 3. Enable the evolution on client and server

**Client.** Add a coherent 5★→6★ entry to `creaturerebirth`, including requirements, destination and materials. For Alex, `tools/lab_alex_awake_gate.py` creates a copy of a donor record and adjusts the IDs; the screen stopped displaying the unavailability message. This step alone does not enable the transaction on the server and does not create a skill. The fixture used 160 crystals and 1,020,000 gold; these values are not a final balance decision.

**Server.** Locate the evolution-rule query and make sure the returned rule has strings and data with valid lifetimes, correct references and safe behavior under ASLR. On the reference server, `kFwtRebirthRules` is a fixed-size table with pointers subject to GNU_RELRO relocation. The bytes after its end belong to other structures: do not blindly append a row. The experiment in `tools/lab_alex_server_rule.py` and `tools/lab_alex_server_flow.py` handles the Alex case through a specific path and models storage in the last writable segment. Read its checks and limitations before adapting it; addresses are valid only for the verified binary.

**Reverse-direction identity.** Audit every reader that walks evolution from destination back to origin, not just the query used when awakening. In the prototype, buying genes after the Awake created a duplicate Alex because the server did not recognize the 6★ form as belonging to the same family. Three identification paths were adjusted and the later test confirmed gene increments without duplication and an upgrade of an existing skill. One additional special reader remains unchanged and needs evaluation. Repeat the purchase, gene, skill-upgrade, achievement and related-flow tests for each hero.

`tools/lab_alex_evolution_build.py` produces a DEV evolution build without the skill; its `--verify-only`, `--server`, `--apk` and `--verify-artifact` options help compare the composition against the reference. Check the code and `--help` before running. Before a transaction, test the screen first; then test evolution, restart, equipment, identity, level 70 and transcendence in isolation. An enabled screen does not demonstrate that the server accepts the evolution.

## 4. Create the skill records

`tools/lab_alex_skill_records.py` shows a round-trip of 26 assets: eight `skilldata` variants, eight `skilleffecttable`, eight `creaturedata`, plus `skillleveltable` and `skillfxdata`. The integration build also includes `creaturerebirth`: 27 assets in total. The code decrypts, reads the MonoBehaviour with UnityPy, edits the planned rows, preserves the original compression, re-encrypts and reads back, comparing the remaining records. This serialization validation does not replace loading and testing on the device. The Vietnamese language needed a different format donor; real translations for all languages remain a product decision.

For a new skill, check at least:

| Data | Responsibility |
| --- | --- |
| `creaturedata*` | Bind the skill to the awakened form, preserving the other skills. |
| `skilldata*` | ID, name, description, target, range, effects, chance, cooldown and parameter kind. |
| `skilleffecttable*` | Semantics, values and factors of damage and other effects. |
| `skillleveltable` | Levels and costs shown by the client; check the equivalent server table. |
| `skillfxdata` and assets | Visual, audio and timing references; verify model and costumes. |
| Local server | 6★ skill row, skill recognition and persisted costs. |

In the example, `_useParameterKind=5` identifies the Awake format used by the donor; `_cooltime=1` is the cooldown candidate. The damage clones an effect with `_effectValue=2.0` and `_effectValueFactor=0.5`, so 200% refers to the intended base value at level 1, not to a fixed final damage or to every level. The swap uses Persona's existing effect `21172225`. Actually confirm formula, defense, factors, chance, effect order and in-combat upgrades; plausible data or a tooltip is not proof.

## 5. Target, range and execution

Changing a range field is not enough. The prototype uncovered two independent paths: the Easy Skill shortcut made Alex walk up to a regular enemy, ignoring the selection hook; later, `Skill.IsInRange` accepted `All=2`, but `AIManager.GetTypeTiles` generated no selectable cells for that configuration. The experimental fix routes the skill through normal selection and marks eligible cells using `GameMapTile.SetAttribute`, preserving the UI and input flow. `255` in `_range` is an invalid sentinel in that predicate; the prototype uses `0` with type `All`.

The model looks for living enemies classified as bosses in the monster data. The examined content has classifications 80, 90 and 100; the 63 bosses in the examined Guild Raid table use 100. The AI type can be changed by the map and is not a reliable substitute for the original classification. Check types, pointers, HP, enemy field, map bounds, occupancy, immunity and multi-target handling for the chosen mode.

`tools/lab_alex_skill_client.py` contains the hooks and emulation tests; the RVAs, expected bytes and caves are restricted to the reference build. An additional DEV hook on `PlayerAI`'s attack call replaces the target with the nearest living boss for Alex's skill only; the user confirmed the swap in Guild Raid Auto. Also verify scenarios with several bosses, a dead boss, immunity effects, blocked tiles, allies and minions, without generalizing one isolated test to every mode. Confirm there is no undue automatic movement and no selectable target outside the rules.

## 6. Animation and presentation

The current solution reuses the `Paladin_Skill2` clip from Giga-break. The FX record is derived from Alex's skill 3, but copying FX alone does not guarantee that a clip plays: the Awake uses its own state machine. The investigation found `SkillContainer.get_animationType` returning index 16 for Awakening, while the analyzed Awake states did not automatically play the base animation. The lab uses skill-specific detours, routing it through the common attack path and selecting the compatible animation. Visual validation must watch the whole jump and the timing of the effects, including different costumes and battle conditions.

Options for a more striking presentation, in rough effort order: combine existing animation and FX; adapt a clip/effects from another asset with skeleton compatibility; or produce and integrate an original clip, effects, audio and possible camera scenes. A brand-new animation may require modeling/animation tools, knowledge of the bundle formats, and import, rig, event and timing tests in Unity. There is still no proof in this project of a complete original-animation import pipeline; do not promise a schedule or compatibility before a prototype. See `tools/probe_alex_animation.py` and the research notes for the read-only tests already performed.

## 7. Binary safety and lab builds

Treat versions and addresses as specific: validate the reference hash, the original bytes and the compatibility of every hook; translate VAs per `PT_LOAD` segment, never by a global offset. Check conflicts with other patches, relocations, permissions, ABI, registers, stack alignment, branch distances, concurrency, signals and unwinding. Zero bytes do not prove a cave is free. `brk` trap exercises cover only executed paths; some prototype regions have not yet received that isolated verification.

`tools/lab_alex_skill_build.py` assembles a specific DEV build using the patcher and fails on identified conflicts. For the artifact with the paths the script expects:

```bash
JAVA_HOME="$JDK_PATH" .venv/bin/python -m tools.lab_alex_skill_build
JAVA_HOME="$JDK_PATH" .venv/bin/python -m tools.lab_alex_skill_build --verify
JAVA_HOME="$JDK_PATH" .venv/bin/python -m pytest -q tests/test_alex_skill_lab.py tests/test_alex_targeting_lab.py
```

`--verify` compares DEV identity, 27 assets, expected bytes and conflict rejection; the build's signature, DEX and 16 KiB alignment checks are also required. The synthetic tests use mocks and simulated bases: they do not reproduce the full state machine, loader, AppSealing or every game path. DEV instrumentation must not enter a production distribution.

## 8. On-device testing and progress protection

Use only authorized test devices and state. Do not interrupt an active match. Before installing a build, keep a private backup on the device itself and compare the hashes of the two state copies, internal and external. In this game the external copy can replace the internal one on restart; a partial restore can look successful and later revert. Do not transfer or read saves unnecessarily. Do not restore old backups after user progress without need and authorization. Use an install that preserves data and verify a compatible signature.

Recommended sequence:

1. Awakening screen: requirements, icon and costs. Transaction: 6★ form, identity, equipment, restart, level 70 and transcendence.
2. Gene purchase, ownership recognition, skill upgrades, achievements and regressions on other heroes.
3. Controlled arena with one tough boss and minions: initial and final position, range, absence of undue walking, animation, damage, selection and swap.
4. No living boss; several bosses; dead target; obstacles, immunity, height and effects that can block the swap.
5. Guild Raid and other relevant modes; turn 2 without reduction and turn 1 with the equipment set. Check the reduction effect, not just the equipment's display name.
6. Restart, persistence, interaction with other patch options and supported devices/versions.

The `FWT-ALEX-LAB` telemetry reports hook installation, skill ID, boss discovery/count, cell attribute and input result. `input_result=1` means the input was processed, not that a swap or damage occurred. Current logs do not directly record coordinates or damage; combine them with on-screen observation. AppSealing may block or kill an initialization; document the code, the context and a later attempt without reading a single run as proof of stability.

## 9. Final integration

For Alex, Feature `12.01` (`--alex-awakening`) completed this integration in `core/alex_awakening*.py`, `gui/feature_catalog.py`, `docs/FEATURE_CATALOG.md`, and `tests/` (with the rebalance follow-up `12.02` in `core/alex_rebalance.py`). Use the same checklist when promoting any future hero awakening prototype into a selectable production feature:

1. Turn validated lab scripts into clean `core/` modules with explicit `PatchOptions` flags, conflict validation, and an independent inspector check in `core/patch_inspector.py`.
2. Register permanent feature IDs in `gui/feature_catalog.py` and `docs/FEATURE_CATALOG.md` under **Original hero modifications**, wire CLI/GUI parity, and update `README.md`, `docs/PATCH_SPEC.md`, and `CHANGELOG.md`.
3. Run the full verification checks, including GUI parity (`tests/test_gui_feature_parity.py`), unit and integration tests, Android 16 KB alignment, and APK signing before marking items complete.
