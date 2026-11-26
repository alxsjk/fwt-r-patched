"""Merlin Slot-1 Auto Mode Awakening-support targeting patch (Feature 14.01).

When **Merlin** (``_creatureId`` ``1249585..1249590`` / ``3346741``) is placed
in **Team Slot 1** (``playerCamp._members[0] == caster``) and the battle is in
**Player Auto Mode** (``Character._characterType == 0``,
``Player._isAutoPlay != 0``, ``Camp._campType == 0``), this client runtime hook
changes how her Awakening-cooldown-reduction support skill *Magic infusion*
(``_skill2``, skill ID ``1053188``, ``_skillTarget=2``, ``_range=4``) chooses
targets:

1. **Healing skills untouched**: HP/MP healing thresholds and all non-Merlin /
   non-Slot-1 / manual / PvP-defense / enemy behaviors keep stock rules.
2. **Awake CD == 1 targeting**: ``AIStatePhaseFindSupport::IsUseSupportSkillState``
   (``0x20EDBCC``) and ``AIStatePhaseFindSupportInPlace::IsUseSupportSkillState``
   (``0x20F1AF0``) accept living allies (``target != caster``, ``_isDead == 0``)
   that possess an Awakening skill (``(byte[skillData + 0x4d] | 1) == 5``) whose
   **true remaining cooldown == 1**. The check calls the client helper at
   ``libil2cpp.so`` RVA ``0x1606428`` (``IsAwakeningSkill(skill) ?
   Skill::GetCurrentCoolTime(skill) : -1``) through the tail cave at
   ``0xB2B620``: ``[Skill + 0x30]`` is a turns-elapsed counter
   (``Skill::ResetRemainCoolTime`` ``0x1B718E0`` stores ``0`` there), not the
   remaining cooldown, so Lord/stage/buff cooldown modifiers and any
   ``_cooltime != 2`` made the old ``[skill + 0x30] == 1`` test wrong.
3. **Team slot tie-breaking & range fallback**: ``CompareFindTargetStep + 0x178``
   (``0x20EEF2C`` and ``0x20F3338``) breaks ties among reachable qualifying
   allies by lowest index in ``Camp._members`` (team slot order), while
   replaying the normal distance comparison for the same ally across different
   walkable tiles. If no qualifying ally is in range, ``SupportFindTarget``
   returns false and Auto Mode naturally falls back to normal attacks.

Delivery hooks the post-Covault common exit path in ``libfwt_local_server.so``
at ``0xAB3300`` (``stlrb w8, [x9]`` -> ``bl 0xB2B1B4``), between
``0xAB32F4`` (``guild_raid_protection_persist``) and ``0xAB3304``
(``alex_heros_mark``), inside the unused ``AbstractManglingParser::parseName``
tail (``0xB2B1B4..0xB2B530``), plus a 48-byte cooldown-helper trampoline cave
at ``0xB2B620..0xB2B650`` in the remaining free ``parseName`` tail.

**Feature 14.02 — skills before cells (same option).** ``14.01`` decides *who*
Merlin supports, but ``CharactersAI::InitActing`` (``0x1A35F2C``) calls the virtual
``MoveEnableToTile`` at ``0x1A35F68`` before any skill is evaluated, and that call
sets ``AIPhaseAction`` — the following ``NormalStateFindTargetWithPath`` then
returns immediately, so a reachable bonus / occupy / item cell outranked every
skill. The installer's tail ``ret`` (``0xB2B244``) is therefore turned into
``b 0xB30538``, a second cave in the dead ``parseEncoding`` tail right after
``dungeon_recom_info``. It installs a fifth 4-word absolute trampoline at the
``MoveEnableToTile`` call site; the body guards on the same Slot-1 / player-camp /
Auto-Mode / non-semi-auto conditions, locates *Magic infusion* in the descending
scan, runs the stock pair (``IsEnableUsingSkill`` + virtual
``EnableUseSkillToTarget``) for every index above it — so a ready Awakening skill
is cast instead of walking — and then runs the stock **support branch only** for
*Magic infusion* (no ``FindAttackPlayer`` fallback). Success resumes the client at
``0x1A35F7C`` and skips the tile move; any failure replays the four displaced
words and resumes at ``0x1A35F78``, i.e. stock behaviour. Static client data is
addressed as ``IL2CPP_BASE_CACHE + RVA``: a PC-relative ``adrp`` in this cave
would resolve inside the server library, not the client.
"""
from __future__ import annotations

import hashlib
import struct
from collections.abc import Callable
from functools import partial

from core.elf_mapping import read_load_segments, translate_vaddr

MAGIC_INFUSION_SKILL_ID = 1053188
PATCH_IL2CPP_HELPER = 0xAB575C
IL2CPP_BASE_CACHE = 0xBE3798

CAVE_VADDR = 0xB2B1B4
_CAVE_BYTES_1401 = bytes.fromhex(
    "28fd9f08fd7bbba9fd030091f35301a9d305009073ce43f9930300b4281900100801"
    "40f9e81b00f981799b52c141a072c2180010a5190010e90a001016000094015e8352"
    "e141a07202180010e5180010890a00101000009481e59d52c141a072c21700102518"
    "0010691000100a00009401678652e141a07202170010651700100910001004000094"
    "f35341a9fd7bc5a8bd140014e91f00f9e00313aae3c30091840080524129fe176004"
    "00b4021040f9220400b4081c40f9e80300b4080d40f9a80300b4091140b98a408252"
    "0a02a0723f010a6b0103005449604039c90200354900473989020034413c40f94102"
    "00b42960403909020035281040f9c80100b4091940b93f0500716b010054080940f9"
    "280100b4091940b93f050071cb000054091140f93f0102eb6100005420008052c003"
    "5fd6e0031f2ac0035fd6281040f9480200b4091940b9080940f9e80100b40a1940b9"
    "3f010a6b29b18a1aea031f2a5f01096b2a0100540b4d2a8b6c1140f99f0102eb6000"
    "00544a050011f9ffff17e0030a2ac0035fd6e0ff9f52e0ffaf72c0035fd68f7b9b52"
    "cf41a072030000140f608352ef41a072e007bda9e27b01a9ef1300f9bdffff976004"
    "0034e10740f9a10300b43f0002eb600300542868443928030035282040f9e80200b4"
    "080d40f9a80200b4091940b9ea031f2a5f01096b2a0200540b4d2a8b6b1140f94b01"
    "00b46c0d40f90c0100b48d354139ad010032bf15007181000054950000941f040071"
    "600000544a050011f1ffff172000805202000014e0031f2afe0f40f9ffc30091c003"
    "5fd6e00740a9e27b41a9ef1340f9ffc30091f30f1ef8fd7b01a9fd43009108004139"
    "d005009010ce43f910020f8b00021fd68fe59d52cf41a072030000140f678652ef41"
    "a072e007bca9e21b01a9e82702a9ef7b03a9e00316aa83ffff9780010034e82742a9"
    "a9020034020940f9620200b4a2ffff97ed03002ae20315aa9fffff971f000d6bab01"
    "00546c020054e00740a9e21b41a9e82742a9ef7b43a9ff03019169010034013940bd"
    "0020211e04010054ef4100910e000014e00740a9e21b41a9e82742a9ef7b43a9ff03"
    "0191ef01019107000014e00740a9e21b41a9e82742a9ef7b43a9ff030191ef910191"
    "d005009010ce43f910020f8b00021fd65000005800021fd6f30f1ef8fd7b01a9fd43"
    "00910800413909020034013940bd0020211ea40100546d65726c696e5f6175746f5f"
    "737570706f727400"
)
CAVE_ORIGINAL_SHA256 = "ab58f4a2c3d1fa79c556d1e833ef5333e672744eb4b18ddbe23821cec0ead041"

# libil2cpp.so (client 0.682) helper: the true remaining Awakening cooldown.
# 0x1606428: IsAwakeningSkill(skill) ? Skill::GetCurrentCoolTime(skill) : -1.
# [Skill + 0x30] must NOT be tested directly: ResetRemainCoolTime (0x1B718E0)
# zeroes it and GetCurrentCoolTime (0x16064B4) subtracts it from
# SkillData._cooltime (byte at +0x4c) with buff/stage/Lord-rule adjustments.
AWAKE_CD_HELPER_RVA = 0x1606428

# Tail cave (remaining free parseName tail, after trait_multi_unique's
# 0xB2B530..0xB2B620): saves x8/x9/x10/x30 around the helper call, resolves
# the libil2cpp base from IL2CPP_BASE_CACHE, and tail-calls the RVA.
# Entered by the 3-word swap at 0xB2B3CC (bl + cmp w0,#1 + b.eq accept).
TAIL_CAVE_VADDR = 0xB2B620
TAIL_CAVE_BYTES = bytes.fromhex(
    "e827bea9ea7b01a9d005009010ce43f9e0030baa11858cd2112ca0f2"
    "1002118b00023fd6ea7b41a9e827c2a8c0035fd6"
)
TAIL_CAVE_SIZE = len(TAIL_CAVE_BYTES)
TAIL_CAVE_ORIGINAL_SHA256 = "a1d099953f88154395eee0f7a1e3ce020e351e0085838291e0bca362f3a9f850"

# --- Feature 14.02: skill priority over bonus / occupy / item cells ----------
# Hooks the four-word MoveEnableToTile call site in CharactersAI::InitActing
# (client `0x1A35F68`) so a ready Awakening skill and *Magic infusion* are
# evaluated before the tile move. Lives in the dead parseEncoding tail directly
# after dungeon_recom_info (0xB301F8..0xB30538); the 14.01 installer's final
# `ret` at 0xB2B244 becomes `b 0xB30538` (PRIORITY_INSTALL_JUMP).
PRIORITY_CAVE_VADDR = 0xB30538
PRIORITY_CAVE_BYTES = bytes.fromhex(
    "ffc300d1fd7b02a9fd030091f35301a9930500f073ce43f9930200b4080a80520800"
    "ab72e80300b908408052e8c3ba72e80700b969feff1029a10291e90700f9e00313aa"
    "01ed8b526134a0720200009042c01691e30300918400805205000090a50017917014"
    "fe97f35341a9fd7b42a9ffc30091c0035fd6680240f9e00313aa099141f9019541f9"
    "6d65726c696e5f6175746f5f737570706f72745f7072696f7269747900000000ff03"
    "01d1f45700a9f65f01a9f86702a9fa6f03a9940500f094ce43f9750e40f9d51200b4"
    "b662403996120035b602473956120034b63e40f9161200b4d7624039d7110035d612"
    "40f9961100b4d71a40b9ff0600712b110054d60a40f9f61000b4d71a40b9ff060071"
    "8b100054d71240f9ff0215eb21100054764a40f9f60f00b5769a40b9df060031810f"
    "0054777e40b9788240b97b5a40b91a008012f903172a3f03186beb0200543f031b6b"
    "60020054a02240f9200200b4e103192ae2031faa11d385d25140a0f29002118b0002"
    "3fd6400100b4090c40f9090100b4291140b98a4082520a02a0723f010a6b61000054"
    "fa03192a0300001439070051e9ffff175f070031a00b0054f903172a3f031a6bad02"
    "00543f031b6b20020054e00313aae103192ae2031faa11758dd27134a0f29002118b"
    "00023fd620010034680240f9e00313aae103192a2200805209a141f903a541f92001"
    "3fd6e007003539070051ebffff17b1dc88d2b179a0f29002118b09024039e9010037"
    "11a99ad25173a0f29002118b080240f9000140b991969bd2911ca0f29002118b0002"
    "3fd6b1dc88d2b179a0f29002118b290080520902003911148fd2b173a0f29002118b"
    "080240f9000140f911b09bd2911ca0f29002118b00023fd6200500b4f60300aae103"
    "1a2a22008052e3031faa11c199d2d141a0f29002118b00023fd6773a40f9f70300b4"
    "e00317aae10316aae2031faa11e99cd2f142a0f29002118b00023fd6e00317aae103"
    "13aae2031faa91079dd2f142a0f29002118b00023fd6e00317aae1031faa91219dd2"
    "f142a0f29002118b00023fd64001003491ef8bd27134a0f29002118bf45740a9f65f"
    "41a9f86742a9fa6f43a9ff03019100021fd611ef8bd27134a0f29002118bf45740a9"
    "f65f41a9f86742a9fa6f43a9ff030191680240f9e00313aa099141f9019541f90002"
    "1fd6ff4301d1f35300a9f55b01a9f76302a9f96b03a9fe2300f913008052020600b4"
    "552040f9d50500b4b50e40f9950500b4b61a40b956050034990500f039cf43f9f904"
    "00b4140080529f02166b8a040054a84e348b081140f9e80300b4170d40f9b70300b4"
    "e9364139290100323f15007121030054180080521f1300710a030054e84a388b003d"
    "40b91f0000710d02005491618ed25140a0f23003118b00023fd6600100b409804039"
    "29010035003840bd88020010010140bd0008211e0900381e3f0100714d0000547302"
    "090b18070011eaffff1794060011dcffff17e0ff8f520000134bfe2340f9f35340a9"
    "f55b41a9f76342a9f96b43a9ff430191c0035fd60000c842"
)
PRIORITY_CAVE_SIZE = len(PRIORITY_CAVE_BYTES)
PRIORITY_CAVE_ORIGINAL_SHA256 = "0850149e3cf4323560985a0c555b466bb123bf7785bba7e98e78f73f67defe1a"
PRIORITY_INSTALL_JUMP = 0x140014BD  # b 0xB30538 (stock word: b 0xB2B634)
PRIORITY_INSTALL_JUMP_OFFSET = 0x90  # inside CAVE_BYTES
PRIORITY_CLIENT_SITE = 0x1A35F68
PRIORITY_CLIENT_WORDS = (0xF9400268, 0xAA1303E0, 0xF9419109, 0xF9419501)
PRIORITY_BODY_OFFSET = 0xA8  # InitActing hook body
PRIORITY_POWER_OFFSET = 0x354  # awaken_power helper (14.03)
PRIORITY_POWER_VADDR = PRIORITY_CAVE_VADDR + PRIORITY_POWER_OFFSET

# `awaken_power` reads the awakening skill's damage multipliers through
# SkillEffectTableManager::GetData (client-side, called via IL2CPP_BASE_CACHE).
# `_skillEffectType == 0` marks a damage effect; `_effectValue` is the
# multiplier shown to the player (4.25 -> 425%).
SKILL_EFFECT_TABLE_GET_DATA = 0x202730C
SKILL_EFFECT_TYPE_OFFSET = 0x20
SKILL_EFFECT_VALUE_OFFSET = 0x38

# --- Feature 14.03: tie-break by Awakening-skill damage ----------------------
# The 14.01 cave picks between two reachable allies with `slot_index_in_camp`
# (0xB2B2F0) and accepts the lower value. Those two calls now go to
# `awaken_power`, which returns `0x7FFF - power` (power = summed
# `SkillEffectTable._effectValue` of the awakening skill's damage effects,
# scaled by 100), so the same `b.lt` accepts the stronger Awakening and an ally
# with no awakening skill (0x7FFF) still ranks last.
_SLOT_INDEX_IN_CAMP = 0xB2B2F0
_POWER_TIEBREAK_CALLS = ((0x2B4, 0xB2B468), (0x2C0, 0xB2B474))


def _with_power_tiebreak(blob: bytes, target: int) -> bytes:
    """Repoints the 14.01 compare calls from `slot_index_in_camp` to `awaken_power`."""
    data = bytearray(blob)
    for word_offset, site in _POWER_TIEBREAK_CALLS:
        old = 0x94000000 | (((_SLOT_INDEX_IN_CAMP - site) >> 2) & 0x03FFFFFF)
        if int.from_bytes(data[word_offset : word_offset + 4], "little") != old:
            raise ValueError(f"unexpected compare call at 0x{site:X}")
        diff = target - site
        if diff % 4 or not -(1 << 27) <= diff < (1 << 27):
            raise ValueError("Unsupported ARM64 branch-link distance")
        data[word_offset : word_offset + 4] = struct.pack(
            "<I", 0x94000000 | ((diff >> 2) & 0x03FFFFFF)
        )
    return bytes(data)


CAVE_BYTES = _with_power_tiebreak(_CAVE_BYTES_1401, PRIORITY_POWER_VADDR)
CAVE_SIZE = len(CAVE_BYTES)

LATE_HOOK_SITE = 0xAB3300
LATE_HOOK_ORIGINAL = bytes.fromhex("28fd9f08")  # stlrb w8, [x9]

CAVES: tuple[tuple[int, bytes, str], ...] = (
    (CAVE_VADDR, CAVE_BYTES, CAVE_ORIGINAL_SHA256),
    (TAIL_CAVE_VADDR, TAIL_CAVE_BYTES, TAIL_CAVE_ORIGINAL_SHA256),
    (PRIORITY_CAVE_VADDR, PRIORITY_CAVE_BYTES, PRIORITY_CAVE_ORIGINAL_SHA256),
)
HOOKS: tuple[tuple[int, bytes, int], ...] = (
    (LATE_HOOK_SITE, LATE_HOOK_ORIGINAL, CAVE_VADDR),
)

CLIENT_HOOK_TARGETS: tuple[tuple[str, int, tuple[int, int, int, int]], ...] = (
    (
        "AIStatePhaseFindSupport::IsUseSupportSkillState",
        0x20EDBCC,
        (0xF81E0FF3, 0xA9017BFD, 0x910043FD, 0x39410008),
    ),
    (
        "AIStatePhaseFindSupportInPlace::IsUseSupportSkillState",
        0x20F1AF0,
        (0xF81E0FF3, 0xA9017BFD, 0x910043FD, 0x39410008),
    ),
    (
        "AIStatePhaseFindSupport::CompareFindTargetStep+0x178",
        0x20EEF2C,
        (0x34000209, 0xBD403901, 0x1E212000, 0x540001A4),
    ),
    (
        "AIStatePhaseFindSupportInPlace::CompareFindTargetStep+0x178",
        0x20F3338,
        (0x34000209, 0xBD403901, 0x1E212000, 0x540001A4),
    ),
    (
        "CharactersAI::InitActing (MoveEnableToTile call site)",
        PRIORITY_CLIENT_SITE,
        PRIORITY_CLIENT_WORDS,
    ),
)


def _branch_link(source: int, target: int) -> bytes:
    diff = target - source
    if diff % 4 or not -(1 << 27) <= diff < (1 << 27):
        raise ValueError("Unsupported ARM64 branch-link distance")
    return struct.pack("<I", 0x94000000 | ((diff >> 2) & 0x03FFFFFF))


def merlin_auto_support_state(
    data: bytes | bytearray, offset: Callable[[int], int] | None = None
) -> str:
    """Return 'stock', 'patched', or raise ValueError on mixed/unexpected bytes."""
    if offset is None:
        offset = partial(translate_vaddr, read_load_segments(data))
    states: list[str] = []
    for addr, original, target in HOOKS:
        off = offset(addr)
        current = bytes(data[off : off + 4])
        states.append(
            "stock"
            if current == original
            else "patched"
            if current == _branch_link(addr, target)
            else "invalid"
        )
    for addr, payload, digest in CAVES:
        off = offset(addr)
        current = bytes(data[off : off + len(payload)])
        states.append(
            "stock"
            if hashlib.sha256(current).hexdigest() == digest
            else "patched"
            if current == payload
            else "invalid"
        )
    if len(set(states)) != 1 or states[0] == "invalid":
        raise ValueError("Unexpected or partially patched Merlin Auto Support code")
    return states[0]


def apply_merlin_auto_support(
    buf: bytearray, offset: Callable[[int], int] | None = None
) -> int:
    """Install the Merlin Slot-1 Auto Support post-Covault client hook cave."""
    if offset is None:
        offset = partial(translate_vaddr, read_load_segments(buf))
    state = merlin_auto_support_state(buf, offset)
    if state == "patched":
        return 0
    for addr, payload, _digest in CAVES:
        off = offset(addr)
        buf[off : off + len(payload)] = payload
    for addr, _original, target in HOOKS:
        off = offset(addr)
        buf[off : off + 4] = _branch_link(addr, target)
    return len(HOOKS) + len(CAVES)


def inspect_merlin_auto_support(
    buf: bytes | bytearray, offset: Callable[[int], int] | None = None
) -> bool:
    """Return True if the Merlin Slot-1 Auto Support hook and cave are intact."""
    try:
        return merlin_auto_support_state(buf, offset) == "patched"
    except (IndexError, TypeError, ValueError):
        return False
