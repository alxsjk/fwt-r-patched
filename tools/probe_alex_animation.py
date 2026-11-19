"""Read and disassemble selected live client animation code from an ADB device.

The target must already be running and ADB must be authorized to read its code.
Only fixed instruction ranges from libil2cpp.so are read; no save is accessed
and process memory is never modified.
"""

from __future__ import annotations

import argparse
import re
import struct
import subprocess

from capstone import CS_ARCH_ARM64, CS_MODE_ARM, Cs
from unicorn import UC_ARCH_ARM64, UC_MODE_ARM, Uc
from unicorn.arm64_const import UC_ARM64_REG_SP, UC_ARM64_REG_X0, UC_ARM64_REG_X22, UC_ARM64_REG_X23

_RANGES = {
    "AttackState.get_animationType": (0x1867BEC, 40),
    "SkillContainer.get_animationType": (0x2022F80, 172),
    "AwakeningAttackState.PlayAnimation": (0x1E60BE8, 48),
    "AwakeningAttackVer2State.get_playAnimationAtAwake": (0x1E60C28, 8),
    "AwakeningAttackVer2State.OnUpdateFrame": (0x1E60C30, 1192),
    "GameStateWithAsset.PlayAnimation": (0x17EF00C, 160),
    "Player.OnGUICastButtonPressed": (0x18E9360, 180),
    "Character.SelectSkill": (0x1F06448, 436),
    "Player.HandleInput": (0x18E6AA8, 176),
    "Character.HandleInput": (0x1F04C1C, 216),
    "HandleInputState.Action": (0x18853C4, 392),
    "GameRule.GetReaminTurnCount": (0x16064B4, 1280),
    "GameMapTile.GetDistance": (0x1C9B86C, 192),
    "GameMapTile.GetDistanceCoordinates": (0x1C9B5D4, 664),
    "Monster.GetMonsterType": (0x1A1EAE8, 372),
    "GuildSkillEffect.GetBossMultiTargets": (0x1BAB2EC, 460),
    "Skill.IsInRange": (0x1B6FB44, 768),
    "InvalidValueByte": (0x17FEE24, 16),
    "Skill.IsInRange.jump_table": (0x2F9FFFC, 84),
    "ResourceTemplate.GetAnimationName": (0x168C950, 152),
}


def inspect(adb: str, serial: str) -> None:
    prefix = [adb, "-s", serial]

    def output(*args: str) -> bytes:
        return subprocess.run([*prefix, *args], check=True, capture_output=True).stdout

    pids = output("shell", "pidof", "com.nexon.fwar").decode().split()
    probes: list[str] = []
    for pid in pids:
        maps = output("shell", "cat", f"/proc/{pid}/maps").decode().replace("\r", "")
        matches = re.findall(r"(?m)^([0-9a-f]+)-[0-9a-f]+\s+\S+\s+00000000\s+.*"
                             r"/libil2cpp\.so$", maps)
        for candidate in matches:
            probe_address = int(candidate, 16) + 0x15FC56C
            observed = output("exec-out", "dd", f"if=/proc/{pid}/mem", "bs=1",
                              f"skip={probe_address}", "count=16", "status=none")
            probes.append(f"pid={pid} bytes={observed.hex()}")
            if observed.hex() == "f44fbea9fd7b01a9fd430091b43601d0":
                base = int(candidate, 16)
                break
        else:
            continue
        break
    else:
        raise ValueError(f"Could not identify the live client module: {probes}")
    decoder = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    captured: dict[str, bytes] = {}
    for label, (rva, length) in _RANGES.items():
        address = base + rva
        mapped = any(int(match.group(1), 16) <= address
                     and address + length <= int(match.group(2), 16)
                     and match.group(3).startswith("r")
                     for line in maps.splitlines()
                     if line.endswith("/libil2cpp.so")
                     if (match := re.match(r"^([0-9a-f]+)-([0-9a-f]+)\s+(\S+)", line)))
        if not mapped:
            raise ValueError(f"Requested code range is not readable: {label}")
        data = output("exec-out", "dd", f"if=/proc/{pid}/mem", "bs=1",
                      f"skip={address}", f"count={length}", "status=none")
        if len(data) != length:
            raise ValueError(f"Short code read for {label}: {len(data)} bytes")
        captured[label] = data
        print(f"{label} RVA {rva:#x} bytes {data.hex()}")
        for ins in decoder.disasm(data, rva):
            print(f"  {ins.address:#x}: {ins.mnemonic} {ins.op_str}")

    invalid = captured["InvalidValueByte"]
    code = captured["Skill.IsInRange"]
    table = captured["Skill.IsInRange.jump_table"]
    if invalid != bytes.fromhex("e81f00321f01206ae0179f1ac0035fd6"):
        raise ValueError("Unexpected byte-sentinel validator")
    if code[0x128:0x12C] != bytes.fromhex("e0030032"):
        raise ValueError("Unexpected range switch default result")
    branch = 0x2F9FFFC + int.from_bytes(table[8:12], "little", signed=True)
    if branch != 0x1B6FC30:
        raise ValueError("Unexpected RangeType.All branch target")
    vm = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
    for address, size in ((0x17FE000, 0x1000), (0x1B6F000, 0x2000),
                          (0x2F9F000, 0x2000), (0x4000000, 0x10000),
                          (0x5000000, 0x1000)):
        vm.mem_map(address, size)
    vm.mem_write(0x17FEE24, invalid)
    vm.mem_write(0x1B6FB44, code)
    vm.mem_write(0x2F9FFFC, table)
    stack = 0x4008000
    for value, expected in ((0, 1), (255, 0)):
        vm.mem_write(stack, bytes(0x70))
        vm.mem_write(stack + 0x68, struct.pack("<Q", 0x5000000))
        vm.reg_write(UC_ARM64_REG_SP, stack)
        vm.reg_write(UC_ARM64_REG_X22, value)
        vm.reg_write(UC_ARM64_REG_X23, 2)
        vm.emu_start(0x1B6FC1C, 0x5000000, count=100)
        if vm.reg_read(UC_ARM64_REG_X0) != expected:
            raise ValueError(f"Range predicate returned unexpected result for {value}")
    print("Range audit: live instructions emulated for range 0 and invalid sentinel 255.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--adb", default="adb")
    parser.add_argument("--serial", required=True)
    args = parser.parse_args()
    inspect(args.adb, args.serial)
