"""Builds the DUNGEON_RECOM_INFO handler cave, as AArch64 assembly.

The stock embedded server never implements `DUNGEON_RECOM_INFO` (one of the
protocol's empty "cascas"): the client asks for per-dungeon recommended friend
mercenaries right before a battle (its `Result_DUNGEON_RECOM_INFO` parses
`recom_list`), and the stub answers the generic
`{"CMD":..,"packet_no":..,"ERROR":0,"msg":""}` ack with no list at all -- so
the pre-battle auto-select never has a candidate and no mercenary is picked
automatically, even though manual friend selection works.

This cave wraps the dispatch call in `fwt::EmbeddedStub::handle_json_request`
(`0x7DAED0`, the only `bl dispatch_json_impl` in the binary):

  * it byte-scans the request payload for `"DUNGEON_RECOM_INFO"` without any
    C++ call (`x8/x0/x1` and the link register stay intact), then returns to
    the stock dispatcher for every other CMD -- the overhead is one short scan;
  * on a match it answers
    `{"CMD":"DUNGEON_RECOM_INFO","packet_no":<echo>,"ERROR":0,"msg":"","recom_list":[...]}`,
    building `recom_list` with the server's own `friend_list_json` (the same
    source `START_GAME` serves as `recommend_list`), after loading the state
    through `load_state_snapshot`;
  * if the state cannot be loaded it answers the plain ack (no `recom_list`),
    which is exactly the stock behavior.

Measured facts it relies on (reference build `03ec76a1`):

  * the hook site `0x7DAED0` is `bl 0x7E4030` (word `0x94002458`) with
    `x8` = the response sret buffer, `x0` = the config whose first member is
    the state-path `std::string`, `x1` = the request `std::string`;
  * libc++ string layout: byte0 bit0 set -> long (size at +8, data at +0x10),
    else size = byte0>>1 with the characters inline at +1;
  * `load_state_snapshot` (`0x7DDECC`) takes that config string and returns a
    `StateSnapshot` through `x8`: `+0x00` valid byte, `+0x08` the state JSON
    `std::string`;
  * `friend_list_json` (`0x8D5674`) = `(x8=&out, x0=&state_json, x1=&"friends")`
    and returns the friend array `[...]` (the same source `GET_FRIEND_LIST`
    serves as `friend_lists` and `START_GAME` as `recommend_list`);
  * `int_field` (`0x7E08B8`) = `(x0=&json, x1=&key, w2=default) -> x0`.

Usage:
    python tools/gen_dungeon_recom_cave.py            # listing + disassembly
    python tools/gen_dungeon_recom_cave.py --hex      # hex only
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from tools.asm_cave import assemble_cave  # noqa: E402

# every branch family whose target operand may be a label (keystone resolves
# backward references only, and asm_cave only rewrites b/bl/b.cond)
_BRANCH_LINE = re.compile(r"^\s*(b|bl|b\.\w+|cbz|cbnz|tbz|tbnz)\b")

CAVE_VADDR = 0xB301F8  # itanium_demangle AbstractManglingParser::parseEncoding (3620 B, demangler-only)

DISPATCH = 0x7E4030  # dispatch_json_impl / fwt_stub_handle_json
LOAD_SNAPSHOT = 0x7DDECC  # load_state_snapshot(config_string&) -> StateSnapshot via x8
SNAPSHOT_DTOR = 0x7E0A14  # StateSnapshot::~StateSnapshot
FRIEND_LIST_JSON = 0x8D5674  # friend_list_json(&state, &"friends") -> std::string via x8
STRING_CTOR = 0x7DBFB0  # basic_string(char const*) at x0
STRING_CONCAT = 0x7E1750  # operator+(string const&, string const&) -> string via x8
STRING_DTOR = 0xAD913C  # ~basic_string()
INT_FIELD = 0x7E08B8  # int_field(json&, key&, default) -> x0

SYMBOLS = {
    "DISPATCH": DISPATCH,
    "LOAD_SNAPSHOT": LOAD_SNAPSHOT,
    "SNAPSHOT_DTOR": SNAPSHOT_DTOR,
    "FRIEND_LIST_JSON": FRIEND_LIST_JSON,
    "STRING_CTOR": STRING_CTOR,
    "STRING_CONCAT": STRING_CONCAT,
    "STRING_DTOR": STRING_DTOR,
    "INT_FIELD": INT_FIELD,
}

# --- stack layout (relative to the matched-path frame) ---
# x29/x30 are stored at [sp,#0x00]; every other slot starts at 0x20 so the
# stp/ldp offsets stay inside the +504-byte imm7 range.
SNAP = 0x20  # StateSnapshot (valid byte at +0, state JSON string at +8); 0x100 reserved
KEY_PNO = 0x120
KEY_FRIENDS = 0x140
T_A = 0x160
T_B = 0x180
T_C = 0x1A0
T_D = 0x1C0
T_DIGITS = 0x1E0
T1 = 0x200
T2 = 0x220
T3 = 0x240
LIST_OUT = 0x260
BUF_DIGITS = 0x280
X19S = 0x2A0
X20S = 0x2A8
X21S = 0x2B0
FRAME = 0x2D0

# needle halves: "DUNGEON_" and "RECOM_IN" as little-endian qwords, "FO" halfword
NEEDLE_Q0 = 0x5F4E4F45474E5544
NEEDLE_Q1 = 0x4E495F4D4F434552
NEEDLE_H2 = 0x4F46

# cave-embedded literals (appended after the code; addresses computed per pass)
LITERALS = (
    ("LIT_PNO", b"packet_no\x00"),
    ("LIT_FRIENDS", b"friends\x00"),
    ("LIT_A", b'{"CMD":"DUNGEON_RECOM_INFO","packet_no":\x00'),
    ("LIT_B", b',"ERROR":0,"msg":"","recom_list":\x00'),
    ("LIT_C", b"}\x00"),
    ("LIT_D", b',"ERROR":0,"msg":""}\x00'),
)


def _imm64(reg: str, value: int) -> list[str]:
    low, high = (value >> 0) & 0xFFFF, (value >> 16) & 0xFFFF
    mid1, mid2 = (value >> 32) & 0xFFFF, (value >> 48) & 0xFFFF
    return [
        f"    movz {reg}, #{low:#x}",
        f"    movk {reg}, #{high:#x}, lsl #16",
        f"    movk {reg}, #{mid1:#x}, lsl #32",
        f"    movk {reg}, #{mid2:#x}, lsl #48",
    ]


def _lit(reg: str, addr: int) -> list[str]:
    return [f"    adrp {reg}, #{addr & ~0xFFF:#x}", f"    add  {reg}, {reg}, #{addr & 0xFFF:#x}"]


def _ctor_from_lit(dest: int, label: str, lit_addrs: dict[str, int]) -> list[str]:
    return [
        f"    add  x0, sp, #{dest:#x}",
        *_lit("x1", lit_addrs[label]),
        "    bl   STRING_CTOR",
    ]


def _ctor_from_buf(dest: int, buf: int) -> list[str]:
    return [
        f"    add  x0, sp, #{dest:#x}",
        f"    add  x1, sp, #{buf:#x}",
        "    bl   STRING_CTOR",
    ]


def _destroy(dest: int) -> list[str]:
    return [f"    add  x0, sp, #{dest:#x}", "    bl   STRING_DTOR"]


def _concat(out_expr: str, a: int, b: int) -> list[str]:
    return [
        f"    {out_expr}",
        f"    add  x0, sp, #{a:#x}",
        f"    add  x1, sp, #{b:#x}",
        "    bl   STRING_CONCAT",
    ]


def _packet_no_digits(lit_addrs: dict[str, int]) -> list[str]:
    return [
        *_ctor_from_lit(KEY_PNO, "LIT_PNO", lit_addrs),
        # x0 = int_field(request, "packet_no", 900)
        "    mov  x0, x21",
        f"    add  x1, sp, #{KEY_PNO:#x}",
        "    mov  w2, #900",
        "    bl   INT_FIELD",
        # itoa(x0) into BUF_DIGITS, lowest digit first, then flip in place
        f"    add  x12, sp, #{BUF_DIGITS:#x}",
        "    mov  x13, x0",
        "    mov  x14, #10",
        "    mov  x15, #0",
        "    cbnz x13, DIGLOOP",
        "    mov  w17, #0x30",
        f"    strb w17, [sp, #{BUF_DIGITS:#x}]",
        f"    strb wzr, [sp, #{BUF_DIGITS + 1:#x}]",
        "    b    DIGDONE",
        "DIGLOOP:",
        "    udiv x16, x13, x14",
        "    msub x17, x16, x14, x13",
        "    add  x17, x17, #0x30",
        "    strb w17, [x12, x15]",
        "    add  x15, x15, #1",
        "    mov  x13, x16",
        "    cbnz x13, DIGLOOP",
        "    sub  x16, x15, #1",  # hi index
        "DIGFLIP:",
        "    sub  x9, x15, #1",
        "    sub  x9, x9, x16",  # lo = len-1-hi
        "    cmp  x9, x16",
        "    b.ge DIGFLIP_END",  # lo >= hi: nothing left to swap
        "    ldrb w17, [x12, x16]",  # char at hi
        "    ldrb w10, [x12, x9]",  # char at lo
        "    strb w10, [x12, x16]",
        "    strb w17, [x12, x9]",
        "    subs x16, x16, #1",
        "    b.ne DIGFLIP",  # hi reaches 0 with len >= 2
        "DIGFLIP_END:",
        "    strb wzr, [x12, x15]",  # NUL after the digits
        "DIGDONE:",
        *_ctor_from_buf(T_DIGITS, BUF_DIGITS),
        *_destroy(KEY_PNO),
    ]


def build_source(lit_addrs: dict[str, int]) -> str:
    lines = [
        # ---- fast path: byte-scan the request; x8/x0/x1 stay intact ----
        "    ldrb w9, [x1]",
        "    tbnz w9, #0, REQ_LONG",
        "    lsr  x10, x9, #1",
        "    add  x11, x1, #1",
        "    b    REQ_SCAN",
        "REQ_LONG:",
        "    ldr  x10, [x1, #8]",
        "    ldr  x11, [x1, #0x10]",
        "REQ_SCAN:",
        # positions = len - 18 + 1 (SUBS sets the flags the b.le below tests);
        # the counter must reach exactly zero so an 18-byte payload scans its
        # single position and nothing beyond
        "    subs x12, x10, #17",
        "    b.le PASSTHROUGH",
        *_imm64("x13", NEEDLE_Q0),
        *_imm64("x14", NEEDLE_Q1),
        "    movz w15, #0x4f46",
        "SCANLOOP:",
        "    ldr  x16, [x11]",
        "    cmp  x16, x13",
        "    b.eq SCANQ1",
        "    b    SCANNEXT",
        "SCANQ1:",
        "    ldr  x16, [x11, #8]",
        "    cmp  x16, x14",
        "    b.eq SCANQ2",
        "    b    SCANNEXT",
        "SCANQ2:",
        "    ldrh w16, [x11, #16]",
        "    cmp  w16, w15",
        "    b.eq MATCHED",
        "SCANNEXT:",
        "    add  x11, x11, #1",
        "    subs x12, x12, #1",
        "    b.ne SCANLOOP",
        "PASSTHROUGH:",
        "    stp  x29, x30, [sp, #-0x10]!",  # keep the caller's LR across the bl
        "    bl   DISPATCH",
        "    ldp  x29, x30, [sp], #0x10",
        "    ret",
        # ---- matched: build the recom_list response ----
        "MATCHED:",
        f"    sub  sp, sp, #{FRAME:#x}",
        "    stp  x29, x30, [sp]",  # slot 0x00, inside the stp imm7 range
        "    mov  x29, sp",
        f"    str  x19, [sp, #{X19S:#x}]",
        f"    str  x20, [sp, #{X20S:#x}]",
        f"    str  x21, [sp, #{X21S:#x}]",
        "    mov  x19, x8",  # response sret
        "    mov  x20, x0",  # config (state path string)
        "    mov  x21, x1",  # request
        # packet_no echo (shared by both response paths)
        *_packet_no_digits(lit_addrs),
        # state snapshot
        f"    add  x8, sp, #{SNAP:#x}",
        "    mov  x0, x20",
        "    bl   LOAD_SNAPSHOT",
        f"    ldrb w9, [sp, #{SNAP:#x}]",
        "    cbz  w9, ACK_ONLY",
        # recom_list = friend_list_json(state, "friends")
        *_ctor_from_lit(KEY_FRIENDS, "LIT_FRIENDS", lit_addrs),
        f"    add  x8, sp, #{LIST_OUT:#x}",
        f"    add  x0, sp, #{SNAP + 8:#x}",
        f"    add  x1, sp, #{KEY_FRIENDS:#x}",
        "    bl   FRIEND_LIST_JSON",
        # response = A + digits + B + list + C; the final concat lands in x19
        *_ctor_from_lit(T_A, "LIT_A", lit_addrs),
        *_concat(f"    add  x8, sp, #{T1:#x}", T_A, T_DIGITS),
        *_ctor_from_lit(T_B, "LIT_B", lit_addrs),
        *_concat(f"    add  x8, sp, #{T2:#x}", T1, T_B),
        *_concat(f"    add  x8, sp, #{T3:#x}", T2, LIST_OUT),
        *_ctor_from_lit(T_C, "LIT_C", lit_addrs),
        *_concat("    mov  x8, x19", T3, T_C),
        *_destroy(T_A),
        *_destroy(T_DIGITS),
        *_destroy(T_B),
        *_destroy(T_C),
        *_destroy(T1),
        *_destroy(T2),
        *_destroy(T3),
        *_destroy(LIST_OUT),
        *_destroy(KEY_FRIENDS),
        f"    add  x0, sp, #{SNAP:#x}",
        "    bl   SNAPSHOT_DTOR",
        "    b    CAVE_DONE",
        # ---- fallback: state unavailable -> plain ack ----
        "ACK_ONLY:",
        *_ctor_from_lit(T_A, "LIT_A", lit_addrs),
        *_concat(f"    add  x8, sp, #{T1:#x}", T_A, T_DIGITS),
        *_ctor_from_lit(T_D, "LIT_D", lit_addrs),
        *_concat("    mov  x8, x19", T1, T_D),
        *_destroy(T_A),
        *_destroy(T_DIGITS),
        *_destroy(T_D),
        *_destroy(T1),
        "CAVE_DONE:",
        "    mov  x0, x19",
        f"    ldr  x19, [sp, #{X19S:#x}]",
        f"    ldr  x20, [sp, #{X20S:#x}]",
        f"    ldr  x21, [sp, #{X21S:#x}]",
        "    ldp  x29, x30, [sp]",
        f"    add  sp, sp, #{FRAME:#x}",
        "    ret",
    ]
    return "\n".join(lines)


def _resolve_labels(src: str, base: int) -> str:
    """Turn branch-to-label operands into absolute addresses.

    Every source line is a single 4-byte instruction (or a `label:` marker),
    so each label's address is `base + 4 * (instructions before it)`.  Only
    tokens that are known labels are substituted, so the external helper names
    (DISPATCH, STRING_CTOR, ...) keep flowing to asm_cave's own rewriter.
    """
    label_at: dict[str, int] = {}
    count = 0
    for line in src.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        if stripped.endswith(":"):
            label_at[stripped[:-1]] = base + 4 * count
        else:
            count += 1
    out: list[str] = []
    for line in src.splitlines():
        stripped = line.strip()
        if _BRANCH_LINE.match(line) and stripped and not stripped.endswith(":"):
            target = re.split(r"[,\s]+", stripped)[-1].strip()
            if target in label_at:
                line = line[: line.rfind(target)] + f"#{label_at[target]:#x}"
        out.append(line)
    return "\n".join(out)


def build_cave() -> bytes:
    # pass 1 measures the code; pass 2 re-emits with real literal addresses,
    # then the literal bytes are appended after the code.
    zero_addrs = {name: CAVE_VADDR for name, _ in LITERALS}
    code = assemble_cave(_resolve_labels(build_source(zero_addrs), CAVE_VADDR), base=CAVE_VADDR, symbols=SYMBOLS)
    base = CAVE_VADDR + len(code)
    lit_addrs: dict[str, int] = {}
    blob = bytearray()
    for name, data in LITERALS:
        lit_addrs[name] = base + len(blob)
        blob += data
    code = assemble_cave(_resolve_labels(build_source(lit_addrs), CAVE_VADDR), base=CAVE_VADDR, symbols=SYMBOLS)
    return bytes(code + blob)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--hex", action="store_true", help="print hex only")
    parser.add_argument("--listing", action="store_true", help="print generated assembly")
    args = parser.parse_args(argv)

    if args.listing:
        zero_addrs = {name: CAVE_VADDR for name, _ in LITERALS}
        print(build_source(zero_addrs))
        return 0
    code = build_cave()
    if args.hex:
        print(code.hex())
        return 0
    from capstone import CS_ARCH_ARM64, CS_MODE_ARM, Cs

    code_len = len(code) - sum(len(data) for _, data in LITERALS)
    print(f"; {len(code)} bytes, {code_len // 4} instructions + {len(code) - code_len} literal bytes")
    for ins in Cs(CS_ARCH_ARM64, CS_MODE_ARM).disasm(code[:code_len], CAVE_VADDR):
        target = ""
        if ins.mnemonic.startswith("b") and not ins.mnemonic.startswith("bl"):
            try:
                target = f"   -> 0x{int(ins.op_str.lstrip('#'), 16):x}"
            except ValueError:
                target = ""
        print(f"0x{ins.address:x}  {ins.mnemonic:10s} {ins.op_str}{target}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
