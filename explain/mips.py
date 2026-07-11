"""Bounded MIPS decoding needed by the retail/candidate explainer.

Control-flow facts come from instruction words, not disassembler prose. Capstone
is optional and is used only to improve human-readable mnemonic/operand text.
"""

from __future__ import annotations

import struct
from collections.abc import Iterable, Mapping

from .model import Instruction


_REGISTERS = (
    "$zero", "$at", "$v0", "$v1", "$a0", "$a1", "$a2", "$a3",
    "$t0", "$t1", "$t2", "$t3", "$t4", "$t5", "$t6", "$t7",
    "$s0", "$s1", "$s2", "$s3", "$s4", "$s5", "$s6", "$s7",
    "$t8", "$t9", "$k0", "$k1", "$gp", "$sp", "$fp", "$ra",
)
_BRANCH_OPS = {
    0x04: "beq", 0x05: "bne", 0x06: "blez", 0x07: "bgtz",
    0x14: "beql", 0x15: "bnel", 0x16: "blezl", 0x17: "bgtzl",
}
_REGIMM = {
    0x00: "bltz", 0x01: "bgez", 0x02: "bltzl", 0x03: "bgezl",
    0x10: "bltzal", 0x11: "bgezal", 0x12: "bltzall", 0x13: "bgezall",
}
_IMMEDIATE_OPS = {
    0x08: "addi", 0x09: "addiu", 0x0A: "slti", 0x0B: "sltiu",
    0x0C: "andi", 0x0D: "ori", 0x0E: "xori", 0x0F: "lui",
    0x20: "lb", 0x21: "lh", 0x22: "lwl", 0x23: "lw",
    0x24: "lbu", 0x25: "lhu", 0x26: "lwr", 0x28: "sb",
    0x29: "sh", 0x2A: "swl", 0x2B: "sw", 0x2E: "swr",
    0x31: "lwc1", 0x39: "swc1", 0x37: "ld", 0x3F: "sd",
}
_SPECIAL = {
    0x00: "sll", 0x02: "srl", 0x03: "sra", 0x04: "sllv",
    0x06: "srlv", 0x07: "srav", 0x08: "jr", 0x09: "jalr",
    0x10: "mfhi", 0x11: "mthi", 0x12: "mflo", 0x13: "mtlo",
    0x18: "mult", 0x19: "multu", 0x1A: "div", 0x1B: "divu",
    0x20: "add", 0x21: "addu", 0x22: "sub", 0x23: "subu",
    0x24: "and", 0x25: "or", 0x26: "xor", 0x27: "nor",
    0x2A: "slt", 0x2B: "sltu",
}


def _capstone_decoder():
    try:
        from capstone import Cs, CS_ARCH_MIPS, CS_MODE_LITTLE_ENDIAN, CS_MODE_MIPS64
    except ImportError:
        return None
    return Cs(CS_ARCH_MIPS, CS_MODE_MIPS64 | CS_MODE_LITTLE_ENDIAN)


def _signed16(value: int) -> int:
    return value - 0x10000 if value & 0x8000 else value


def _fallback_text(word: int, address: int) -> tuple[str, str]:
    opcode = word >> 26
    rs = (word >> 21) & 31
    rt = (word >> 16) & 31
    rd = (word >> 11) & 31
    immediate = word & 0xFFFF
    if word == 0:
        return "nop", ""
    if opcode == 0:
        mnemonic = _SPECIAL.get(word & 63, "special")
        if mnemonic == "jr":
            return mnemonic, _REGISTERS[rs]
        if mnemonic == "jalr":
            return mnemonic, f"{_REGISTERS[rd]}, {_REGISTERS[rs]}"
        return mnemonic, f"{_REGISTERS[rd]}, {_REGISTERS[rs]}, {_REGISTERS[rt]}"
    if opcode in (2, 3):
        target = ((address + 4) & 0xF0000000) | ((word & 0x03FFFFFF) << 2)
        return ("j" if opcode == 2 else "jal"), f"0x{target:08x}"
    if opcode == 1:
        mnemonic = _REGIMM.get(rt, "regimm")
        target = address + 4 + (_signed16(immediate) << 2)
        return mnemonic, f"{_REGISTERS[rs]}, 0x{target:08x}"
    if opcode in _BRANCH_OPS:
        mnemonic = _BRANCH_OPS[opcode]
        target = address + 4 + (_signed16(immediate) << 2)
        operands = f"{_REGISTERS[rs]}, {_REGISTERS[rt]}, 0x{target:08x}"
        return mnemonic, operands
    mnemonic = _IMMEDIATE_OPS.get(opcode, f"op_{opcode:02x}")
    if mnemonic == "lui":
        return mnemonic, f"{_REGISTERS[rt]}, 0x{immediate:x}"
    return mnemonic, f"{_REGISTERS[rt]}, {_signed16(immediate)}({_REGISTERS[rs]})"


def _control_flow(word: int, address: int) -> tuple[str, int | None]:
    opcode = word >> 26
    if opcode in (2, 3):
        target = ((address + 4) & 0xF0000000) | ((word & 0x03FFFFFF) << 2)
        return ("jump" if opcode == 2 else "call"), target
    if opcode == 0:
        funct = word & 63
        if funct == 0x08:
            return "return" if ((word >> 21) & 31) == 31 else "indirect_jump", None
        if funct == 0x09:
            return "indirect_call", None
    if opcode in _BRANCH_OPS or opcode == 1:
        return "branch", address + 4 + (_signed16(word & 0xFFFF) << 2)
    if opcode == 0x11 and ((word >> 21) & 31) == 0x08:
        return "branch", address + 4 + (_signed16(word & 0xFFFF) << 2)
    return "ordinary", None


def decode_instructions(
    data: bytes,
    base_address: int,
    relocations: Iterable[Mapping[str, object]] = (),
) -> tuple[Instruction, ...]:
    """Decode complete little-endian words and attach bounded relocation facts."""
    relocation_by_word: dict[int, list[str]] = {}
    for record in relocations:
        offset = record.get("offset")
        if not isinstance(offset, int) or offset < 0:
            continue
        kind = record.get("type", "?")
        symbol = record.get("symbol", "?")
        relocation_by_word.setdefault(offset & ~3, []).append(f"{kind}:{symbol}")

    decoder = _capstone_decoder()
    result: list[Instruction] = []
    for offset in range(0, len(data) - (len(data) % 4), 4):
        chunk = data[offset:offset + 4]
        word = struct.unpack_from("<I", chunk)[0]
        address = base_address + offset
        mnemonic, operands = _fallback_text(word, address)
        if decoder is not None:
            decoded = next(iter(decoder.disasm(chunk, address)), None)
            if decoded is not None:
                mnemonic, operands = decoded.mnemonic, decoded.op_str
        kind, target = _control_flow(word, address)
        reloc = relocation_by_word.get(offset)
        result.append(Instruction(
            offset=offset,
            address=address,
            word=word,
            mnemonic=mnemonic,
            operands=operands,
            kind=kind,
            target=target,
            relocation=",".join(reloc) if reloc else None,
        ))
    return tuple(result)


def direct_calls(instructions: Iterable[Instruction]) -> tuple[int, ...]:
    return tuple(ins.target for ins in instructions if ins.kind == "call" and ins.target is not None)
