"""CFG construction, instruction alignment, and bounded mismatch diagnosis."""

from __future__ import annotations

import hashlib
from collections.abc import Callable, Mapping, Sequence
from typing import Any

from .mips import decode_instructions, direct_calls
from .model import AlignmentRow, BasicBlock, Finding, SCHEMA_NAME, SCHEMA_VERSION, Instruction


def build_blocks(instructions: Sequence[Instruction]) -> tuple[BasicBlock, ...]:
    if not instructions:
        return ()
    base = instructions[0].address
    end = instructions[-1].address + 4
    leaders = {0}
    for index, ins in enumerate(instructions):
        if ins.target is not None and base <= ins.target < end and (ins.target - base) % 4 == 0:
            leaders.add((ins.target - base) // 4)
        if ins.kind in {"branch", "jump", "return", "indirect_jump"} and index + 2 < len(instructions):
            leaders.add(index + 2)
    ordered = sorted(leaders)
    blocks: list[BasicBlock] = []
    for number, start in enumerate(ordered):
        stop = ordered[number + 1] if number + 1 < len(ordered) else len(instructions)
        indexes = tuple(range(start, stop))
        successors: list[int] = []
        control = next(
            (instructions[index] for index in reversed(indexes[-2:]) if instructions[index].kind != "ordinary"),
            None,
        )
        if control is None or control.kind in {"call", "indirect_call"}:
            if stop < len(instructions):
                successors.append(instructions[stop].offset)
        elif control.kind == "branch":
            if control.target is not None and base <= control.target < end:
                successors.append(control.target - base)
            if stop < len(instructions):
                successors.append(instructions[stop].offset)
        elif control.kind == "jump":
            if control.target is not None and base <= control.target < end:
                successors.append(control.target - base)
        blocks.append(BasicBlock(
            identifier=f"block-{number:04d}",
            start_offset=instructions[start].offset,
            end_offset=instructions[stop - 1].offset + 4,
            instruction_indexes=indexes,
            successors=tuple(dict.fromkeys(successors)),
        ))
    return tuple(blocks)


def _instruction_relation(candidate: Instruction, retail: Instruction) -> str:
    if candidate.word == retail.word:
        return "exact"
    if candidate.relocation is not None and candidate.mnemonic == retail.mnemonic:
        return "relocation"
    if candidate.mnemonic == retail.mnemonic:
        return "operand_difference"
    return "instruction_difference"


def _instruction_cost(candidate: Instruction, retail: Instruction) -> int:
    return {
        "exact": 0,
        "relocation": 0,
        "operand_difference": 1,
        "instruction_difference": 3,
    }[_instruction_relation(candidate, retail)]


def _align_instruction_indexes(
    candidate: Sequence[Instruction],
    retail: Sequence[Instruction],
    candidate_indexes: Sequence[int],
    retail_indexes: Sequence[int],
) -> list[AlignmentRow]:
    left, right = len(candidate_indexes), len(retail_indexes)
    costs = [[0] * (right + 1) for _ in range(left + 1)]
    choice = [[""] * (right + 1) for _ in range(left + 1)]
    for i in range(1, left + 1):
        costs[i][0], choice[i][0] = i * 2, "delete"
    for j in range(1, right + 1):
        costs[0][j], choice[0][j] = j * 2, "insert"
    for i in range(1, left + 1):
        for j in range(1, right + 1):
            diagonal = costs[i - 1][j - 1] + _instruction_cost(
                candidate[candidate_indexes[i - 1]], retail[retail_indexes[j - 1]])
            deletion = costs[i - 1][j] + 2
            insertion = costs[i][j - 1] + 2
            best = min((diagonal, 0, "pair"), (deletion, 1, "delete"), (insertion, 2, "insert"))
            costs[i][j], _, choice[i][j] = best
    rows: list[AlignmentRow] = []
    i, j = left, right
    while i or j:
        action = choice[i][j]
        if action == "pair":
            ci, ri = candidate_indexes[i - 1], retail_indexes[j - 1]
            rows.append(AlignmentRow(ci, ri, _instruction_relation(candidate[ci], retail[ri])))
            i -= 1
            j -= 1
        elif action == "delete":
            rows.append(AlignmentRow(candidate_indexes[i - 1], None, "candidate_only"))
            i -= 1
        else:
            rows.append(AlignmentRow(None, retail_indexes[j - 1], "retail_only"))
            j -= 1
    rows.reverse()
    return rows


def _block_cost(
    candidate: Sequence[Instruction],
    retail: Sequence[Instruction],
    left: BasicBlock,
    right: BasicBlock,
) -> int:
    rows = _align_instruction_indexes(candidate, retail, left.instruction_indexes, right.instruction_indexes)
    mismatch = sum(row.relation not in {"exact", "relocation"} for row in rows)
    return mismatch + abs(len(left.successors) - len(right.successors)) * 2


def align_cfg(
    candidate: Sequence[Instruction],
    retail: Sequence[Instruction],
    candidate_blocks: Sequence[BasicBlock],
    retail_blocks: Sequence[BasicBlock],
) -> tuple[AlignmentRow, ...]:
    """Align blocks first, then instructions inside paired blocks."""
    left, right = len(candidate_blocks), len(retail_blocks)
    costs = [[0] * (right + 1) for _ in range(left + 1)]
    choice = [[""] * (right + 1) for _ in range(left + 1)]
    for i in range(1, left + 1):
        costs[i][0] = costs[i - 1][0] + len(candidate_blocks[i - 1].instruction_indexes) + 2
        choice[i][0] = "delete"
    for j in range(1, right + 1):
        costs[0][j] = costs[0][j - 1] + len(retail_blocks[j - 1].instruction_indexes) + 2
        choice[0][j] = "insert"
    for i in range(1, left + 1):
        for j in range(1, right + 1):
            pair = costs[i - 1][j - 1] + _block_cost(
                candidate, retail, candidate_blocks[i - 1], retail_blocks[j - 1])
            delete = costs[i - 1][j] + len(candidate_blocks[i - 1].instruction_indexes) + 2
            insert = costs[i][j - 1] + len(retail_blocks[j - 1].instruction_indexes) + 2
            best = min((pair, 0, "pair"), (delete, 1, "delete"), (insert, 2, "insert"))
            costs[i][j], _, choice[i][j] = best
    groups: list[tuple[str, BasicBlock | None, BasicBlock | None]] = []
    i, j = left, right
    while i or j:
        action = choice[i][j]
        if action == "pair":
            groups.append((action, candidate_blocks[i - 1], retail_blocks[j - 1]))
            i -= 1
            j -= 1
        elif action == "delete":
            groups.append((action, candidate_blocks[i - 1], None))
            i -= 1
        else:
            groups.append((action, None, retail_blocks[j - 1]))
            j -= 1
    rows: list[AlignmentRow] = []
    for action, left_block, right_block in reversed(groups):
        if action == "pair":
            assert left_block is not None and right_block is not None
            rows.extend(_align_instruction_indexes(
                candidate, retail, left_block.instruction_indexes, right_block.instruction_indexes))
        elif action == "delete":
            assert left_block is not None
            rows.extend(AlignmentRow(index, None, "candidate_only") for index in left_block.instruction_indexes)
        else:
            assert right_block is not None
            rows.extend(AlignmentRow(None, index, "retail_only") for index in right_block.instruction_indexes)
    return tuple(rows)


def classify(
    candidate: Sequence[Instruction],
    retail: Sequence[Instruction],
    candidate_blocks: Sequence[BasicBlock],
    retail_blocks: Sequence[BasicBlock],
    rows: Sequence[AlignmentRow],
) -> tuple[Finding, ...]:
    differing = [index for index, row in enumerate(rows) if row.relation not in {"exact", "relocation"}]
    if not differing:
        return (Finding(
            "exact-instruction-stream", "Instruction streams agree after relocation normalization",
            "observed", "Every aligned instruction is exact or relocation-bearing with the same mnemonic.", (),
            "No source-shape diagnosis is required; retain authoritative retail verification as the match gate."),)

    findings: list[Finding] = []
    pairs: list[tuple[int, str, str]] = []
    for row_index in differing:
        row = rows[row_index]
        if row.candidate_index is not None and row.retail_index is not None:
            pairs.append((row_index, candidate[row.candidate_index].mnemonic, retail[row.retail_index].mnemonic))

    def add(identifier: str, title: str, selected: list[int], recommendation: str, confidence: str = "inference") -> None:
        if selected:
            findings.append(Finding(identifier, title, confidence,
                "Aligned instruction mnemonic pairs and CFG shape; no retail compiler IR is claimed.",
                tuple(selected), recommendation))

    add("integer-signedness", "Likely integer signedness or extension mismatch",
        [i for i, left, right in pairs if {left, right} in ({"lb", "lbu"}, {"lh", "lhu"}, {"slt", "sltu"}, {"slti", "sltiu"})],
        "Trace the field, parameter, and return types through every caller before changing signedness.")
    add("integer-float-storage", "Likely integer-bit-pattern versus floating-point storage/ABI mismatch",
        [i for i, left, right in pairs if {left, right} in ({"lw", "lwc1"}, {"sw", "swc1"})],
        "Check the declared field type and argument ABI; identical bits do not imply identical C types.")
    branch_rows = [i for i, left, right in pairs if left.startswith("b") or right.startswith("b") or left in {"j", "jr"} or right in {"j", "jr"}]
    cfg_changed = len(candidate_blocks) != len(retail_blocks) or [len(b.successors) for b in candidate_blocks] != [len(b.successors) for b in retail_blocks]
    if cfg_changed or branch_rows:
        selected = branch_rows or differing[:8]
        add("control-flow-shape", "Control-flow shape differs", selected,
            "Reconstruct branch conditions, loop form, switch cases, early exits, and delay-slot side effects before tuning allocation.",
            "observed" if cfg_changed else "inference")
    add("instruction-selection", "Equivalent region uses different instruction-selection families",
        [i for i, left, right in pairs if left != right],
        "Inspect casts, expression grouping, temporary extraction, addressing form, and operand order with a reduced compiler experiment.")
    same_mnemonic = [i for i, left, right in pairs if left == right]
    add("operand-or-allocation", "Opcode agrees but operands or immediates differ", same_mnemonic,
        "Separate relocation/constants from register differences; if PCode agrees, inspect live ranges and colorgraph assignment.")
    gaps = [i for i in differing if rows[i].candidate_index is None or rows[i].retail_index is None]
    add("operation-count", "Candidate and retail contain unmatched operations", gaps,
        "Check missing side effects, duplicated expressions, temporary materialization, and function boundary/size before codegen shaping.",
        "observed")
    return tuple(findings)


def _trim_post_terminal_padding(instructions: Sequence[Instruction]) -> tuple[Instruction, ...]:
    """Exclude zero words after a terminal instruction's required delay slot."""
    for index in range(len(instructions) - 2, -1, -1):
        instruction = instructions[index]
        if instruction.kind not in {"return", "jump", "indirect_jump"}:
            continue
        trailing = instructions[index + 2:]
        if all(item.word == 0 for item in trailing):
            return tuple(instructions[:index + 2])
    return tuple(instructions)


_REGISTER_NAMES = (
    "$zero", "$at", "$v0", "$v1", "$a0", "$a1", "$a2", "$a3",
    "$t0", "$t1", "$t2", "$t3", "$t4", "$t5", "$t6", "$t7",
    "$s0", "$s1", "$s2", "$s3", "$s4", "$s5", "$s6", "$s7",
    "$t8", "$t9", "$k0", "$k1", "$gp", "$sp", "$fp", "$ra",
)
_MEMORY_ACCESS = {
    0x20: ("read", 1, "signed"), 0x24: ("read", 1, "unsigned"),
    0x21: ("read", 2, "signed"), 0x25: ("read", 2, "unsigned"),
    0x23: ("read", 4, "integer"), 0x31: ("read", 4, "float"),
    0x37: ("read", 8, "integer"), 0x28: ("write", 1, "integer"),
    0x29: ("write", 2, "integer"), 0x2B: ("write", 4, "integer"),
    0x39: ("write", 4, "float"), 0x3F: ("write", 8, "integer"),
}


def _signed16(value: int) -> int:
    return value - 0x10000 if value & 0x8000 else value


def _printable_string(
    address: int,
    read_memory: Callable[[int, int], bytes] | None,
) -> str | None:
    if read_memory is None:
        return None
    try:
        data = read_memory(address, 256)
    except (OSError, ValueError):
        return None
    terminator = data.find(b"\0")
    if terminator < 4:
        return None
    raw = data[:terminator]
    if any(byte not in b"\t\n\r" and not 0x20 <= byte <= 0x7E for byte in raw):
        return None
    return raw.decode("ascii")


def _retail_references(
    instructions: Sequence[Instruction],
    *,
    gp: int | None,
    symbols: Mapping[int, str],
    read_memory: Callable[[int, int], bytes] | None,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    registers: dict[int, tuple[int, str]] = {0: (0, "constant")}
    if gp is not None:
        registers[28] = (gp, "gp")
    globals_found: list[dict[str, Any]] = []
    fields_found: list[dict[str, Any]] = []
    strings: dict[int, dict[str, Any]] = {}
    seen_addresses: set[tuple[int, int]] = set()

    def record_address(instruction: Instruction, address: int, provenance: str) -> None:
        key = (instruction.offset, address)
        if key in seen_addresses:
            return
        seen_addresses.add(key)
        text = _printable_string(address, read_memory)
        if text is not None:
            strings.setdefault(address, {
                "address": f"{address:08x}",
                "text": text,
                "first_reference_offset": instruction.offset,
                "provenance": provenance,
            })

    for instruction in instructions:
        word = instruction.word
        opcode = word >> 26
        rs = (word >> 21) & 31
        rt = (word >> 16) & 31
        rd = (word >> 11) & 31
        immediate = word & 0xFFFF

        access = _MEMORY_ACCESS.get(opcode)
        if access is not None:
            operation, width, interpretation = access
            displacement = _signed16(immediate)
            resolved = registers.get(rs)
            record: dict[str, Any] = {
                "instruction_offset": instruction.offset,
                "operation": operation,
                "width": width,
                "interpretation": interpretation,
                "base_register": _REGISTER_NAMES[rs],
                "displacement": displacement,
            }
            if resolved is not None:
                address = (resolved[0] + displacement) & 0xFFFFFFFF
                record.update({
                    "address": f"{address:08x}",
                    "symbol": symbols.get(address),
                    "provenance": resolved[1],
                })
                globals_found.append(record)
                record_address(instruction, address, resolved[1])
            elif rs not in {0, 28, 29}:
                fields_found.append(record)

        if opcode == 0x0F:
            registers[rt] = ((immediate << 16) & 0xFFFFFFFF, "lui")
            continue
        if opcode in {0x08, 0x09, 0x0D}:
            source = registers.get(rs)
            if source is not None:
                value = ((source[0] | immediate) if opcode == 0x0D
                         else (source[0] + _signed16(immediate))) & 0xFFFFFFFF
                provenance = "gp" if source[1] == "gp" else (
                    "lui-low" if source[1] == "lui" else source[1])
                registers[rt] = (value, provenance)
                if source[1] == "lui":
                    record_address(instruction, value, provenance)
            else:
                registers.pop(rt, None)
            continue
        if opcode == 0 and (word & 63) in {0x20, 0x21}:
            left, right = registers.get(rs), registers.get(rt)
            if left is not None and right is not None:
                registers[rd] = ((left[0] + right[0]) & 0xFFFFFFFF, "register-add")
            else:
                registers.pop(rd, None)
            continue
        if access is not None and access[0] == "read":
            registers.pop(rt, None)

    globals_found.sort(key=lambda item: (item["instruction_offset"], item["address"]))
    fields_found.sort(key=lambda item: (item["base_register"], item["displacement"], item["instruction_offset"]))
    return globals_found, fields_found, [strings[address] for address in sorted(strings)]


def _final_lowering(
    instructions: Sequence[Instruction],
    relocations: Sequence[Mapping[str, object]],
) -> dict[str, Any]:
    frame_size: int | None = None
    stack_slots: list[dict[str, Any]] = []
    for instruction in instructions:
        word = instruction.word
        opcode = word >> 26
        rs = (word >> 21) & 31
        rt = (word >> 16) & 31
        immediate = _signed16(word & 0xFFFF)
        if opcode == 0x09 and rs == 29 and rt == 29 and immediate < 0 and frame_size is None:
            frame_size = -immediate
        access = _MEMORY_ACCESS.get(opcode)
        if access is not None and rs == 29:
            stack_slots.append({
                "instruction_offset": instruction.offset,
                "operation": access[0],
                "width": access[1],
                "register": _REGISTER_NAMES[rt],
                "stack_offset": immediate,
            })
    return_index = next((i for i, item in enumerate(instructions) if item.kind == "return"), None)
    delay = instructions[return_index + 1].evidence() if return_index is not None and return_index + 1 < len(instructions) else None
    return {
        "evidence": "observed-final-object",
        "frame_size": frame_size,
        "stack_slots": stack_slots,
        "return_delay_slot": delay,
        "relocation_count": len(relocations),
        "internal_final_lowering_capture": "not-claimed",
    }


def build_analysis(
    *,
    project: Mapping[str, Any],
    function: Mapping[str, Any],
    verification: Mapping[str, Any],
    candidate_bytes: bytes,
    retail_bytes: bytes,
    relocations: Sequence[Mapping[str, object]],
    symbols: Mapping[int, str],
    gp: int | None = None,
    read_memory: Callable[[int, int], bytes] | None = None,
    callers: Sequence[Mapping[str, Any]] = (),
    cross_game: Sequence[Mapping[str, Any]] = (),
    compiler_capture: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    address_text = function.get("address")
    if not isinstance(address_text, str):
        raise ValueError("function address must be a hexadecimal string")
    address = int(address_text, 16)
    candidate = _trim_post_terminal_padding(decode_instructions(candidate_bytes, address, relocations))
    retail = _trim_post_terminal_padding(decode_instructions(retail_bytes, address))
    candidate_blocks = build_blocks(candidate)
    retail_blocks = build_blocks(retail)
    alignment = align_cfg(candidate, retail, candidate_blocks, retail_blocks)
    findings = classify(candidate, retail, candidate_blocks, retail_blocks, alignment)

    calls = []
    for target in direct_calls(retail):
        calls.append({"address": f"{target:08x}", "symbol": symbols.get(target)})
    globals_found, fields_found, strings = _retail_references(
        retail, gp=gp, symbols=symbols, read_memory=read_memory)
    relocation_evidence = []
    for record in relocations:
        relocation_evidence.append({
            key: value for key, value in record.items()
            if key in {"offset", "type", "symbol", "addend", "retail_value"}
            and isinstance(value, (str, int, bool, type(None)))
        })

    return {
        "schema": {"name": SCHEMA_NAME, "version": SCHEMA_VERSION},
        "authority": {
            "match": "Only the project verifier row can certify MATCH.",
            "observed": "Bytes, decoded control flow, relocations, calls, and verifier fields are observed evidence.",
            "inferred": "Findings are bounded hypotheses; no retail AST, PCode, scheduler queue, or allocation graph is claimed.",
        },
        "project": dict(project),
        "function": dict(function),
        "verification": dict(verification),
        "artifacts": {
            "candidate_sha256": hashlib.sha256(candidate_bytes).hexdigest(),
            "retail_sha256": hashlib.sha256(retail_bytes).hexdigest(),
            "candidate_size": len(candidate_bytes),
            "retail_window": len(retail_bytes),
        },
        "calls": calls,
        "callers": [dict(item) for item in callers],
        "cross_game": [dict(item) for item in cross_game],
        "retail_globals": globals_found,
        "structure_fields": fields_found,
        "strings": strings,
        "final_lowering": _final_lowering(candidate, relocations),
        "compiler_capture": dict(compiler_capture) if compiler_capture is not None else None,
        "candidate_relocations": relocation_evidence,
        "candidate": {
            "instructions": [item.evidence() for item in candidate],
            "blocks": [item.evidence() for item in candidate_blocks],
        },
        "retail": {
            "instructions": [item.evidence() for item in retail],
            "blocks": [item.evidence() for item in retail_blocks],
        },
        "alignment": [item.evidence() for item in alignment],
        "findings": [item.evidence() for item in findings],
    }
