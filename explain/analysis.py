"""CFG construction, instruction alignment, and bounded mismatch diagnosis."""

from __future__ import annotations

import hashlib
from collections.abc import Mapping, Sequence
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


def build_analysis(
    *,
    project: Mapping[str, Any],
    function: Mapping[str, Any],
    verification: Mapping[str, Any],
    candidate_bytes: bytes,
    retail_bytes: bytes,
    relocations: Sequence[Mapping[str, object]],
    symbols: Mapping[int, str],
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
