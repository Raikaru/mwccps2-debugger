"""Version-profiled MWCCPS2 live-state decoding with bounded memory walks."""
from __future__ import annotations

import hashlib
import json
import struct
from pathlib import Path
from typing import Any, Mapping


class ProfileError(ValueError):
    pass


class MemoryReadError(RuntimeError):
    pass


def address(value: Any, name: str = "address") -> int:
    try:
        result = int(value, 0) if isinstance(value, str) else int(value)
    except (TypeError, ValueError) as exc:
        raise ProfileError(f"{name} is not an integer address") from exc
    if not 0 <= result <= 0xFFFFFFFF:
        raise ProfileError(f"{name} is outside the 32-bit address space")
    return result


def load_profile(path: str | Path) -> dict[str, Any]:
    profile_path = Path(path)
    try:
        value = json.loads(profile_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ProfileError(f"cannot load profile {profile_path}: {exc}") from exc
    if not isinstance(value, dict) or value.get("schema_version") not in (1, 2):
        raise ProfileError("profile must be a schema-version 1 or 2 object")
    for key in ("name", "binary", "functions", "globals"):
        if key not in value:
            raise ProfileError(f"profile is missing {key}")
    binary = value["binary"]
    if not isinstance(binary, dict) or not isinstance(binary.get("sha256"), str):
        raise ProfileError("profile.binary.sha256 is required")
    if len(binary["sha256"]) != 64:
        raise ProfileError("profile.binary.sha256 must contain 64 hexadecimal characters")
    try:
        int(binary["sha256"], 16)
    except ValueError as exc:
        raise ProfileError("profile.binary.sha256 is not hexadecimal") from exc
    if value.get("schema_version") == 2:
        for key in ("pcode_layout", "pcode_opcode_table", "pcode_breakpoints", "scheduler", "register_allocation", "frontend_ir"):
            if key not in value:
                raise ProfileError(f"schema-version 2 profile is missing {key}")
        if not isinstance(value["pcode_breakpoints"], list) or not value["pcode_breakpoints"]:
            raise ProfileError("pcode_breakpoints must be a non-empty list")
        seen: set[str] = set()
        for index, stage in enumerate(value["pcode_breakpoints"]):
            if not isinstance(stage, dict) or not isinstance(stage.get("name"), str):
                raise ProfileError(f"pcode_breakpoints[{index}] is invalid")
            address(stage.get("address"), f"pcode_breakpoints[{index}].address")
            if stage["name"] in seen:
                raise ProfileError(f"duplicate PCode stage {stage['name']!r}")
            seen.add(stage["name"])
    return value


def fingerprint_executable(path: str | Path, profile: Mapping[str, Any]) -> dict[str, Any]:
    executable = Path(path).resolve(strict=True)
    data = executable.read_bytes()
    binary = profile["binary"]
    if executable.name.casefold() != str(binary["filename"]).casefold():
        raise ProfileError(f"compiler filename {executable.name!r} does not match {binary['filename']!r}")
    if len(data) != int(binary["size"]):
        raise ProfileError(f"compiler size {len(data)} does not match {binary['size']}")
    digest = hashlib.sha256(data).hexdigest()
    if digest.casefold() != str(binary["sha256"]).casefold():
        raise ProfileError("compiler SHA-256 does not match the selected live profile")
    if data[:2] != b"MZ":
        raise ProfileError("compiler is not a PE image")
    pe = struct.unpack_from("<I", data, 0x3C)[0]
    timestamp = struct.unpack_from("<I", data, pe + 8)[0]
    expected_timestamp = address(binary["pe_timestamp"], "binary.pe_timestamp")
    if timestamp != expected_timestamp:
        raise ProfileError("compiler PE timestamp does not match the selected live profile")
    return {"path": str(executable), "sha256": digest, "size": len(data), "pe_timestamp": f"0x{timestamp:08x}"}


def _read(memory: Any, pointer: int, size: int, context: str) -> bytes:
    try:
        value = bytes(memory.read(pointer, size))
    except Exception as exc:
        raise MemoryReadError(f"cannot read {context} at 0x{pointer:08x}: {exc}") from exc
    if len(value) != size:
        raise MemoryReadError(f"short read for {context} at 0x{pointer:08x}")
    return value


def u8(data: bytes, offset: int) -> int:
    return data[offset]


def u16(data: bytes, offset: int) -> int:
    return struct.unpack_from("<H", data, offset)[0]


def i16(data: bytes, offset: int) -> int:
    return struct.unpack_from("<h", data, offset)[0]


def u32(data: bytes, offset: int) -> int:
    return struct.unpack_from("<I", data, offset)[0]


def i32(data: bytes, offset: int) -> int:
    return struct.unpack_from("<i", data, offset)[0]


def read_c_string(memory: Any, pointer: int, limit: int = 256) -> str:
    if pointer == 0:
        return ""
    out = bytearray()
    for offset in range(limit):
        byte = _read(memory, pointer + offset, 1, "string")[0]
        if byte == 0:
            return out.decode("latin-1", errors="replace")
        out.append(byte)
    return out.decode("latin-1", errors="replace") + "…"


def codegen_function_name(memory: Any, stack_pointer: int, profile: Mapping[str, Any]) -> str:
    layout = profile["function_name"]
    argument = u32(_read(memory, stack_pointer + int(layout["codegen_argument_stack_offset"]), 4, "CodeGen argument"), 0)
    if not argument:
        return "<anonymous>"
    record = u32(_read(memory, argument + int(layout["name_record_pointer_offset"]), 4, "function name record"), 0)
    if not record:
        return "<anonymous>"
    return read_c_string(
        memory,
        record + int(layout["inline_name_offset"]),
        int(layout.get("max_bytes", 256)),
    ) or "<anonymous>"


def _opcode(memory: Any, profile: Mapping[str, Any], opcode: int) -> dict[str, Any]:
    table = profile["pcode_opcode_table"]
    if opcode < 0 or opcode >= int(table["entry_count"]):
        return {"opcode": opcode, "mnemonic": f"op_{opcode}"}
    base = address(table["address"]) + opcode * int(table["entry_stride"])
    fields = table["fields"]
    data = _read(memory, base, int(table["entry_stride"]), "opcode entry")
    result: dict[str, Any] = {"opcode": opcode}
    for name in ("mnemonic", "alternate_mnemonic", "operand_format", "aux_internal_name"):
        if name in fields:
            pointer = u32(data, int(fields[name]))
            result[name] = read_c_string(memory, pointer, int(table.get("string_max_bytes", 128))) if pointer else None
    for name in ("operand_slot_count", "opaque_format_class"):
        if name in fields:
            result[name] = u8(data, int(fields[name]))
    for name in ("encoding_template", "property_flags", "format_derived_flags"):
        if name in fields:
            result[name] = f"0x{u32(data, int(fields[name])):08x}"
    result["mnemonic"] = result.get("mnemonic") or f"op_{opcode}"
    return result


def _operand(memory: Any, pointer: int, profile: Mapping[str, Any], block_ids: Mapping[int, int]) -> dict[str, Any]:
    layout = profile["pcode_layout"]["operand"]
    stride = int(profile["pcode_layout"]["instruction"]["operand_stride"])
    data = _read(memory, pointer, stride, "PCode operand")
    fields = layout["fields"]
    tag = u8(data, int(fields["tag_u8"]))
    result: dict[str, Any] = {
        "tag": tag,
        "kind": layout.get("tags", {}).get(str(tag), "unknown"),
        "attributes": f"0x{u16(data, int(fields['attributes_u16'])):04x}",
        "raw": data.hex(),
    }
    payload = u32(data, int(fields["payload_u32"]))
    secondary = u32(data, int(fields["secondary_u32"]))
    if tag == 0:
        register_class = u8(data, int(fields["register_class_u8"]))
        labels = layout.get("register_classes", [])
        result.update(register_class=register_class, register_class_name=labels[register_class] if register_class < len(labels) else f"class{register_class}", register=u16(data, int(fields["payload_u32"])))
    elif tag == 1:
        result["system_register"] = u16(data, int(fields["payload_u32"]))
    elif tag in (2, 3):
        result.update(
            value=i32(data, int(fields["payload_u32"])),
            object_pointer=f"0x{secondary:08x}",
        )
    elif tag == 4:
        result.update(
            value=i32(data, int(fields["payload_u32"])),
            object_pointer=f"0x{secondary:08x}",
        )
    elif tag == 6 and payload:
        label = profile["pcode_layout"]["label_record"]
        label_size = max(
            int(label["block_pointer_offset"]) + 4,
            int(label["bound_u16_offset"]) + 2,
            int(label["index_u16_offset"]) + 2,
        )
        label_data = _read(memory, payload, label_size, "label record")
        if u16(label_data, int(label["bound_u16_offset"])) == 1:
            block_pointer = u32(label_data, int(label["block_pointer_offset"]))
            result.update(
                label_index=u16(label_data, int(label["index_u16_offset"])),
                block_id=block_ids.get(block_pointer),
            )
        else:
            result["label_state"] = "unbound"
    else:
        result.update(payload=f"0x{payload:08x}", secondary=f"0x{secondary:08x}")
    return result


def collect_pcode(memory: Any, profile: Mapping[str, Any], max_blocks: int = 4096, max_instructions: int = 65536, max_operands: int = 32) -> dict[str, Any]:
    block_layout = profile["pcode_layout"]["basic_block"]
    instruction_layout = profile["pcode_layout"]["instruction"]
    bf = block_layout["fields"]
    inf = instruction_layout["fields"]
    head = u32(_read(memory, address(profile["globals"]["pcbasicblocks"]["address"]), 4, "pcbasicblocks"), 0)
    block_records: list[tuple[int, bytes]] = []
    seen: set[int] = set()
    pointer = head
    while pointer and len(block_records) < max_blocks and pointer not in seen:
        seen.add(pointer)
        data = _read(memory, pointer, int(block_layout["byte_size"]), "basic block")
        block_records.append((pointer, data))
        pointer = u32(data, int(bf["next"]))
    block_ids = {pointer: index for index, (pointer, _) in enumerate(block_records)}
    blocks: list[dict[str, Any]] = []
    instruction_total = 0
    for block_pointer, data in block_records:
        block: dict[str, Any] = {
            "id": block_ids[block_pointer],
            "index": i32(data, int(bf["index_i32"])),
            "flags": f"0x{u16(data, int(bf['flags_u16'])):04x}",
            "declared_instruction_count": i16(data, int(bf["pcode_count_i16"])),
            "instructions": [],
        }
        current = u32(data, int(bf["pcode_head"]))
        local_seen: set[int] = set()
        while current and current not in local_seen and instruction_total < max_instructions:
            local_seen.add(current)
            header = _read(memory, current, int(instruction_layout["header_size"]), "PCode instruction")
            opcode_value = u16(header, int(inf["opcode_u16"]))
            count = i16(header, int(inf["operand_count_i16"]))
            instruction = {
                "id": instruction_total,
                "opcode": _opcode(memory, profile, opcode_value),
                "property_flags": f"0x{u32(header, int(inf['property_flags'])):08x}",
                "encoded_word": f"0x{u32(header, int(inf['encoded_word_u32'])):08x}",
                "operands": [],
            }
            if 0 <= count <= max_operands:
                operand_pointer = current + int(instruction_layout["header_size"])
                for index in range(count):
                    instruction["operands"].append(_operand(memory, operand_pointer + index * int(instruction_layout["operand_stride"]), profile, block_ids))
            else:
                instruction["operand_error"] = f"invalid operand count {count}"
            block["instructions"].append(instruction)
            instruction_total += 1
            current = u32(header, int(inf["next"]))
        blocks.append(block)
    return {"block_count": len(blocks), "instruction_count": instruction_total, "truncated": bool(pointer) or instruction_total >= max_instructions, "blocks": blocks}


def _render_operand(operand: Mapping[str, Any]) -> str:
    kind = operand["kind"]
    if kind == "register":
        prefix = {"GPR": "r", "FPR": "f"}.get(str(operand["register_class_name"]), str(operand["register_class_name"]) + ":")
        return f"{prefix}{operand['register']}"
    if kind == "system_register":
        return f"spr{operand['system_register']}"
    if kind in ("immediate", "inline_immediate", "memory"):
        value = int(operand["value"])
        rendered = f"-0x{-value:x}" if value < 0 else str(value) if value < 10 else f"0x{value:x}"
        return rendered if kind != "memory" else rendered + f"({operand['object_pointer']})"
    if kind == "label":
        return f"B{operand.get('block_id', '?')}"
    if kind == "placeholder":
        return "_"
    return f"<{kind}:{operand.get('payload', '?')}>"


def format_pcode(graph: Mapping[str, Any]) -> str:
    lines = [f"{graph['block_count']} blocks, {graph['instruction_count']} instructions"]
    for block in graph["blocks"]:
        lines.append(f"\nB{block['id']} (compiler index {block['index']}, flags {block['flags']}):")
        for instruction in block["instructions"]:
            mnemonic = instruction["opcode"]["mnemonic"]
            operands = ", ".join(_render_operand(value) for value in instruction["operands"])
            lines.append(f"  {instruction['id']:04d}: {mnemonic}" + (f" {operands}" if operands else ""))
    if graph.get("truncated"):
        lines.append("\n[capture truncated by safety limits]")
    return "\n".join(lines) + "\n"


def collect_scheduler_ready(memory: Any, profile: Mapping[str, Any], max_nodes: int = 4096) -> list[dict[str, Any]]:
    scheduler = profile["scheduler"]
    fields = scheduler["node_fields"]
    head = u32(_read(memory, address(scheduler["globals"]["ready_head"]), 4, "scheduler ready head"), 0)
    result: list[dict[str, Any]] = []
    seen: set[int] = set()
    pointer = head
    while pointer and pointer not in seen and len(result) < max_nodes:
        seen.add(pointer)
        data = _read(memory, pointer, int(scheduler["node_stride"]), "scheduler node")
        result.append({
            "address": pointer,
            "pcode": u32(data, int(fields["pcode"])),
            "actual_latency": u16(data, int(fields["actual_latency"])),
            "heuristic_latency": u16(data, int(fields["heuristic_latency"])),
            "earliest_issue_cycle": u16(data, int(fields["earliest_issue_cycle"])),
            "critical_deadline_cycle": u16(data, int(fields["critical_deadline_cycle"])),
            "critical_path_length": u16(data, int(fields["critical_path_length"])),
            "pending_predecessors": i16(data, int(fields["pending_predecessors"])),
        })
        pointer = u32(data, int(fields["next"]))
    return result


def collect_regalloc_list(memory: Any, profile: Mapping[str, Any], head: int, max_nodes: int = 32767) -> dict[str, Any]:
    allocation = profile["register_allocation"]
    fields = allocation["node_fields"]
    class_id = struct.unpack("<b", _read(memory, address(allocation["globals"]["coloring_class"]), 1, "coloring class"))[0]
    labels = allocation["class_labels"]
    nodes: list[dict[str, Any]] = []
    seen: set[int] = set()
    pointer = head
    while pointer and pointer not in seen and len(nodes) < max_nodes:
        seen.add(pointer)
        data = _read(memory, pointer, int(allocation["node_stride"]), "interference node")
        flags = u16(data, int(fields["flags_u16"]))
        names = [name for bit, name in allocation.get("flag_bits", {}).items() if flags & int(bit)]
        nodes.append({"priority": len(nodes), "address": pointer, "virtual_register": i16(data, int(fields["virtual_register_i16"])), "physical_register": i16(data, int(fields["physical_register_i16"])), "flags": f"0x{flags:04x}", "flag_names": names, "interference_tree": u32(data, int(fields["interference_tree"]))})
        pointer = u32(data, int(fields["next"]))
    return {"class": {"id": class_id, "name": labels[class_id] if 0 <= class_id < len(labels) else f"class{class_id}"}, "node_count": len(nodes), "truncated": bool(pointer), "nodes": nodes}


def format_regalloc(capture: Mapping[str, Any]) -> str:
    lines = [f"{capture['class']['name']} allocation priority ({capture['node_count']} nodes):"]
    for node in capture["nodes"]:
        color = "SPILL" if node["physical_register"] < 0 else str(node["physical_register"])
        flags = ",".join(node["flag_names"]) or "-"
        lines.append(f"  {node['priority']:04d}: v{node['virtual_register']} -> {color}  [{flags}]")
    if capture.get("truncated"):
        lines.append("  [capture truncated by safety limit]")
    return "\n".join(lines) + "\n"
