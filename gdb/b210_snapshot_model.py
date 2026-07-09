"""Pure b210 snapshot schema, identity validation, graph normalization, and PCode decoding.

This module deliberately knows nothing about GDB.  The companion GDB command supplies a
small reader with a ``read(address, size) -> bytes`` method, while this module validates
profile data, bounds every inferior-memory walk, and removes structural heap addresses
from graph links.  Opcode and operand metadata is used only after the exact executable
fingerprint and b210 table sentinel have been validated at a capture breakpoint.
"""

from __future__ import annotations

import hashlib
import json
import struct
from pathlib import Path
from typing import Any, Mapping


SNAPSHOT_SCHEMA_NAME = "mwccps2-b210-stage-snapshot"
SNAPSHOT_SCHEMA_VERSION = 2
MANIFEST_SCHEMA_NAME = "mwccps2-b210-snapshot-manifest"
MANIFEST_SCHEMA_VERSION = 1
EXPECTED_PROFILE_NAME = "mwcps2-3.0.1b210-060308"

_BLOCK_SIZE = 0x30
_PCODE_HEADER_SIZE = 0x40
_OPERAND_SIZE = 0x18
_MAX_U32 = 0xFFFFFFFF
_OPCODE_TABLE_ADDRESS = 0x00626638
_OPCODE_ENTRY_COUNT = 0x4AF
_OPCODE_ENTRY_STRIDE = 0x30
_OPCODE_FIELDS: tuple[tuple[str, int, str], ...] = (
    ("mnemonic", 0x00, "pointer"),
    ("alternate_mnemonic", 0x04, "pointer"),
    ("operand_format", 0x08, "pointer"),
    ("operand_slot_count", 0x0C, "u8"),
    ("opaque_format_class", 0x0D, "u8"),
    ("opaque_0e", 0x0E, "u16"),
    ("encoding_template", 0x10, "u32"),
    ("opaque_14", 0x14, "u32"),
    ("property_flags", 0x18, "u32"),
    ("format_derived_flags", 0x1C, "u32"),
    ("aux_internal_name", 0x20, "pointer"),
    ("aux_ordinal", 0x24, "u32"),
    ("aux_value", 0x28, "u32"),
    ("aux_class", 0x2C, "u16"),
    ("opaque_2e", 0x2E, "u16"),
)


class SnapshotModelError(Exception):
    """Raised for invalid profiles, binaries, or snapshot configuration."""


class MemoryReadError(Exception):
    """Raised by a runtime-memory reader when a requested range is unavailable."""


# Every decoded field below is backed by exact b210 decompiler evidence.  Fields whose
# source-level names have not been proven remain explicitly raw or opaque.
B210_LAYOUT_EVIDENCE: dict[str, Any] = {
    "profile": EXPECTED_PROFILE_NAME,
    "pointer_width_bits": 32,
    "endianness": "little",
    "opcode_table": {
        "address": "0x00626638",
        "entry_count": "0x4af",
        "entry_stride": "0x30",
        "initialization": "0x0047ccc0 clears and populates the runtime .bss table before backend generation.",
        "sentinel": "Opcode 1 is add / =d,s,t / encoding 0x20 / flags 0x6000 / __I_add.",
        "evidence_addresses": "0x0047ccc0, 0x004925c0, 0x00485e10, 0x0049bd50, 0x004c2f30",
    },
    "fields": [
        {
            "subject": "pcbasicblocks",
            "address": "0x006363f0",
            "encoding": "u32 pointer",
            "decompiled_behavior": "CodeGen_Generator initializes its block walk from pcbasicblocks.",
            "evidence_address": "0x00435d90, 0x00436009, 0x004363db",
            "confidence": "high",
        },
        {
            "subject": "PCBasicBlock",
            "encoding": "size 0x30; next +0x00, previous +0x04, PCode head +0x14, tail +0x18",
            "decompiled_behavior": "PCode.c links blocks and CodeGen walks the head and PCode list.",
            "evidence_address": "0x0047c9c1, 0x0047ca03, 0x0047ca0b, 0x0047c6f6, 0x004360e0",
            "confidence": "high",
        },
        {
            "subject": "PCode",
            "encoding": "header size 0x40; next +0x00, previous +0x04, owner +0x08, property flags +0x0c, opcode u16 +0x28, operand count i16 +0x2a, encoded word +0x30",
            "decompiled_behavior": "PCodeInfo allocates 0x40 + 0x18 * count and CodeGen traverses linked nodes.",
            "evidence_address": "0x0048f2bf, 0x0048f2e7, 0x0047c6f0, 0x0043640d, 0x00436418",
            "confidence": "high",
        },
        {
            "subject": "PCode operand records",
            "encoding": "base +0x40, stride 0x18; tag u8 +0x00, class u8 +0x01, attrs u16 +0x02, payload +0x04",
            "decompiled_behavior": "PCodeInfo builder emits descriptors and the binary encoder consumes them.",
            "evidence_address": "0x0048f321, 0x0048f349, 0x0049bd50, 0x004c2f30",
            "confidence": "high",
        },
        {
            "subject": "PCode operand tags",
            "encoding": "0 register, 2 raw scalar/pointer category, 3 inline immediate/blob, 4 compound memory/object, 6 LabelRecord reference, 7 unresolved placeholder",
            "decompiled_behavior": "Tag 6 is a label only after LabelRecord+8 u16 equals 1; LabelRecord+4 then names the bound PCBasicBlock, which is normalized to a stable block ID when captured.",
            "evidence_address": "0x0047c820, 0x0047c920, 0x0049bd50, 0x004c2f30, 0x0048f8d0",
            "confidence": "high for tag categories and offsets; intentionally opaque for unproven payload meanings",
        },
    ],
}


def parse_address(value: str | int, field_name: str) -> int:
    """Parse a non-negative 32-bit profile address."""

    try:
        parsed = int(value, 0) if isinstance(value, str) else int(value)
    except (TypeError, ValueError) as exc:
        raise SnapshotModelError(f"{field_name} is not an integer address") from exc
    if not 0 <= parsed <= _MAX_U32:
        raise SnapshotModelError(f"{field_name} is outside the 32-bit address range")
    return parsed


def format_address(value: int) -> str:
    """Format a static or raw 32-bit word consistently."""

    return f"0x{value & _MAX_U32:08x}"


def _required_mapping(mapping: Mapping[str, Any], key: str, location: str) -> Mapping[str, Any]:
    value = mapping.get(key)
    if not isinstance(value, Mapping):
        raise SnapshotModelError(f"{location}.{key} must be an object")
    return value


def _require_exact_integer(
    mapping: Mapping[str, Any], key: str, expected: int, location: str
) -> None:
    value = mapping.get(key)
    if not isinstance(value, int) or value != expected:
        raise SnapshotModelError(f"{location}.{key} must be {expected}")


def _validate_opcode_table(profile: Mapping[str, Any]) -> None:
    """Reject profile drift before an address can be used against a live inferior."""

    table = _required_mapping(profile, "pcode_opcode_table", "profile")
    address = parse_address(table.get("address"), "pcode_opcode_table.address")
    if address != _OPCODE_TABLE_ADDRESS:
        raise SnapshotModelError(
            "pcode_opcode_table.address must be " + format_address(_OPCODE_TABLE_ADDRESS)
        )
    _require_exact_integer(table, "entry_count", _OPCODE_ENTRY_COUNT, "pcode_opcode_table")
    _require_exact_integer(table, "entry_stride", _OPCODE_ENTRY_STRIDE, "pcode_opcode_table")
    string_max_bytes = table.get("string_max_bytes")
    if not isinstance(string_max_bytes, int) or not 1 <= string_max_bytes <= 4096:
        raise SnapshotModelError("pcode_opcode_table.string_max_bytes must be 1..4096")

    fields = _required_mapping(table, "fields", "pcode_opcode_table")
    for field_name, expected_offset, expected_kind in _OPCODE_FIELDS:
        field = _required_mapping(fields, field_name, "pcode_opcode_table.fields")
        _require_exact_integer(field, "offset", expected_offset, f"pcode_opcode_table.fields.{field_name}")
        if field.get("kind") != expected_kind:
            raise SnapshotModelError(
                f"pcode_opcode_table.fields.{field_name}.kind must be {expected_kind!r}"
            )

    sentinel = _required_mapping(table, "post_initialization_sentinel", "pcode_opcode_table")
    _require_exact_integer(sentinel, "opcode", 1, "pcode_opcode_table.post_initialization_sentinel")
    expected_strings = {
        "mnemonic": "add",
        "operand_format": "=d,s,t",
        "aux_internal_name": "__I_add",
    }
    for name, expected in expected_strings.items():
        if sentinel.get(name) != expected:
            raise SnapshotModelError(
                f"pcode_opcode_table.post_initialization_sentinel.{name} must be {expected!r}"
            )
    for name, expected in (("encoding_template", 0x20), ("property_flags", 0x6000)):
        try:
            value = parse_address(sentinel.get(name), f"pcode_opcode_table.post_initialization_sentinel.{name}")
        except SnapshotModelError:
            raise
        if value != expected:
            raise SnapshotModelError(
                f"pcode_opcode_table.post_initialization_sentinel.{name} must be {format_address(expected)}"
            )


def load_b210_profile(path: str | Path) -> dict[str, Any]:
    """Load and validate the only profile that this command supports."""

    profile_path = Path(path)
    try:
        parsed = json.loads(profile_path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise SnapshotModelError(f"cannot read profile {profile_path}") from exc
    except json.JSONDecodeError as exc:
        raise SnapshotModelError(f"profile {profile_path} is not JSON") from exc
    if not isinstance(parsed, dict):
        raise SnapshotModelError("profile root must be an object")
    if parsed.get("schema_version") != 1:
        raise SnapshotModelError("profile schema_version must be 1")
    if parsed.get("name") != EXPECTED_PROFILE_NAME:
        raise SnapshotModelError(
            f"profile name must be {EXPECTED_PROFILE_NAME!r}, not {parsed.get('name')!r}"
        )

    binary = _required_mapping(parsed, "binary", "profile")
    if binary.get("filename") != "mwccps2.exe":
        raise SnapshotModelError("profile binary.filename must be 'mwccps2.exe'")
    expected_hash = binary.get("sha256")
    if not isinstance(expected_hash, str) or len(expected_hash) != 64:
        raise SnapshotModelError("profile binary.sha256 must be a SHA-256 hex digest")
    try:
        int(expected_hash, 16)
    except ValueError as exc:
        raise SnapshotModelError("profile binary.sha256 must be hexadecimal") from exc
    if not isinstance(binary.get("size"), int) or binary["size"] < 1:
        raise SnapshotModelError("profile binary.size must be a positive integer")
    parse_address(binary.get("image_base"), "profile.binary.image_base")
    parse_address(binary.get("pe_timestamp"), "profile.binary.pe_timestamp")

    functions = _required_mapping(parsed, "functions", "profile")
    _required_mapping(functions, "CodeGen_Generator", "profile.functions")
    parse_address(functions["CodeGen_Generator"].get("address"), "CodeGen_Generator.address")
    globals_ = _required_mapping(parsed, "globals", "profile")
    _required_mapping(globals_, "pcbasicblocks", "profile.globals")
    parse_address(globals_["pcbasicblocks"].get("address"), "pcbasicblocks.address")
    breakpoints = _required_mapping(parsed, "pcode_breakpoints", "profile")
    for stage in (
        "before_scheduling",
        "after_scheduling",
        "before_register_allocation",
        "after_register_allocation",
        "after_colorgraph_assignment",
    ):
        parse_address(breakpoints.get(stage), f"pcode_breakpoints.{stage}")
    _validate_opcode_table(parsed)
    return parsed


def _pe_timestamp(path: Path) -> int:
    """Read the COFF timestamp from a PE32 image without trusting the debugger."""

    try:
        with path.open("rb") as binary:
            if binary.read(2) != b"MZ":
                raise SnapshotModelError("loaded executable is not an MZ image")
            binary.seek(0x3C)
            offset_data = binary.read(4)
            if len(offset_data) != 4:
                raise SnapshotModelError("loaded executable has no PE offset")
            pe_offset = struct.unpack("<I", offset_data)[0]
            binary.seek(pe_offset)
            if binary.read(4) != b"PE\0\0":
                raise SnapshotModelError("loaded executable has no PE signature")
            coff_header = binary.read(20)
    except OSError as exc:
        raise SnapshotModelError(f"cannot read loaded executable {path}") from exc
    if len(coff_header) != 20:
        raise SnapshotModelError("loaded executable has a truncated COFF header")
    return struct.unpack_from("<I", coff_header, 4)[0]


def fingerprint_executable(path: str | Path, profile: Mapping[str, Any]) -> dict[str, Any]:
    """Validate the on-disk image that GDB loaded against the b210 profile."""

    executable = Path(path)
    try:
        resolved = executable.resolve(strict=True)
        stat_result = resolved.stat()
    except OSError as exc:
        raise SnapshotModelError(f"cannot resolve loaded executable {executable}") from exc
    binary = _required_mapping(profile, "binary", "profile")
    if resolved.name.casefold() != str(binary["filename"]).casefold():
        raise SnapshotModelError(
            f"loaded executable filename {resolved.name!r} does not match {binary['filename']!r}"
        )
    if stat_result.st_size != binary["size"]:
        raise SnapshotModelError(
            f"loaded executable size {stat_result.st_size} does not match profile size {binary['size']}"
        )

    digest = hashlib.sha256()
    try:
        with resolved.open("rb") as binary_file:
            for chunk in iter(lambda: binary_file.read(1024 * 1024), b""):
                digest.update(chunk)
    except OSError as exc:
        raise SnapshotModelError(f"cannot hash loaded executable {resolved}") from exc
    actual_hash = digest.hexdigest()
    if actual_hash.casefold() != str(binary["sha256"]).casefold():
        raise SnapshotModelError("loaded executable SHA-256 does not match b210 profile")

    actual_timestamp = _pe_timestamp(resolved)
    expected_timestamp = parse_address(binary["pe_timestamp"], "profile.binary.pe_timestamp")
    if actual_timestamp != expected_timestamp:
        raise SnapshotModelError(
            "loaded executable PE timestamp "
            f"{format_address(actual_timestamp)} does not match profile {format_address(expected_timestamp)}"
        )
    return {
        "filename": resolved.name,
        "path": str(resolved),
        "size": stat_result.st_size,
        "sha256": actual_hash,
        "pe_timestamp": format_address(actual_timestamp),
        "image_base": format_address(parse_address(binary["image_base"], "profile.binary.image_base")),
    }


def _read_exact(memory: Any, address: int, size: int, error: str) -> bytes:
    data = memory.read(address, size)
    if len(data) != size:
        raise MemoryReadError(error)
    return data


def _read_block(memory: Any, address: int) -> dict[str, int]:
    data = _read_exact(memory, address, _BLOCK_SIZE, "short basic-block read")
    return {
        "address": address,
        "next": struct.unpack_from("<I", data, 0x00)[0],
        "previous": struct.unpack_from("<I", data, 0x04)[0],
        "pcode_head": struct.unpack_from("<I", data, 0x14)[0],
        "pcode_tail": struct.unpack_from("<I", data, 0x18)[0],
        "pcode_count_i16": struct.unpack_from("<h", data, 0x2C)[0],
        "flags_u16": struct.unpack_from("<H", data, 0x2E)[0],
    }


def _read_pcode(memory: Any, address: int) -> dict[str, Any]:
    data = _read_exact(memory, address, _PCODE_HEADER_SIZE, "short PCode read")
    return {
        "address": address,
        "next": struct.unpack_from("<I", data, 0x00)[0],
        "previous": struct.unpack_from("<I", data, 0x04)[0],
        "owner_block": struct.unpack_from("<I", data, 0x08)[0],
        "property_flags": struct.unpack_from("<I", data, 0x0C)[0],
        "opcode_u16": struct.unpack_from("<H", data, 0x28)[0],
        "operand_count_i16": struct.unpack_from("<h", data, 0x2A)[0],
        "encoded_word": struct.unpack_from("<I", data, 0x30)[0],
        "operands": [],
    }


def _read_operand(memory: Any, address: int) -> dict[str, Any]:
    data = _read_exact(memory, address, _OPERAND_SIZE, "short PCode operand read")
    return {
        "raw_words": list(struct.unpack("<6I", data)),
        "tag": data[0],
        "register_class": data[1],
        "attributes": struct.unpack_from("<H", data, 0x02)[0],
        "payload_i16": struct.unpack_from("<h", data, 0x04)[0],
    }


def _termination(reason: str, limit: int | None = None) -> dict[str, Any]:
    value: dict[str, Any] = {"reason": reason}
    if limit is not None:
        value["limit"] = limit
    return value


def _bounded_string(memory: Any, address: int, maximum: int) -> dict[str, Any]:
    """Read at most ``maximum`` bytes so malformed table pointers remain harmless."""

    if address == 0:
        return {"state": "null"}
    data = bytearray()
    offset = 0
    # Table strings normally reside in readable static storage.  Batch those reads to avoid
    # a GDB round trip per character, but fall back to bytes at an unreadable page boundary
    # so a valid prefix is still retained as bounded partial output.
    while offset < maximum:
        chunk_size = min(32, maximum - offset)
        try:
            chunk = _read_exact(memory, address + offset, chunk_size, "short string read")
        except Exception:
            while offset < maximum:
                try:
                    byte = _read_exact(memory, address + offset, 1, "short string read")[0]
                except Exception:
                    value: dict[str, Any] = {"state": "unreadable"}
                    if data:
                        value["text"] = bytes(data).decode("ascii", errors="backslashreplace")
                    return value
                if byte == 0:
                    return {
                        "state": "complete",
                        "text": bytes(data).decode("ascii", errors="backslashreplace"),
                    }
                data.append(byte)
                offset += 1
            break
        terminator = chunk.find(b"\0")
        if terminator >= 0:
            data.extend(chunk[:terminator])
            return {"state": "complete", "text": bytes(data).decode("ascii", errors="backslashreplace")}
        data.extend(chunk)
        offset += chunk_size
    return {
        "state": "truncated",
        "text": bytes(data).decode("ascii", errors="backslashreplace"),
        "max_bytes": maximum,
    }


def _entry_u8(data: bytes, offset: int) -> int:
    return data[offset]


def _entry_u16(data: bytes, offset: int) -> int:
    return struct.unpack_from("<H", data, offset)[0]


def _entry_u32(data: bytes, offset: int) -> int:
    return struct.unpack_from("<I", data, offset)[0]


def _read_opcode_entry(memory: Any, table: Mapping[str, Any], opcode: int) -> dict[str, Any]:
    entry_count = int(table["entry_count"])
    entry_stride = int(table["entry_stride"])
    if not 0 <= opcode < entry_count:
        raise SnapshotModelError("opcode is outside the exact b210 table")
    base = parse_address(table["address"], "pcode_opcode_table.address")
    entry_address = base + opcode * entry_stride
    if entry_address > _MAX_U32 or entry_address + entry_stride > _MAX_U32 + 1:
        raise MemoryReadError("opcode table address overflow")
    data = _read_exact(memory, entry_address, entry_stride, "short opcode table entry read")
    offsets = {name: offset for name, offset, _ in _OPCODE_FIELDS}
    maximum = int(table["string_max_bytes"])
    return {
        "opcode": opcode,
        "mnemonic": _bounded_string(memory, _entry_u32(data, offsets["mnemonic"]), maximum),
        "alternate_mnemonic": _bounded_string(
            memory, _entry_u32(data, offsets["alternate_mnemonic"]), maximum
        ),
        "operand_format": _bounded_string(
            memory, _entry_u32(data, offsets["operand_format"]), maximum
        ),
        "operand_slot_count": _entry_u8(data, offsets["operand_slot_count"]),
        "opaque_format_class": _entry_u8(data, offsets["opaque_format_class"]),
        "opaque_0e": _entry_u16(data, offsets["opaque_0e"]),
        "encoding_template": _entry_u32(data, offsets["encoding_template"]),
        "opaque_14": _entry_u32(data, offsets["opaque_14"]),
        "property_flags": _entry_u32(data, offsets["property_flags"]),
        "format_derived_flags": _entry_u32(data, offsets["format_derived_flags"]),
        "aux_internal_name": _bounded_string(
            memory, _entry_u32(data, offsets["aux_internal_name"]), maximum
        ),
        "aux_ordinal": _entry_u32(data, offsets["aux_ordinal"]),
        "aux_value": _entry_u32(data, offsets["aux_value"]),
        "aux_class": _entry_u16(data, offsets["aux_class"]),
        "opaque_2e": _entry_u16(data, offsets["opaque_2e"]),
    }


def _complete_string(value: Mapping[str, Any]) -> str | None:
    text = value.get("text")
    return text if value.get("state") == "complete" and isinstance(text, str) else None


def _validate_opcode_sentinel(memory: Any, table: Mapping[str, Any]) -> dict[str, Any]:
    """Validate opcode 1 at a backend breakpoint, after normal initialization occurred."""

    sentinel = _required_mapping(table, "post_initialization_sentinel", "pcode_opcode_table")
    opcode = int(sentinel["opcode"])
    try:
        entry = _read_opcode_entry(memory, table, opcode)
    except Exception:
        return {"state": "unreadable_memory", "opcode": opcode}

    expected_strings = ("mnemonic", "operand_format", "aux_internal_name")
    strings_match = all(
        _complete_string(entry[name]) == sentinel[name] for name in expected_strings
    )
    numbers_match = (
        entry["encoding_template"]
        == parse_address(sentinel["encoding_template"], "pcode_opcode_table.sentinel.encoding_template")
        and entry["property_flags"]
        == parse_address(sentinel["property_flags"], "pcode_opcode_table.sentinel.property_flags")
    )
    return {
        "state": "validated" if strings_match and numbers_match else "mismatch",
        "opcode": opcode,
    }


def _capture_opcode_entries(
    memory: Any, table: Mapping[str, Any] | None, nodes: list[dict[str, Any]], errors: list[dict[str, str]]
) -> dict[str, Any]:
    """Read only entries actually referenced by captured PCode nodes, never the whole table."""

    if table is None:
        return {"sentinel": {"state": "not_configured"}, "entries": []}

    sentinel = _validate_opcode_sentinel(memory, table)
    if sentinel["state"] != "validated":
        errors.append({"scope": "opcode_table", "reason": f"sentinel_{sentinel['state']}"})

    entry_count = int(table["entry_count"])
    entries: list[dict[str, Any]] = []
    for opcode in sorted({node["opcode_u16"] for node in nodes}):
        if opcode >= entry_count:
            entries.append({"opcode": opcode, "state": "invalid_opcode"})
            errors.append({"scope": "opcode_table", "reason": "invalid_opcode"})
            continue
        try:
            entry = _read_opcode_entry(memory, table, opcode)
        except Exception:
            entries.append({"opcode": opcode, "state": "unreadable_memory"})
            errors.append({"scope": "opcode_table", "reason": "unreadable_memory"})
            continue
        entries.append({"state": "captured", **entry})
        string_states = {
            entry[name].get("state")
            for name in ("mnemonic", "alternate_mnemonic", "operand_format", "aux_internal_name")
        }
        if "unreadable" in string_states:
            errors.append({"scope": "opcode_table", "reason": "unreadable_string"})
        if "truncated" in string_states:
            errors.append({"scope": "opcode_table", "reason": "truncated_string"})
    return {"sentinel": sentinel, "entries": entries}


def _capture_node_operands(
    memory: Any,
    node: dict[str, Any],
    max_operands: int,
    total_operands: int,
    errors: list[dict[str, str]],
) -> int:
    """Capture a count-governed descriptor tail without trusting malformed counts."""

    count = node["operand_count_i16"]
    if count < 0:
        node["operand_capture"] = {
            "requested_count_i16": count,
            "captured_count": 0,
            "termination": _termination("invalid_count"),
        }
        errors.append({"scope": "operand_records", "reason": "invalid_count"})
        return total_operands
    if count > (_MAX_U32 - _PCODE_HEADER_SIZE) // _OPERAND_SIZE:
        node["operand_capture"] = {
            "requested_count_i16": count,
            "captured_count": 0,
            "termination": _termination("count_overflow"),
        }
        errors.append({"scope": "operand_records", "reason": "count_overflow"})
        return total_operands

    remaining = max(0, max_operands - total_operands)
    capture_count = min(count, remaining)
    termination: dict[str, Any] | None = None
    if capture_count != count:
        termination = _termination("count_limit", max_operands)
        errors.append({"scope": "operand_records", "reason": "count_limit"})

    operands: list[dict[str, Any]] = []
    for index in range(capture_count):
        operand_address = node["address"] + _PCODE_HEADER_SIZE + index * _OPERAND_SIZE
        if operand_address > _MAX_U32 or operand_address + _OPERAND_SIZE > _MAX_U32 + 1:
            termination = _termination("address_overflow")
            errors.append({"scope": "operand_records", "reason": "address_overflow"})
            break
        try:
            operand = _read_operand(memory, operand_address)
        except Exception:
            termination = _termination("unreadable_memory")
            errors.append({"scope": "operand_records", "reason": "unreadable_memory"})
            break
        operand["index"] = index
        operands.append(operand)

    node["operands"] = operands
    node["operand_capture"] = {
        "requested_count_i16": count,
        "captured_count": len(operands),
        "termination": termination or _termination("complete"),
    }
    return total_operands + len(operands)


def _resolve_label_targets(
    memory: Any,
    nodes: list[Mapping[str, Any]],
    blocks_by_address: Mapping[int, Mapping[str, Any]],
    errors: list[dict[str, str]],
) -> None:
    """Resolve tag-6 only through a bound LabelRecord to a captured basic block.

    Before a label is bound, its +0x04 field is a pending-list link rather than a block
    pointer.  The +0x08 bound marker is therefore mandatory before using that field.
    """

    for node in nodes:
        for operand in node["operands"]:
            tag = operand["tag"]
            if tag not in {0, 2, 3, 4, 6, 7}:
                errors.append({"scope": "operand_records", "reason": "unknown_tag"})
            if tag != 6:
                continue
            label_object = operand["raw_words"][1]
            if label_object == 0:
                operand["label_target"] = {"state": "null"}
                continue
            if label_object > _MAX_U32 - 0x0C:
                operand["label_target"] = {"state": "address_overflow"}
                errors.append({"scope": "label_target", "reason": "address_overflow"})
                continue
            try:
                label_data = _read_exact(memory, label_object, 0x0C, "short label record read")
            except Exception:
                operand["label_target"] = {"state": "unreadable_memory"}
                errors.append({"scope": "label_target", "reason": "unreadable_memory"})
                continue
            if struct.unpack_from("<H", label_data, 0x08)[0] != 1:
                operand["label_target"] = {"state": "unbound"}
                continue
            target_block = struct.unpack_from("<I", label_data, 0x04)[0]
            if target_block == 0:
                operand["label_target"] = {"state": "null"}
            elif target_block in blocks_by_address:
                operand["label_target"] = {
                    "state": "resolved",
                    "block_address": target_block,
                }
            else:
                # Do not dereference an arbitrary block pointer.  A stable target exists
                # only when the linked-list graph already captured that exact block.
                operand["label_target"] = {"state": "not_captured"}


def collect_runtime_graph(
    memory: Any,
    pcbasicblocks_address: int,
    max_blocks: int,
    max_nodes: int,
    opcode_table: Mapping[str, Any] | None = None,
    max_operands: int | None = None,
) -> dict[str, Any]:
    """Capture a bounded PCode graph and its used runtime opcode metadata.

    The return value is addressful and private to this module.  Call
    :func:`normalize_runtime_graph` before serializing it.  Any malformed pointer, count,
    cycle, unknown tag, or unreadable metadata produces a bounded partial graph rather than
    an exception escaping an auto-continuing GDB breakpoint handler.
    """

    if max_blocks < 1 or max_nodes < 1:
        raise SnapshotModelError("max_blocks and max_nodes must both be positive")
    if max_operands is None:
        max_operands = max_nodes
    if max_operands < 1:
        raise SnapshotModelError("max_operands must be positive")
    try:
        root_bytes = _read_exact(memory, pcbasicblocks_address, 4, "short pcbasicblocks read")
        current_block = struct.unpack("<I", root_bytes)[0]
    except Exception:
        errors = [{"scope": "pcbasicblocks", "reason": "unreadable_memory"}]
        return {
            "blocks": [],
            "nodes": [],
            "block_walk": {"termination": _termination("unreadable_memory")},
            "node_walks": [],
            "errors": errors,
            "opcode_table": _capture_opcode_entries(memory, opcode_table, [], errors),
        }

    blocks: list[dict[str, int]] = []
    nodes: list[dict[str, Any]] = []
    block_seen: set[int] = set()
    nodes_by_address: dict[int, dict[str, Any]] = {}
    node_walks: list[dict[str, Any]] = []
    errors: list[dict[str, str]] = []
    total_operands = 0

    while current_block:
        if current_block in block_seen:
            block_walk = {"termination": _termination("cycle")}
            break
        if len(blocks) >= max_blocks:
            block_walk = {"termination": _termination("count_limit", max_blocks)}
            break
        try:
            block = _read_block(memory, current_block)
        except Exception:
            block_walk = {"termination": _termination("unreadable_memory")}
            errors.append({"scope": "pcbasicblocks", "reason": "unreadable_memory"})
            break
        blocks.append(block)
        block_seen.add(current_block)

        current_node = block["pcode_head"]
        pcode_seen_in_list: set[int] = set()
        while current_node:
            if current_node in pcode_seen_in_list:
                node_walks.append(
                    {"block_address": current_block, "termination": _termination("cycle")}
                )
                break
            if len(nodes) >= max_nodes and current_node not in nodes_by_address:
                node_walks.append(
                    {
                        "block_address": current_block,
                        "termination": _termination("count_limit", max_nodes),
                    }
                )
                break
            pcode_seen_in_list.add(current_node)
            node = nodes_by_address.get(current_node)
            if node is None:
                try:
                    node = _read_pcode(memory, current_node)
                except Exception:
                    node_walks.append(
                        {
                            "block_address": current_block,
                            "termination": _termination("unreadable_memory"),
                        }
                    )
                    errors.append({"scope": "pcode_list", "reason": "unreadable_memory"})
                    break
                total_operands = _capture_node_operands(
                    memory, node, max_operands, total_operands, errors
                )
                nodes_by_address[current_node] = node
                nodes.append(node)
            current_node = node["next"]
        else:
            node_walks.append({"block_address": current_block, "termination": _termination("null")})

        current_block = block["next"]
    else:
        block_walk = {"termination": _termination("null")}

    _resolve_label_targets(memory, nodes, {block["address"]: block for block in blocks}, errors)
    opcode_capture = _capture_opcode_entries(memory, opcode_table, nodes, errors)
    return {
        "blocks": blocks,
        "nodes": nodes,
        "block_walk": block_walk,
        "node_walks": node_walks,
        "errors": errors,
        "opcode_table": opcode_capture,
    }


def _make_ids(records: list[Mapping[str, Any]], prefix: str) -> dict[int, str]:
    return {
        int(record["address"]): f"{prefix}-{index:04d}"
        for index, record in enumerate(records, start=1)
    }


def _reference(address: int, identifiers: Mapping[int, str]) -> dict[str, Any]:
    """Represent a pointer without leaking an unstable runtime address."""

    if address == 0:
        return {"state": "null"}
    identifier = identifiers.get(address)
    if identifier is None:
        return {"state": "not_captured"}
    return {"state": "resolved", "id": identifier}


def _normalized_termination(value: Mapping[str, Any]) -> dict[str, Any]:
    return dict(value["termination"])


def _normalized_string(value: Mapping[str, Any]) -> dict[str, Any]:
    result: dict[str, Any] = {"state": value["state"]}
    if "text" in value:
        result["text"] = value["text"]
    if "max_bytes" in value:
        result["max_bytes"] = value["max_bytes"]
    return result


def _normalize_opcode_entry(entry: Mapping[str, Any]) -> dict[str, Any]:
    if entry["state"] != "captured":
        return {"opcode": entry["opcode"], "state": entry["state"]}
    return {
        "opcode": entry["opcode"],
        "state": "captured",
        "mnemonic": _normalized_string(entry["mnemonic"]),
        "alternate_mnemonic": _normalized_string(entry["alternate_mnemonic"]),
        "operand_format": _normalized_string(entry["operand_format"]),
        "operand_slot_count": entry["operand_slot_count"],
        "encoding_template": format_address(entry["encoding_template"]),
        "property_flags": format_address(entry["property_flags"]),
        "format_derived_flags": format_address(entry["format_derived_flags"]),
        "aux_internal_name": _normalized_string(entry["aux_internal_name"]),
        "opaque": {
            "format_class_u8": entry["opaque_format_class"],
            "word_0e_u16": entry["opaque_0e"],
            "word_14_u32": format_address(entry["opaque_14"]),
            "aux_ordinal_u32": format_address(entry["aux_ordinal"]),
            "aux_value_u32": format_address(entry["aux_value"]),
            "aux_class_u16": entry["aux_class"],
            "word_2e_u16": entry["opaque_2e"],
        },
    }


def _register_class_name(code: int) -> str:
    # Only class zero has a b210-proven source-level name.  Remaining numeric classes are
    # retained without guessing names such as FP or control.
    return "gpr" if code == 0 else f"class-{code}"


def _decode_operand(operand: Mapping[str, Any], block_ids: Mapping[int, str]) -> dict[str, Any]:
    words = operand["raw_words"]
    tag = operand["tag"]
    decoded: dict[str, Any] = {
        "index": operand["index"],
        "tag_u8": tag,
        "attributes_u16": f"0x{operand['attributes']:04x}",
        "raw_words": [format_address(word) for word in words],
    }
    if tag == 0:
        decoded.update(
            {
                "kind": "register",
                "register_class": {
                    "code": operand["register_class"],
                    "name": _register_class_name(operand["register_class"]),
                },
                "register_number_i16": operand["payload_i16"],
            }
        )
    elif tag == 3:
        decoded.update(
            {
                "kind": "inline_immediate_or_blob",
                "immediate_u32": format_address(words[1]),
                "immediate_i32": struct.unpack("<i", struct.pack("<I", words[1]))[0],
                "payload_words": [format_address(word) for word in words[1:]],
            }
        )
    elif tag == 4:
        decoded.update(
            {
                "kind": "compound_memory_or_object",
                "offset_or_value_u32": format_address(words[1]),
                "object_pointer_raw": format_address(words[2]),
                "payload_words": [format_address(word) for word in words[3:]],
            }
        )
    elif tag == 6:
        label_target = operand.get("label_target", {"state": "not_resolved"})
        target: dict[str, Any] = {"state": label_target["state"]}
        if label_target["state"] == "resolved":
            target["block"] = _reference(label_target["block_address"], block_ids)
        decoded.update(
            {
                "kind": "label_target",
                "label_target": target,
                "payload_words": [format_address(word) for word in words[1:]],
            }
        )
    elif tag == 7:
        decoded.update(
            {"kind": "unresolved_placeholder", "payload_words": [format_address(word) for word in words[1:]]}
        )
    elif tag == 2:
        decoded.update(
            {
                "kind": "raw_scalar_or_pointer",
                "value_u32": format_address(words[1]),
                "payload_words": [format_address(word) for word in words[2:]],
            }
        )
    else:
        decoded.update(
            {"kind": "unknown_tag", "payload_words": [format_address(word) for word in words[1:]]}
        )
    return decoded


def _opcode_summary(entry: Mapping[str, Any] | None, opcode: int) -> dict[str, Any]:
    if entry is None:
        return {"state": "not_captured", "opcode": opcode}
    if entry["state"] != "captured":
        return {"state": entry["state"], "opcode": opcode}
    return {
        "state": "resolved",
        "opcode": opcode,
        "mnemonic": _normalized_string(entry["mnemonic"]),
        "operand_format": _normalized_string(entry["operand_format"]),
        "table_property_flags": format_address(entry["property_flags"]),
    }


def normalize_runtime_graph(raw: Mapping[str, Any]) -> dict[str, Any]:
    """Replace structural heap pointers with snapshot-local identities and decode PCode."""

    blocks = list(raw["blocks"])
    nodes = list(raw["nodes"])
    block_ids = _make_ids(blocks, "block")
    node_ids = _make_ids(nodes, "pcode")
    opcode_table = raw.get("opcode_table", {"sentinel": {"state": "not_configured"}, "entries": []})
    raw_entries = list(opcode_table["entries"])
    entries_by_opcode = {entry["opcode"]: entry for entry in raw_entries}
    normalized_blocks = [
        {
            "id": block_ids[block["address"]],
            "previous": _reference(block["previous"], block_ids),
            "next": _reference(block["next"], block_ids),
            "pcode_head": _reference(block["pcode_head"], node_ids),
            "pcode_tail": _reference(block["pcode_tail"], node_ids),
            "pcode_count_i16": block["pcode_count_i16"],
            "flags_u16": f"0x{block['flags_u16']:04x}",
        }
        for block in blocks
    ]
    normalized_nodes = [
        {
            "id": node_ids[node["address"]],
            "previous": _reference(node["previous"], node_ids),
            "next": _reference(node["next"], node_ids),
            "owner_block": _reference(node["owner_block"], block_ids),
            "opcode_u16": node["opcode_u16"],
            "opcode_metadata": _opcode_summary(
                entries_by_opcode.get(node["opcode_u16"]), node["opcode_u16"]
            ),
            "operand_count_i16": node["operand_count_i16"],
            "operand_capture": dict(node["operand_capture"]),
            "property_flags": format_address(node["property_flags"]),
            "encoded_word": format_address(node["encoded_word"]),
            "operands": [
                _decode_operand(operand, block_ids) for operand in node["operands"]
            ],
        }
        for node in nodes
    ]
    normalized_walks = [
        {
            "block_id": block_ids.get(walk["block_address"]),
            "termination": _normalized_termination(walk),
        }
        for walk in raw["node_walks"]
    ]
    return {
        "blocks": normalized_blocks,
        "pcodes": normalized_nodes,
        "opcode_table": {
            "sentinel": dict(opcode_table["sentinel"]),
            "entries": [_normalize_opcode_entry(entry) for entry in raw_entries],
        },
        "collection": {
            "block_walk": _normalized_termination(raw["block_walk"]),
            "pcode_walks": normalized_walks,
            "errors": list(raw["errors"]),
        },
    }


def capture_status(normalized_graph: Mapping[str, Any]) -> str:
    """Classify bounded partial captures without treating them as target failures."""

    collection = normalized_graph["collection"]
    reasons = [collection["block_walk"]["reason"]]
    reasons.extend(walk["termination"]["reason"] for walk in collection["pcode_walks"])
    reasons.extend(error["reason"] for error in collection["errors"])
    if "unreadable_memory" in reasons or "unreadable_string" in reasons:
        return "partial_memory_unreadable"
    if "cycle" in reasons:
        return "partial_cycle_guarded"
    if "count_limit" in reasons:
        return "partial_count_guarded"
    if "count_overflow" in reasons or "address_overflow" in reasons or "invalid_count" in reasons:
        return "partial_operand_guarded"
    if any(reason.startswith("sentinel_") for reason in reasons):
        return "partial_opcode_table_unvalidated"
    if "invalid_opcode" in reasons or "unknown_tag" in reasons or "truncated_string" in reasons:
        return "partial_decode"
    return "complete"


def _operand_text(operand: Mapping[str, Any]) -> str:
    kind = operand["kind"]
    if kind == "register":
        register_class = operand["register_class"]
        return f"{register_class['name']}:r{operand['register_number_i16']}"
    if kind == "inline_immediate_or_blob":
        return f"imm({operand['immediate_u32']})"
    if kind == "compound_memory_or_object":
        return f"mem[object+{operand['offset_or_value_u32']}]"
    if kind == "label_target":
        target = operand["label_target"]
        block = target.get("block")
        if isinstance(block, Mapping) and block.get("state") == "resolved":
            return str(block["id"])
        return f"label<{target['state']}>"
    if kind == "unresolved_placeholder":
        return "unresolved"
    if kind == "raw_scalar_or_pointer":
        return f"raw-scalar-or-pointer({operand['value_u32']})"
    return f"tag-{operand['tag_u8']}"


def _pcode_mnemonic(pcode: Mapping[str, Any]) -> str:
    metadata = pcode["opcode_metadata"]
    mnemonic = metadata.get("mnemonic")
    if isinstance(mnemonic, Mapping) and mnemonic.get("state") == "complete":
        text = mnemonic.get("text")
        if isinstance(text, str) and text:
            return text
    return f"opcode_{pcode['opcode_u16']:04x}"


def format_pcode_text(graph: Mapping[str, Any]) -> str:
    """Return an address-free, deterministic human-readable view of normalized PCode."""

    pcodes_by_owner: dict[str, list[Mapping[str, Any]]] = {}
    orphaned: list[Mapping[str, Any]] = []
    for pcode in graph["pcodes"]:
        owner = pcode["owner_block"]
        if owner["state"] == "resolved":
            pcodes_by_owner.setdefault(owner["id"], []).append(pcode)
        else:
            orphaned.append(pcode)

    lines = ["# MWCCPS2 b210 PCode", ""]
    for block in graph["blocks"]:
        block_id = block["id"]
        lines.append(f"{block_id}:")
        for pcode in pcodes_by_owner.get(block_id, []):
            operands = pcode["operands"]
            rendered: list[str] = []
            index = 0
            while index < len(operands):
                operand = operands[index]
                # A tag-4 compound o(s|t) descriptor is followed by its synthetic register
                # descriptor.  Render it as one memory form while preserving both JSON records.
                if (
                    operand["kind"] == "compound_memory_or_object"
                    and index + 1 < len(operands)
                    and operands[index + 1]["kind"] == "register"
                ):
                    rendered.append(
                        f"mem[{_operand_text(operands[index + 1])}+{operand['offset_or_value_u32']}]"
                    )
                    index += 2
                    continue
                rendered.append(_operand_text(operand))
                index += 1
            operand_text = ", ".join(rendered)
            instruction = _pcode_mnemonic(pcode)
            if operand_text:
                instruction += " " + operand_text
            lines.append(
                f"  {pcode['id']}: {instruction}"
                f"  ; flags={pcode['property_flags']} word={pcode['encoded_word']}"
            )
        if not pcodes_by_owner.get(block_id):
            lines.append("  <empty>")
        lines.append("")
    if orphaned:
        lines.append("<orphaned-pcodes>:")
        for pcode in orphaned:
            lines.append(f"  {pcode['id']}: {_pcode_mnemonic(pcode)}")
        lines.append("")
    return "\n".join(lines)


def profile_manifest(profile: Mapping[str, Any]) -> dict[str, Any]:
    """Select immutable profile/fingerprint fields placed in every output file."""

    binary = _required_mapping(profile, "binary", "profile")
    table = _required_mapping(profile, "pcode_opcode_table", "profile")
    return {
        "name": profile["name"],
        "schema_version": profile["schema_version"],
        "binary": {
            "filename": binary["filename"],
            "sha256": binary["sha256"],
            "size": binary["size"],
            "pe_timestamp": binary["pe_timestamp"],
            "image_base": binary["image_base"],
        },
        "pcode_opcode_table": {
            "address": table["address"],
            "entry_count": table["entry_count"],
            "entry_stride": table["entry_stride"],
        },
    }
