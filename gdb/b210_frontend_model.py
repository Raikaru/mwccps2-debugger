"""Pure bounded b210 frontend IR and name-record capture helpers.

This module intentionally has no GDB dependency.  GDB instrumentation supplies a
``read(address, size) -> bytes`` adapter; unit callers can provide an in-memory
adapter instead.  Every heap walk is bounded and detects cycles before following
the next pointer.
"""

from __future__ import annotations

import json
from pathlib import Path
import struct
from typing import Any, Mapping, Protocol


EXPECTED_PROFILE_NAME = "mwcps2-3.0.1b210-060308"
FRONTEND_SNAPSHOT_SCHEMA_NAME = "mwccps2-b210-frontend-snapshot"
FRONTEND_SNAPSHOT_SCHEMA_VERSION = 1

_MAX_U32 = 0xFFFFFFFF
_FUNCTION_RECORD_MIN_SIZE = 0x0C
_NAME_TABLE_ENTRY_SIZE = 0x08
_IRO_NODE_SIZE = 0x44


class FrontendModelError(ValueError):
    """Raised when a frontend profile or capture request is malformed."""


class MemoryReadError(RuntimeError):
    """Raised when an exact read cannot be performed by a memory adapter."""


class MemoryReader(Protocol):
    """Minimal live-memory interface used by this pure model."""

    def read(self, address: int, size: int) -> bytes:
        """Return exactly ``size`` bytes beginning at ``address``."""


# Names below state only behavior observed in the b210 decompiler and the live
# smoke capture.  Fields without a proven semantic role remain raw by design.
B210_FRONTEND_LAYOUT_EVIDENCE: dict[str, Any] = {
    "function_record": {
        "minimum_bytes": _FUNCTION_RECORD_MIN_SIZE,
        "fields": {
            "kind_u8": {"offset": 0, "kind": "u8"},
            "kind_flags_u8": {"offset": 1, "kind": "u8"},
            "ordinal_u16": {"offset": 2, "kind": "u16"},
            "opaque_04": {"offset": 4, "kind": "pointer"},
            "symbol": {"offset": 8, "kind": "pointer"},
        },
        "symbol_name_offset": 10,
        "evidence": (
            "IrOptimizer_driver at 0x004d13c6 stores its first argument in "
            "gFunction (0x00636144); its diagnostic path reads "
            "*(gFunction+0x08)+0x0a as the function name.  A live GDB batch "
            "capture of fixtures/codegen_smoke.c decoded load_indexed."
        ),
    },
    "name_table_entry": {
        "byte_size": _NAME_TABLE_ENTRY_SIZE,
        "fields": {
            "next": {"offset": 0, "kind": "pointer"},
            "record": {"offset": 4, "kind": "pointer"},
        },
        "evidence": (
            "FUN_004e4140 walks DAT_00636424 through entry+0 and reads the "
            "record at entry+4 before applying the shared record+0x08/+0x0a "
            "name path."
        ),
    },
    "iro_node": {
        "byte_size": _IRO_NODE_SIZE,
        "fields": {
            "kind_u8": {"offset": 0, "kind": "u8"},
            "opaque_01": {"offset": 1, "kind": "u8"},
            "opaque_02": {"offset": 2, "kind": "u16"},
            "flags_u32": {"offset": 4, "kind": "u32"},
            "operand_root": {"offset": 16, "kind": "pointer"},
            "operation": {"offset": 44, "kind": "pointer"},
            "next": {"offset": 64, "kind": "pointer"},
        },
        "evidence": (
            "FUN_00579d90 allocates and zeroes 0x44 bytes.  FUN_00564c70 and "
            "FUN_0058c840 traverse node+0x40; the latter reads node+0x2c as "
            "the operation descriptor.  The live post-BuildflowGraph smoke "
            "record has kind 1, flags 0x00001022, and operation tag 0x3a."
        ),
    },
    "operation_record": {
        "minimum_bytes": 1,
        "fields": {"opcode_u8": {"offset": 0, "kind": "u8"}},
        "evidence": (
            "IRO consumers dispatch on the byte at the node+0x2c descriptor; "
            "only that byte has a source-level behavior established here."
        ),
    },
}


def format_address(value: int) -> str:
    """Format a non-negative 32-bit address as the profile's canonical hex string."""

    if not isinstance(value, int) or value < 0 or value > _MAX_U32:
        raise FrontendModelError("address must be an unsigned 32-bit integer")
    return f"0x{value:08x}"


def parse_address(value: str | int, field_name: str) -> int:
    """Parse one canonical profile address without silently accepting negatives."""

    if isinstance(value, str):
        if not value.startswith("0x"):
            raise FrontendModelError(f"{field_name} must be a 0x-prefixed address")
        try:
            parsed = int(value, 16)
        except ValueError as error:
            raise FrontendModelError(f"{field_name} is not a hexadecimal address") from error
    elif isinstance(value, int) and not isinstance(value, bool):
        parsed = value
    else:
        raise FrontendModelError(f"{field_name} must be an address string or integer")
    if parsed < 0 or parsed > _MAX_U32:
        raise FrontendModelError(f"{field_name} must fit in 32 bits")
    return parsed


def _mapping(value: Any, field_name: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise FrontendModelError(f"{field_name} must be an object")
    return value


def _positive_int(value: Any, field_name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise FrontendModelError(f"{field_name} must be a positive integer")
    return value


def _required_exact_int(mapping: Mapping[str, Any], key: str, expected: int, location: str) -> None:
    if mapping.get(key) != expected:
        raise FrontendModelError(f"{location}.{key} must be {expected}")


def _validate_fields(
    mapping: Mapping[str, Any], expected: Mapping[str, tuple[int, str]], location: str
) -> None:
    fields = _mapping(mapping.get("fields"), f"{location}.fields")
    if set(fields) != set(expected):
        raise FrontendModelError(f"{location}.fields must contain exactly {sorted(expected)}")
    for field_name, (offset, kind) in expected.items():
        field = _mapping(fields[field_name], f"{location}.fields.{field_name}")
        if field.get("offset") != offset or field.get("kind") != kind:
            raise FrontendModelError(
                f"{location}.fields.{field_name} must be offset {offset}, kind {kind!r}"
            )


def validate_frontend_profile(profile: Mapping[str, Any]) -> None:
    """Reject layout drift before a debugger reads a b210 frontend heap object."""

    if profile.get("name") != EXPECTED_PROFILE_NAME:
        raise FrontendModelError("profile.name does not identify b210")
    frontend = _mapping(profile.get("frontend_ir"), "frontend_ir")
    _positive_int(frontend.get("max_nodes"), "frontend_ir.max_nodes")
    _positive_int(frontend.get("max_name_bytes"), "frontend_ir.max_name_bytes")

    globals_ = _mapping(frontend.get("globals"), "frontend_ir.globals")
    if set(globals_) != {"gFunction", "name_table_head", "ast_traversal_root", "ast_null_sentinel", "iro_root"}:
        raise FrontendModelError("frontend_ir.globals has an unexpected set of anchors")
    for name, value in globals_.items():
        parse_address(value, f"frontend_ir.globals.{name}")

    breakpoints = _mapping(frontend.get("breakpoints"), "frontend_ir.breakpoints")
    if set(breakpoints) != {"gFunction_assigned", "after_flow_graph"}:
        raise FrontendModelError("frontend_ir.breakpoints has an unexpected set of anchors")
    for name, value in breakpoints.items():
        parse_address(value, f"frontend_ir.breakpoints.{name}")

    function_record = _mapping(frontend.get("function_record"), "frontend_ir.function_record")
    _required_exact_int(function_record, "minimum_bytes", _FUNCTION_RECORD_MIN_SIZE, "frontend_ir.function_record")
    _required_exact_int(function_record, "symbol_name_offset", 10, "frontend_ir.function_record")
    _validate_fields(
        function_record,
        {
            "kind_u8": (0, "u8"),
            "kind_flags_u8": (1, "u8"),
            "ordinal_u16": (2, "u16"),
            "opaque_04": (4, "pointer"),
            "symbol": (8, "pointer"),
        },
        "frontend_ir.function_record",
    )

    name_table = _mapping(frontend.get("name_table_entry"), "frontend_ir.name_table_entry")
    _required_exact_int(name_table, "byte_size", _NAME_TABLE_ENTRY_SIZE, "frontend_ir.name_table_entry")
    _validate_fields(
        name_table,
        {"next": (0, "pointer"), "record": (4, "pointer")},
        "frontend_ir.name_table_entry",
    )

    node = _mapping(frontend.get("iro_node"), "frontend_ir.iro_node")
    _required_exact_int(node, "byte_size", _IRO_NODE_SIZE, "frontend_ir.iro_node")
    _validate_fields(
        node,
        {
            "kind_u8": (0, "u8"),
            "opaque_01": (1, "u8"),
            "opaque_02": (2, "u16"),
            "flags_u32": (4, "u32"),
            "operand_root": (16, "pointer"),
            "operation": (44, "pointer"),
            "next": (64, "pointer"),
        },
        "frontend_ir.iro_node",
    )

    operation = _mapping(frontend.get("operation_record"), "frontend_ir.operation_record")
    _required_exact_int(operation, "minimum_bytes", 1, "frontend_ir.operation_record")
    _validate_fields(
        operation,
        {"opcode_u8": (0, "u8")},
        "frontend_ir.operation_record",
    )


def load_b210_profile(path: str | Path) -> dict[str, Any]:
    """Load and validate a schema-v1 profile containing the b210 frontend layout."""

    try:
        parsed = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise FrontendModelError(f"cannot load frontend profile: {error}") from error
    if not isinstance(parsed, dict):
        raise FrontendModelError("profile root must be an object")
    if parsed.get("schema_version") != 1:
        raise FrontendModelError("profile.schema_version must be 1")
    validate_frontend_profile(parsed)
    return parsed


def _read_exact(memory: MemoryReader, address: int, size: int, description: str) -> bytes:
    if not isinstance(address, int) or not isinstance(size, int) or address < 0 or size < 0:
        raise MemoryReadError(f"invalid {description} read range")
    if address > _MAX_U32 or size > _MAX_U32 + 1 - address:
        raise MemoryReadError(f"{description} read range overflows 32-bit address space")
    try:
        data = memory.read(address, size)
    except Exception as error:  # adapters expose different read-failure types
        raise MemoryReadError(f"cannot read {description} at {format_address(address)}") from error
    if not isinstance(data, bytes) or len(data) != size:
        raise MemoryReadError(f"short {description} read at {format_address(address)}")
    return data


def _u32(data: bytes, offset: int) -> int:
    return struct.unpack_from("<I", data, offset)[0]


def _u16(data: bytes, offset: int) -> int:
    return struct.unpack_from("<H", data, offset)[0]


def _bounded_string(memory: MemoryReader, address: int, maximum: int) -> dict[str, Any]:
    """Read a NUL-terminated byte string without trusting its address or length."""

    if address == 0:
        return {"state": "null"}
    if maximum <= 0:
        raise FrontendModelError("maximum string length must be positive")
    result = bytearray()
    for offset in range(maximum):
        try:
            byte = _read_exact(memory, address + offset, 1, "symbol name")[0]
        except MemoryReadError:
            return {"state": "unreadable", "bytes_read": len(result)}
        if byte == 0:
            return {
                "state": "complete",
                "text": result.decode("utf-8", errors="replace"),
                "bytes_read": len(result),
            }
        result.append(byte)
    return {
        "state": "truncated",
        "text": result.decode("utf-8", errors="replace"),
        "bytes_read": len(result),
    }


def read_function_record(memory: MemoryReader, address: int, max_name_bytes: int) -> dict[str, Any]:
    """Decode only the evidence-backed prefix of a frontend function/name record."""

    data = _read_exact(memory, address, _FUNCTION_RECORD_MIN_SIZE, "function record")
    symbol_address = _u32(data, 8)
    name_address = 0 if symbol_address == 0 else symbol_address + 10
    if name_address > _MAX_U32:
        raise MemoryReadError("function-record symbol name address overflows 32-bit space")
    return {
        "address": format_address(address),
        "kind_u8": data[0],
        "kind_flags_u8": data[1],
        "ordinal_u16": _u16(data, 2),
        "opaque_04_address": format_address(_u32(data, 4)),
        "symbol_address": format_address(symbol_address),
        "name": _bounded_string(memory, name_address, max_name_bytes),
    }


def read_operation_record(memory: MemoryReader, address: int) -> dict[str, Any]:
    """Decode the only established operation-descriptor field: its leading opcode."""

    data = _read_exact(memory, address, 1, "operation record")
    return {"address": format_address(address), "opcode_u8": data[0]}


def read_iro_node(memory: MemoryReader, address: int) -> dict[str, Any]:
    """Decode one fixed-width IRO node without following any heap pointer."""

    data = _read_exact(memory, address, _IRO_NODE_SIZE, "IRO node")
    operation_address = _u32(data, 44)
    operation: dict[str, Any]
    if operation_address == 0:
        operation = {"state": "null"}
    else:
        try:
            operation = {"state": "captured", **read_operation_record(memory, operation_address)}
        except MemoryReadError:
            operation = {"state": "unreadable", "address": format_address(operation_address)}
    return {
        "address": format_address(address),
        "kind_u8": data[0],
        "opaque_01_u8": data[1],
        "opaque_02_u16": _u16(data, 2),
        "flags_u32": f"0x{_u32(data, 4):08x}",
        "operand_root_address": format_address(_u32(data, 16)),
        "operation": operation,
        "next_address": format_address(_u32(data, 64)),
    }


def _termination(reason: str, limit: int | None = None) -> dict[str, Any]:
    result: dict[str, Any] = {"reason": reason}
    if limit is not None:
        result["limit"] = limit
    return result


def collect_name_table(
    memory: MemoryReader, head_address: int, max_entries: int, max_name_bytes: int
) -> dict[str, Any]:
    """Walk the live AST name-table list with strict entry and cycle guards."""

    max_entries = _positive_int(max_entries, "max_entries")
    max_name_bytes = _positive_int(max_name_bytes, "max_name_bytes")
    current = _u32(_read_exact(memory, head_address, 4, "name-table head"), 0)
    entries: list[dict[str, Any]] = []
    visited: set[int] = set()

    while current:
        if current in visited:
            return {"entries": entries, "termination": _termination("cycle")}
        if len(entries) >= max_entries:
            return {"entries": entries, "termination": _termination("limit", max_entries)}
        visited.add(current)
        try:
            entry = _read_exact(memory, current, _NAME_TABLE_ENTRY_SIZE, "name-table entry")
            record_address = _u32(entry, 4)
            record = (
                {"state": "null"}
                if record_address == 0
                else {"state": "captured", **read_function_record(memory, record_address, max_name_bytes)}
            )
        except MemoryReadError:
            return {"entries": entries, "termination": _termination("unreadable")}
        entries.append(
            {
                "address": format_address(current),
                "record": record,
                "next_address": format_address(_u32(entry, 0)),
            }
        )
        current = _u32(entry, 0)
    return {"entries": entries, "termination": _termination("null")}


def collect_iro_nodes(memory: MemoryReader, root_address: int, max_nodes: int) -> dict[str, Any]:
    """Walk one IRO node chain with strict node and cycle guards."""

    max_nodes = _positive_int(max_nodes, "max_nodes")
    current = _u32(_read_exact(memory, root_address, 4, "IRO root"), 0)
    nodes: list[dict[str, Any]] = []
    visited: set[int] = set()

    while current:
        if current in visited:
            return {"nodes": nodes, "termination": _termination("cycle")}
        if len(nodes) >= max_nodes:
            return {"nodes": nodes, "termination": _termination("limit", max_nodes)}
        visited.add(current)
        try:
            node = read_iro_node(memory, current)
        except MemoryReadError:
            return {"nodes": nodes, "termination": _termination("unreadable")}
        nodes.append(node)
        current = parse_address(node["next_address"], "IRO node next address")
    return {"nodes": nodes, "termination": _termination("null")}


def _normalize_name(value: Mapping[str, Any]) -> dict[str, Any]:
    normalized: dict[str, Any] = {"state": value["state"]}
    if value["state"] in {"complete", "truncated"}:
        normalized["text"] = value["text"]
        normalized["bytes_read"] = value["bytes_read"]
    elif value["state"] == "unreadable":
        normalized["bytes_read"] = value["bytes_read"]
    return normalized


def normalize_frontend_capture(raw: Mapping[str, Any]) -> dict[str, Any]:
    """Remove unstable heap addresses and replace links with deterministic local IDs."""

    names_raw = raw.get("name_table", {})
    nodes_raw = raw.get("iro_nodes", {})
    names = names_raw.get("entries", []) if isinstance(names_raw, Mapping) else []
    nodes = nodes_raw.get("nodes", []) if isinstance(nodes_raw, Mapping) else []
    if not isinstance(names, list) or not isinstance(nodes, list):
        raise FrontendModelError("raw capture has invalid collection records")

    name_ids = {entry["address"]: f"name-{index:04d}" for index, entry in enumerate(names)}
    node_ids = {node["address"]: f"iro-{index:04d}" for index, node in enumerate(nodes)}

    normalized_names: list[dict[str, Any]] = []
    for index, entry in enumerate(names):
        if not isinstance(entry, Mapping) or not isinstance(entry.get("record"), Mapping):
            raise FrontendModelError("raw capture contains malformed name-table entry")
        record = entry["record"]
        item: dict[str, Any] = {
            "id": f"name-{index:04d}",
            "next": {"state": "resolved", "id": name_ids[entry["next_address"]]}
            if entry.get("next_address") in name_ids
            else {"state": "not_captured" if entry.get("next_address") != "0x00000000" else "null"},
            "record": {"state": record["state"]},
        }
        if record["state"] == "captured":
            item["record"] = {
                "state": "captured",
                "kind_u8": record["kind_u8"],
                "kind_flags_u8": record["kind_flags_u8"],
                "ordinal_u16": record["ordinal_u16"],
                "name": _normalize_name(record["name"]),
            }
        normalized_names.append(item)

    normalized_nodes: list[dict[str, Any]] = []
    for index, node in enumerate(nodes):
        if not isinstance(node, Mapping) or not isinstance(node.get("operation"), Mapping):
            raise FrontendModelError("raw capture contains malformed IRO node")
        operation = node["operation"]
        item = {
            "id": f"iro-{index:04d}",
            "kind_u8": node["kind_u8"],
            "opaque_01_u8": node["opaque_01_u8"],
            "opaque_02_u16": node["opaque_02_u16"],
            "flags_u32": node["flags_u32"],
            "operand_root": {"state": "present"}
            if node["operand_root_address"] != "0x00000000"
            else {"state": "null"},
            "operation": {"state": operation["state"]},
            "next": {"state": "resolved", "id": node_ids[node["next_address"]]}
            if node.get("next_address") in node_ids
            else {"state": "not_captured" if node.get("next_address") != "0x00000000" else "null"},
        }
        if operation["state"] == "captured":
            item["operation"]["opcode_u8"] = operation["opcode_u8"]
        normalized_nodes.append(item)

    function = raw.get("gFunction")
    if not isinstance(function, Mapping):
        raise FrontendModelError("raw capture has no gFunction record")
    return {
        "schema": {
            "name": FRONTEND_SNAPSHOT_SCHEMA_NAME,
            "version": FRONTEND_SNAPSHOT_SCHEMA_VERSION,
        },
        "gFunction": {
            "kind_u8": function["kind_u8"],
            "kind_flags_u8": function["kind_flags_u8"],
            "ordinal_u16": function["ordinal_u16"],
            "name": _normalize_name(function["name"]),
        },
        "name_table": {
            "entries": normalized_names,
            "termination": dict(names_raw.get("termination", {})),
        },
        "iro_nodes": {
            "nodes": normalized_nodes,
            "termination": dict(nodes_raw.get("termination", {})),
        },
    }


def capture_frontend_state(memory: MemoryReader, profile: Mapping[str, Any]) -> dict[str, Any]:
    """Capture all evidence-backed frontend records at the post-flow-graph boundary."""

    validate_frontend_profile(profile)
    frontend = _mapping(profile["frontend_ir"], "frontend_ir")
    globals_ = _mapping(frontend["globals"], "frontend_ir.globals")
    max_nodes = _positive_int(frontend["max_nodes"], "frontend_ir.max_nodes")
    max_name_bytes = _positive_int(frontend["max_name_bytes"], "frontend_ir.max_name_bytes")

    gfunction_global = parse_address(globals_["gFunction"], "frontend_ir.globals.gFunction")
    gfunction_address = _u32(_read_exact(memory, gfunction_global, 4, "gFunction global"), 0)
    if gfunction_address == 0:
        raise MemoryReadError("gFunction is null at the requested capture boundary")
    return {
        "gFunction": read_function_record(memory, gfunction_address, max_name_bytes),
        "name_table": collect_name_table(
            memory,
            parse_address(globals_["name_table_head"], "frontend_ir.globals.name_table_head"),
            max_nodes,
            max_name_bytes,
        ),
        "iro_nodes": collect_iro_nodes(
            memory,
            parse_address(globals_["iro_root"], "frontend_ir.globals.iro_root"),
            max_nodes,
        ),
    }
