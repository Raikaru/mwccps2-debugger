"""Pure, bounded b210 register-allocation snapshot collection and rendering.

The GDB command supplies only a ``read(address, size) -> bytes`` adapter and the EAX
value visible at the colorgraph-completion breakpoint.  This module keeps every layout
claim local to the exact b210 profile, bounds all walks independently, and emits a
parseable partial snapshot for malformed or unreadable inferior state.
"""

from __future__ import annotations

import struct
from typing import Any, Mapping


_MAX_U32 = 0xFFFFFFFF
_MAX_SIGNED_I16 = 0x7FFF
_NODE_STRIDE = 0x20
_EDGE_STRIDE = 0x10
_PHYSICAL_TABLE_WIDTH = 32
_EXPECTED_PHYSICAL_SLOTS = (32, 32, 32, 16, 32, 32, 32)
_EXPECTED_CLASS_LABELS = (
    "GPR",
    "FPR",
    "SPECIAL",
    "COPROC2_i",
    "COPROC2_ii",
    "COPROC2_f",
    "COPROC2_special",
)
_EXPECTED_GLOBALS = {
    "coloring_class": 0x006373AC,
    "interferencegraph": 0x00636634,
    "physical_slots": 0x00635B34,
    "total_nodes": 0x00636F98,
    "allocatable_phys": 0x00624E80,
    "allocatable_count": 0x006355D0,
    "physical_state": 0x006257F8,
    "fallback_phys": 0x00625338,
    "fallback_count": 0x00635A60,
    "fallback_cursor": 0x00636930,
    "saved_fallback_cursor": 0x0061B8C8,
    "coalesce_parent": 0x0060B708,
}
_FLAG_NAMES = (
    (0x0001, "spill_required"),
    (0x0002, "simplified_or_removed"),
    (0x0004, "coalesced_alias"),
    (0x0008, "coalesced_root"),
    (0x0010, "assignment_owner_second_field"),
    (0x0020, "paired_assignment_owner"),
    (0x0040, "unique_aux_owner_ambiguous"),
    (0x0080, "spill_score_forced_maximum"),
    (0x0200, "paired_color"),
    (0x0400, "spill_score_forced_secondary"),
)
_KNOWN_FLAG_MASK = sum(bit for bit, _ in _FLAG_NAMES)

_OMITTED_FIELDS = (
    {
        "field": "IGNode[+0x1a..+0x1b]",
        "reason": "uninitialized_or_unused_in_observed_b210_graph_builder",
    },
    {
        "field": "IGEdge hash_next and endpoint-specific next links",
        "reason": "structural_pointer_links_are_replaced_by_normalized_edges_and_incidence_ids",
    },
    {
        "field": "assignment_owner and unique_aux_owner pointee_contents",
        "reason": "backing_pointer_types_are_opaque; only_raw_pointer_values_are_preserved",
    },
    {
        "field": "simplification, coalescing-decision, and color-selection events",
        "reason": "not_observable_at_the_post_colorgraph_completion_breakpoint",
    },
)


REGALLOC_LAYOUT_EVIDENCE: dict[str, Any] = {
    "profile": "mwcps2-3.0.1b210-060308",
    "capture_boundary": {
        "address": "0x004c1d74",
        "phase": "post-color",
        "meaning": "colorgraph has returned while the transient class graph and coalesce-parent map remain live",
    },
    "graph": {
        "root": "*(u32 *)0x00636634",
        "node_stride": "0x20",
        "edge_stride": "0x10",
        "physical_then_virtual": "physical nodes [0,P), virtual nodes [P,N)",
        "physical_slots": [32, 32, 32, 16, 32, 32, 32],
    },
    "node_fields": {
        "work_next": "+0x00 u32 allocator work-list link",
        "assignment_owner": "+0x04 opaque backing pointer",
        "unique_aux_owner": "+0x08 opaque backing pointer",
        "spill_score": "+0x0c i32",
        "node_id": "+0x10 i16",
        "assigned_color": "+0x12 i16",
        "flags": "+0x14 u16",
        "dynamic_degree": "+0x16 i16",
        "static_neighbor_count": "+0x18 i16",
        "neighbor_head": "+0x1c u32 intrusive-incidence head",
        "excluded": "+0x1a..+0x1b are uninitialized/opaque and deliberately not serialized",
    },
    "edge_fields": {
        "hash_next": "+0x00 u32 duplicate-hash link",
        "next_for_low_endpoint": "+0x04 u32",
        "next_for_high_endpoint": "+0x08 u32",
        "u": "+0x0c i16",
        "v": "+0x0e i16",
    },
    "limits": "N is signed-16-bit bounded; collector independently guards class, node, parent, and every incidence walk.",
    "opaque": [
        "Semantic C types behind assignment_owner and unique_aux_owner are not claimed.",
        "Undocumented flag bits are retained only through flags_raw_u16/unknown_bits_u16.",
        "No color-selection, simplification, coalescing-decision, or spill-rewrite event is inferred from this completion-only capture.",
    ],
}


class RegisterAllocationProfileError(ValueError):
    """Raised when the b210-only register-allocation profile shape drifts."""


def _format_address(value: int) -> str:
    return f"0x{value & _MAX_U32:08x}"


def _parse_address(value: Any, field_name: str) -> int:
    try:
        parsed = int(value, 0) if isinstance(value, str) else int(value)
    except (TypeError, ValueError) as exc:
        raise RegisterAllocationProfileError(f"{field_name} is not an integer address") from exc
    if not 0 <= parsed <= _MAX_U32:
        raise RegisterAllocationProfileError(f"{field_name} is outside the 32-bit address range")
    return parsed


def _mapping(value: Any, field_name: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise RegisterAllocationProfileError(f"{field_name} must be an object")
    return value


def validate_register_allocation_profile(profile: Mapping[str, Any]) -> None:
    """Require every address and size used by this model to be exact b210 evidence."""

    configuration = _mapping(profile.get("register_allocation"), "profile.register_allocation")
    breakpoint = _parse_address(
        configuration.get("capture_breakpoint"), "register_allocation.capture_breakpoint"
    )
    if breakpoint != 0x004C1D74:
        raise RegisterAllocationProfileError(
            "register_allocation.capture_breakpoint must be 0x004c1d74"
        )
    breakpoints = _mapping(profile.get("pcode_breakpoints"), "profile.pcode_breakpoints")
    if _parse_address(
        breakpoints.get("after_colorgraph_assignment"),
        "pcode_breakpoints.after_colorgraph_assignment",
    ) != breakpoint:
        raise RegisterAllocationProfileError(
            "after_colorgraph_assignment must equal register_allocation.capture_breakpoint"
        )
    for name, expected in (("max_nodes", _MAX_SIGNED_I16), ("node_stride", _NODE_STRIDE), ("edge_stride", _EDGE_STRIDE)):
        if configuration.get(name) != expected:
            raise RegisterAllocationProfileError(f"register_allocation.{name} must be {expected}")
    if tuple(configuration.get("physical_slots", ())) != _EXPECTED_PHYSICAL_SLOTS:
        raise RegisterAllocationProfileError(
            "register_allocation.physical_slots must be the exact b210 [32,32,32,16,32,32,32]"
        )
    if tuple(configuration.get("class_labels", ())) != _EXPECTED_CLASS_LABELS:
        raise RegisterAllocationProfileError("register_allocation.class_labels must be the exact b210 labels")
    globals_ = _mapping(configuration.get("globals"), "register_allocation.globals")
    if set(globals_) != set(_EXPECTED_GLOBALS):
        raise RegisterAllocationProfileError("register_allocation.globals has an unexpected key set")
    for name, expected in _EXPECTED_GLOBALS.items():
        actual = _parse_address(globals_.get(name), f"register_allocation.globals.{name}")
        if actual != expected:
            raise RegisterAllocationProfileError(
                f"register_allocation.globals.{name} must be {_format_address(expected)}"
            )


def _add_error(errors: list[dict[str, str]], scope: str, reason: str) -> None:
    value = {"scope": scope, "reason": reason}
    if value not in errors:
        errors.append(value)


def _termination(reason: str, limit: int | None = None) -> dict[str, int | str]:
    value: dict[str, int | str] = {"reason": reason}
    if limit is not None:
        value["limit"] = limit
    return value


def _read_exact(memory: Any, address: int, size: int) -> bytes:
    if address < 0 or size < 0 or address > _MAX_U32 or size > _MAX_U32 + 1 - address:
        raise ValueError("address_overflow")
    data = memory.read(address, size)
    if len(data) != size:
        raise ValueError("short_read")
    return data


def _try_read(memory: Any, address: int, size: int) -> bytes | None:
    try:
        return _read_exact(memory, address, size)
    except Exception:
        return None


def _read_u32(memory: Any, address: int) -> int | None:
    data = _try_read(memory, address, 4)
    return struct.unpack("<I", data)[0] if data is not None else None


def _read_u16(memory: Any, address: int) -> int | None:
    data = _try_read(memory, address, 2)
    return struct.unpack("<H", data)[0] if data is not None else None


def _read_i8(memory: Any, address: int) -> int | None:
    data = _try_read(memory, address, 1)
    return struct.unpack("<b", data)[0] if data is not None else None


def _node_id(class_id: int, physical_slots: int, index: int) -> str:
    kind = "physical" if index < physical_slots else "virtual"
    return f"class-{class_id}-{kind}-{index:05d}"


def _opaque_pointer(value: int) -> str | None:
    return None if value == 0 else _format_address(value)


def _flag_state(flags: int) -> dict[str, Any]:
    result = {name: bool(flags & bit) for bit, name in _FLAG_NAMES}
    result["unknown_bits_u16"] = f"0x{flags & ~_KNOWN_FLAG_MASK:04x}"
    return result


def _read_node_records(
    memory: Any, root: int, count: int, errors: list[dict[str, str]]
) -> tuple[list[dict[str, int]], dict[str, Any]]:
    """Read a contiguous node array in bounded blocks with a record-level fallback."""

    records: list[dict[str, int]] = []
    index = 0
    while index < count:
        block_count = min(128, count - index)
        address = root + index * _NODE_STRIDE
        data = _try_read(memory, address, block_count * _NODE_STRIDE)
        if data is not None:
            for offset in range(block_count):
                item = data[offset * _NODE_STRIDE : (offset + 1) * _NODE_STRIDE]
                records.append(
                    {
                        "array_index": index + offset,
                        "work_next": struct.unpack_from("<I", item, 0x00)[0],
                        "assignment_owner": struct.unpack_from("<I", item, 0x04)[0],
                        "unique_aux_owner": struct.unpack_from("<I", item, 0x08)[0],
                        "spill_score": struct.unpack_from("<i", item, 0x0C)[0],
                        "node_id": struct.unpack_from("<h", item, 0x10)[0],
                        "assigned_color": struct.unpack_from("<h", item, 0x12)[0],
                        "flags": struct.unpack_from("<H", item, 0x14)[0],
                        "dynamic_degree": struct.unpack_from("<h", item, 0x16)[0],
                        "static_neighbor_count": struct.unpack_from("<h", item, 0x18)[0],
                        "neighbor_head": struct.unpack_from("<I", item, 0x1C)[0],
                    }
                )
            index += block_count
            continue
        # A readable allocation can straddle a page; retain its readable prefix rather than
        # throwing away a whole failed bulk read.
        while index < count:
            address = root + index * _NODE_STRIDE
            item = _try_read(memory, address, _NODE_STRIDE)
            if item is None:
                _add_error(errors, "ignode_array", "unreadable_memory")
                return records, {
                    "requested_count": count,
                    "captured_count": len(records),
                    "termination": _termination("unreadable_memory"),
                }
            records.append(
                {
                    "array_index": index,
                    "work_next": struct.unpack_from("<I", item, 0x00)[0],
                    "assignment_owner": struct.unpack_from("<I", item, 0x04)[0],
                    "unique_aux_owner": struct.unpack_from("<I", item, 0x08)[0],
                    "spill_score": struct.unpack_from("<i", item, 0x0C)[0],
                    "node_id": struct.unpack_from("<h", item, 0x10)[0],
                    "assigned_color": struct.unpack_from("<h", item, 0x12)[0],
                    "flags": struct.unpack_from("<H", item, 0x14)[0],
                    "dynamic_degree": struct.unpack_from("<h", item, 0x16)[0],
                    "static_neighbor_count": struct.unpack_from("<h", item, 0x18)[0],
                    "neighbor_head": struct.unpack_from("<I", item, 0x1C)[0],
                }
            )
            index += 1
    return records, {
        "requested_count": count,
        "captured_count": len(records),
        "termination": _termination("complete"),
    }


def _read_parent_records(
    memory: Any, root: int, count: int, errors: list[dict[str, str]]
) -> tuple[list[int], dict[str, Any]]:
    records: list[int] = []
    index = 0
    while index < count:
        block_count = min(256, count - index)
        data = _try_read(memory, root + index * 2, block_count * 2)
        if data is not None:
            records.extend(struct.unpack(f"<{block_count}H", data))
            index += block_count
            continue
        while index < count:
            value = _read_u16(memory, root + index * 2)
            if value is None:
                _add_error(errors, "coalesce_parent", "unreadable_memory")
                return records, {
                    "requested_count": count,
                    "captured_count": len(records),
                    "termination": _termination("unreadable_memory"),
                }
            records.append(value)
            index += 1
    return records, {
        "requested_count": count,
        "captured_count": len(records),
        "termination": _termination("complete"),
    }


def _capture_resource_tables(
    memory: Any,
    globals_: Mapping[str, int],
    class_id: int,
    physical_slots: int,
    errors: list[dict[str, str]],
) -> dict[str, Any]:
    """Capture fixed-width class tables and derive masks only from validated entries."""

    state_data = _try_read(memory, globals_["physical_state"] + class_id * _PHYSICAL_TABLE_WIDTH, _PHYSICAL_TABLE_WIDTH)
    physical_state = list(state_data[:physical_slots]) if state_data is not None else []
    if state_data is None:
        _add_error(errors, "physical_state", "unreadable_memory")
    elif any(state not in {0, 1, 2} for state in physical_state):
        _add_error(errors, "physical_state", "invalid_state")

    alloc_count = _read_u32(memory, globals_["allocatable_count"] + class_id * 4)
    alloc_data = _try_read(memory, globals_["allocatable_phys"] + class_id * 0x80, 0x80)
    fallback_count = _read_u32(memory, globals_["fallback_count"] + class_id * 4)
    fallback_data = _try_read(memory, globals_["fallback_phys"] + class_id * 0x80, 0x80)
    saved_cursor = _read_u16(memory, globals_["saved_fallback_cursor"])
    cursor_end = _read_u32(memory, globals_["fallback_cursor"] + class_id * 4)

    if alloc_count is None:
        _add_error(errors, "allocatable_phys", "unreadable_count")
    if alloc_data is None:
        _add_error(errors, "allocatable_phys", "unreadable_memory")
    if fallback_count is None:
        _add_error(errors, "fallback_phys", "unreadable_count")
    if fallback_data is None:
        _add_error(errors, "fallback_phys", "unreadable_memory")
    if saved_cursor is None:
        _add_error(errors, "fallback_cursor_start", "unreadable_memory")
    if cursor_end is None:
        _add_error(errors, "fallback_cursor_end", "unreadable_memory")

    alloc_table = list(struct.unpack("<32i", alloc_data)) if alloc_data is not None else []
    fallback_table = list(struct.unpack("<32i", fallback_data)) if fallback_data is not None else []

    def entries_and_mask(
        scope: str, count: int | None, table: list[int], require_state_zero: bool
    ) -> tuple[list[int], str | None, dict[str, Any]]:
        if count is None or not table:
            return [], None, {
                "requested_count_u32": count,
                "captured_count": 0,
                "termination": _termination("unreadable_memory"),
            }
        capture_count = min(count, _PHYSICAL_TABLE_WIDTH)
        termination = _termination("complete")
        if count > _PHYSICAL_TABLE_WIDTH:
            _add_error(errors, scope, "invalid_count")
            termination = _termination("invalid_count")
        entries = table[:capture_count]
        mask: int | None = 0
        if (
            count > _PHYSICAL_TABLE_WIDTH
            or len(physical_state) != physical_slots
            or any(state not in {0, 1, 2} for state in physical_state)
        ):
            mask = None
        for physical_id in entries:
            if not 0 <= physical_id < physical_slots:
                _add_error(errors, scope, "invalid_physical_id")
                mask = None
                continue
            if mask is not None and (not require_state_zero or physical_state[physical_id] == 0):
                mask |= 1 << physical_id
        return entries, None if mask is None else _format_address(mask), {
            "requested_count_u32": count,
            "captured_count": len(entries),
            "termination": termination,
        }

    alloc_entries, ordinary_mask, alloc_capture = entries_and_mask(
        "allocatable_phys", alloc_count, alloc_table, True
    )
    fallback_entries, fallback_mask, fallback_capture = entries_and_mask(
        "fallback_phys", fallback_count, fallback_table, False
    )
    if fallback_count is not None and cursor_end is not None and cursor_end > fallback_count:
        _add_error(errors, "fallback_cursor_end", "out_of_range")

    return {
        "physical_state_u8": physical_state,
        "allocatable": {
            "physical_ids_i32": alloc_entries,
            "ordinary_mask_recomputed_u32": ordinary_mask,
            "capture": alloc_capture,
        },
        "fallback": {
            "physical_ids_i32": fallback_entries,
            "mask_u32": fallback_mask,
            "cursor_start_u16": saved_cursor,
            "cursor_end_u32": cursor_end,
            "capture": fallback_capture,
        },
    }


def _collect_edges(
    memory: Any,
    node_records: list[dict[str, int]],
    total_nodes: int,
    max_edges: int,
    errors: list[dict[str, str]],
) -> tuple[dict[tuple[int, int], int], dict[int, list[tuple[int, int]]], list[dict[str, Any]]]:
    """Walk every captured incidence list with per-list cycle and global edge guards."""

    edges: dict[tuple[int, int], int] = {}
    incidences: dict[int, list[tuple[int, int]]] = {record["array_index"]: [] for record in node_records}
    walks: list[dict[str, Any]] = []
    captured_indices = set(incidences)
    incidence_limit = max_edges * 2
    incidence_visits = 0
    exhausted = False

    for record in node_records:
        index = record["array_index"]
        pointer = record["neighbor_head"]
        seen: set[int] = set()
        captured_count = 0
        if exhausted:
            walks.append(
                {
                    "node_index": index,
                    "captured_incidence_count": 0,
                    "termination": _termination("count_limit", max_edges),
                }
            )
            continue
        while pointer:
            if pointer in seen:
                _add_error(errors, "edge_incidence", "cycle")
                walks.append(
                    {
                        "node_index": index,
                        "captured_incidence_count": captured_count,
                        "termination": _termination("cycle"),
                    }
                )
                break
            if incidence_visits >= incidence_limit or len(edges) >= max_edges:
                _add_error(errors, "edge_incidence", "count_limit")
                walks.append(
                    {
                        "node_index": index,
                        "captured_incidence_count": captured_count,
                        "termination": _termination("count_limit", max_edges),
                    }
                )
                exhausted = True
                break
            seen.add(pointer)
            data = _try_read(memory, pointer, _EDGE_STRIDE)
            if data is None:
                _add_error(errors, "edge_incidence", "unreadable_memory")
                walks.append(
                    {
                        "node_index": index,
                        "captured_incidence_count": captured_count,
                        "termination": _termination("unreadable_memory"),
                    }
                )
                break
            incidence_visits += 1
            next_low, next_high = struct.unpack_from("<II", data, 0x04)
            u, v = struct.unpack_from("<hh", data, 0x0C)
            if not (0 <= u < v < total_nodes):
                _add_error(errors, "edge_incidence", "invalid_endpoint")
                walks.append(
                    {
                        "node_index": index,
                        "captured_incidence_count": captured_count,
                        "termination": _termination("invalid_endpoint"),
                    }
                )
                break
            if index != u and index != v:
                _add_error(errors, "edge_incidence", "endpoint_mismatch")
                walks.append(
                    {
                        "node_index": index,
                        "captured_incidence_count": captured_count,
                        "termination": _termination("endpoint_mismatch"),
                    }
                )
                break
            pointer = next_low if index == u else next_high
            if u not in captured_indices or v not in captured_indices:
                _add_error(errors, "edge_incidence", "endpoint_not_captured")
                walks.append(
                    {
                        "node_index": index,
                        "captured_incidence_count": captured_count,
                        "termination": _termination("endpoint_not_captured"),
                    }
                )
                break
            pair = (u, v)
            edges[pair] = edges.get(pair, 0) + 1
            incidences[index].append(pair)
            captured_count += 1
        else:
            walks.append(
                {
                    "node_index": index,
                    "captured_incidence_count": captured_count,
                    "termination": _termination("null"),
                }
            )
    return edges, incidences, walks


def _parent_resolution(
    index: int, parents: list[int], total_nodes: int
) -> tuple[int | None, str]:
    seen: set[int] = set()
    current = index
    while True:
        if current in seen:
            return None, "cycle"
        seen.add(current)
        if current >= len(parents):
            return None, "not_captured"
        parent = parents[current]
        if not 0 <= parent < total_nodes:
            return None, "invalid_parent"
        if parent == current:
            return current, "resolved"
        current = parent


def _capture_status(errors: list[dict[str, str]]) -> str:
    reasons = {error["reason"] for error in errors}
    if not reasons:
        return "complete"
    if "unreadable_memory" in reasons or "unreadable_count" in reasons:
        return "partial_memory_unreadable"
    if "cycle" in reasons:
        return "partial_cycle_guarded"
    if "count_limit" in reasons:
        return "partial_count_guarded"
    if reasons & {
        "invalid_class",
        "invalid_physical_slots",
        "invalid_total_nodes",
        "null_graph_root",
        "invalid_count",
        "invalid_physical_id",
        "invalid_endpoint",
        "endpoint_mismatch",
        "invalid_parent",
        "out_of_range",
        "invalid_state",
        "invalid_pair",
        "null_root",
        "invalid_return_value",
    }:
        return "partial_invalid_state"
    return "partial_validation"


def _empty_capture(colorgraph_result_i32: int | None) -> dict[str, Any]:
    result_state = "unavailable"
    if colorgraph_result_i32 is not None:
        result_state = (
            "success"
            if colorgraph_result_i32 == 1
            else "failure"
            if colorgraph_result_i32 == 0
            else "unrecognized"
        )
    return {
        "schema": {"name": "mwccps2-b210-register-allocation", "version": 1},
        "phase": "post-color",
        "colorgraph_result": {
            "source": "stack_dword_at_esp",
            "value_i32": colorgraph_result_i32,
            "state": result_state,
        },
        "class": {"id": None, "label": None, "physical_slots": None, "total_nodes": None, "virtual_nodes": None},
        "resources": {},
        "parent_map": {"entries": [], "capture": {"requested_count": 0, "captured_count": 0, "termination": _termination("not_started")}},
        "nodes": [],
        "edges": [],
        "final_assignments": {"state": "not_final", "entries": []},
        "pcode_virtual_registers": {"state": "not_correlated", "entries": []},
        "omitted_fields": [dict(value) for value in _OMITTED_FIELDS],
        "collection": {
            "globals": {},
            "node_array": {"requested_count": 0, "captured_count": 0, "termination": _termination("not_started")},
            "edge_incidence_walks": [],
            "errors": [],
        },
        "capture_status": "partial_validation",
    }


def collect_runtime_register_allocation(
    memory: Any,
    configuration: Mapping[str, Any],
    max_nodes: int,
    max_edges: int,
    colorgraph_result_i32: int | None,
) -> dict[str, Any]:
    """Collect one post-colorgraph class graph into stable, address-normalized records.

    ``max_nodes`` and ``max_edges`` are independent hard guards supplied by the command.
    Counts and pointers from the inferior are never trusted as allocation sizes.
    """

    if max_nodes < 1 or max_edges < 1:
        raise ValueError("register-allocation limits must be positive")
    profile = {"register_allocation": configuration, "pcode_breakpoints": {"after_colorgraph_assignment": configuration["capture_breakpoint"]}}
    # The caller has already validated the full profile.  This isolated call protects direct
    # model users from accidentally applying this decoder to a look-alike configuration.
    validate_register_allocation_profile(profile)
    globals_ = {name: _parse_address(value, name) for name, value in configuration["globals"].items()}
    errors: list[dict[str, str]] = []
    result = _empty_capture(colorgraph_result_i32)
    if colorgraph_result_i32 is not None and colorgraph_result_i32 not in {0, 1}:
        _add_error(errors, "colorgraph_result", "invalid_return_value")
    result["collection"]["limits"] = {
        "max_nodes": max_nodes,
        "max_edges": max_edges,
        "profile_max_nodes": configuration["max_nodes"],
    }

    class_id = _read_i8(memory, globals_["coloring_class"])
    root = _read_u32(memory, globals_["interferencegraph"])
    result["collection"]["globals"].update(
        {
            "coloring_class_i8": class_id,
            "interferencegraph_root_raw": None if root is None else _format_address(root),
        }
    )
    if class_id is None:
        _add_error(errors, "coloring_class", "unreadable_memory")
    if root is None:
        _add_error(errors, "interferencegraph", "unreadable_memory")
    if class_id is None or root is None:
        result["collection"]["errors"] = errors
        result["capture_status"] = _capture_status(errors)
        return result
    if not 0 <= class_id < len(_EXPECTED_PHYSICAL_SLOTS):
        _add_error(errors, "coloring_class", "invalid_class")
        result["class"]["id"] = class_id
        result["collection"]["errors"] = errors
        result["capture_status"] = _capture_status(errors)
        return result

    physical_slots = _read_u32(memory, globals_["physical_slots"] + class_id * 4)
    total_nodes = _read_u32(memory, globals_["total_nodes"] + class_id * 4)
    result["collection"]["globals"].update(
        {"physical_slots_u32": physical_slots, "total_nodes_u32": total_nodes}
    )
    label = configuration["class_labels"][class_id]
    result["class"].update({"id": class_id, "label": label, "physical_slots": physical_slots, "total_nodes": total_nodes})
    if physical_slots is None:
        _add_error(errors, "physical_slots", "unreadable_memory")
    elif physical_slots != _EXPECTED_PHYSICAL_SLOTS[class_id]:
        _add_error(errors, "physical_slots", "invalid_physical_slots")
    if total_nodes is None:
        _add_error(errors, "total_nodes", "unreadable_memory")
    elif physical_slots is not None and not physical_slots <= total_nodes <= _MAX_SIGNED_I16:
        _add_error(errors, "total_nodes", "invalid_total_nodes")
    if root == 0:
        _add_error(errors, "interferencegraph", "null_graph_root")
    if errors:
        result["collection"]["errors"] = errors
        result["capture_status"] = _capture_status(errors)
        return result

    assert physical_slots is not None and total_nodes is not None
    result["class"]["virtual_nodes"] = total_nodes - physical_slots
    result["resources"] = _capture_resource_tables(memory, globals_, class_id, physical_slots, errors)

    requested_nodes = min(total_nodes, max_nodes)
    if total_nodes > max_nodes:
        _add_error(errors, "ignode_array", "count_limit")
    node_records, node_capture = _read_node_records(memory, root, requested_nodes, errors)
    result["collection"]["node_array"] = node_capture

    parent_root = _read_u32(memory, globals_["coalesce_parent"])
    result["collection"]["globals"]["coalesce_parent_root_raw"] = (
        None if parent_root is None else _format_address(parent_root)
    )
    if parent_root is None:
        _add_error(errors, "coalesce_parent", "unreadable_memory")
        parents: list[int] = []
        parent_capture = {
            "requested_count": requested_nodes,
            "captured_count": 0,
            "termination": _termination("unreadable_memory"),
        }
    elif parent_root == 0:
        _add_error(errors, "coalesce_parent", "null_root")
        parents = []
        parent_capture = {
            "requested_count": requested_nodes,
            "captured_count": 0,
            "termination": _termination("null_root"),
        }
    else:
        parents, parent_capture = _read_parent_records(memory, parent_root, requested_nodes, errors)
    result["parent_map"]["capture"] = parent_capture

    canonical: dict[int, tuple[int | None, str]] = {}
    for record in node_records:
        index = record["array_index"]
        canonical[index] = _parent_resolution(index, parents, total_nodes)
        _, resolution = canonical[index]
        if resolution != "resolved":
            _add_error(errors, "coalesce_parent", resolution)
        elif record["node_id"] != index:
            _add_error(errors, "ignode_array", "node_id_mismatch")
        if record["flags"] & 0x0004 and canonical[index][0] == index:
            _add_error(errors, "coalesce_parent", "alias_self_parent")

    edges, incidences, edge_walks = _collect_edges(
        memory, node_records, total_nodes, max_edges, errors
    )
    result["collection"]["edge_incidence_walks"] = edge_walks
    edge_pairs = sorted(edges)
    edge_ids = {pair: f"edge-{ordinal:06d}" for ordinal, pair in enumerate(edge_pairs, start=1)}
    neighbors: dict[int, set[int]] = {record["array_index"]: set() for record in node_records}
    for u, v in edge_pairs:
        neighbors[u].add(v)
        neighbors[v].add(u)

    normalized_nodes: list[dict[str, Any]] = []
    for record in node_records:
        index = record["array_index"]
        canonical_index, parent_state = canonical[index]
        canonical_color: int | None = None
        if canonical_index is not None and canonical_index < len(node_records):
            canonical_color = node_records[canonical_index]["assigned_color"]
        if index < physical_slots and record["assigned_color"] != index:
            _add_error(errors, "physical_precolor", "mismatch")
        if record["assigned_color"] not in {-1} and index >= physical_slots:
            if not 0 <= record["assigned_color"] < physical_slots:
                _add_error(errors, "assigned_color", "out_of_range")
            if record["flags"] & 0x0200 and (
                record["assigned_color"] % 2 != 0 or record["assigned_color"] + 1 >= physical_slots
            ):
                _add_error(errors, "assigned_color", "invalid_pair")
        if (
            result["colorgraph_result"]["state"] == "success"
            and record["flags"] & 0x0001
        ):
            _add_error(errors, "colorgraph_result", "success_with_spill_flag")
        if record["static_neighbor_count"] != len(neighbors[index]):
            _add_error(errors, "static_neighbor_count", "incidence_mismatch")
        if record["dynamic_degree"] != record["static_neighbor_count"]:
            # At this post-color breakpoint dynamic degree is mutable allocator state.  Retain
            # it without treating divergence as corruption.
            pass
        normalized_nodes.append(
            {
                "id": _node_id(class_id, physical_slots, index),
                "array_index": index,
                "kind": "physical" if index < physical_slots else "virtual",
                "node_id_i16": record["node_id"],
                "assigned_color_i16": record["assigned_color"],
                "canonical_id": (
                    _node_id(class_id, physical_slots, canonical_index)
                    if canonical_index is not None
                    else None
                ),
                "canonical_color_i16": canonical_color,
                "parent_resolution": parent_state,
                "spill_score_i32": record["spill_score"],
                "dynamic_degree_i16": record["dynamic_degree"],
                "static_neighbor_count_i16": record["static_neighbor_count"],
                "flags_raw_u16": f"0x{record['flags']:04x}",
                "flags": _flag_state(record["flags"]),
                "backing": {
                    "work_next_raw": _opaque_pointer(record["work_next"]),
                    "assignment_owner_raw": _opaque_pointer(record["assignment_owner"]),
                    "unique_aux_owner_raw": _opaque_pointer(record["unique_aux_owner"]),
                },
                "incidence_edge_ids": [edge_ids[pair] for pair in incidences[index] if pair in edge_ids],
                "neighbors": [
                    _node_id(class_id, physical_slots, neighbor) for neighbor in sorted(neighbors[index])
                ],
            }
        )

    result["nodes"] = normalized_nodes
    success = result["colorgraph_result"]["state"] == "success"
    result["final_assignments"] = {
        "state": "success" if success else "not_final",
        "entries": [
            {
                "id": node["id"],
                "raw_color_i16": node["assigned_color_i16"],
                "canonical_id": node["canonical_id"],
                "canonical_color_i16": node["canonical_color_i16"],
                "flags_raw_u16": node["flags_raw_u16"],
            }
            for node in normalized_nodes
            if node["kind"] == "virtual"
        ]
        if success
        else [],
    }
    result["edges"] = [
        {
            "id": edge_ids[(u, v)],
            "u": _node_id(class_id, physical_slots, u),
            "v": _node_id(class_id, physical_slots, v),
            "incidence_count": edges[(u, v)],
        }
        for u, v in edge_pairs
    ]
    for pair, count in edges.items():
        if count != 2:
            _add_error(errors, "edge_incidence", "incidence_mismatch")
            break
    parent_entries: list[dict[str, Any]] = []
    for index, raw_parent in enumerate(parents):
        canonical_index, parent_state = canonical.get(index, (None, "not_captured"))
        parent_entries.append(
            {
                "node_id": _node_id(class_id, physical_slots, index),
                "raw_parent_index_u16": raw_parent,
                "parent_id": (
                    _node_id(class_id, physical_slots, raw_parent)
                    if raw_parent < len(node_records)
                    else None
                ),
                "canonical_id": (
                    _node_id(class_id, physical_slots, canonical_index)
                    if canonical_index is not None
                    else None
                ),
                "resolution": parent_state,
            }
        )
    result["parent_map"]["entries"] = parent_entries
    result["collection"]["errors"] = errors
    result["capture_status"] = _capture_status(errors)
    return result


def correlate_register_allocation_pcode(
    allocation: dict[str, Any], graph: Mapping[str, Any]
) -> None:
    """Attach only direct, same-snapshot virtual-register/color correlations.

    PCode operand payloads have already been rewritten through a coalesce parent before this
    point.  Therefore the correlation reports the observed PCode virtual identifier and the
    captured canonical IG assignment; it never invents a pre-coalesce operand identity.
    """

    class_id = allocation["class"].get("id")
    physical_slots = allocation["class"].get("physical_slots")
    if not isinstance(class_id, int) or not isinstance(physical_slots, int):
        allocation["pcode_virtual_registers"] = {"state": "unavailable", "entries": []}
        return
    nodes_by_index = {node["array_index"]: node for node in allocation["nodes"]}
    entries: list[dict[str, Any]] = []
    for pcode in graph.get("pcodes", []):
        for operand in pcode.get("operands", []):
            register_class = operand.get("register_class")
            number = operand.get("register_number_i16")
            if (
                operand.get("kind") != "register"
                or not isinstance(register_class, Mapping)
                or register_class.get("code") != class_id
                or not isinstance(number, int)
                or number < physical_slots
            ):
                continue
            node = nodes_by_index.get(number)
            if node is None:
                continue
            canonical_color = node["canonical_color_i16"]
            success = allocation["colorgraph_result"]["state"] == "success"
            predicted = (
                canonical_color
                if success
                and isinstance(canonical_color, int)
                and 0 <= canonical_color < physical_slots
                else None
            )
            assignment_state = (
                "assigned"
                if predicted is not None
                else "unassigned"
                if success
                else "not_final"
            )
            entries.append(
                {
                    "pcode_id": pcode["id"],
                    "operand_index": operand["index"],
                    "virtual_node_id": node["id"],
                    "virtual_index_i16": number,
                    "canonical_node_id": node["canonical_id"],
                    "raw_color_i16": node["assigned_color_i16"],
                    "canonical_color_i16": canonical_color,
                    "predicted_physical_register_i16": predicted,
                    "assignment_state": assignment_state,
                }
            )
    allocation["pcode_virtual_registers"] = {
        "state": (
            "correlated_final"
            if allocation["colorgraph_result"]["state"] == "success"
            else "correlated_nonfinal"
        ),
        "entries": entries,
    }


def format_register_allocation_text(allocation: Mapping[str, Any]) -> str:
    """Render stable node IDs, colors, spill, coalesce, and PCode correlations deterministically."""

    class_info = allocation["class"]
    lines = ["# MWCCPS2 b210 register allocation", ""]
    lines.append(f"phase: {allocation['phase']}")
    lines.append(
        "colorgraph-result: "
        f"{allocation['colorgraph_result']['state']} "
        f"source={allocation['colorgraph_result']['source']} "
        f"value={allocation['colorgraph_result']['value_i32']}"
    )
    lines.append(
        "class: "
        f"{class_info['label']} ({class_info['id']}); P={class_info['physical_slots']} "
        f"N={class_info['total_nodes']} V={class_info['virtual_nodes']}"
    )
    resources = allocation.get("resources", {})
    if resources:
        allocatable = resources["allocatable"]
        fallback = resources["fallback"]
        lines.append(
            "ordinary-mask-recomputed: "
            f"{allocatable['ordinary_mask_recomputed_u32']} "
            f"allocatable={allocatable['physical_ids_i32']}"
        )
        lines.append(
            "fallback: "
            f"mask={fallback['mask_u32']} entries={fallback['physical_ids_i32']} "
            f"cursor={fallback['cursor_start_u16']}->{fallback['cursor_end_u32']}"
        )
    lines.extend(["", "observed virtual color fields and spill/coalesce state:"])
    for node in allocation["nodes"]:
        if node["kind"] != "virtual":
            continue
        flags = node["flags"]
        state = []
        if flags["spill_required"]:
            state.append("spill")
        if flags["coalesced_alias"]:
            state.append("coalesced-alias")
        if flags["coalesced_root"]:
            state.append("coalesced-root")
        if not state:
            state.append("observed")
        lines.append(
            f"  {node['id']}: raw={node['assigned_color_i16']} "
            f"canonical={node['canonical_id']}:{node['canonical_color_i16']} "
            f"flags={node['flags_raw_u16']} ({', '.join(state)})"
        )
    if not any(node["kind"] == "virtual" for node in allocation["nodes"]):
        lines.append("  <none captured>")
    lines.extend(["", "PCode virtual-register correlations:"])
    correlation = allocation["pcode_virtual_registers"]
    if correlation["entries"]:
        for entry in correlation["entries"]:
            prediction = entry["predicted_physical_register_i16"]
            replacement = (
                f"r{prediction}"
                if prediction is not None
                else "<not-final>"
                if entry["assignment_state"] == "not_final"
                else "<unassigned>"
            )
            lines.append(
                f"  {entry['pcode_id']} operand[{entry['operand_index']}]: "
                f"{entry['virtual_node_id']} -> {replacement} ({entry['assignment_state']})"
            )
    else:
        lines.append(f"  <{correlation['state']}>")
    lines.extend(["", "collection:"])
    lines.append(f"  status: {allocation['capture_status']}")
    limits = allocation["collection"].get("limits", {})
    if limits:
        lines.append(
            "  limits: "
            f"nodes={limits['max_nodes']} edges={limits['max_edges']} "
            f"profile-nodes={limits['profile_max_nodes']}"
        )
    for omitted in allocation["omitted_fields"]:
        lines.append(f"  omitted {omitted['field']}: {omitted['reason']}")
    for error in allocation["collection"]["errors"]:
        lines.append(f"  {error['scope']}: {error['reason']}")
    if not allocation["collection"]["errors"]:
        lines.append("  complete")
    lines.append("")
    return "\n".join(lines)
