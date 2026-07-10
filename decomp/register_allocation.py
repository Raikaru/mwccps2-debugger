"""Replay the observed b210 colorgraph from a post-color allocation snapshot.

This is a deliberately narrow semantic model, not a replacement allocator.  It validates
and replays the stack and color-selection behavior of ``colorgraph`` at ``0x004c1c20``
from a schema-v1 runtime graph capture.  The surrounding observed pipeline is:

* ``0x004c1920`` runs a per-class build/simplify/color/rewrite retry loop;
* ``0x004be440`` rebuilds the graph until ``0x004be880`` has no accepted move merge;
* ``0x004c1de0`` overwrites ``IGNode.work_next`` with the simplify stack consumed here;
* ``0x004c1d74`` is the safe post-color capture point.

The capture is post-color, so this module restores only work-list virtual colors to ``-1``
and retains precolored physical nodes.  It is therefore appropriate for replaying a
completed colorgraph attempt, not for inferring liveness, coalescing, cost, or spill
rewrites that were not captured at this boundary.
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Sequence

MODEL_SCHEMA = {"name": "mwccps2-b210-colorgraph-replay", "version": 1}
EVIDENCE = {
    "allocation_driver": "0x004c1920",
    "class_graph_builder": "0x004be440",
    "coalescing_pass": "0x004be880",
    "simplify_stack_builder": "0x004c1de0",
    "colorgraph": "0x004c1c20",
    "post_color_capture": "0x004c1d74",
}
NODE_STRIDE = 0x20
FLAG_SPILL = 0x0001
FLAG_SIMPLIFIED = 0x0002
FLAG_COALESCED_ALIAS = 0x0004
FLAG_PAIRED_COLOR = 0x0200


class ReplayError(ValueError):
    """Raised when a snapshot cannot faithfully drive this semantic replay."""


def _mapping(value: Any, name: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise ReplayError(f"{name} must be an object")
    return value


def _sequence(value: Any, name: str) -> Sequence[Any]:
    if not isinstance(value, list):
        raise ReplayError(f"{name} must be an array")
    return value


def _integer(value: Any, name: str, *, minimum: int | None = None, maximum: int | None = None) -> int:
    try:
        parsed = int(value, 0) if isinstance(value, str) else int(value)
    except (TypeError, ValueError) as exc:
        raise ReplayError(f"{name} must be an integer") from exc
    if minimum is not None and parsed < minimum:
        raise ReplayError(f"{name} must be >= {minimum}")
    if maximum is not None and parsed > maximum:
        raise ReplayError(f"{name} must be <= {maximum}")
    return parsed


def _hex_u32(value: int) -> str:
    return f"0x{value & 0xffffffff:08x}"


def _hex_u16(value: int) -> str:
    return f"0x{value & 0xffff:04x}"


@dataclass(frozen=True)
class Node:
    index: int
    node_id: str
    flags: int
    assigned_color: int
    work_next: int | None
    neighbors: tuple[int, ...]

    @property
    def is_paired(self) -> bool:
        return bool(self.flags & FLAG_PAIRED_COLOR)


@dataclass(frozen=True)
class Capture:
    class_id: int
    physical_slots: int
    total_nodes: int
    graph_root: int
    ordinary_mask: int
    fallback_colors: tuple[int, ...]
    fallback_cursor: int
    expected_state: str
    expected_assignments: Mapping[int, int]
    expected_spills: frozenset[int]
    nodes: tuple[Node, ...]


def _parse_node_id(value: Any, class_id: int, index: int) -> str:
    if not isinstance(value, str):
        raise ReplayError(f"nodes[{index}].id must be a string")
    expected_suffix = f"-{index:05d}"
    expected_prefix = f"class-{class_id}-"
    if not value.startswith(expected_prefix) or not value.endswith(expected_suffix):
        raise ReplayError(f"nodes[{index}].id does not identify class {class_id} index {index}")
    return value


def _index_from_node_id(value: Any, class_id: int, total_nodes: int, name: str) -> int:
    if not isinstance(value, str):
        raise ReplayError(f"{name} must be a node id")
    prefix = f"class-{class_id}-"
    if not value.startswith(prefix):
        raise ReplayError(f"{name} is from another class")
    try:
        index = int(value.rsplit("-", 1)[1], 10)
    except (IndexError, ValueError) as exc:
        raise ReplayError(f"{name} has an invalid node index") from exc
    if not 0 <= index < total_nodes:
        raise ReplayError(f"{name} is outside the captured node range")
    return index


def _parse_capture(document: Mapping[str, Any]) -> Capture:
    schema = _mapping(document.get("schema"), "snapshot.schema")
    if schema.get("name") != "mwccps2-b210-stage-snapshot" or schema.get("version") != 3:
        raise ReplayError("snapshot must use mwccps2-b210-stage-snapshot schema v3")
    allocation = _mapping(document.get("register_allocation"), "snapshot.register_allocation")
    allocation_schema = _mapping(allocation.get("schema"), "register_allocation.schema")
    if allocation_schema.get("name") != "mwccps2-b210-register-allocation" or allocation_schema.get("version") != 1:
        raise ReplayError("register_allocation must use mwccps2-b210-register-allocation schema v1")
    if allocation.get("capture_status") != "complete" or allocation.get("phase") != "post-color":
        raise ReplayError("replay requires a complete post-color allocation capture")

    class_info = _mapping(allocation.get("class"), "register_allocation.class")
    class_id = _integer(class_info.get("id"), "class.id", minimum=0, maximum=6)
    physical_slots = _integer(class_info.get("physical_slots"), "class.physical_slots", minimum=1, maximum=32)
    total_nodes = _integer(class_info.get("total_nodes"), "class.total_nodes", minimum=physical_slots, maximum=32767)
    if _integer(class_info.get("virtual_nodes"), "class.virtual_nodes", minimum=0) != total_nodes - physical_slots:
        raise ReplayError("class.virtual_nodes must equal total_nodes - physical_slots")

    collection = _mapping(allocation.get("collection"), "register_allocation.collection")
    globals_ = _mapping(collection.get("globals"), "register_allocation.collection.globals")
    graph_root = _integer(globals_.get("interferencegraph_root_raw"), "interferencegraph_root_raw", minimum=1, maximum=0xffffffff)

    resources = _mapping(allocation.get("resources"), "register_allocation.resources")
    allocatable = _mapping(resources.get("allocatable"), "register_allocation.resources.allocatable")
    ordinary_mask = _integer(allocatable.get("ordinary_mask_recomputed_u32"), "ordinary_mask_recomputed_u32", minimum=0, maximum=0xffffffff)
    fallback = _mapping(resources.get("fallback"), "register_allocation.resources.fallback")
    fallback_colors = tuple(
        _integer(color, f"fallback.physical_ids_i32[{position}]", minimum=0, maximum=physical_slots - 1)
        for position, color in enumerate(_sequence(fallback.get("physical_ids_i32"), "fallback.physical_ids_i32"))
    )
    fallback_cursor = _integer(fallback.get("cursor_start_u16"), "fallback.cursor_start_u16", minimum=0, maximum=len(fallback_colors))

    result = _mapping(allocation.get("colorgraph_result"), "register_allocation.colorgraph_result")
    expected_state = result.get("state")
    if expected_state not in {"success", "failure"}:
        raise ReplayError("colorgraph_result.state must be success or failure")

    raw_nodes = _sequence(allocation.get("nodes"), "register_allocation.nodes")
    if len(raw_nodes) != total_nodes:
        raise ReplayError("nodes length must equal class.total_nodes")
    nodes: list[Node] = []
    for index, raw_node in enumerate(raw_nodes):
        node = _mapping(raw_node, f"nodes[{index}]")
        if _integer(node.get("array_index"), f"nodes[{index}].array_index", minimum=0) != index:
            raise ReplayError(f"nodes[{index}].array_index must equal its array position")
        node_id = _parse_node_id(node.get("id"), class_id, index)
        if _integer(node.get("node_id_i16"), f"nodes[{index}].node_id_i16", minimum=0, maximum=32767) != index:
            raise ReplayError(f"nodes[{index}].node_id_i16 must equal its array position")
        assigned_color = _integer(node.get("assigned_color_i16"), f"nodes[{index}].assigned_color_i16", minimum=-1, maximum=physical_slots - 1)
        flags = _integer(node.get("flags_raw_u16"), f"nodes[{index}].flags_raw_u16", minimum=0, maximum=0xffff)
        backing = _mapping(node.get("backing"), f"nodes[{index}].backing")
        raw_next = backing.get("work_next_raw")
        work_next = None if raw_next is None else _integer(raw_next, f"nodes[{index}].backing.work_next_raw", minimum=1, maximum=0xffffffff)
        neighbors = tuple(
            _index_from_node_id(neighbor, class_id, total_nodes, f"nodes[{index}].neighbors[{neighbor_index}]")
            for neighbor_index, neighbor in enumerate(_sequence(node.get("neighbors"), f"nodes[{index}].neighbors"))
        )
        if len(set(neighbors)) != len(neighbors) or index in neighbors:
            raise ReplayError(f"nodes[{index}].neighbors must be unique non-self endpoints")
        nodes.append(Node(index, node_id, flags, assigned_color, work_next, neighbors))

    expected_assignments: dict[int, int] = {}
    final_assignments = _mapping(allocation.get("final_assignments"), "register_allocation.final_assignments")
    entries = _sequence(final_assignments.get("entries"), "final_assignments.entries")
    for entry_index, raw_entry in enumerate(entries):
        entry = _mapping(raw_entry, f"final_assignments.entries[{entry_index}]")
        index = _index_from_node_id(entry.get("id"), class_id, total_nodes, f"final_assignments.entries[{entry_index}].id")
        if index < physical_slots:
            raise ReplayError("final_assignments must only list virtual nodes")
        if index in expected_assignments:
            raise ReplayError("final_assignments contains duplicate virtual nodes")
        expected_assignments[index] = _integer(entry.get("raw_color_i16"), f"final_assignments.entries[{entry_index}].raw_color_i16", minimum=-1, maximum=physical_slots - 1)

    expected_spills = frozenset(node.index for node in nodes if node.flags & FLAG_SPILL)
    return Capture(
        class_id=class_id,
        physical_slots=physical_slots,
        total_nodes=total_nodes,
        graph_root=graph_root,
        ordinary_mask=ordinary_mask,
        fallback_colors=fallback_colors,
        fallback_cursor=fallback_cursor,
        expected_state=expected_state,
        expected_assignments=expected_assignments,
        expected_spills=expected_spills,
        nodes=tuple(nodes),
    )


def _work_list(capture: Capture) -> list[int]:
    """Recover the simplify stack encoded in IGNode+0x00 after 0x004c1de0."""
    active = {node.index for node in capture.nodes if node.flags & FLAG_SIMPLIFIED}
    if not active:
        return []
    successor: dict[int, int | None] = {}
    inbound: dict[int, int] = {index: 0 for index in active}
    for index in sorted(active):
        raw_next = capture.nodes[index].work_next
        if raw_next is None:
            successor[index] = None
            continue
        relative = raw_next - capture.graph_root
        if relative < 0 or relative % NODE_STRIDE:
            raise ReplayError(f"work_next for node {index} is not an aligned IGNode address")
        next_index = relative // NODE_STRIDE
        if next_index not in active:
            raise ReplayError(f"work_next for node {index} leaves the simplified work list")
        successor[index] = next_index
        inbound[next_index] += 1
    heads = [index for index in sorted(active) if inbound[index] == 0]
    if len(heads) != 1:
        raise ReplayError("simplify work list must have exactly one head")
    order: list[int] = []
    current: int | None = heads[0]
    while current is not None:
        if current in order:
            raise ReplayError("simplify work list contains a cycle")
        order.append(current)
        current = successor[current]
    if set(order) != active:
        raise ReplayError("simplify work list does not contain every simplified node")
    return order


def _lowest_color(mask: int, physical_slots: int, paired: bool) -> int | None:
    if paired:
        for color in range(0, physical_slots, 2):
            if color + 1 < physical_slots and mask & (3 << color) == 3 << color:
                return color
        return None
    for color in range(physical_slots):
        if mask & (1 << color):
            return color
    return None


def replay_colorgraph(document: Mapping[str, Any]) -> dict[str, Any]:
    """Replay ``colorgraph`` and report whether its assignment matches the capture."""
    capture = _parse_capture(document)
    work_order = _work_list(capture)
    colors = [node.assigned_color if node.index < capture.physical_slots else -1 for node in capture.nodes]
    baseline_mask = capture.ordinary_mask
    fallback_cursor = capture.fallback_cursor
    spilled: list[int] = []

    for index in work_order:
        node = capture.nodes[index]
        while True:
            available = baseline_mask
            for neighbor_index in node.neighbors:
                neighbor = capture.nodes[neighbor_index]
                neighbor_color = colors[neighbor_index]
                if neighbor_color == -1:
                    continue
                clear = 3 << neighbor_color if neighbor.is_paired else 1 << neighbor_color
                available &= ~clear
            color = _lowest_color(available, capture.physical_slots, node.is_paired)
            if color is not None:
                colors[index] = color
                break
            if fallback_cursor < len(capture.fallback_colors):
                fallback_color = capture.fallback_colors[fallback_cursor]
                fallback_cursor += 1
                baseline_mask |= 1 << fallback_color
                continue
            spilled.append(index)
            break

    actual_state = "success" if not spilled else "failure"
    assignment_mismatches = [
        {
            "expected_color_i16": capture.expected_assignments[index],
            "id": capture.nodes[index].node_id,
            "model_color_i16": colors[index],
        }
        for index in sorted(capture.expected_assignments)
        if capture.expected_assignments[index] != colors[index]
    ]
    expected_spills = sorted(capture.expected_spills)
    actual_spills = sorted(spilled)
    matched = (
        actual_state == capture.expected_state
        and not assignment_mismatches
        and actual_spills == expected_spills
    )
    return {
        "assignments": [
            {
                "assigned_color_i16": colors[index],
                "flags_raw_u16": _hex_u16(capture.nodes[index].flags | (FLAG_SPILL if index in spilled else 0)),
                "id": capture.nodes[index].node_id,
            }
            for index in range(capture.physical_slots, capture.total_nodes)
        ],
        "capture": {
            "class_id": capture.class_id,
            "graph_root": _hex_u32(capture.graph_root),
            "physical_slots": capture.physical_slots,
            "total_nodes": capture.total_nodes,
        },
        "evidence": EVIDENCE,
        "match_observed": matched,
        "mismatches": assignment_mismatches,
        "schema": MODEL_SCHEMA,
        "replay": {
            "baseline_mask_initial": _hex_u32(capture.ordinary_mask),
            "baseline_mask_final": _hex_u32(baseline_mask),
            "fallback_cursor_end": fallback_cursor,
            "fallback_cursor_start": capture.fallback_cursor,
            "result": actual_state,
            "spilled_node_ids": [capture.nodes[index].node_id for index in actual_spills],
            "work_list_order": [capture.nodes[index].node_id for index in work_order],
        },
        "observed": {
            "result": capture.expected_state,
            "spilled_node_ids": [capture.nodes[index].node_id for index in expected_spills],
        },
    }


def _read_json(path: Path) -> Mapping[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise ReplayError(f"snapshot does not exist: {path}") from exc
    except UnicodeDecodeError as exc:
        raise ReplayError(f"snapshot is not UTF-8 JSON: {path}") from exc
    except json.JSONDecodeError as exc:
        raise ReplayError(f"snapshot has invalid JSON: {path}: {exc.msg}") from exc
    return _mapping(value, "snapshot")


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Replay the b210 colorgraph from a post-color snapshot")
    parser.add_argument("snapshot", type=Path, help="schema-v3 stage snapshot captured at 0x004c1d74")
    parser.add_argument("--output", type=Path, help="write stable schema-v1 replay JSON instead of stdout")
    parser.add_argument("--allow-mismatch", action="store_true", help="report mismatch without a nonzero exit status")
    args = parser.parse_args(argv)
    try:
        result = replay_colorgraph(_read_json(args.snapshot))
    except ReplayError as exc:
        print(f"register-allocation replay: {exc}", file=sys.stderr)
        return 2
    rendered = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.output is None:
        sys.stdout.write(rendered)
    else:
        args.output.write_text(rendered, encoding="utf-8")
    if not result["match_observed"] and not args.allow_mismatch:
        print("register-allocation replay: modeled result differs from captured colorgraph", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
