"""Pure, bounded b210 scheduler-state collection, normalization, and prediction.

The companion GDB command supplies a small ``read(address, size) -> bytes`` adapter.
This module deliberately does not import GDB: it validates the exact b210 scheduler
profile, bounds every linked-list traversal, and converts transient heap pointers into
stable ready-list identities before writing analysis artifacts.
"""

from __future__ import annotations

import struct
from typing import Any, Mapping


SCHEDULER_CAPTURE_SCHEMA_NAME = "mwccps2-b210-scheduler-capture"
SCHEDULER_CAPTURE_SCHEMA_VERSION = 1
SCHEDULER_MANIFEST_SCHEMA_NAME = "mwccps2-b210-scheduler-manifest"
SCHEDULER_MANIFEST_SCHEMA_VERSION = 1
EXPECTED_PROFILE_NAME = "mwcps2-3.0.1b210-060308"

_MAX_U16 = 0xFFFF
_MAX_U32 = 0xFFFFFFFF
_NODE_STRIDE = 0x1C
_EDGE_STRIDE = 0x0C
_EXPECTED_ADDRESSES = {
    "driver": 0x004C0790,
    "ready_selector": 0x004C0A00,
    "resource_pressure_score": 0x004C14B0,
    "ready_head": 0x0061B8C4,
    "pressure_mode": 0x00635C24,
    "callback_table": 0x0061B85C,
}


class SchedulerProfileError(ValueError):
    """Raised when a scheduler profile is not exact b210 evidence."""


class SchedulerCollectionError(ValueError):
    """Raised for invalid runtime collection inputs."""


def format_address(value: int) -> str:
    """Render a 32-bit value as the profile's canonical hexadecimal string."""

    return f"0x{value & _MAX_U32:08x}"


def _parse_address(value: Any, location: str) -> int:
    try:
        parsed = int(value, 0) if isinstance(value, str) else int(value)
    except (TypeError, ValueError) as exc:
        raise SchedulerProfileError(f"{location} is not an integer address") from exc
    if not 0 <= parsed <= _MAX_U32:
        raise SchedulerProfileError(f"{location} is outside the 32-bit address range")
    return parsed


def _mapping(value: Any, location: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise SchedulerProfileError(f"{location} must be an object")
    return value


def _exact_int(value: Any, expected: int, location: str) -> None:
    if not isinstance(value, int) or isinstance(value, bool) or value != expected:
        raise SchedulerProfileError(f"{location} must be {expected}")


def _require_address(mapping: Mapping[str, Any], name: str, expected: int, location: str) -> None:
    value = _parse_address(mapping.get(name), f"{location}.{name}")
    if value != expected:
        raise SchedulerProfileError(f"{location}.{name} must be {format_address(expected)}")


def validate_scheduler_profile(profile: Mapping[str, Any]) -> None:
    """Reject scheduler layout drift before a live inferior can be read."""

    if profile.get("name") != EXPECTED_PROFILE_NAME:
        raise SchedulerProfileError(f"profile.name must be {EXPECTED_PROFILE_NAME!r}")
    scheduler = _mapping(profile.get("scheduler"), "profile.scheduler")
    _require_address(scheduler, "driver", _EXPECTED_ADDRESSES["driver"], "scheduler")
    _require_address(scheduler, "ready_selector", _EXPECTED_ADDRESSES["ready_selector"], "scheduler")
    _require_address(
        scheduler,
        "resource_pressure_score",
        _EXPECTED_ADDRESSES["resource_pressure_score"],
        "scheduler",
    )
    _exact_int(scheduler.get("node_stride"), _NODE_STRIDE, "scheduler.node_stride")
    _exact_int(scheduler.get("edge_stride"), _EDGE_STRIDE, "scheduler.edge_stride")

    globals_ = _mapping(scheduler.get("globals"), "scheduler.globals")
    if set(globals_) != {"ready_head", "pressure_mode", "callback_table"}:
        raise SchedulerProfileError("scheduler.globals has an unexpected key set")
    for name in ("ready_head", "pressure_mode", "callback_table"):
        _require_address(globals_, name, _EXPECTED_ADDRESSES[name], "scheduler.globals")

    node_fields = _mapping(scheduler.get("node_fields"), "scheduler.node_fields")
    expected_node_offsets = {
        "next": 0x00,
        "previous": 0x04,
        "outgoing_edges": 0x08,
        "pcode": 0x0C,
        "actual_latency": 0x10,
        "heuristic_latency": 0x12,
        "earliest_issue_cycle": 0x14,
        "critical_deadline_cycle": 0x16,
        "critical_path_length": 0x18,
        "pending_predecessors": 0x1A,
    }
    if set(node_fields) != set(expected_node_offsets):
        raise SchedulerProfileError("scheduler.node_fields has an unexpected key set")
    for name, offset in expected_node_offsets.items():
        _exact_int(node_fields.get(name), offset, f"scheduler.node_fields.{name}")

    edge_fields = _mapping(scheduler.get("edge_fields"), "scheduler.edge_fields")
    expected_edge_offsets = {"next": 0x00, "target": 0x04, "latency": 0x08}
    if set(edge_fields) != set(expected_edge_offsets):
        raise SchedulerProfileError("scheduler.edge_fields has an unexpected key set")
    for name, offset in expected_edge_offsets.items():
        _exact_int(edge_fields.get(name), offset, f"scheduler.edge_fields.{name}")


def scheduler_profile_manifest(profile: Mapping[str, Any]) -> dict[str, Any]:
    """Select immutable scheduler evidence used in every scheduler artifact."""

    validate_scheduler_profile(profile)
    scheduler = _mapping(profile["scheduler"], "profile.scheduler")
    return {
        "profile_name": str(profile["name"]),
        "profile_schema_version": int(profile["schema_version"]),
        "driver": format_address(_parse_address(scheduler["driver"], "scheduler.driver")),
        "ready_selector": format_address(
            _parse_address(scheduler["ready_selector"], "scheduler.ready_selector")
        ),
        "resource_pressure_score": format_address(
            _parse_address(scheduler["resource_pressure_score"], "scheduler.resource_pressure_score")
        ),
        "node_stride": scheduler["node_stride"],
        "edge_stride": scheduler["edge_stride"],
        "globals": {
            name: format_address(_parse_address(value, f"scheduler.globals.{name}"))
            for name, value in sorted(_mapping(scheduler["globals"], "scheduler.globals").items())
        },
    }


def scheduler_layout_evidence(profile: Mapping[str, Any]) -> dict[str, Any]:
    """Return the profile's scheduler evidence without mutable heap addresses."""

    validate_scheduler_profile(profile)
    scheduler = _mapping(profile["scheduler"], "profile.scheduler")
    evidence = scheduler.get("evidence")
    if not isinstance(evidence, str) or not evidence:
        raise SchedulerProfileError("scheduler.evidence must be a non-empty string")
    return {
        "profile": str(profile["name"]),
        "driver": format_address(_parse_address(scheduler["driver"], "scheduler.driver")),
        "ready_selector": format_address(
            _parse_address(scheduler["ready_selector"], "scheduler.ready_selector")
        ),
        "node": {
            "stride": f"0x{_NODE_STRIDE:02x}",
            "fields": dict(sorted(_mapping(scheduler["node_fields"], "scheduler.node_fields").items())),
        },
        "edge": {
            "stride": f"0x{_EDGE_STRIDE:02x}",
            "fields": dict(sorted(_mapping(scheduler["edge_fields"], "scheduler.edge_fields").items())),
        },
        "selector_semantics": evidence,
        "resource_pressure_score": format_address(
            _parse_address(scheduler["resource_pressure_score"], "scheduler.resource_pressure_score")
        ),
    }


def _read_exact(memory: Any, address: int, size: int) -> bytes:
    if address < 0 or size < 0 or address > _MAX_U32 or size > _MAX_U32 + 1 - address:
        raise SchedulerCollectionError("address_overflow")
    try:
        result = memory.read(address, size)
    except Exception as exc:
        raise SchedulerCollectionError("unreadable_memory") from exc
    if len(result) != size:
        raise SchedulerCollectionError("short_read")
    return bytes(result)


def _read_node(memory: Any, address: int) -> dict[str, int]:
    raw = _read_exact(memory, address, _NODE_STRIDE)
    return {
        "address": address,
        "next": struct.unpack_from("<I", raw, 0x00)[0],
        "previous": struct.unpack_from("<I", raw, 0x04)[0],
        "outgoing_edges": struct.unpack_from("<I", raw, 0x08)[0],
        "pcode": struct.unpack_from("<I", raw, 0x0C)[0],
        "actual_latency": struct.unpack_from("<H", raw, 0x10)[0],
        "heuristic_latency": struct.unpack_from("<H", raw, 0x12)[0],
        "earliest_issue_cycle": struct.unpack_from("<H", raw, 0x14)[0],
        "critical_deadline_cycle": struct.unpack_from("<H", raw, 0x16)[0],
        "critical_path_length": struct.unpack_from("<H", raw, 0x18)[0],
        "pending_predecessors": struct.unpack_from("<h", raw, 0x1A)[0],
    }


def _read_pcode_signature(memory: Any, pcode_address: int) -> dict[str, Any] | None:
    """Read an address-free PCode identity sufficient to compare emitted order."""

    if pcode_address == 0:
        return None
    try:
        header = _read_exact(memory, pcode_address, 0x40)
    except SchedulerCollectionError:
        return None
    operand_count = struct.unpack_from("<h", header, 0x2A)[0]
    result: dict[str, Any] = {
        "opcode_u16": struct.unpack_from("<H", header, 0x28)[0],
        "operand_count_i16": operand_count,
        "property_flags_u32": format_address(struct.unpack_from("<I", header, 0x0C)[0]),
        "encoded_word_u32": format_address(struct.unpack_from("<I", header, 0x30)[0]),
        "operands": [],
    }
    if not 0 <= operand_count <= 16:
        result["operand_capture"] = {"reason": "invalid_or_excessive_operand_count"}
        return result
    try:
        operands = _read_exact(memory, pcode_address + 0x40, operand_count * 0x18)
    except SchedulerCollectionError:
        result["operand_capture"] = {"reason": "unreadable_memory"}
        return result
    result["operands"] = [
        {
            "tag_u8": operands[index * 0x18],
            "register_class_u8": operands[index * 0x18 + 1],
            "attributes_u16": struct.unpack_from("<H", operands, index * 0x18 + 2)[0],
            "payload_i16": struct.unpack_from("<h", operands, index * 0x18 + 4)[0],
        }
        for index in range(operand_count)
    ]
    result["operand_capture"] = {"reason": "complete"}
    return result


def _collect_outgoing_edges(
    memory: Any, edge_head: int, max_edges: int
) -> tuple[list[dict[str, int]], dict[str, Any]]:
    edges: list[dict[str, int]] = []
    seen: set[int] = set()
    address = edge_head
    termination: dict[str, Any] = {"reason": "null"}
    while address:
        if len(edges) >= max_edges:
            termination = {"reason": "limit", "limit": max_edges}
            break
        if address in seen:
            termination = {"reason": "cycle"}
            break
        seen.add(address)
        try:
            raw = _read_exact(memory, address, _EDGE_STRIDE)
        except SchedulerCollectionError as exc:
            termination = {"reason": str(exc)}
            break
        edges.append(
            {
                "address": address,
                "next": struct.unpack_from("<I", raw, 0x00)[0],
                "target": struct.unpack_from("<I", raw, 0x04)[0],
                "latency": struct.unpack_from("<H", raw, 0x08)[0],
            }
        )
        address = edges[-1]["next"]
    return edges, termination


def collect_ready_candidates(
    memory: Any,
    scheduler: Mapping[str, Any],
    head: int,
    cycle: int,
    max_nodes: int,
    max_edges: int,
) -> dict[str, Any]:
    """Capture one selector-entry ready-list snapshot without invoking compiler callbacks.

    ``selector_eligible`` is deliberately left unresolved here.  The GDB companion fills
    it using the selector's live ``callback_table[+0x10]`` result before prediction.
    """

    if not 0 <= head <= _MAX_U32:
        raise SchedulerCollectionError("ready_head_outside_u32")
    if not 0 <= cycle <= _MAX_U16:
        raise SchedulerCollectionError("cycle_outside_u16")
    if max_nodes < 1 or max_edges < 1:
        raise SchedulerCollectionError("capture_limits_must_be_positive")

    records: list[dict[str, Any]] = []
    seen: set[int] = set()
    address = head
    list_termination: dict[str, Any] = {"reason": "null"}
    while address:
        if len(records) >= max_nodes:
            list_termination = {"reason": "limit", "limit": max_nodes}
            break
        if address in seen:
            list_termination = {"reason": "cycle"}
            break
        seen.add(address)
        try:
            node = _read_node(memory, address)
        except SchedulerCollectionError as exc:
            list_termination = {"reason": str(exc)}
            break
        edges, edge_termination = _collect_outgoing_edges(
            memory, node["outgoing_edges"], max_edges
        )
        successor_waiting_count = 0
        edge_read_errors = 0
        for edge in edges:
            target = edge["target"]
            try:
                pending = struct.unpack_from("<h", _read_exact(memory, target + 0x1A, 2))[0]
            except SchedulerCollectionError:
                edge_read_errors += 1
                continue
            if pending == 1:
                successor_waiting_count += 1
        pcode_signature = _read_pcode_signature(memory, node["pcode"])
        records.append(
            {
                **node,
                "pcode_signature": pcode_signature,
                "pcode_opcode_u16": (
                    None if pcode_signature is None else pcode_signature["opcode_u16"]
                ),
                "outgoing_edge_count": len(edges),
                "successor_waiting_count": successor_waiting_count,
                "edge_read_errors": edge_read_errors,
                "edge_termination": edge_termination,
            }
        )
        address = node["next"]

    return {
        "ready_head_address": head,
        "cycle": cycle,
        "candidates": records,
        "collection": {
            "ready_list": {
                "requested_max_nodes": max_nodes,
                "captured_count": len(records),
                "termination": list_termination,
            }
        },
    }


def apply_selector_predicates(
    raw_capture: Mapping[str, Any],
    predicates_by_pcode: Mapping[int, bool],
    resource_scores_by_pcode: Mapping[int, int] | None = None,
) -> dict[str, Any]:
    """Attach selector callback and optional pressure-score observations immutably."""

    result = {
        "ready_head_address": int(raw_capture["ready_head_address"]),
        "cycle": int(raw_capture["cycle"]),
        "collection": dict(_mapping(raw_capture["collection"], "raw_capture.collection")),
        "candidates": [],
    }
    for candidate in raw_capture.get("candidates", []):
        if not isinstance(candidate, Mapping):
            raise SchedulerCollectionError("raw_capture.candidates must contain objects")
        item = dict(candidate)
        pcode = int(item["pcode"])
        structural = item["pending_predecessors"] == 0 and item["earliest_issue_cycle"] <= result["cycle"]
        predicate = predicates_by_pcode.get(pcode)
        item["resource_score"] = (
            None if resource_scores_by_pcode is None else resource_scores_by_pcode.get(pcode)
        )
        item["structurally_ready"] = structural
        item["selector_predicate"] = predicate
        item["eligible"] = structural and predicate is True
        result["candidates"].append(item)
    return result




def predict_ready_selection(
    candidates: list[Mapping[str, Any]], cycle: int, pressure_mode: bool
) -> dict[str, Any]:
    """Apply 0x004c0a00's documented selection order to observed eligible nodes."""

    if not 0 <= cycle <= _MAX_U16:
        raise SchedulerCollectionError("cycle_outside_u16")
    eligible: list[Mapping[str, Any]] = []
    unresolved: list[str] = []
    for candidate in candidates:
        identifier = str(candidate.get("id", "<unidentified>"))
        if candidate.get("structurally_ready") and candidate.get("selector_predicate") is None:
            unresolved.append(identifier)
        if candidate.get("eligible") is True:
            eligible.append(candidate)
    if unresolved:
        return {
            "status": "incomplete_selector_predicates",
            "reason": "selector eligibility callback was not observed for every structurally ready candidate",
            "unresolved_candidate_ids": unresolved,
            "winner_id": None,
        }
    if not eligible:
        return {
            "status": "no_eligible_candidate",
            "reason": "no ready-list candidate passed selector eligibility",
            "winner_id": None,
        }
    scored = [candidate for candidate in eligible if candidate.get("resource_score") is not None]
    if scored and len(scored) == len(eligible):
        winner = min(scored, key=lambda candidate: int(candidate["resource_score"]))
        return {
            "status": "complete",
            "selector_address": "0x004c0a00",
            "cycle": cycle,
            "pressure_mode": pressure_mode,
            "selection_mode": "resource_pressure_score",
            "tie_order": ["lower_resource_score", "ready_list_order"],
            "winner_id": str(winner["id"]),
        }


    winner = eligible[0]
    for candidate in eligible[1:]:
        candidate_deadline = int(candidate["critical_deadline_cycle"]) <= cycle
        winner_deadline = int(winner["critical_deadline_cycle"]) <= cycle
        replace = candidate_deadline and not winner_deadline
        if candidate_deadline == winner_deadline:
            if int(candidate["successor_waiting_count"]) > int(winner["successor_waiting_count"]):
                replace = True
            elif int(candidate["successor_waiting_count"]) == int(winner["successor_waiting_count"]):
                if int(candidate["critical_path_length"]) > int(winner["critical_path_length"]):
                    replace = True
                elif (
                    pressure_mode
                    and int(candidate["critical_path_length"]) == int(winner["critical_path_length"])
                    and int(candidate["heuristic_latency"]) < int(winner["heuristic_latency"])
                ):
                    replace = True
        if replace:
            winner = candidate

    return {
        "status": "complete",
        "selector_address": "0x004c0a00",
        "cycle": cycle,
        "pressure_mode": pressure_mode,
        "selection_mode": "deadline_and_tie_ladder",
        "tie_order": [
            "crossed_critical_deadline",
            "greater_successor_waiting_count",
            "greater_critical_path_length",
            "lower_heuristic_latency_when_pressure_mode",
            "ready_list_order",
        ],
        "winner_id": str(winner["id"]),
    }


def normalize_scheduler_capture(
    raw_capture: Mapping[str, Any], pressure_mode: bool) -> dict[str, Any]:
    """Replace every scheduler heap address with a stable ready-list identity."""

    cycle = int(raw_capture["cycle"])
    raw_candidates = raw_capture.get("candidates")
    if not isinstance(raw_candidates, list):
        raise SchedulerCollectionError("raw_capture.candidates must be an array")
    candidates: list[dict[str, Any]] = []
    for list_order, raw in enumerate(raw_candidates, start=1):
        if not isinstance(raw, Mapping):
            raise SchedulerCollectionError("raw_capture.candidates must contain objects")
        selector_predicate = raw.get("selector_predicate")
        if selector_predicate is not None and not isinstance(selector_predicate, bool):
            raise SchedulerCollectionError("selector_predicate must be boolean or null")
        structural = bool(raw.get("structurally_ready"))
        candidates.append(
            {
                "id": f"candidate-{list_order:04d}",
                "list_order": list_order,
                "pcode_opcode_u16": raw.get("pcode_opcode_u16"),
                "pcode_signature": raw.get("pcode_signature"),
                "actual_latency_u16": int(raw["actual_latency"]),
                "heuristic_latency_u16": int(raw["heuristic_latency"]),
                "resource_score": raw.get("resource_score"),
                "earliest_issue_cycle_u16": int(raw["earliest_issue_cycle"]),
                "critical_deadline_cycle_u16": int(raw["critical_deadline_cycle"]),
                "critical_path_length_u16": int(raw["critical_path_length"]),
                "pending_predecessors_i16": int(raw["pending_predecessors"]),
                "outgoing_edge_count": int(raw["outgoing_edge_count"]),
                "successor_waiting_count": int(raw["successor_waiting_count"]),
                "edge_read_errors": int(raw["edge_read_errors"]),
                "structurally_ready": structural,
                "selector_predicate": selector_predicate,
                "eligible": bool(raw.get("eligible")),
            }
        )
    prediction_candidates = [
        {
            **candidate,
            "cycle": cycle,
            "critical_deadline_cycle": candidate["critical_deadline_cycle_u16"],
            "heuristic_latency": candidate["heuristic_latency_u16"],
            "critical_path_length": candidate["critical_path_length_u16"],
        }
        for candidate in candidates
    ]
    prediction = predict_ready_selection(prediction_candidates, cycle, pressure_mode)
    collection = _mapping(raw_capture["collection"], "raw_capture.collection")
    return {
        "cycle_u16": cycle,
        "pressure_mode": pressure_mode,
        "candidates": candidates,
        "collection": dict(collection),
        "prediction": prediction,
    }


def observed_selection(
    normalized_capture: Mapping[str, Any], selected_node_address: int, raw_capture: Mapping[str, Any]
) -> dict[str, Any]:
    """Map EAX from the selector return to a stable normalized candidate identity."""

    raw_candidates = raw_capture.get("candidates")
    candidates = normalized_capture.get("candidates")
    if not isinstance(raw_candidates, list) or not isinstance(candidates, list):
        raise SchedulerCollectionError("capture candidates must be arrays")
    if selected_node_address == 0:
        return {"status": "no_selection", "winner_id": None}
    for raw, normalized in zip(raw_candidates, candidates):
        if int(raw["address"]) == selected_node_address:
            return {
                "status": "complete",
                "winner_id": str(normalized["id"]),
                "pcode_opcode_u16": normalized["pcode_opcode_u16"],
                "pcode_signature": normalized["pcode_signature"],
            }
    return {
        "status": "selected_node_not_in_entry_ready_list",
        "winner_id": None,
    }


def format_scheduler_capture_text(capture: Mapping[str, Any]) -> str:
    """Render an address-free, deterministic companion for one selector capture."""

    lines = [
        "# MWCCPS2 b210 scheduler ready-selector capture",
        f"cycle: {capture['cycle_u16']}",
        f"pressure_mode: {str(bool(capture['pressure_mode'])).lower()}",
        "",
        "candidates:",
    ]
    for candidate in capture["candidates"]:
        lines.append(
            "  {id}: opcode={opcode} ready={ready} predicate={predicate} eligible={eligible} "
            "earliest={earliest} deadline={deadline} successors_waiting={successors} "
            "critical_path={critical_path} heuristic={heuristic} resource_score={resource_score}".format(
                id=candidate["id"],
                opcode=candidate["pcode_opcode_u16"],
                ready=str(candidate["structurally_ready"]).lower(),
                predicate=candidate["selector_predicate"],
                eligible=str(candidate["eligible"]).lower(),
                earliest=candidate["earliest_issue_cycle_u16"],
                deadline=candidate["critical_deadline_cycle_u16"],
                successors=candidate["successor_waiting_count"],
                critical_path=candidate["critical_path_length_u16"],
                heuristic=candidate["heuristic_latency_u16"],
                resource_score=candidate["resource_score"],
            )
        )
    prediction = _mapping(capture["prediction"], "capture.prediction")
    observed = _mapping(capture["observed"], "capture.observed")
    lines.extend(
        [
            "",
            f"prediction: {prediction.get('winner_id')} ({prediction.get('status')})",
            f"observed: {observed.get('winner_id')} ({observed.get('status')})",
            f"prediction_matches_observed: {str(capture['prediction_matches_observed']).lower()}",
            "",
        ]
    )
    return "\n".join(lines)
