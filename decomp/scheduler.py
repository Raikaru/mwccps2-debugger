"""Deterministic semantic model of the b210 Scheduler.c ready queue.

This is deliberately a small model, not a second scheduler implementation.  Every
field below is tied to a field or callback observed in the exact b210 executable.
It is useful for replaying a captured ready set without retaining heap addresses.

Static evidence:
* 0x004c0790 drives scheduling for each eligible PCBasicBlock.
* 0x004c07e0 allocates 0x1c-byte SchedulerNode records and issues at most two
  nodes per cycle.
* 0x004c0a00 scans the intrusive node list and selects one ready node using the
  comparator reproduced by :func:`select_ready_node`.
* 0x004c1180 creates 0x0c-byte source-to-target dependency edges.
* Callback profiles at 0x005e9090 (pre-color) and 0x005e9070 (post-color) differ
  only in their optional +0x1c dependency callback.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
import json
from typing import Any, Iterable, Mapping, Sequence


SCHEDULER_SCHEMA_NAME = "mwccps2-b210-scheduler-semantic"
SCHEDULER_SCHEMA_VERSION = 1
_PROFILE_TABLE_SLOT_COUNT = 8
_MAX_U16 = 0xFFFF


class SchedulerModelError(ValueError):
    """Raised when a replay would not satisfy the observed b210 invariants."""


def format_address(value: int) -> str:
    """Return a stable hexadecimal address representation for an artifact."""

    if not isinstance(value, int) or not 0 <= value <= 0xFFFFFFFF:
        raise SchedulerModelError("address must be an unsigned 32-bit integer")
    return f"0x{value:08x}"


def _u16(value: int, field_name: str) -> int:
    if not isinstance(value, int) or not 0 <= value <= _MAX_U16:
        raise SchedulerModelError(f"{field_name} must be an unsigned 16-bit integer")
    return value


def _nonnegative(value: int, field_name: str) -> int:
    if not isinstance(value, int) or value < 0:
        raise SchedulerModelError(f"{field_name} must be non-negative")
    return value


@dataclass(frozen=True)
class SchedulerProfile:
    """One literal scheduler callback table, normalized without raw pointers."""

    name: str
    table_address: int
    issue_width: int
    war_latency_mode: int
    latency_callback: int
    reset_resources_callback: int
    resource_ready_callback: int
    issue_callback: int
    advance_cycle_callback: int
    additional_dependency_callback: int | None

    def __post_init__(self) -> None:
        if self.name not in {"pre_color", "post_color"}:
            raise SchedulerModelError("profile name must be pre_color or post_color")
        format_address(self.table_address)
        _nonnegative(self.issue_width, "issue_width")
        if self.issue_width != 2:
            raise SchedulerModelError("the exact b210 scheduler issues exactly two nodes per cycle")
        if self.war_latency_mode != 0:
            raise SchedulerModelError("b210 scheduler profile +0x04 is zero")
        for field_name, callback in (
            ("latency_callback", self.latency_callback),
            ("reset_resources_callback", self.reset_resources_callback),
            ("resource_ready_callback", self.resource_ready_callback),
            ("issue_callback", self.issue_callback),
            ("advance_cycle_callback", self.advance_cycle_callback),
        ):
            format_address(callback)
            if callback == 0:
                raise SchedulerModelError(f"{field_name} must be a callback address")
        if self.additional_dependency_callback is not None:
            format_address(self.additional_dependency_callback)
        if self.name == "pre_color" and self.additional_dependency_callback is not None:
            raise SchedulerModelError("pre_color has no +0x1c dependency callback")
        if self.name == "post_color" and self.additional_dependency_callback != 0x004C0120:
            raise SchedulerModelError("post_color +0x1c callback must be 0x004c0120")

    @property
    def supports_post_color_dependencies(self) -> bool:
        """Whether the profile invokes the allocation-aware dependency callback."""

        return self.additional_dependency_callback is not None

    def to_artifact(self) -> dict[str, Any]:
        """Normalize the literal eight-slot callback table without host pointers."""

        slots: list[int | None] = [
            self.issue_width,
            self.war_latency_mode,
            self.latency_callback,
            self.reset_resources_callback,
            self.resource_ready_callback,
            self.issue_callback,
            self.advance_cycle_callback,
            self.additional_dependency_callback,
        ]
        if len(slots) != _PROFILE_TABLE_SLOT_COUNT:
            raise AssertionError("b210 scheduler profile table must have eight slots")
        return {
            "name": self.name,
            "table_address": format_address(self.table_address),
            "issue_width": self.issue_width,
            "callbacks": {
                "latency": format_address(self.latency_callback),
                "reset_resources": format_address(self.reset_resources_callback),
                "resource_ready": format_address(self.resource_ready_callback),
                "issue": format_address(self.issue_callback),
                "advance_cycle": format_address(self.advance_cycle_callback),
                "additional_dependency": (
                    None
                    if self.additional_dependency_callback is None
                    else format_address(self.additional_dependency_callback)
                ),
            },
            "evidence": {
                "table_offsets": {
                    "issue_width": "0x00",
                    "war_latency_mode": "0x04",
                    "latency": "0x08",
                    "reset_resources": "0x0c",
                    "resource_ready": "0x10",
                    "issue": "0x14",
                    "advance_cycle": "0x18",
                    "additional_dependency": "0x1c",
                },
                "profiles_read_at": ["0x00435fec", "0x00436345"],
                "profile_setter": "0x004c07d0",
                "table_pointer_global": "0x0061b85c",
            },
        }


# The raw table words were read from the b210 image, not reconstructed from symbols.
PRE_COLOR_PROFILE = SchedulerProfile(
    name="pre_color",
    table_address=0x005E9090,
    issue_width=2,
    war_latency_mode=0,
    latency_callback=0x004C0730,
    reset_resources_callback=0x004BFEC0,
    resource_ready_callback=0x004BF7F0,
    issue_callback=0x004BFB00,
    advance_cycle_callback=0x004C0030,
    additional_dependency_callback=None,
)
POST_COLOR_PROFILE = SchedulerProfile(
    name="post_color",
    table_address=0x005E9070,
    issue_width=2,
    war_latency_mode=0,
    latency_callback=0x004C0730,
    reset_resources_callback=0x004BFEC0,
    resource_ready_callback=0x004BF7F0,
    issue_callback=0x004BFB00,
    advance_cycle_callback=0x004C0030,
    additional_dependency_callback=0x004C0120,
)


@dataclass(frozen=True)
class SchedulerNode:
    """Heap-address-free view of one 0x1c-byte SchedulerNode.

    ``list_index`` preserves the source intrusive-list order.  It is deliberately
    not used as an explicit score: 0x004c0a00 retains the first equal candidate.
    ``resource_score`` is the result of the 0x004c14b0 temporary pressure probe.
    """

    node_id: str
    list_index: int
    pending_predecessors: int
    earliest_cycle: int
    critical_deadline: int
    critical_path_length: int
    heuristic_latency: int
    resource_ready: bool
    successor_pending_one_count: int
    resource_score: int = 0

    def __post_init__(self) -> None:
        if not isinstance(self.node_id, str) or not self.node_id:
            raise SchedulerModelError("node_id must be a non-empty string")
        _nonnegative(self.list_index, "list_index")
        _nonnegative(self.pending_predecessors, "pending_predecessors")
        _u16(self.earliest_cycle, "earliest_cycle")
        _u16(self.critical_deadline, "critical_deadline")
        _u16(self.critical_path_length, "critical_path_length")
        _u16(self.heuristic_latency, "heuristic_latency")
        _nonnegative(self.successor_pending_one_count, "successor_pending_one_count")
        if not isinstance(self.resource_ready, bool):
            raise SchedulerModelError("resource_ready must be boolean")
        if not isinstance(self.resource_score, int):
            raise SchedulerModelError("resource_score must be an integer")

    def ready_at(self, cycle: int) -> bool:
        """The three 0x004c0a00 admission predicates in source order."""

        _u16(cycle, "cycle")
        return (
            self.pending_predecessors == 0
            and self.earliest_cycle <= cycle
            and self.resource_ready
        )

    def to_artifact(self) -> dict[str, Any]:
        return {
            "critical_deadline": self.critical_deadline,
            "critical_path_length": self.critical_path_length,
            "earliest_cycle": self.earliest_cycle,
            "heuristic_latency": self.heuristic_latency,
            "list_index": self.list_index,
            "node_id": self.node_id,
            "pending_predecessors": self.pending_predecessors,
            "resource_ready": self.resource_ready,
            "resource_score": self.resource_score,
            "successor_pending_one_count": self.successor_pending_one_count,
        }


@dataclass(frozen=True)
class SchedulerEdge:
    """A source->target 0x0c-byte edge emitted by 0x004c1180."""

    source_id: str
    target_id: str
    latency: int

    def __post_init__(self) -> None:
        if not isinstance(self.source_id, str) or not self.source_id:
            raise SchedulerModelError("source_id must be a non-empty string")
        if not isinstance(self.target_id, str) or not self.target_id:
            raise SchedulerModelError("target_id must be a non-empty string")
        if self.source_id == self.target_id:
            raise SchedulerModelError("scheduler edges cannot self-reference")
        _u16(self.latency, "latency")

    def to_artifact(self) -> dict[str, Any]:
        return {
            "latency": self.latency,
            "source_id": self.source_id,
            "target_id": self.target_id,
        }


def add_dependency(edges: Sequence[SchedulerEdge], edge: SchedulerEdge) -> tuple[SchedulerEdge, ...]:
    """Mirror 0x004c1180's source-list de-duplication.

    A duplicate source/target pair leaves the already-recorded edge and its latency
    unchanged.  The executable prepends edges, but queue semantics observe only the
    target count and latency; retaining insertion order gives deterministic artifacts.
    """

    for existing in edges:
        if existing.source_id == edge.source_id and existing.target_id == edge.target_id:
            return tuple(edges)
    return (*edges, edge)


def issue_node(
    nodes: Sequence[SchedulerNode], edges: Iterable[SchedulerEdge], selected_node_id: str, cycle: int
) -> tuple[SchedulerNode, ...]:
    """Apply the 0x004c07e0 edge-release invariant to a normalized node list.

    Issuing a source decrements every target's pending count and raises the target's
    earliest issue cycle to ``max(old, cycle + edge.latency)``.  This is intentionally
    separate from resource callbacks, which are opaque outside the callback profile.
    """

    _u16(cycle, "cycle")
    node_by_id = {node.node_id: node for node in nodes}
    if len(node_by_id) != len(nodes):
        raise SchedulerModelError("node_id values must be unique")
    if selected_node_id not in node_by_id:
        raise SchedulerModelError("selected_node_id is not present in nodes")
    outgoing = [edge for edge in edges if edge.source_id == selected_node_id]
    for edge in outgoing:
        if edge.target_id not in node_by_id:
            raise SchedulerModelError("dependency target is not present in nodes")
        target = node_by_id[edge.target_id]
        if target.pending_predecessors == 0:
            raise SchedulerModelError("dependency release would underflow pending_predecessors")
        node_by_id[edge.target_id] = replace(
            target,
            pending_predecessors=target.pending_predecessors - 1,
            earliest_cycle=max(target.earliest_cycle, cycle + edge.latency),
        )
    return tuple(node_by_id[node.node_id] for node in nodes)


@dataclass(frozen=True)
class ResourceAccess:
    """One proven tag-0 register read/write used by 0x004c14b0's probe."""

    register_class: int
    register_index: int
    reads: bool
    writes: bool
    trackable: bool = True

    def __post_init__(self) -> None:
        _nonnegative(self.register_class, "register_class")
        _nonnegative(self.register_index, "register_index")
        if not isinstance(self.reads, bool) or not isinstance(self.writes, bool):
            raise SchedulerModelError("reads and writes must be boolean")
        if not isinstance(self.trackable, bool):
            raise SchedulerModelError("trackable must be boolean")


@dataclass(frozen=True)
class ResourcePressureState:
    """Normalized state temporarily perturbed by the 0x004c14b0 callback."""

    remaining_uses: Mapping[tuple[int, int], int]
    class_pressure_delta: Mapping[int, int]

    def __post_init__(self) -> None:
        for (register_class, register_index), uses in self.remaining_uses.items():
            _nonnegative(register_class, "remaining_uses register_class")
            _nonnegative(register_index, "remaining_uses register_index")
            _nonnegative(uses, "remaining_uses value")
        for register_class, delta in self.class_pressure_delta.items():
            _nonnegative(register_class, "class_pressure_delta register_class")
            if not isinstance(delta, int):
                raise SchedulerModelError("class_pressure_delta value must be an integer")


def score_resource_pressure(
    accesses: Sequence[ResourceAccess], state: ResourcePressureState
) -> int:
    """Replay the temporary use-count probe at 0x004c14b0.

    The callback starts at 16, removes a candidate's reads, rewards last uses, and
    penalizes writes that would revive a currently-dead tracked register.  It restores
    the decremented read counters before returning; this pure model therefore copies
    only its normalized counter map and does not mutate ``state``.
    """

    uses = dict(state.remaining_uses)
    score = 16
    for access in accesses:
        key = (access.register_class, access.register_index)
        if access.trackable and access.reads:
            prior = uses.get(key, 0)
            if prior == 0:
                raise SchedulerModelError("resource-pressure read would underflow remaining uses")
            uses[key] = prior - 1
    for access in accesses:
        key = (access.register_class, access.register_index)
        scarcity = max(state.class_pressure_delta.get(access.register_class, 0), 1)
        if access.trackable and access.reads and uses.get(key, 0) == 0:
            score -= 1 + scarcity
        if access.trackable and access.writes and not access.reads and uses.get(key, 0) != 0:
            score += scarcity
    return score


def _candidate_precedes(
    candidate: SchedulerNode, selected: SchedulerNode, cycle: int, profile: SchedulerProfile
) -> bool:
    """The non-pressure comparison ladder at 0x004c0b1a..0x004c0bc8."""

    candidate_crosses_deadline = candidate.critical_deadline <= cycle
    selected_crosses_deadline = selected.critical_deadline <= cycle
    if candidate_crosses_deadline != selected_crosses_deadline:
        return candidate_crosses_deadline
    if candidate.successor_pending_one_count != selected.successor_pending_one_count:
        return candidate.successor_pending_one_count > selected.successor_pending_one_count
    if candidate.critical_path_length != selected.critical_path_length:
        return candidate.critical_path_length > selected.critical_path_length
    if profile.supports_post_color_dependencies:
        return candidate.heuristic_latency < selected.heuristic_latency
    return False


def select_ready_node(
    nodes: Sequence[SchedulerNode], cycle: int, profile: SchedulerProfile, *, pressure_mode: bool = False
) -> SchedulerNode | None:
    """Choose exactly the node that 0x004c0a00 would select from ``nodes``.

    ``nodes`` must be supplied in intrusive-list order.  The first eligible entry is
    the incumbent.  In post-color pressure mode, 0x004c0a7e selects strictly lower
    ``resource_score`` and does *not* run the remaining tie ladder.  Outside that
    mode, the ladder is deadline crossing, count of targets with pending==1, greater
    critical path, then (post-color only) smaller heuristic latency.  Exact equality
    keeps the earlier list entry.
    """

    _u16(cycle, "cycle")
    if pressure_mode and not profile.supports_post_color_dependencies:
        raise SchedulerModelError("pressure_mode requires the post_color callback profile")
    ordered = sorted(nodes, key=lambda node: node.list_index)
    if len({node.list_index for node in ordered}) != len(ordered):
        raise SchedulerModelError("list_index values must be unique")
    selected: SchedulerNode | None = None
    for candidate in ordered:
        if not candidate.ready_at(cycle):
            continue
        if selected is None:
            selected = candidate
        elif pressure_mode:
            if candidate.resource_score < selected.resource_score:
                selected = candidate
        elif _candidate_precedes(candidate, selected, cycle, profile):
            selected = candidate
    return selected


# A compact, independently replayable ready set taken from the decision fields at
# 0x004c0a00.  It demonstrates the deadline-crossing branch (0x004c0b1a..0x004c0b38):
# the later "deadline_now" node displaces "later_deadline" at cycle 7.
OBSERVED_READY_SET: tuple[SchedulerNode, ...] = (
    SchedulerNode(
        node_id="later_deadline",
        list_index=0,
        pending_predecessors=0,
        earliest_cycle=7,
        critical_deadline=9,
        critical_path_length=5,
        heuristic_latency=4,
        resource_ready=True,
        successor_pending_one_count=0,
        resource_score=11,
    ),
    SchedulerNode(
        node_id="deadline_now",
        list_index=1,
        pending_predecessors=0,
        earliest_cycle=7,
        critical_deadline=7,
        critical_path_length=1,
        heuristic_latency=3,
        resource_ready=True,
        successor_pending_one_count=0,
        resource_score=9,
    ),
    SchedulerNode(
        node_id="blocked_successor",
        list_index=2,
        pending_predecessors=1,
        earliest_cycle=0,
        critical_deadline=0,
        critical_path_length=99,
        heuristic_latency=0,
        resource_ready=True,
        successor_pending_one_count=9,
        resource_score=0,
    ),
)
OBSERVED_READY_SET_EVIDENCE: dict[str, Any] = {
    "observation_kind": "static_selector_replay",
    "selector": "0x004c0a00",
    "cycle": "0x0007",
    "selected_node_id": "deadline_now",
    "decision_branch": "0x004c0b1a..0x004c0b38",
    "invariants": [
        "0x004c0a16: pending_predecessors == 0",
        "0x004c0a1d: earliest_cycle <= cycle",
        "0x004c0a23: profile resource_ready callback returns nonzero",
    ],
}


def replay_observed_ready_set() -> dict[str, Any]:
    """Return the versioned artifact for the documented 0x004c0a00 replay."""

    selected = select_ready_node(OBSERVED_READY_SET, 7, PRE_COLOR_PROFILE)
    if selected is None:
        raise AssertionError("documented ready set must select a node")
    if selected.node_id != OBSERVED_READY_SET_EVIDENCE["selected_node_id"]:
        raise AssertionError("documented ready set no longer matches selector evidence")
    return {
        "evidence": OBSERVED_READY_SET_EVIDENCE,
        "nodes": [node.to_artifact() for node in OBSERVED_READY_SET],
        "profile": PRE_COLOR_PROFILE.to_artifact(),
        "schema_name": SCHEDULER_SCHEMA_NAME,
        "schema_version": SCHEDULER_SCHEMA_VERSION,
        "selected_node_id": selected.node_id,
    }


def assert_model_invariants() -> None:
    """Exercise the selector replay and the pre/post-color callback distinction."""

    artifact = replay_observed_ready_set()
    if artifact["selected_node_id"] != "deadline_now":
        raise AssertionError("ready-set replay did not select the observed candidate")
    if PRE_COLOR_PROFILE.additional_dependency_callback is not None:
        raise AssertionError("pre-color profile unexpectedly gained a dependency callback")
    if POST_COLOR_PROFILE.additional_dependency_callback != 0x004C0120:
        raise AssertionError("post-color profile lost its allocation-aware callback")

    pressure_nodes = (
        replace(OBSERVED_READY_SET[0], critical_deadline=9, resource_score=8),
        replace(OBSERVED_READY_SET[1], critical_deadline=9, resource_score=3),
    )
    selected = select_ready_node(pressure_nodes, 7, POST_COLOR_PROFILE, pressure_mode=True)
    if selected is None or selected.node_id != "deadline_now":
        raise AssertionError("post-color pressure callback did not select the lower resource score")
    try:
        select_ready_node(pressure_nodes, 7, PRE_COLOR_PROFILE, pressure_mode=True)
    except SchedulerModelError:
        return
    raise AssertionError("pre-color profile accepted an unavailable post-color callback")


def render_observed_ready_set() -> str:
    """Emit the normalized fixture with deterministic key ordering."""

    return json.dumps(replay_observed_ready_set(), sort_keys=True, separators=(",", ":"))


if __name__ == "__main__":
    assert_model_invariants()
    print(render_observed_ready_set())
