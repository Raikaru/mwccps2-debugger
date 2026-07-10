"""Regression coverage for decomp scheduler: SchedulerProfile, SchedulerNode, replay, selection."""

from __future__ import annotations

import unittest

from decomp.scheduler import (
    SchedulerModelError,
    SchedulerProfile,
    SchedulerNode,
    SchedulerEdge,
    ResourceAccess,
    ResourcePressureState,
    add_dependency,
    issue_node,
    score_resource_pressure,
    select_ready_node,
    replay_observed_ready_set,
    assert_model_invariants,
    PRE_COLOR_PROFILE,
    POST_COLOR_PROFILE,
)


class SchedulerProfileTests(unittest.TestCase):
    """SchedulerProfile creation and validation."""

    def test_pre_color_builtin(self) -> None:
        profile = PRE_COLOR_PROFILE
        self.assertIsInstance(profile, SchedulerProfile)
        self.assertEqual(profile.name, "pre_color")

    def test_post_color_builtin(self) -> None:
        profile = POST_COLOR_PROFILE
        self.assertIsInstance(profile, SchedulerProfile)
        self.assertEqual(profile.name, "post_color")

    def test_pre_and_post_differ(self) -> None:
        self.assertNotEqual(PRE_COLOR_PROFILE, POST_COLOR_PROFILE)

    def test_post_color_has_dependency_callback(self) -> None:
        self.assertIsNotNone(POST_COLOR_PROFILE.additional_dependency_callback)

    def test_pre_color_has_no_dependency_callback(self) -> None:
        self.assertIsNone(PRE_COLOR_PROFILE.additional_dependency_callback)

    def test_rejects_wrong_name(self) -> None:
        with self.assertRaises(SchedulerModelError, msg="profile name must be"):
            SchedulerProfile(
                name="unknown",
                table_address=0x00435FEC,
                issue_width=2,
                war_latency_mode=0,
                latency_callback=0x004C07E0,
                reset_resources_callback=0x004C0A00,
                resource_ready_callback=0x004C14B0,
                issue_callback=0x004C1900,
                advance_cycle_callback=0x004C1A00,
                additional_dependency_callback=None,
            )

    def test_rejects_zero_callback_address(self) -> None:
        with self.assertRaises(SchedulerModelError, msg="must be a callback address"):
            SchedulerProfile(
                name="pre_color",
                table_address=0x00435FEC,
                issue_width=2,
                war_latency_mode=0,
                latency_callback=0x0,
                reset_resources_callback=0x004C0A00,
                resource_ready_callback=0x004C14B0,
                issue_callback=0x004C1900,
                advance_cycle_callback=0x004C1A00,
                additional_dependency_callback=None,
            )

    def test_rejects_wrong_issue_width(self) -> None:
        with self.assertRaises(SchedulerModelError, msg="exactly two"):
            SchedulerProfile(
                name="pre_color",
                table_address=0x00435FEC,
                issue_width=1,
                war_latency_mode=0,
                latency_callback=0x004C07E0,
                reset_resources_callback=0x004C0A00,
                resource_ready_callback=0x004C14B0,
                issue_callback=0x004C1900,
                advance_cycle_callback=0x004C1A00,
                additional_dependency_callback=None,
            )

    def test_post_color_requires_0x004c0120_callback(self) -> None:
        with self.assertRaises(SchedulerModelError):
            SchedulerProfile(
                name="post_color",
                table_address=0x00436340,
                issue_width=2,
                war_latency_mode=0,
                latency_callback=0x004C07E0,
                reset_resources_callback=0x004C0A00,
                resource_ready_callback=0x004C14B0,
                issue_callback=0x004C1900,
                advance_cycle_callback=0x004C1A00,
                additional_dependency_callback=0x00400000,
            )

    def test_to_artifact_has_callbacks(self) -> None:
        artifact = PRE_COLOR_PROFILE.to_artifact()
        self.assertIn("callbacks", artifact)
        self.assertEqual(artifact["name"], "pre_color")


class SchedulerNodeTests(unittest.TestCase):
    """SchedulerNode creation and properties."""

    def _make_node(self, **overrides: object) -> SchedulerNode:
        fields = {
            "node_id": "n0",
            "list_index": 0,
            "pending_predecessors": 0,
            "earliest_cycle": 0,
            "critical_deadline": 10,
            "critical_path_length": 5,
            "heuristic_latency": 1,
            "resource_ready": True,
            "successor_pending_one_count": 2,
            "resource_score": 0,
        }
        fields.update(overrides)
        return SchedulerNode(**fields)

    def test_minimal_node(self) -> None:
        node = self._make_node()
        self.assertEqual(node.node_id, "n0")
        self.assertEqual(node.critical_deadline, 10)
        self.assertEqual(node.critical_path_length, 5)

    def test_rejects_empty_node_id(self) -> None:
        with self.assertRaises(SchedulerModelError, msg="non-empty"):
            self._make_node(node_id="")

    def test_rejects_negative_index(self) -> None:
        with self.assertRaises(SchedulerModelError, msg="non-negative"):
            self._make_node(list_index=-1)

    def test_rejects_large_u16_fields(self) -> None:
        with self.assertRaises(SchedulerModelError, msg="unsigned 16-bit"):
            self._make_node(earliest_cycle=0x10000)

    def test_ready_true_at_cycle(self) -> None:
        node = self._make_node(pending_predecessors=0, earliest_cycle=5, resource_ready=True)
        self.assertTrue(node.ready_at(7))

    def test_ready_false_when_pending_nonzero(self) -> None:
        node = self._make_node(pending_predecessors=2, earliest_cycle=0, resource_ready=True)
        self.assertFalse(node.ready_at(5))

    def test_ready_false_when_cycle_too_early(self) -> None:
        node = self._make_node(pending_predecessors=0, earliest_cycle=10, resource_ready=True)
        self.assertFalse(node.ready_at(5))

    def test_ready_false_when_not_resource_ready(self) -> None:
        node = self._make_node(pending_predecessors=0, earliest_cycle=0, resource_ready=False)
        self.assertFalse(node.ready_at(5))

    def test_to_artifact_roundtrip(self) -> None:
        node = self._make_node()
        art = node.to_artifact()
        self.assertEqual(art["node_id"], "n0")
        self.assertIn("critical_deadline", art)


class SchedulerEdgeTests(unittest.TestCase):
    """SchedulerEdge creation."""

    def test_create(self) -> None:
        edge = SchedulerEdge(source_id="a", target_id="b", latency=2)
        self.assertEqual(edge.source_id, "a")
        self.assertEqual(edge.target_id, "b")
        self.assertEqual(edge.latency, 2)

    def test_rejects_empty_source(self) -> None:
        with self.assertRaises(SchedulerModelError, msg="non-empty"):
            SchedulerEdge(source_id="", target_id="b", latency=0)

    def test_rejects_self_reference(self) -> None:
        with self.assertRaises(SchedulerModelError, msg="cannot self-reference"):
            SchedulerEdge(source_id="a", target_id="a", latency=0)

    def test_to_artifact_roundtrip(self) -> None:
        edge = SchedulerEdge(source_id="a", target_id="b", latency=2)
        art = edge.to_artifact()
        self.assertEqual(art["source_id"], "a")


class AddDependencyTests(unittest.TestCase):
    """add_dependency de-duplication."""

    def test_adds_new_edge(self) -> None:
        edges = ()
        edge = SchedulerEdge(source_id="a", target_id="b", latency=2)
        result = add_dependency(edges, edge)
        self.assertEqual(len(result), 1)

    def test_deduplicates_exact_edge(self) -> None:
        edge = SchedulerEdge(source_id="a", target_id="b", latency=2)
        edges = (edge,)
        result = add_dependency(edges, edge)
        self.assertEqual(len(result), 1)
    def test_allows_same_source_target_diff_latency(self) -> None:
        e1 = SchedulerEdge(source_id="a", target_id="b", latency=2)
        e2 = SchedulerEdge(source_id="a", target_id="b", latency=4)
        result = add_dependency((e1,), e2)
        self.assertEqual(len(result), 1)


class IssueNodeTests(unittest.TestCase):
    """issue_node edge-release invariant."""

    def _node(self, node_id: str, pending: int = 0, earliest: int = 0, lat: int = 0) -> SchedulerNode:
        return SchedulerNode(
            node_id=node_id, list_index=0,
            pending_predecessors=pending, earliest_cycle=earliest,
            critical_deadline=0, critical_path_length=0,
            heuristic_latency=lat, resource_ready=True,
            successor_pending_one_count=0, resource_score=0,
        )

    def test_releases_edges(self) -> None:
        nodes = [self._node("a"), self._node("b", pending=1)]
        edges = [SchedulerEdge(source_id="a", target_id="b", latency=1)]
        updated = issue_node(nodes, edges, "a", 5)
        updated_by_id = {n.node_id: n for n in updated}
        self.assertEqual(updated_by_id["b"].pending_predecessors, 0)

    def test_latency_not_yet_passed(self) -> None:
        nodes = [self._node("a", lat=5), self._node("b", pending=1)]
        edges = [SchedulerEdge(source_id="a", target_id="b", latency=5)]
        updated = issue_node(nodes, edges, "a", 3)
        updated_by_id = {n.node_id: n for n in updated}
        self.assertEqual(updated_by_id["b"].pending_predecessors, 0)
        self.assertEqual(updated_by_id["b"].earliest_cycle, 8)

class ScoreResourcePressureTests(unittest.TestCase):
    """score_resource_pressure replay."""

    def _access(self, rc: int, ri: int = 0, reads: bool = True, writes: bool = False, track: bool = True) -> ResourceAccess:
        return ResourceAccess(register_class=rc, register_index=ri, reads=reads, writes=writes, trackable=track)

    def test_single_access_tally(self) -> None:
        state = ResourcePressureState(
            remaining_uses={(0, 0): 2},
            class_pressure_delta={0: 1, 1: 0},
        )
        accesses = [self._access(0), self._access(0)]
        score = score_resource_pressure(accesses, state)
        self.assertEqual(score, 12)

    def test_untracked_ignored(self) -> None:
        state = ResourcePressureState(remaining_uses={}, class_pressure_delta={0: 1})
        accesses = [self._access(0, track=False)]
        score = score_resource_pressure(accesses, state)
        self.assertEqual(score, 16)

    def test_unknown_class(self) -> None:
        state = ResourcePressureState(remaining_uses={}, class_pressure_delta={0: 1})
        accesses = [self._access(999, track=False)]
        score = score_resource_pressure(accesses, state)
        self.assertEqual(score, 16)


class SelectReadyNodeTests(unittest.TestCase):
    """select_ready_node winner resolution."""

    def _node(self, node_id: str, pending: int = 0, earliest: int = 0,
              deadline: int = 10, path_len: int = 5, lat: int = 1,
              successors: int = 0, ready: bool = True,
              list_index: int = 0) -> SchedulerNode:
        return SchedulerNode(
            node_id=node_id, list_index=list_index,
            pending_predecessors=pending, earliest_cycle=earliest,
            critical_deadline=deadline, critical_path_length=path_len,
            heuristic_latency=lat, resource_ready=ready,
            successor_pending_one_count=successors, resource_score=0,
        )

    def test_selects_ready_over_non_ready(self) -> None:
        nodes = [
            self._node("a", pending=1, list_index=0),
            self._node("b", list_index=1),
        ]
        selected = select_ready_node(nodes, 5, PRE_COLOR_PROFILE)
        self.assertIsNotNone(selected)
        self.assertEqual(selected.node_id, "b")

    def test_no_ready_returns_none(self) -> None:
        nodes = [self._node("a", pending=2)]
        selected = select_ready_node(nodes, 5, PRE_COLOR_PROFILE)
        self.assertIsNone(selected)


class ReplayObservedReadySetTests(unittest.TestCase):
    """replay_observed_ready_set produces consistent output."""

    def test_replay_returns_artifact(self) -> None:
        result = replay_observed_ready_set()
        self.assertIn("evidence", result)
        self.assertIn("nodes", result)

    def test_replay_deterministic(self) -> None:
        self.assertEqual(replay_observed_ready_set(), replay_observed_ready_set())

    def test_replay_has_selection_evidence(self) -> None:
        result = replay_observed_ready_set()
        evidence = result.get("evidence", {})
        self.assertIn("selected_node_id", evidence)


class AssertModelInvariantsTests(unittest.TestCase):
    """assert_model_invariants exercises selector and pressure replay."""

    def test_invariants_pass(self) -> None:
        try:
            assert_model_invariants()
        except AssertionError as exc:
            self.fail(f"assert_model_invariants raised: {exc}")


if __name__ == "__main__":
    unittest.main()
