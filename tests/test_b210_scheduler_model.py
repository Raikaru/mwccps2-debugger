"""Regression coverage for b210 scheduler model: profile, capture, selection, normalization."""

from __future__ import annotations

import unittest

from gdb.b210_scheduler_model import (
    SchedulerProfileError,
    SchedulerCollectionError,
    format_address,
    validate_scheduler_profile,
    scheduler_profile_manifest,
    scheduler_layout_evidence,
    collect_ready_candidates,
    apply_selector_predicates,
    predict_ready_selection,
    normalize_scheduler_capture,
    format_scheduler_capture_text,
)


class ProfileValidationTests(unittest.TestCase):
    """validate_scheduler_profile shape rejection using real profile expectations."""

    def test_rejects_non_mapping(self) -> None:
        with self.assertRaises((SchedulerProfileError, AttributeError)):
            validate_scheduler_profile("not-a-dict")
    def test_rejects_missing_scheduler_section(self) -> None:
        with self.assertRaises(SchedulerProfileError):
            validate_scheduler_profile({"scheduler": {}})

    def test_accepts_valid(self) -> None:
        profile = _valid_profile()
        try:
            validate_scheduler_profile(profile)
        except SchedulerProfileError as exc:
            self.fail(f"validate_scheduler_profile raised: {exc}")

    def test_rejects_wrong_node_stride(self) -> None:
        profile = _valid_profile()
        profile["scheduler"]["node_stride"] = 0x20
        with self.assertRaises(SchedulerProfileError):
            validate_scheduler_profile(profile)

    def test_rejects_wrong_edge_stride(self) -> None:
        profile = _valid_profile()
        profile["scheduler"]["edge_stride"] = 0x10
        with self.assertRaises(SchedulerProfileError):
            validate_scheduler_profile(profile)

    def test_rejects_node_field_wrong_offset(self) -> None:
        profile = _valid_profile()
        profile["scheduler"]["node_fields"]["outgoing_edges"] = 0xFF
        with self.assertRaises(SchedulerProfileError):
            validate_scheduler_profile(profile)

    def test_rejects_edge_field_wrong_offset(self) -> None:
        profile = _valid_profile()
        profile["scheduler"]["edge_fields"]["target"] = 0xFF
        with self.assertRaises(SchedulerProfileError):
            validate_scheduler_profile(profile)


class SchedulerManifestTests(unittest.TestCase):
    """scheduler_profile_manifest output."""

    def test_contains_expected_keys(self) -> None:
        profile = _valid_profile()
        manifest = scheduler_profile_manifest(profile)
        self.assertIn("profile_name", manifest)
        self.assertIn("driver", manifest)

    def test_layout_evidence_contains_fields(self) -> None:
        profile = _valid_profile()
        evidence = scheduler_layout_evidence(profile)
        self.assertIn("node", evidence)
        self.assertIn("edge", evidence)


class CollectReadyCandidatesTests(unittest.TestCase):
    """collect_ready_candidates boundary conditions."""

    def test_rejects_head_outside_u32(self) -> None:
        with self.assertRaises(SchedulerCollectionError):
            collect_ready_candidates(None, {}, -1, 0, 10, 10)

    def test_rejects_cycle_outside_u16(self) -> None:
        with self.assertRaises(SchedulerCollectionError):
            collect_ready_candidates(None, {}, 0, -1, 10, 10)

    def test_rejects_cycle_above_u16(self) -> None:
        with self.assertRaises(SchedulerCollectionError):
            collect_ready_candidates(None, {}, 0, 0x10000, 10, 10)

    def test_rejects_negative_max_nodes(self) -> None:
        with self.assertRaises(SchedulerCollectionError):
            collect_ready_candidates(None, {}, 0, 0, 0, 10)

    def test_rejects_negative_max_edges(self) -> None:
        with self.assertRaises(SchedulerCollectionError):
            collect_ready_candidates(None, {}, 0, 0, 10, 0)


class ApplySelectorPredicatesTests(unittest.TestCase):
    """apply_selector_predicates input validation."""

    def test_rejects_non_mapping_candidates(self) -> None:
        raw = {
            "ready_head_address": 0x1000,
            "cycle": 5,
            "collection": {"ready_list": {"captured_count": 0}},
            "candidates": ["not-a-mapping"],
        }
        with self.assertRaises(SchedulerCollectionError):
            apply_selector_predicates(raw, {})

    def test_empty_candidates(self) -> None:
        raw = {
            "ready_head_address": 0x1000,
            "cycle": 5,
            "collection": {"ready_list": {"captured_count": 0}},
            "candidates": [],
        }
        result = apply_selector_predicates(raw, {})
        self.assertEqual(len(result["candidates"]), 0)


class PredictReadySelectionTests(unittest.TestCase):
    """predict_ready_selection: winners, ties, incomplete predicates."""

    def test_rejects_cycle_above_u16(self) -> None:
        with self.assertRaises(SchedulerCollectionError):
            predict_ready_selection([], 0x10000, False)

    def test_incomplete_predicates_reported(self) -> None:
        candidates = [
            {
                "id": "node-0",
                "structurally_ready": True,
                "eligible": False,
                "selector_predicate": None,
            }
        ]
        result = predict_ready_selection(candidates, 5, False)
        self.assertEqual(result["status"], "incomplete_selector_predicates")

    def test_no_eligible_candidate(self) -> None:
        candidates = [
            {
                "id": "node-0",
                "structurally_ready": False,
                "eligible": False,
                "selector_predicate": True,
            }
        ]
        result = predict_ready_selection(candidates, 5, False)
        self.assertEqual(result["status"], "no_eligible_candidate")

    def test_single_eligible_wins(self) -> None:
        candidates = [
            {
                "id": "node-1",
                "structurally_ready": True,
                "eligible": True,
                "selector_predicate": True,
                "critical_deadline_cycle": 10,
                "successor_waiting_count": 2,
                "critical_path_length": 5,
                "heuristic_latency": 3,
            }
        ]
        result = predict_ready_selection(candidates, 5, False)
        self.assertEqual(result["status"], "complete")
        self.assertEqual(result["winner_id"], "node-1")

    def test_first_in_list_wins_all_ties(self) -> None:
        candidates = [
            {
                "id": "node-a",
                "structurally_ready": True,
                "eligible": True,
                "selector_predicate": True,
                "critical_deadline_cycle": 10,
                "successor_waiting_count": 2,
                "critical_path_length": 5,
                "heuristic_latency": 3,
            },
            {
                "id": "node-b",
                "structurally_ready": True,
                "eligible": True,
                "selector_predicate": True,
                "critical_deadline_cycle": 10,
                "successor_waiting_count": 2,
                "critical_path_length": 5,
                "heuristic_latency": 3,
            },
        ]
        result = predict_ready_selection(candidates, 5, False)
        self.assertEqual(result["winner_id"], "node-a")


class FormatSchedulerCaptureTextTests(unittest.TestCase):
    """format_scheduler_capture_text with synthetic fixture."""

    def test_synthetic_capture(self) -> None:
        capture = {
            "cycle_u16": 5,
            "pressure_mode": False,
            "candidates": [
                {
                    "id": "candidate-0001",
                    "pcode_opcode_u16": 0x1234,
                    "structurally_ready": True,
                    "selector_predicate": True,
                    "eligible": True,
                    "earliest_issue_cycle_u16": 0,
                    "critical_deadline_cycle_u16": 10,
                    "successor_waiting_count": 1,
                    "critical_path_length_u16": 5,
                    "heuristic_latency_u16": 2,
                    "resource_score": None,
                }
            ],
            "collection": {},
            "prediction": {"winner_id": "candidate-0001", "status": "complete"},
            "observed": {"winner_id": "candidate-0001", "status": "complete"},
            "prediction_matches_observed": True,
        }
        text = format_scheduler_capture_text(capture)
        self.assertIsInstance(text, str)
        self.assertIn("candidate-0001", text)


class NormalizeSchedulerCaptureTests(unittest.TestCase):
    """normalize_scheduler_capture output shape."""

    def test_minimal_capture(self) -> None:
        raw = {
            "cycle": 5,
            "candidates": [],
            "collection": {"ready_list": {"requested_max_nodes": 10, "captured_count": 0, "termination": {"reason": "null"}}},
        }
        result = normalize_scheduler_capture(raw, False)
        self.assertIn("cycle_u16", result)
        self.assertIn("candidates", result)
        self.assertIn("prediction", result)

    def test_pressure_mode_preserved(self) -> None:
        raw = {
            "cycle": 5,
            "candidates": [],
            "collection": {"ready_list": {"requested_max_nodes": 10, "captured_count": 0, "termination": {"reason": "null"}}},
        }
        result = normalize_scheduler_capture(raw, True)
        self.assertTrue(result["pressure_mode"])


# ---------------------------------------------------------------------------
# Helpers - match the real b210 profile shape expected by validate_scheduler_profile
# ---------------------------------------------------------------------------

def _valid_profile() -> dict:
    return {
        "name": "mwcps2-3.0.1b210-060308",
        "schema_version": 1,
        "scheduler": {
            "driver": "0x004c0790",
            "ready_selector": "0x004c0a00",
            "resource_pressure_score": "0x004c14b0",
            "node_stride": 28,
            "edge_stride": 12,
            "evidence": "per-thread ready-list capture, scoreboard, selector callback",
            "globals": {
                "ready_head": "0x0061b8c4",
                "pressure_mode": "0x00635c24",
                "callback_table": "0x0061b85c",
            },
            "node_fields": {
                "next": 0,
                "previous": 4,
                "outgoing_edges": 8,
                "pcode": 12,
                "actual_latency": 16,
                "heuristic_latency": 18,
                "earliest_issue_cycle": 20,
                "critical_deadline_cycle": 22,
                "critical_path_length": 24,
                "pending_predecessors": 26,
            },
            "edge_fields": {
                "next": 0,
                "target": 4,
                "latency": 8,
            },
        },
    }


if __name__ == "__main__":
    unittest.main()
