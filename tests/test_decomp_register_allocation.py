"""Regression coverage for decomp register-allocation colorgraph replay."""

from __future__ import annotations

import unittest

from decomp.register_allocation import (
    ReplayError,
    Node,
    Capture,
    _parse_capture,
    _work_list,
    _lowest_color,
    FLAG_SPILL,
    FLAG_SIMPLIFIED,
    FLAG_COALESCED_ALIAS,
    FLAG_PAIRED_COLOR,
)


class NodeFlagTests(unittest.TestCase):
    """Node flags checked via bitwise operations on .flags."""

    def _node(self, **overrides: object) -> Node:
        fields = {
            "index": 32,
            "node_id": "class-0-virtual-00000",
            "flags": 0,
            "assigned_color": 0,
            "work_next": None,
            "neighbors": (),
        }
        fields.update(overrides)
        return Node(**fields)

    def test_spilled_flag_bit(self) -> None:
        node = self._node(flags=FLAG_SPILL)
        self.assertTrue(bool(node.flags & FLAG_SPILL))

    def test_not_spilled(self) -> None:
        node = self._node(flags=0)
        self.assertFalse(bool(node.flags & FLAG_SPILL))

    def test_simplified_flag_bit(self) -> None:
        node = self._node(flags=FLAG_SIMPLIFIED)
        self.assertTrue(bool(node.flags & FLAG_SIMPLIFIED))

    def test_coalesced_alias_flag_bit(self) -> None:
        node = self._node(flags=FLAG_COALESCED_ALIAS)
        self.assertTrue(bool(node.flags & FLAG_COALESCED_ALIAS))

    def test_is_paired_property(self) -> None:
        node = self._node(flags=FLAG_PAIRED_COLOR)
        self.assertTrue(node.is_paired)

    def test_not_paired(self) -> None:
        node = self._node(flags=0)
        self.assertFalse(node.is_paired)


class LowestColorTests(unittest.TestCase):
    """_lowest_color: mask with set bits = available colors."""

    def test_none_when_mask_zero(self) -> None:
        self.assertIsNone(_lowest_color(0x00, 8, False))

    def test_lowest_set_bit_returned(self) -> None:
        self.assertEqual(_lowest_color(0x02, 8, False), 1)

    def test_bit_zero_is_lowest(self) -> None:
        self.assertEqual(_lowest_color(0x01, 8, False), 0)

    def test_paired_requires_both_bits(self) -> None:
        self.assertEqual(_lowest_color(0x03, 8, True), 0)


class WorkListTests(unittest.TestCase):
    """_work_list operates on FLAG_SIMPLIFIED nodes only."""

    def test_empty_nodes_returns_empty(self) -> None:
        cap = Capture(class_id=0, physical_slots=32, total_nodes=0,
                      graph_root=0, ordinary_mask=0,
                      fallback_colors=(), fallback_cursor=0,
                      expected_state="success", expected_assignments={},
                      expected_spills=frozenset(), nodes=())
        self.assertEqual(_work_list(cap), [])


class ParseCaptureRejectionTests(unittest.TestCase):
    """_parse_capture basic rejection (not full document validation)."""

    def test_rejects_non_mapping(self) -> None:
        with self.assertRaises((ReplayError, AttributeError, TypeError)):
            _parse_capture("not-a-dict")


if __name__ == "__main__":
    unittest.main()
