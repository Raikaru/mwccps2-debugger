"""Regression coverage for b210 register-allocation model: profile, rendering."""

from __future__ import annotations

import unittest

from gdb.b210_regalloc_model import (
    RegisterAllocationProfileError,
    validate_register_allocation_profile,
    format_register_allocation_text,
)


class ProfileValidationTests(unittest.TestCase):
    """validate_register_allocation_profile shape and boundary rejection."""

    def test_accepted_when_exact(self) -> None:
        profile = _valid_profile()
        try:
            validate_register_allocation_profile(profile)
        except RegisterAllocationProfileError as exc:
            self.fail(f"validate_register_allocation_profile raised: {exc}")

    def test_rejects_wrong_breakpoint(self) -> None:
        profile = _valid_profile()
        profile["register_allocation"]["capture_breakpoint"] = "0x00400000"
        with self.assertRaises(RegisterAllocationProfileError):
            validate_register_allocation_profile(profile)

    def test_rejects_wrong_max_nodes(self) -> None:
        profile = _valid_profile()
        profile["register_allocation"]["max_nodes"] = 999
        with self.assertRaises(RegisterAllocationProfileError):
            validate_register_allocation_profile(profile)

    def test_rejects_wrong_node_stride(self) -> None:
        profile = _valid_profile()
        profile["register_allocation"]["node_stride"] = 0x10
        with self.assertRaises(RegisterAllocationProfileError):
            validate_register_allocation_profile(profile)

    def test_rejects_wrong_edge_stride(self) -> None:
        profile = _valid_profile()
        profile["register_allocation"]["edge_stride"] = 0x08
        with self.assertRaises(RegisterAllocationProfileError):
            validate_register_allocation_profile(profile)

    def test_rejects_wrong_physical_slots(self) -> None:
        profile = _valid_profile()
        profile["register_allocation"]["physical_slots"] = [32, 32, 32, 16, 32, 32, 31]
        with self.assertRaises(RegisterAllocationProfileError):
            validate_register_allocation_profile(profile)

    def test_rejects_wrong_globals_key(self) -> None:
        profile = _valid_profile()
        profile["register_allocation"]["globals"]["extra_key"] = "0x00000000"
        with self.assertRaises(RegisterAllocationProfileError):
            validate_register_allocation_profile(profile)


class FormatRegisterAllocationTextTests(unittest.TestCase):
    """format_register_allocation_text with synthetic fixture."""

    def test_synthetic_allocation_text(self) -> None:
        allocation: dict = {
            "class": {"id": 0, "label": "gpr", "physical_slots": 32, "total_nodes": 34, "virtual_nodes": 2},
            "phase": "post-color",
            "colorgraph_result": {"state": "complete", "source": "colorgraph", "value_i32": 0},
            "nodes": [
                {"id": "class-0-virtual-00000", "kind": "virtual", "assigned_color_i16": 3,
                 "canonical_id": "class-0-virtual-00000", "canonical_color_i16": 3,
                 "flags_raw_u16": "0x0000",
                 "flags": {"spill_required": False, "coalesced_alias": False, "coalesced_root": False}},
            ],
            "pcode_virtual_registers": {"state": "empty", "entries": []},
            "capture_status": "complete",
            "collection": {"errors": [], "limits": {"max_nodes": 100, "max_edges": 200, "profile_max_nodes": 32767}},
            "omitted_fields": [],
        }
        text = format_register_allocation_text(allocation)
        self.assertIsInstance(text, str)
        self.assertIn("gpr", text)


# ---------------------------------------------------------------------------
# Helpers - match the exact expected register_allocation profile
# ---------------------------------------------------------------------------

_GLOBALS = {
    "coloring_class": "0x006373ac",
    "interferencegraph": "0x00636634",
    "physical_slots": "0x00635b34",
    "total_nodes": "0x00636f98",
    "allocatable_phys": "0x00624e80",
    "allocatable_count": "0x006355d0",
    "physical_state": "0x006257f8",
    "fallback_phys": "0x00625338",
    "fallback_count": "0x00635a60",
    "fallback_cursor": "0x00636930",
    "saved_fallback_cursor": "0x0061b8c8",
    "coalesce_parent": "0x0060b708",
}

_CLASS_LABELS = (
    "GPR", "FPR", "SPECIAL", "COPROC2_i", "COPROC2_ii", "COPROC2_f", "COPROC2_special",
)


def _valid_profile() -> dict:
    return {
        "register_allocation": {
            "capture_breakpoint": "0x004c1d74",
            "max_nodes": 0x7FFF,
            "node_stride": 0x20,
            "edge_stride": 0x10,
            "physical_slots": [32, 32, 32, 16, 32, 32, 32],
            "class_labels": list(_CLASS_LABELS),
            "globals": dict(_GLOBALS),
        },
        "pcode_breakpoints": {
            "after_colorgraph_assignment": "0x004c1d74",
        },
    }


if __name__ == "__main__":
    unittest.main()
