"""Regression coverage for b210 snapshot model: schema, identity, normalization, PCode decoding."""

from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest

from gdb.b210_snapshot_model import (
    SnapshotModelError,
    parse_address,
    format_address,
    load_b210_profile,
    normalize_runtime_graph,
    format_pcode_text,
    capture_status,
    profile_manifest,
    EXPECTED_PROFILE_NAME,
)


class AddressParsingTests(unittest.TestCase):
    """parse_address / format_address normalization."""

    def test_parse_address_from_int(self) -> None:
        self.assertEqual(parse_address(0x00626638, "test"), 0x00626638)

    def test_parse_address_from_string(self) -> None:
        self.assertEqual(parse_address("0x00626638", "test"), 0x00626638)

    def test_parse_address_lowercase_hex(self) -> None:
        self.assertEqual(parse_address("0xdeadbeef", "test"), 0xDEADBEEF)

    def test_parse_address_rejects_negative_int(self) -> None:
        with self.assertRaises(SnapshotModelError):
            parse_address(-1, "test")

    def test_parse_address_rejects_overflow(self) -> None:
        with self.assertRaises(SnapshotModelError):
            parse_address("0x100000000", "test")

    def test_format_address_zero(self) -> None:
        self.assertEqual(format_address(0), "0x00000000")

    def test_format_address_max(self) -> None:
        self.assertEqual(format_address(0xFFFFFFFF), "0xffffffff")

    def test_format_address_masks_to_32bit(self) -> None:
        self.assertEqual(format_address(0x1FFFFFFFF), "0xffffffff")


class ProfileValidationTests(unittest.TestCase):
    """load_b210_profile shape validation."""

    def test_accepts_valid_profile(self) -> None:
        profile = _valid_profile()
        try:
            load_b210_profile(_write_json(profile))
        except SnapshotModelError as exc:
            self.fail(f"load_b210_profile raised: {exc}")

    def test_rejects_wrong_schema_version(self) -> None:
        profile = _valid_profile()
        profile["schema_version"] = 2
        with self.assertRaises(SnapshotModelError):
            load_b210_profile(_write_json(profile))

    def test_rejects_wrong_name(self) -> None:
        profile = _valid_profile()
        profile["name"] = "wrong"
        with self.assertRaises(SnapshotModelError):
            load_b210_profile(_write_json(profile))

    def test_rejects_nonexistent_file(self) -> None:
        with self.assertRaises(SnapshotModelError):
            load_b210_profile("/nonexistent/path.json")

    def test_rejects_missing_binary(self) -> None:
        profile = _valid_profile()
        del profile["binary"]
        with self.assertRaises(SnapshotModelError):
            load_b210_profile(_write_json(profile))

    def test_rejects_binary_wrong_filename(self) -> None:
        profile = _valid_profile()
        profile["binary"]["filename"] = "not-mwccps2.exe"
        with self.assertRaises(SnapshotModelError):
            load_b210_profile(_write_json(profile))

    def test_rejects_binary_wrong_sha256_length(self) -> None:
        profile = _valid_profile()
        profile["binary"]["sha256"] = "abc"
        with self.assertRaises(SnapshotModelError):
            load_b210_profile(_write_json(profile))

    def test_rejects_missing_functions(self) -> None:
        profile = _valid_profile()
        del profile["functions"]
        with self.assertRaises(SnapshotModelError):
            load_b210_profile(_write_json(profile))

    def test_rejects_missing_opcode_table(self) -> None:
        profile = _valid_profile()
        del profile["pcode_opcode_table"]
        with self.assertRaises(SnapshotModelError):
            load_b210_profile(_write_json(profile))

    def test_rejects_missing_pcode_breakpoints(self) -> None:
        profile = _valid_profile()
        del profile["pcode_breakpoints"]
        with self.assertRaises(SnapshotModelError):
            load_b210_profile(_write_json(profile))

    def test_rejects_missing_register_allocation(self) -> None:
        profile = _valid_profile()
        del profile["register_allocation"]
        with self.assertRaises(SnapshotModelError):
            load_b210_profile(_write_json(profile))


class CaptureStatusTests(unittest.TestCase):
    """capture_status classification."""

    def _graph(self, termination: dict, errors: list | None = None) -> dict:
        return {
            "collection": {
                "block_walk": {"reason": termination["reason"]},
                "pcode_walks": [],
                "errors": errors or [],
            },
        }

    def test_complete(self) -> None:
        self.assertEqual(capture_status(self._graph({"reason": "null"})), "complete")

    def test_unreadable_memory(self) -> None:
        self.assertEqual(
            capture_status(self._graph({"reason": "unreadable_memory"})),
            "partial_memory_unreadable",
        )

    def test_cycle(self) -> None:
        self.assertEqual(
            capture_status(self._graph({"reason": "cycle"})),
            "partial_cycle_guarded",
        )

    def test_count_limit(self) -> None:
        self.assertEqual(
            capture_status(self._graph({"reason": "count_limit"})),
            "partial_count_guarded",
        )


class NormalizeRuntimeGraphTests(unittest.TestCase):
    """normalize_runtime_graph with valid raw input."""

    def test_empty_graph_normalizes(self) -> None:
        raw = {
            "blocks": [],
            "pcode_nodes": [],
            "operands": [],
            "termination": {"reason": "null"},
            "nodes": [],
            "node_walks": [],
            "block_walk": {"termination": {"reason": "null"}},
            "errors": [],
        }
        result = normalize_runtime_graph(raw)
        self.assertIn("pcodes", result)
        self.assertIn("collection", result)

    def test_deterministic_output(self) -> None:
        raw = {
            "blocks": [],
            "pcode_nodes": [],
            "operands": [],
            "termination": {"reason": "null"},
            "nodes": [],
            "node_walks": [],
            "block_walk": {"termination": {"reason": "null"}},
            "errors": [],
        }
        self.assertEqual(normalize_runtime_graph(raw), normalize_runtime_graph(raw))


class PCodeFormattingTests(unittest.TestCase):
    """format_pcode_text determinism."""

    def test_empty_graph_produces_string(self) -> None:
        graph = {
            "blocks": [],
            "pcodes": [],
            "errors": [],
            "termination": {"reason": "null"},
            "pcode_opcodes": [],
        }
        text = format_pcode_text(graph)
        self.assertIsInstance(text, str)

    def test_deterministic_output(self) -> None:
        graph = {
            "blocks": [],
            "pcodes": [],
            "errors": [],
            "termination": {"reason": "null"},
            "pcode_opcodes": [],
        }
        self.assertEqual(format_pcode_text(graph), format_pcode_text(graph))


class ProfileManifestTests(unittest.TestCase):
    """profile_manifest field selection."""

    def test_valid_profile_manifest_fields(self) -> None:
        profile = _valid_profile()
        manifest = profile_manifest(profile)
        self.assertIn("name", manifest)
        self.assertIn("schema_version", manifest)
        self.assertIn("binary", manifest)

    def test_fingerprint_contains_binary_fields(self) -> None:
        profile = _valid_profile()
        manifest = profile_manifest(profile)
        fp = manifest["binary"]
        self.assertIn("sha256", fp)
        self.assertIn("size", fp)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _opcode_fields_dict() -> dict:
    return {
        "mnemonic": {"offset": 0, "kind": "pointer"},
        "alternate_mnemonic": {"offset": 4, "kind": "pointer"},
        "operand_format": {"offset": 8, "kind": "pointer"},
        "operand_slot_count": {"offset": 12, "kind": "u8"},
        "opaque_format_class": {"offset": 13, "kind": "u8"},
        "opaque_0e": {"offset": 14, "kind": "u16"},
        "encoding_template": {"offset": 16, "kind": "u32"},
        "opaque_14": {"offset": 20, "kind": "u32"},
        "property_flags": {"offset": 24, "kind": "u32"},
        "format_derived_flags": {"offset": 28, "kind": "u32"},
        "aux_internal_name": {"offset": 32, "kind": "pointer"},
        "aux_ordinal": {"offset": 36, "kind": "u32"},
        "aux_value": {"offset": 40, "kind": "u32"},
        "aux_class": {"offset": 44, "kind": "u16"},
        "opaque_2e": {"offset": 46, "kind": "u16"},
    }


def _valid_profile() -> dict:
    return {
        "schema_version": 1,
        "name": EXPECTED_PROFILE_NAME,
        "binary": {
            "filename": "mwccps2.exe",
            "sha256": "286548490e2e902cfef21dcf39cd5af23766731585d90dea747f8781eadcafd7",
            "size": 2180096,
            "image_base": "0x00400000",
            "pe_timestamp": "0x440f429b",
        },
        "functions": {
            "CodeGen_Generator": {"address": "0x0042f9f0"},
            "colorgraph": {"address": "0x004c1d74"},
            "register_allocation_driver": {"address": "0x0042fb30"},
            "schedule_current_function": {"address": "0x00436001"},
        },
        "globals": {
            "pcbasicblocks": {"address": "0x006373ac"},
            "interferencegraph": {"address": "0x00636634"},
            "coloring_class": {"address": "0x006373ac"},
        },
        "pcode_opcode_table": {
            "address": "0x00626638",
            "entry_count": 0x4AF,
            "entry_stride": 0x30,
            "string_max_bytes": 128,
            "fields": _opcode_fields_dict(),
            "post_initialization_sentinel": {
                "opcode": 1,
                "mnemonic": "add",
                "operand_format": "=d,s,t",
                "encoding_template": "0x00000020",
                "property_flags": "0x00006000",
                "aux_internal_name": "__I_add",
            },
        },
        "pcode_breakpoints": {
            "before_scheduling": "0x00435ff7",
            "after_scheduling": "0x00435ffc",
            "before_register_allocation": "0x0043602b",
            "after_register_allocation": "0x00436030",
            "after_colorgraph_assignment": "0x004c1d74",
        },
        "register_allocation": {
            "capture_breakpoint": "0x004c1d74",
            "max_nodes": 0x7FFF,
            "node_stride": 0x20,
            "edge_stride": 0x10,
            "physical_slots": [32, 32, 32, 16, 32, 32, 32],
            "class_labels": ["GPR", "FPR", "SPECIAL", "COPROC2_i", "COPROC2_ii", "COPROC2_f", "COPROC2_special"],
            "globals": {
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
            },
        },
        "scheduler": {
            "driver": "0x004c0790",
            "ready_selector": "0x004c0a00",
            "resource_pressure_score": "0x004c14b0",
            "node_stride": 28,
            "edge_stride": 12,
            "globals": {
                "ready_head": "0x0061b8c4",
                "pressure_mode": "0x00635c24",
                "callback_table": "0x0061b85c",
            },
            "node_fields": {
                "next": 0, "previous": 4, "outgoing_edges": 8, "pcode": 12,
                "actual_latency": 16, "heuristic_latency": 18,
                "earliest_issue_cycle": 20, "critical_deadline_cycle": 22,
                "critical_path_length": 24, "pending_predecessors": 26,
            },
            "edge_fields": {"next": 0, "target": 4, "latency": 8},
        },
    }


def _write_json(profile: dict) -> str:
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".json", delete=False, encoding="utf-8"
    ) as f:
        json.dump(profile, f, indent=2, sort_keys=True)
        return f.name


if __name__ == "__main__":
    unittest.main()
