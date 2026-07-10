"""Regression coverage for b210 frontend model: profile, name table, IRO nodes, normalization."""

from __future__ import annotations

from pathlib import Path
import struct
import tempfile
import json
import unittest

from gdb.b210_frontend_model import (
    FrontendModelError,
    MemoryReadError,
    format_address,
    parse_address,
    validate_frontend_profile,
    read_function_record,
    read_operation_record,
    read_iro_node,
    collect_name_table,
    collect_iro_nodes,
    normalize_frontend_capture,
    FRONTEND_SNAPSHOT_SCHEMA_NAME,
    FRONTEND_SNAPSHOT_SCHEMA_VERSION,
    EXPECTED_PROFILE_NAME,
)

from gdb.b210_frontend_model import MemoryReader


class InMemoryReader:
    """Simple MemoryReader backed by a bytearray."""

    def __init__(self, data: bytes | None = None) -> None:
        self._data = bytearray(data) if data else bytearray()

    def read(self, address: int, size: int) -> bytes:
        if address < 0 or size < 0 or address + size > len(self._data):
            raise MemoryReadError(f"read 0x{address:x}+0x{size:x} exceeds bounds")
        return bytes(self._data[address : address + size])


class AddressFormattingTests(unittest.TestCase):
    """format_address / parse_address."""

    def test_format_zero(self) -> None:
        self.assertEqual(format_address(0), "0x00000000")

    def test_format_typical(self) -> None:
        self.assertEqual(format_address(0x00626638), "0x00626638")

    def test_parse_valid_string(self) -> None:
        self.assertEqual(parse_address("0x00626638", "test"), 0x00626638)

    def test_parse_valid_int(self) -> None:
        self.assertEqual(parse_address(0x00626638, "test"), 0x00626638)

    def test_parse_rejects_negative(self) -> None:
        with self.assertRaises(FrontendModelError):
            parse_address(-1, "test")


class ProfileValidationTests(unittest.TestCase):
    """validate_frontend_profile shape rejection."""

    def test_accepts_valid(self) -> None:
        profile = _valid_profile()
        try:
            validate_frontend_profile(profile)
        except FrontendModelError as exc:
            self.fail(f"validate_frontend_profile raised: {exc}")

    def test_rejects_non_mapping(self) -> None:
        with self.assertRaises(Exception):
            validate_frontend_profile("invalid")

    def test_rejects_missing_frontend_ir(self) -> None:
        with self.assertRaises(FrontendModelError):
            validate_frontend_profile({"schema": {}, "profile_name": EXPECTED_PROFILE_NAME})

    def test_rejects_wrong_function_record_size(self) -> None:
        profile = _valid_profile()
        profile["frontend_ir"]["function_record"]["minimum_bytes"] = 0x20
        with self.assertRaises(FrontendModelError):
            validate_frontend_profile(profile)

    def test_rejects_wrong_iro_node_size(self) -> None:
        profile = _valid_profile()
        profile["frontend_ir"]["iro_node"]["byte_size"] = 0x30
        with self.assertRaises(FrontendModelError):
            validate_frontend_profile(profile)

    def test_rejects_wrong_name(self) -> None:
        profile = _valid_profile()
        profile["name"] = "wrong"
        with self.assertRaises(FrontendModelError):
            validate_frontend_profile(profile)



class ReadFunctionRecordTests(unittest.TestCase):
    """read_function_record decoding."""

    def test_null_name(self) -> None:
        data = struct.pack("<III", 0, 0, 0)
        reader = InMemoryReader(data)
        record = read_function_record(reader, 0, 32)
        self.assertEqual(record["name"]["state"], "null")


class ReadIroNodeTests(unittest.TestCase):
    """read_iro_node decoding."""

    def test_minimal_node(self) -> None:
        data = bytearray(0x44)
        data[0] = 0x01  # kind_u8
        reader = InMemoryReader(bytes(data))
        node = read_iro_node(reader, 0)
        self.assertEqual(node["kind_u8"], 1)


class CollectNameTableTests(unittest.TestCase):
    """collect_name_table null head."""

    def test_null_head_returns_empty(self) -> None:
        # head_address=0 contains all-zero head pointer -> null chain
        reader = InMemoryReader(b"\x00\x00\x00\x00")
        result = collect_name_table(reader, 0, 100, 32)
        self.assertEqual(result["entries"], [])

    def test_single_entry(self) -> None:
        # Memory layout:
        #   addr 0:    head pointer -> 8 (first entry)
        #   addr 8:    name_table_entry {next=0, record=100}
        #   addr 100:  function_record (0x0C bytes, symbol=0 -> null name)
        #   addr 112:  (unused)
        head_ptr = struct.pack("<I", 8)
        entry = struct.pack("<II", 0, 100)  # next=0 (null), record=100
        func_record = struct.pack("<BBHII", 0, 0, 0, 0, 0)  # 12 bytes: kind_u8, kind_flags_u8, ordinal_u16, opaque_04, symbol
        data = bytearray(200)
        data[0:4] = head_ptr
        data[8:16] = entry
        data[100:112] = func_record
        reader = InMemoryReader(bytes(data))
        result = collect_name_table(reader, 0, 100, 256)
        self.assertEqual(len(result["entries"]), 1)


class CollectIroNodesTests(unittest.TestCase):
    """collect_iro_nodes null root."""

    def test_null_root_returns_empty(self) -> None:
        # root_address=0 contains all-zero root pointer -> null chain
        reader = InMemoryReader(b"\x00\x00\x00\x00")
        result = collect_iro_nodes(reader, 0, 100)
        self.assertEqual(result["nodes"], [])

    def test_single_node(self) -> None:
        # Memory layout:
        #   addr 0:    root pointer -> 8 (first node)
        #   addr 8:    IRO node (0x44 bytes)
        root_ptr = struct.pack("<I", 8)
        node = bytearray(0x44)
        node[0] = 0x01  # kind_u8
        struct.pack_into("<I", node, 4, 0)  # flags_u32=0
        struct.pack_into("<I", node, 64, 0)  # next=0 (null termination)
        data = bytearray(200)
        data[0:4] = root_ptr
        data[8:76] = node
        reader = InMemoryReader(bytes(data))
        result = collect_iro_nodes(reader, 0, 100)
        self.assertEqual(len(result["nodes"]), 1)


class NormalizeFrontendCaptureTests(unittest.TestCase):
    """normalize_frontend_capture output shape."""

    def test_empty_capture_normalizes(self) -> None:
        raw = {
            "gFunction": {
                "kind_u8": 0,
                "kind_flags_u8": 0,
                "ordinal_u16": 0,
                "name": {"state": "null"},
            },
            "operations": [],
            "name_table": {"entries": [], "termination": {"reason": "null"}},
            "iro_nodes": {"nodes": [], "termination": {"reason": "null"}},
        }
        result = normalize_frontend_capture(raw)
        self.assertIn("name_table", result)
        self.assertIn("iro_nodes", result)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _valid_profile() -> dict:
    return {
        "name": EXPECTED_PROFILE_NAME,
        "frontend_ir": {
            "max_nodes": 4096,
            "max_name_bytes": 128,
            "globals": {
                "gFunction": "0x00000000",
                "name_table_head": "0x00000000",
                "ast_traversal_root": "0x00000000",
                "ast_null_sentinel": "0x00000000",
                "iro_root": "0x00000000",
            },
            "breakpoints": {
                "gFunction_assigned": "0x00000000",
                "after_flow_graph": "0x00000000",
            },
            "function_record": {
                "minimum_bytes": 0x0C,
                "symbol_name_offset": 10,
                "fields": {
                    "kind_u8": {"offset": 0, "kind": "u8"},
                    "kind_flags_u8": {"offset": 1, "kind": "u8"},
                    "ordinal_u16": {"offset": 2, "kind": "u16"},
                    "opaque_04": {"offset": 4, "kind": "pointer"},
                    "symbol": {"offset": 8, "kind": "pointer"},
                },
            },
            "name_table_entry": {
                "byte_size": 8,
                "fields": {
                    "next": {"offset": 0, "kind": "pointer"},
                    "record": {"offset": 4, "kind": "pointer"},
                },
            },
            "iro_node": {
                "byte_size": 0x44,
                "fields": {
                    "kind_u8": {"offset": 0, "kind": "u8"},
                    "opaque_01": {"offset": 1, "kind": "u8"},
                    "opaque_02": {"offset": 2, "kind": "u16"},
                    "flags_u32": {"offset": 4, "kind": "u32"},
                    "operand_root": {"offset": 16, "kind": "pointer"},
                    "operation": {"offset": 44, "kind": "pointer"},
                    "next": {"offset": 64, "kind": "pointer"},
                },
            },
            "operation_record": {
                "minimum_bytes": 1,
                "fields": {
                    "opcode_u8": {"offset": 0, "kind": "u8"},
                },
            },
        },
    }


if __name__ == "__main__":
    unittest.main()
