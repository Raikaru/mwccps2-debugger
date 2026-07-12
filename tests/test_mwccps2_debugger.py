"""Behavioral coverage for the human-facing, profile-driven MWCCPS2 debugger."""
from __future__ import annotations

import copy
import json
from pathlib import Path
import struct
import tempfile
import unittest
from unittest import mock

import mwccps2_debugger as debugger
from gdb.mwccps2_profile_model import (
    codegen_function_name,
    collect_pcode,
    format_pcode,
    load_profile,
)

ROOT = Path(__file__).resolve().parents[1]
PROFILE = ROOT / "profiles" / "mwcps2-2.4-0017-001213.json"


class ByteMemory:
    def __init__(self, size: int = 0x4000) -> None:
        self.data = bytearray(size)

    def read(self, address: int, size: int) -> bytes:
        if address < 0 or address + size > len(self.data):
            raise RuntimeError("unmapped")
        return bytes(self.data[address : address + size])

    def u8(self, address: int, value: int) -> None:
        self.data[address] = value

    def u16(self, address: int, value: int) -> None:
        struct.pack_into("<H", self.data, address, value)

    def i16(self, address: int, value: int) -> None:
        struct.pack_into("<h", self.data, address, value)

    def u32(self, address: int, value: int) -> None:
        struct.pack_into("<I", self.data, address, value)

    def i32(self, address: int, value: int) -> None:
        struct.pack_into("<i", self.data, address, value)

    def string(self, address: int, value: str) -> None:
        encoded = value.encode("latin-1") + b"\0"
        self.data[address : address + len(encoded)] = encoded


class ProfileTests(unittest.TestCase):
    def test_full_24_profile_has_all_human_capture_subsystems(self) -> None:
        profile = load_profile(PROFILE)
        self.assertEqual(profile["name"], "mwcps2-2.4-0017-001213")
        self.assertEqual(len(profile["pcode_breakpoints"]), 8)
        self.assertIn("ready_selector_return", profile["scheduler"])
        self.assertIn("colorgraph_return", profile["register_allocation"])
        self.assertEqual(profile["pcode_layout"]["instruction"]["operand_stride"], 22)

    def test_function_name_uses_24_inline_name_record(self) -> None:
        profile = load_profile(PROFILE)
        memory = ByteMemory()
        memory.u32(0x104, 0x200)
        memory.u32(0x208, 0x300)
        memory.string(0x30A, "load_indexed")
        self.assertEqual(codegen_function_name(memory, 0x100, profile), "load_indexed")

    def test_pcode_capture_renders_profiled_24_layout(self) -> None:
        profile = copy.deepcopy(load_profile(PROFILE))
        profile["globals"]["pcbasicblocks"]["address"] = 0x100
        profile["pcode_opcode_table"]["address"] = 0x1000
        memory = ByteMemory()
        memory.u32(0x100, 0x200)
        memory.u32(0x200 + 0x14, 0x300)
        memory.i32(0x200 + 0x1C, 7)
        memory.i16(0x200 + 0x2C, 1)
        memory.u16(0x300 + 0x20, 1)
        memory.i16(0x300 + 0x22, 2)
        memory.u32(0x300 + 0x0C, 0x6000)
        memory.u8(0x334, 0)
        memory.u8(0x335, 0)
        memory.u16(0x338, 5)
        memory.u8(0x34A, 2)
        memory.u32(0x34E, 7)
        opcode = 0x1000 + 42
        memory.u32(opcode, 0x2000)
        memory.u32(opcode + 8, 0x2010)
        memory.string(0x2000, "add")
        memory.string(0x2010, "=d,s,t")

        graph = collect_pcode(memory, profile)
        rendered = format_pcode(graph)

        self.assertEqual(graph["block_count"], 1)
        self.assertEqual(graph["instruction_count"], 1)
        self.assertIn("add r5, 7", rendered)


class CommandLineTests(unittest.TestCase):
    def test_flags_after_separator_do_not_become_function_name(self) -> None:
        args = debugger.parse_args(
            ["-e", "mwccps2.exe", "source.c", "load_indexed", "--", "-O4,p", "-sym", "on"]
        )
        self.assertEqual(args.function, "load_indexed")
        self.assertEqual(args.compiler_flags, ["-O4,p", "-sym", "on"])

    def test_cadmic_style_args_option_can_follow_function(self) -> None:
        args = debugger.parse_args(
            ["-e", "mwccps2.exe", "source.c", "load_indexed", "-a=-O4,p -sym on"]
        )
        self.assertEqual(args.function, "load_indexed")
        self.assertEqual(args.args, "-O4,p -sym on")
        self.assertEqual(args.compiler_flags, [])

    def test_profile_auto_detection_ignores_portability_reports(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            directory = Path(temporary_directory)
            compiler = directory / "mwccps2.exe"
            compiler.write_bytes(b"prepared compiler")
            size, digest = debugger._fingerprint(compiler)
            portability = directory / "a.portability.json"
            portability.write_text(json.dumps({"schema_version": 1, "binary": {"size": size, "sha256": digest}}), encoding="utf-8")
            live = directory / "live.json"
            live.write_text(json.dumps({"schema_version": 2, "binary": {"size": size, "sha256": digest}}), encoding="utf-8")
            with mock.patch.object(debugger, "PROFILE_DIRECTORY", directory):
                self.assertEqual(debugger.discover_profile(compiler), live)

    def test_gdb_command_arms_capture_before_continue(self) -> None:
        lines = debugger._command_lines(Path("mwccps2.exe"), ["-O4,p", "-c", "source.c"], PROFILE, Path("capture"), "load_indexed")
        source_index = next(index for index, line in enumerate(lines) if line.startswith("source "))
        start_index = next(index for index, line in enumerate(lines) if line.startswith("mwccps2-capture start"))
        continue_index = lines.index("continue")
        self.assertLess(source_index, start_index)
        self.assertLess(start_index, continue_index)
        self.assertIn('--function "load_indexed"', lines[start_index])


if __name__ == "__main__":
    unittest.main()
