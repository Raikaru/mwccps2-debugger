"""Regression coverage for the standalone MWCCPS2 PE probe."""

from __future__ import annotations

import contextlib
import io
import json
from pathlib import Path
import struct
import tempfile
import unittest

import mwccps2_probe as probe


PE_OFFSET = 0x80
OPTIONAL_HEADER_SIZE = 0xE0
SECTION_TABLE_OFFSET = PE_OFFSET + 4 + 20 + OPTIONAL_HEADER_SIZE
IMAGE_BASE = 0x00400000
TEXT_OFFSET = 0x200
RDATA_OFFSET = 0x300
TEXT_RVA = 0x1000
RDATA_RVA = 0x3000


def build_pe(
    *,
    machine: int = probe.IMAGE_FILE_MACHINE_I386,
    optional_magic: int = probe.PE32_MAGIC,
    optional_size: int = OPTIONAL_HEADER_SIZE,
    text: bytes = b"\0" * 0x80,
    rdata: bytes = b"\0" * 0x100,
) -> bytes:
    """Build the smallest PE32 layout the probe needs for behavioral tests."""
    sections = (
        (b".text", TEXT_RVA, TEXT_OFFSET, text, 0x60000020),
        (b".rdata", RDATA_RVA, RDATA_OFFSET, rdata, 0x40000040),
    )
    data = bytearray(max(offset + len(contents) for _, _, offset, contents, _ in sections))
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, PE_OFFSET)
    data[PE_OFFSET : PE_OFFSET + 4] = b"PE\0\0"
    struct.pack_into(
        "<HHIIIHH",
        data,
        PE_OFFSET + 4,
        machine,
        len(sections),
        0x12345678,
        0,
        0,
        optional_size,
        0x0102,
    )
    optional_offset = PE_OFFSET + 24
    struct.pack_into("<H", data, optional_offset, optional_magic)
    struct.pack_into("<I", data, optional_offset + 16, TEXT_RVA + 4)
    struct.pack_into("<I", data, optional_offset + 28, IMAGE_BASE)

    for index, (name, rva, offset, contents, characteristics) in enumerate(sections):
        struct.pack_into(
            "<8sIIIIIIHHI",
            data,
            SECTION_TABLE_OFFSET + index * 40,
            name,
            len(contents),
            rva,
            len(contents),
            offset,
            0,
            0,
            0,
            0,
            characteristics,
        )
        data[offset : offset + len(contents)] = contents
    return bytes(data)


class PEImageRegressionTests(unittest.TestCase):
    def write_image(self, directory: Path, data: bytes, name: str = "image.exe") -> Path:
        path = directory / name
        path.write_bytes(data)
        return path

    def test_parses_i386_pe32_and_maps_section_file_offsets(self) -> None:
        """PE section offsets map to RVAs while header offsets remain unmapped."""
        with tempfile.TemporaryDirectory() as temporary_directory:
            path = self.write_image(Path(temporary_directory), build_pe())
            image = probe.PEImage.load(path)

        self.assertEqual(image.machine, probe.IMAGE_FILE_MACHINE_I386)
        self.assertEqual(image.timestamp, 0x12345678)
        self.assertEqual(image.image_base, IMAGE_BASE)
        self.assertEqual(image.entry_point_rva, TEXT_RVA + 4)
        self.assertEqual(
            [(section.name, section.virtual_address) for section in image.sections],
            [(".text", TEXT_RVA), (".rdata", RDATA_RVA)],
        )
        self.assertEqual(image.offset_to_rva(TEXT_OFFSET + 0x7F), TEXT_RVA + 0x7F)
        self.assertEqual(image.offset_to_rva(RDATA_OFFSET + 0x40), RDATA_RVA + 0x40)
        with self.assertRaisesRegex(probe.ProbeError, "not in a mapped section"):
            image.offset_to_rva(TEXT_OFFSET - 1)

    def test_rejects_non_pe_and_truncated_pe_layouts(self) -> None:
        """Invalid DOS, PE, optional-header, section, and raw-data boundaries surface ProbeError."""
        valid = bytearray(build_pe())
        bad_signature = valid[:]
        bad_signature[PE_OFFSET : PE_OFFSET + 4] = b"PX\0\0"
        small_optional_header = valid[:]
        struct.pack_into("<H", small_optional_header, PE_OFFSET + 20, 95)
        section_extends_past_file = valid[:]
        struct.pack_into("<I", section_extends_past_file, SECTION_TABLE_OFFSET + 16, 0x10000)

        cases = (
            ("not-dos", b"not a PE image", "not a DOS/PE executable"),
            ("truncated-dos", b"MZ", "not a DOS/PE executable"),
            ("missing-signature", bytes(bad_signature), "no valid PE signature"),
            ("wrong-optional-magic", build_pe(optional_magic=0x20B), "unsupported optional-header magic"),
            ("short-optional-header", bytes(small_optional_header), "truncated PE32 optional header"),
            ("truncated-section-header", bytes(valid[: SECTION_TABLE_OFFSET + 39]), "truncated section 0"),
            ("section-data-out-of-bounds", bytes(section_extends_past_file), "extends beyond the file"),
        )

        with tempfile.TemporaryDirectory() as temporary_directory:
            directory = Path(temporary_directory)
            for name, data, error_message in cases:
                with self.subTest(name=name):
                    path = self.write_image(directory, data, f"{name}.exe")
                    with self.assertRaisesRegex(probe.ProbeError, error_message):
                        probe.PEImage.load(path)

    def test_report_finds_identity_backend_anchors_and_executable_xrefs(self) -> None:
        """Anchor references are reported only from executable sections, with mapped VAs."""
        identity_offset = 0x10
        source_offset = 0x70
        message_offset = 0x90
        identity_rva = RDATA_RVA + identity_offset
        source_rva = RDATA_RVA + source_offset
        identity_va = IMAGE_BASE + identity_rva
        source_va = IMAGE_BASE + source_rva
        text = bytearray(0x80)
        rdata = bytearray(0x100)
        rdata[identity_offset : identity_offset + len(probe.MWCCPS2_IDENTITY) + 1] = (
            probe.MWCCPS2_IDENTITY.encode("ascii") + b"\0"
        )
        rdata[source_offset : source_offset + len(b"PCode.c\0")] = b"PCode.c\0"
        rdata[message_offset : message_offset + len(b"After peepholeoptimizepcode [POST SCHEDULE]\0")] = (
            b"After peepholeoptimizepcode [POST SCHEDULE]\0"
        )
        struct.pack_into("<I", text, 0x08, identity_va)
        struct.pack_into("<I", text, 0x0C, identity_rva)
        struct.pack_into("<I", text, 0x18, source_va)
        struct.pack_into("<I", rdata, 0x50, identity_va)
        struct.pack_into("<I", rdata, 0x54, identity_rva)
        struct.pack_into("<I", rdata, 0xD0, source_va)

        with tempfile.TemporaryDirectory() as temporary_directory:
            path = self.write_image(Path(temporary_directory), build_pe(text=bytes(text), rdata=bytes(rdata)))
            report = probe.build_report(probe.PEImage.load(path))

        self.assertTrue(report["is_i386"])
        self.assertTrue(report["is_mwccps2"])
        self.assertEqual(report["source_inventory"], {"counts_by_suffix": {".c": 1}, "files": ["PCode.c"]})
        anchors = {anchor["text"]: anchor for anchor in report["anchors"]}
        self.assertEqual(anchors[probe.MWCCPS2_IDENTITY]["category"], "identity")
        self.assertEqual(anchors["PCode.c"]["category"], "backend-source")
        self.assertEqual(
            anchors["After peepholeoptimizepcode [POST SCHEDULE]"]["category"],
            "backend-message",
        )
        identity_location = anchors[probe.MWCCPS2_IDENTITY]["locations"]
        self.assertEqual(len(identity_location), 1)
        self.assertEqual(identity_location[0]["file_offset"], RDATA_OFFSET + identity_offset)
        self.assertEqual(identity_location[0]["rva"], identity_rva)
        self.assertEqual(identity_location[0]["va"], identity_va)
        self.assertEqual(identity_location[0]["absolute_operand_sites"], (IMAGE_BASE + TEXT_RVA + 0x08,))
        self.assertEqual(identity_location[0]["rva_operand_sites"], (IMAGE_BASE + TEXT_RVA + 0x0C,))
        self.assertEqual(anchors["PCode.c"]["locations"][0]["absolute_operand_sites"], (IMAGE_BASE + TEXT_RVA + 0x18,))


class ProbeCommandRegressionTests(unittest.TestCase):
    def test_main_returns_success_and_writes_a_machine_readable_report(self) -> None:
        """A recognized i386 MWCCPS2 image yields exit 0 and a report consumers can parse."""
        rdata = bytearray(0x100)
        rdata[0x10 : 0x10 + len(probe.MWCCPS2_IDENTITY) + 1] = (
            probe.MWCCPS2_IDENTITY.encode("ascii") + b"\0"
        )
        with tempfile.TemporaryDirectory() as temporary_directory:
            directory = Path(temporary_directory)
            image_path = directory / "compiler.exe"
            report_path = directory / "report.json"
            image_path.write_bytes(build_pe(rdata=bytes(rdata)))
            output = io.StringIO()
            errors = io.StringIO()
            with contextlib.redirect_stdout(output), contextlib.redirect_stderr(errors):
                exit_code = probe.main([str(image_path), "--json", str(report_path)])
            report = json.loads(report_path.read_text(encoding="utf-8"))

        self.assertEqual(exit_code, 0)
        self.assertEqual(errors.getvalue(), "")
        self.assertIn("MWCCPS2 identity: yes", output.getvalue())
        self.assertTrue(report["is_mwccps2"])
        self.assertEqual(report["pe"]["machine"], probe.IMAGE_FILE_MACHINE_I386)

    def test_main_maps_invalid_input_to_error_exit(self) -> None:
        """The CLI reports unsupported input as a user-facing exit code 2, not a traceback."""
        with tempfile.TemporaryDirectory() as temporary_directory:
            image_path = Path(temporary_directory) / "not-a-pe.exe"
            image_path.write_bytes(b"not a PE image")
            output = io.StringIO()
            errors = io.StringIO()
            with contextlib.redirect_stdout(output), contextlib.redirect_stderr(errors):
                exit_code = probe.main([str(image_path)])

        self.assertEqual(exit_code, 2)
        self.assertEqual(output.getvalue(), "")
        self.assertIn("error: input is not a DOS/PE executable", errors.getvalue())

    def test_main_rejects_an_unidentified_i386_image(self) -> None:
        """A parseable i386 PE without the identity is rejected with validation exit 1."""
        with tempfile.TemporaryDirectory() as temporary_directory:
            image_path = Path(temporary_directory) / "other-compiler.exe"
            image_path.write_bytes(build_pe())
            errors = io.StringIO()
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(errors):
                exit_code = probe.main([str(image_path)])

        self.assertEqual(exit_code, 1)
        self.assertIn("error: MWCCPS2 identity string was not found", errors.getvalue())


if __name__ == "__main__":
    unittest.main()
