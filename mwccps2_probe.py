#!/usr/bin/env python3
"""Fingerprint MWCCPS2 PE binaries and locate backend-analysis anchors."""

from __future__ import annotations

import argparse
from dataclasses import asdict, dataclass
import hashlib
import json
from pathlib import Path
import re
import struct
import sys
from typing import Iterable


IMAGE_FILE_MACHINE_I386 = 0x014C
PE32_MAGIC = 0x010B
MWCCPS2_IDENTITY = "Metrowerks C/C++ Compiler for MIPS/PlayStation2"

BACKEND_SOURCE_ANCHORS = (
    "CodeGen.c",
    "InstrSelection.c",
    "PCode.c",
    "PCodeUtilities.c",
    "PCodeInfo.c",
    "Alias.c",
    "AliasPropagation.c",
    "ConditionalMoveOptimization.c",
    "InterferenceGraph.c",
    "Coloring.c",
    "Spill.c",
    "Scheduler.c",
    "BE_schedule.c",
    "MIPS_Peephole.c",
    "RegisterInfo.c",
    "VReg.c",
    "ObjGen.c",
    "ELFgen.c",
)

BACKEND_MESSAGE_ANCHORS = (
    "After peepholeoptimizepcode [POST COLORING]",
    "After peepholeoptimizepcode [POST SCHEDULE]",
)


class ProbeError(Exception):
    """Raised when the input is not a supported PE image."""


@dataclass(frozen=True)
class Section:
    name: str
    virtual_address: int
    virtual_size: int
    raw_offset: int
    raw_size: int
    characteristics: int

    @property
    def mapped_size(self) -> int:
        return max(self.virtual_size, self.raw_size)


@dataclass(frozen=True)
class AnchorLocation:
    file_offset: int
    rva: int
    va: int
    absolute_operand_sites: tuple[int, ...]
    rva_operand_sites: tuple[int, ...]


@dataclass(frozen=True)
class Anchor:
    category: str
    text: str
    locations: tuple[AnchorLocation, ...]


@dataclass(frozen=True)
class PEImage:
    path: Path
    data: bytes
    machine: int
    timestamp: int
    characteristics: int
    image_base: int
    entry_point_rva: int
    sections: tuple[Section, ...]

    @classmethod
    def load(cls, path: Path) -> "PEImage":
        try:
            data = path.read_bytes()
        except OSError as error:
            raise ProbeError(f"cannot read {path}: {error}") from error

        if len(data) < 0x40 or data[:2] != b"MZ":
            raise ProbeError("input is not a DOS/PE executable")

        pe_offset = _unpack_from("<I", data, 0x3C, "DOS header")[0]
        if pe_offset + 24 > len(data) or data[pe_offset : pe_offset + 4] != b"PE\0\0":
            raise ProbeError("input has no valid PE signature")

        coff_offset = pe_offset + 4
        machine, section_count, timestamp, _, _, optional_size, characteristics = _unpack_from(
            "<HHIIIHH", data, coff_offset, "COFF header"
        )
        optional_offset = coff_offset + 20
        magic = _unpack_from("<H", data, optional_offset, "optional header")[0]
        if magic != PE32_MAGIC:
            raise ProbeError(f"unsupported optional-header magic 0x{magic:04x}; expected PE32")
        if optional_size < 96:
            raise ProbeError("truncated PE32 optional header")

        entry_point_rva = _unpack_from(
            "<I", data, optional_offset + 16, "entry point"
        )[0]
        image_base = _unpack_from("<I", data, optional_offset + 28, "image base")[0]

        section_offset = optional_offset + optional_size
        sections: list[Section] = []
        for index in range(section_count):
            offset = section_offset + index * 40
            values = _unpack_from("<8sIIIIIIHHI", data, offset, f"section {index}")
            raw_name, virtual_size, virtual_address, raw_size, raw_offset = values[:5]
            name = raw_name.rstrip(b"\0").decode("ascii", errors="replace")
            section_characteristics = values[-1]
            if raw_size and raw_offset + raw_size > len(data):
                raise ProbeError(f"section {name!r} extends beyond the file")
            sections.append(
                Section(
                    name=name,
                    virtual_address=virtual_address,
                    virtual_size=virtual_size,
                    raw_offset=raw_offset,
                    raw_size=raw_size,
                    characteristics=section_characteristics,
                )
            )

        return cls(
            path=path,
            data=data,
            machine=machine,
            timestamp=timestamp,
            characteristics=characteristics,
            image_base=image_base,
            entry_point_rva=entry_point_rva,
            sections=tuple(sections),
        )

    def offset_to_rva(self, file_offset: int) -> int:
        for section in self.sections:
            if section.raw_offset <= file_offset < section.raw_offset + section.raw_size:
                return section.virtual_address + file_offset - section.raw_offset
        raise ProbeError(f"file offset 0x{file_offset:x} is not in a mapped section")

    def executable_sections(self) -> Iterable[Section]:
        for section in self.sections:
            if section.characteristics & 0x20000000 and section.raw_size:
                yield section

    def operand_sites(self, value: int) -> tuple[int, ...]:
        encoded = struct.pack("<I", value)
        sites: list[int] = []
        for section in self.executable_sections():
            section_data = self.data[
                section.raw_offset : section.raw_offset + section.raw_size
            ]
            start = 0
            while True:
                relative_offset = section_data.find(encoded, start)
                if relative_offset < 0:
                    break
                sites.append(
                    self.image_base + section.virtual_address + relative_offset
                )
                start = relative_offset + 1
        return tuple(sites)


def _unpack_from(
    format_string: str, data: bytes, offset: int, description: str
) -> tuple[object, ...]:
    size = struct.calcsize(format_string)
    if offset < 0 or offset + size > len(data):
        raise ProbeError(f"truncated {description}")
    return struct.unpack_from(format_string, data, offset)


def _find_all(data: bytes, needle: bytes) -> tuple[int, ...]:
    offsets: list[int] = []
    start = 0
    while True:
        offset = data.find(needle, start)
        if offset < 0:
            return tuple(offsets)
        offsets.append(offset)
        start = offset + 1


def _anchor(image: PEImage, category: str, text: str) -> Anchor:
    locations: list[AnchorLocation] = []
    for file_offset in _find_all(image.data, text.encode("ascii") + b"\0"):
        try:
            rva = image.offset_to_rva(file_offset)
        except ProbeError:
            continue
        va = image.image_base + rva
        locations.append(
            AnchorLocation(
                file_offset=file_offset,
                rva=rva,
                va=va,
                absolute_operand_sites=image.operand_sites(va),
                rva_operand_sites=image.operand_sites(rva),
            )
        )
    return Anchor(category=category, text=text, locations=tuple(locations))


def _source_inventory(data: bytes) -> dict[str, object]:
    strings = {
        match.group().decode("ascii")
        for match in re.finditer(rb"[A-Za-z0-9_./\\-]+\.(?:c|cc|cpp|cxx|h|hpp)\0", data)
    }
    normalized = sorted(value[:-1] if value.endswith("\0") else value for value in strings)
    counts: dict[str, int] = {}
    for value in normalized:
        suffix = Path(value).suffix.lower()
        counts[suffix] = counts.get(suffix, 0) + 1
    return {"counts_by_suffix": counts, "files": normalized}


def build_report(image: PEImage) -> dict[str, object]:
    anchors = [
        _anchor(image, "identity", MWCCPS2_IDENTITY),
        *(
            _anchor(image, "backend-source", text)
            for text in BACKEND_SOURCE_ANCHORS
        ),
        *(
            _anchor(image, "backend-message", text)
            for text in BACKEND_MESSAGE_ANCHORS
        ),
    ]
    present = [anchor for anchor in anchors if anchor.locations]

    return {
        "schema_version": 1,
        "file": str(image.path.resolve()),
        "size": len(image.data),
        "sha256": hashlib.sha256(image.data).hexdigest(),
        "pe": {
            "machine": image.machine,
            "timestamp": image.timestamp,
            "characteristics": image.characteristics,
            "image_base": image.image_base,
            "entry_point_rva": image.entry_point_rva,
            "sections": [asdict(section) for section in image.sections],
        },
        "is_i386": image.machine == IMAGE_FILE_MACHINE_I386,
        "is_mwccps2": bool(anchors[0].locations),
        "source_inventory": _source_inventory(image.data),
        "anchors": [asdict(anchor) for anchor in present],
        "missing_anchors": [anchor.text for anchor in anchors if not anchor.locations],
    }


def _hex(value: int) -> str:
    return f"0x{value:08x}"


def print_summary(report: dict[str, object]) -> None:
    pe = report["pe"]
    assert isinstance(pe, dict)
    inventory = report["source_inventory"]
    assert isinstance(inventory, dict)
    counts = inventory["counts_by_suffix"]
    assert isinstance(counts, dict)

    print(f"file: {report['file']}")
    print(f"sha256: {report['sha256']}")
    print(f"size: {report['size']} bytes")
    print(
        "PE: machine={} image_base={} entry_rva={} timestamp={}".format(
            _hex(int(pe["machine"])),
            _hex(int(pe["image_base"])),
            _hex(int(pe["entry_point_rva"])),
            _hex(int(pe["timestamp"])),
        )
    )
    print(f"MWCCPS2 identity: {'yes' if report['is_mwccps2'] else 'no'}")
    print(
        "embedded source files: "
        + ", ".join(f"{suffix}={count}" for suffix, count in sorted(counts.items()))
    )
    print("anchors:")
    anchors = report["anchors"]
    assert isinstance(anchors, list)
    for anchor in anchors:
        assert isinstance(anchor, dict)
        locations = anchor["locations"]
        assert isinstance(locations, (list, tuple))
        location_text: list[str] = []
        for location in locations:
            assert isinstance(location, dict)
            xref_count = len(location["absolute_operand_sites"]) + len(
                location["rva_operand_sites"]
            )
            location_text.append(f"{_hex(int(location['va']))} ({xref_count} operand sites)")
        print(f"  [{anchor['category']}] {anchor['text']}: {', '.join(location_text)}")

    missing = report["missing_anchors"]
    assert isinstance(missing, list)
    if missing:
        print("missing optional anchors: " + ", ".join(str(value) for value in missing))


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Fingerprint an MWCCPS2 PE and locate backend-analysis anchors."
    )
    parser.add_argument("compiler", type=Path, help="path to mwccps2.exe")
    parser.add_argument(
        "--json",
        type=Path,
        dest="json_path",
        help="write the complete machine-readable report to this path",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)
    try:
        image = PEImage.load(args.compiler)
        report = build_report(image)
    except ProbeError as error:
        print(f"error: {error}", file=sys.stderr)
        return 2

    print_summary(report)
    if args.json_path is not None:
        try:
            args.json_path.parent.mkdir(parents=True, exist_ok=True)
            args.json_path.write_text(
                json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
            )
        except OSError as error:
            print(f"error: cannot write {args.json_path}: {error}", file=sys.stderr)
            return 2

    if not report["is_i386"]:
        print("error: compiler is not an i386 PE", file=sys.stderr)
        return 1
    if not report["is_mwccps2"]:
        print("error: MWCCPS2 identity string was not found", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
