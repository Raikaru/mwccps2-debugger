from __future__ import annotations

import struct
import unittest

from explain.analysis import build_analysis, build_blocks
from explain.mips import decode_instructions
from explain.report import render_report
from mwccps2_family_sweep import _clusters, _selected_rows


def words(*values: int) -> bytes:
    return b"".join(struct.pack("<I", value) for value in values)


def function_record(address: str = "00100000") -> dict[str, object]:
    return {
        "name": "target",
        "address": address,
        "source": "src/target.c",
        "marker_line": 7,
        "window": 16,
        "nonmatching_marker": True,
        "stub_marker": False,
    }


def verification_record() -> dict[str, object]:
    return {
        "certified": False,
        "outcome": "unverified",
        "row_status": "NONMATCHING",
        "normalized_diff": 4,
        "first_diffs": [0],
    }


class MipsControlFlowTests(unittest.TestCase):
    def test_branch_delay_slot_has_target_and_fallthrough_successors(self) -> None:
        # beq $zero,$zero,+2; nop; addiu $v0,$zero,1; jr $ra; nop
        instructions = decode_instructions(words(0x10000002, 0, 0x24020001, 0x03E00008, 0), 0x1000)
        blocks = build_blocks(instructions)
        self.assertEqual(len(blocks), 3)
        self.assertEqual(blocks[0].successors, (12, 8))
        self.assertEqual(blocks[-1].successors, ())

    def test_direct_call_target_is_decoded_from_instruction_word(self) -> None:
        target = 0x00123450
        jal = 0x0C000000 | (target >> 2)
        instruction = decode_instructions(words(jal), 0x00100000)[0]
        self.assertEqual(instruction.kind, "call")
        self.assertEqual(instruction.target, target)


class FunctionAnalysisTests(unittest.TestCase):
    def test_signed_load_difference_produces_bounded_type_finding(self) -> None:
        # lb/lbu $v0,0($a0); jr $ra; nop
        candidate = words(0x80820000, 0x03E00008, 0)
        retail = words(0x90820000, 0x03E00008, 0)
        dossier = build_analysis(
            project={"adapter": "test"},
            function=function_record(),
            verification=verification_record(),
            candidate_bytes=candidate,
            retail_bytes=retail,
            relocations=(),
            symbols={},
        )
        finding_ids = {finding["id"] for finding in dossier["findings"]}
        self.assertIn("integer-signedness", finding_ids)
        self.assertFalse(dossier["verification"]["certified"])
        self.assertIn("Persona 3 verifier row only", render_report(dossier))

    def test_zero_padding_after_return_delay_slot_is_not_a_cfg_block(self) -> None:
        body = words(0x03E00008, 0)
        dossier = build_analysis(
            project={"adapter": "test"},
            function=function_record(),
            verification=verification_record(),
            candidate_bytes=body,
            retail_bytes=body + words(0, 0, 0),
            relocations=(),
            symbols={},
        )
        self.assertEqual(len(dossier["retail"]["instructions"]), 2)
        self.assertEqual(len(dossier["retail"]["blocks"]), 1)
        self.assertEqual(dossier["alignment"], [
            {"candidate_index": 0, "retail_index": 0, "relation": "exact"},
            {"candidate_index": 1, "retail_index": 1, "relation": "exact"},
        ])

    def test_retail_calls_are_resolved_through_project_symbols(self) -> None:
        target = 0x00123450
        body = words(0x0C000000 | (target >> 2), 0, 0x03E00008, 0)
        dossier = build_analysis(
            project={"adapter": "test"},
            function=function_record(),
            verification=verification_record(),
            candidate_bytes=body,
            retail_bytes=body,
            relocations=(),
            symbols={target: "KnownCallee"},
        )
        self.assertEqual(dossier["calls"], [{"address": "00123450", "symbol": "KnownCallee"}])
        self.assertEqual(dossier["findings"][0]["id"], "exact-instruction-stream")

    def test_reconstructs_gp_lui_fields_and_printable_strings(self) -> None:
        # lw $a1,-0x10($gp); lui/addiu $t0,0x12340500; lw $v0,0($t0);
        # lw $v1,0x18($a0); jr $ra; nop
        body = words(
            0x8F85FFF0, 0x3C081234, 0x25080500, 0x8D020000,
            0x8C830018, 0x03E00008, 0,
        )

        def read_memory(address: int, size: int) -> bytes:
            if address == 0x12340500:
                return b"Menu label\x00" + bytes(size - 11)
            raise ValueError("outside fixture")

        dossier = build_analysis(
            project={"adapter": "test"},
            function=function_record(),
            verification=verification_record(),
            candidate_bytes=body,
            retail_bytes=body,
            relocations=(),
            symbols={0x007D2CE0: "KnownGlobal"},
            gp=0x007D2CF0,
            read_memory=read_memory,
        )
        self.assertEqual(
            [(item["address"], item["provenance"]) for item in dossier["retail_globals"]],
            [("007d2ce0", "gp"), ("12340500", "lui-low")],
        )
        self.assertEqual(dossier["structure_fields"][0]["displacement"], 0x18)
        self.assertEqual(dossier["strings"][0]["text"], "Menu label")
        report = render_report(dossier)
        self.assertIn("KnownGlobal", report)
        self.assertIn("'Menu label'", report)

    def test_final_object_lowering_reports_frame_stack_and_capture(self) -> None:
        body = words(
            0x27BDFFE0,  # addiu $sp,$sp,-0x20
            0xAFBF001C,  # sw $ra,0x1c($sp)
            0x8FBF001C,  # lw $ra,0x1c($sp)
            0x27BD0020,  # addiu $sp,$sp,0x20
            0x03E00008,
            0,
        )
        dossier = build_analysis(
            project={"adapter": "test"},
            function=function_record(),
            verification=verification_record(),
            candidate_bytes=body,
            retail_bytes=body,
            relocations=({"offset": 4, "type": 7, "symbol": "stack_symbol"},),
            symbols={},
            compiler_capture={"outcome": "success", "instrumentation_neutral": True, "stages": [{}, {}]},
        )
        lowering = dossier["final_lowering"]
        self.assertEqual(lowering["frame_size"], 0x20)
        self.assertEqual(
            [(item["operation"], item["register"], item["stack_offset"]) for item in lowering["stack_slots"]],
            [("write", "$ra", 0x1C), ("read", "$ra", 0x1C)],
        )
        self.assertEqual(lowering["relocation_count"], 1)
        self.assertIn("instrumentation neutral:   True", render_report(dossier))


class ResidualFamilyTests(unittest.TestCase):
    def test_selection_bounds_and_clusters_are_deterministic(self) -> None:
        report = {
            "results": [
                {"status": "NONMATCHING", "file": "b.c", "name": "b", "addr": "00000020", "window": 64, "normalized_diff": 2},
                {"status": "MISMATCH", "file": "a.c", "name": "a", "addr": "00000010", "window": 32, "normalized_diff": 1},
                {"status": "MATCH", "file": "c.c", "name": "c", "addr": "00000030", "window": 16, "normalized_diff": 0},
                {"status": "NONMATCHING", "file": "d.c", "name": "d", "addr": "00000040", "window": 1024, "normalized_diff": 1},
            ]
        }
        selected = _selected_rows(report, max_window=128, max_diff=4, limit=0)
        self.assertEqual([row["name"] for row in selected], ["a", "b"])
        functions = [
            {"source": "a.c", "name": "a", "address": "00000010",
             "finding_ids": ["integer-signedness"], "mnemonic_pairs": ["lb/lbu"]},
            {"source": "b.c", "name": "b", "address": "00000020",
             "finding_ids": ["integer-signedness", "operation-count"], "mnemonic_pairs": ["lb/lbu"]},
        ]
        clusters = _clusters(functions)
        self.assertEqual(clusters["findings"][0]["id"], "integer-signedness")
        self.assertEqual(clusters["findings"][0]["function_count"], 2)
        self.assertEqual(clusters["mnemonic_pairs"][0]["id"], "lb/lbu")



if __name__ == "__main__":
    unittest.main()
