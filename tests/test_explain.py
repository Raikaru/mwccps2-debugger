from __future__ import annotations

import struct
import unittest

from explain.analysis import build_analysis, build_blocks
from explain.mips import decode_instructions
from explain.report import render_report


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


if __name__ == "__main__":
    unittest.main()
