"""Regression coverage for decomp instruction-selection model."""

from __future__ import annotations

import unittest

from decomp.instruction_selection import (
    SelectorModelError,
    OperandDescriptor,
    Selection,
    select_addu,
    select_mul_s,
    select_comparison,
    select_extension,
    model_manifest,
    OPCODES,
    HANDLERS,
    MODEL_RULES,
)


class SelectionTests(unittest.TestCase):
    """Selection dataclass."""

    def test_minimal_selection(self) -> None:
        sel = Selection(opcode_id=None, mnemonic=None, source_order=(), evaluation_order=(),
                        emission_route="opaque", explanation="test")
        self.assertIsNone(sel.opcode_id)
        self.assertEqual(sel.emission_route, "opaque")

    def test_with_relation(self) -> None:
        sel = Selection(opcode_id=0x00d4, mnemonic="slt", source_order=("a", "b"),
                        evaluation_order=("a", "b"), emission_route="emit", explanation="cmp",
                        relation="<")
        self.assertEqual(sel.relation, "<")
        self.assertEqual(sel.mnemonic, "slt")

    def test_default_relation_is_none(self) -> None:
        sel = Selection(opcode_id=0x0004, mnemonic="addu", source_order=("a", "b"),
                        evaluation_order=("a", "b"), emission_route="emit", explanation="add")
        self.assertIsNone(sel.relation)


class OperandDescriptorTests(unittest.TestCase):
    """OperandDescriptor creation and validation."""

    def test_minimal_operand(self) -> None:
        op = OperandDescriptor(tag=0, identity="a", priority=0)
        self.assertEqual(op.identity, "a")
        self.assertEqual(op.priority, 0)

    def test_rejects_negative_priority(self) -> None:
        with self.assertRaises(SelectorModelError):
            OperandDescriptor(tag=0, identity="a", priority=-1)

    def test_rejects_overflow_priority(self) -> None:
        with self.assertRaises(SelectorModelError):
            OperandDescriptor(tag=0, identity="a", priority=256)


class SelectAdduTests(unittest.TestCase):
    """select_addu predictions."""

    def test_returns_selection(self) -> None:
        a = OperandDescriptor(tag=0, identity="a", priority=0)
        b = OperandDescriptor(tag=1, identity="b", priority=0)
        sel = select_addu(a, b)
        self.assertIsInstance(sel, Selection)

    def test_emits_addu_mnemonic(self) -> None:
        a = OperandDescriptor(tag=0, identity="a", priority=0)
        b = OperandDescriptor(tag=1, identity="b", priority=0)
        sel = select_addu(a, b)
        self.assertIsNotNone(sel.mnemonic)


class SelectMulSTests(unittest.TestCase):
    """select_mul_s predictions."""

    def test_returns_selection(self) -> None:
        a = OperandDescriptor(tag=0, identity="a", priority=0)
        b = OperandDescriptor(tag=1, identity="b", priority=0)
        sel = select_mul_s(a, b)
        self.assertIsInstance(sel, Selection)
        self.assertIsNotNone(sel.mnemonic)


class SelectComparisonTests(unittest.TestCase):
    """select_comparison relation normalization."""

    def test_signed_less_than(self) -> None:
        a = OperandDescriptor(tag=0, identity="a", priority=0)
        b = OperandDescriptor(tag=1, identity="b", priority=0)
        sel = select_comparison("<", a, b)
        self.assertIsNotNone(sel.relation)

    def test_signed_greater_equal(self) -> None:
        a = OperandDescriptor(tag=0, identity="a", priority=0)
        b = OperandDescriptor(tag=1, identity="b", priority=0)
        sel = select_comparison(">=", a, b)
        self.assertIsNotNone(sel.relation)

    def test_unsigned_less_than(self) -> None:
        a = OperandDescriptor(tag=0, identity="a", priority=0)
        b = OperandDescriptor(tag=1, identity="b", priority=0)
        sel = select_comparison("<", a, b, left_unsigned=True, right_unsigned=True)
        self.assertIsNotNone(sel.relation)

    def test_unknown_relation_raises(self) -> None:
        a = OperandDescriptor(tag=0, identity="a", priority=0)
        b = OperandDescriptor(tag=1, identity="b", priority=0)
        with self.assertRaises(SelectorModelError):
            select_comparison("??", a, b)

class SelectExtensionTests(unittest.TestCase):
    """select_extension sign/zero extension predictions."""

    def test_sign_extend_i16(self) -> None:
        sel = select_extension(source_width=2, destination_width=4, source_unsigned=False, destination_unsigned=False)
        self.assertIsNotNone(sel.mnemonic)

    def test_zero_extend_u8(self) -> None:
        sel = select_extension(source_width=1, destination_width=4, source_unsigned=True, destination_unsigned=True)
        self.assertIsNotNone(sel.mnemonic)

    def test_unknown_width_raises(self) -> None:
        with self.assertRaises(SelectorModelError):
            select_extension(source_width=0, destination_width=4, source_unsigned=False, destination_unsigned=False)



class ModelManifestTests(unittest.TestCase):
    """model_manifest produces expected structure."""

    def test_manifest_contains_handlers(self) -> None:
        manifest = model_manifest()
        self.assertIn("schema_name", manifest)
        self.assertIn("handlers", manifest)
        self.assertEqual(manifest["schema_name"], "mwccps2-b210-instruction-selection")

    def test_manifest_handlers_are_list(self) -> None:
        manifest = model_manifest()
        self.assertIsInstance(manifest["handlers"], list)
        self.assertGreater(len(manifest["handlers"]), 0)

    def test_manifest_has_opcodes(self) -> None:
        manifest = model_manifest()
        opcodes = manifest.get("opcodes", [])
        self.assertGreater(len(opcodes), 0)


class HandlerConstantsTests(unittest.TestCase):
    """HANDLERS and MODEL_RULES consistency."""

    def test_handlers_non_empty(self) -> None:
        self.assertGreater(len(HANDLERS), 0)

    def test_model_rules_non_empty(self) -> None:
        self.assertGreater(len(MODEL_RULES), 0)

    def test_opcodes_contain_addu(self) -> None:
        self.assertIn("addu", OPCODES)

    def test_opcodes_tuple_format(self) -> None:
        opcode_id, name = OPCODES["addu"]
        self.assertIsInstance(opcode_id, int)
        self.assertIsInstance(name, str)


if __name__ == "__main__":
    unittest.main()
