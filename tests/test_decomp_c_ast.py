from __future__ import annotations

import unittest

from decomp.c_ast import CParseError, lex_c, parse_c
from decomp.source_transforms import (
    SemanticGuard, TransformRejected, TransformSpec, apply_applications,
    guarded_application,
)


class LosslessCParsingTests(unittest.TestCase):
    def test_round_trip_preserves_crlf_comments_directive_and_nested_expression(self) -> None:
        source = "  #define ADD(a, b) ((a) + (b))\r\nint f(int x) { /* keep */ return (x + 1) * (x - 2); }\r\n"
        unit = parse_c(source)
        self.assertEqual("".join(token.text for token in unit.tokens), source)
        self.assertTrue(any(token.kind == "directive" for token in unit.tokens))
        mult = next(node for node in unit.nodes if node.kind == "multiplicative")
        self.assertEqual(unit.source[mult.start:mult.end], "x + 1) * (x - 2")

    def test_malformed_delimiters_are_explicit(self) -> None:
        for source in ("int f(void) { return (1; }", "/* unclosed", "int f(void) { return 1; "):
            with self.subTest(source=source):
                with self.assertRaises(CParseError):
                    parse_c(source)

    def test_node_ids_and_spans_are_stable_when_prefix_is_unchanged(self) -> None:
        original = "int f(void) { return a + (b * c); }\n"
        extended = original + "int ignored;\n"
        first = parse_c(original)
        second = parse_c(extended)
        one = next(node for node in first.nodes if node.kind == "additive")
        two = next(node for node in second.nodes if node.kind == "additive")
        self.assertEqual((one.id, one.start, one.end), (two.id, two.start, two.end))


class SourceTransformContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.unit = parse_c("int f(void) { return a + b; }\n")
        self.node = next(node for node in self.unit.nodes if node.kind == "additive")
        self.spec = TransformSpec("swap", "Swap", ("additive",), "semantic", (), {}, "reachable", True)

    def test_assumption_gated_application_is_rejected_without_authorization(self) -> None:
        app = guarded_application(self.spec, self.unit, self.node.id, "b + a", assumptions=("types proven",))
        denied = apply_applications(self.unit, (app,))
        self.assertEqual(denied.rejected[0].rejection, "semantic assumptions were not authorized")
        allowed = apply_applications(self.unit, (app,), allow_assumptions=True)
        self.assertIn("return b + a;", allowed.source)

    def test_overlapping_edits_cannot_silently_corrupt_source(self) -> None:
        outer = guarded_application(self.spec, self.unit, self.node.id, "b + a")
        atom = next(node for node in self.unit.nodes if node.kind == "atom" and self.unit.source[node.start:node.end] == "a")
        inner_spec = TransformSpec("atom", "Atom", ("atom",), "semantic", (), {}, "reachable", True)
        inner = guarded_application(inner_spec, self.unit, atom.id, "z")
        with self.assertRaises(TransformRejected):
            apply_applications(self.unit, (outer, inner))
