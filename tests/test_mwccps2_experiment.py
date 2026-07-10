"""Regression coverage for the MWCCPS2 experiment module."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from mwccps2_experiment import (
    ExperimentError,
    _is_exact_int,
    _require_mapping,
    _require_string,
    _reject_unknown_keys,
    _no_duplicate_json_object,
    _canonical_json_bytes,
    _digest_json,
    _normalize_text,
    _normalize_volatile_snapshot_value,
    _path_in_directory,
    _strip_c_comments_and_literals,
    _exported_function_signature,
    _validate_compiler_flags,
    _validate_source_path,
    _format_command,
    _format_process_output,
    _gdb_quote,
    _gdb_path,
    _expect_schema,
    compare_variant_to_baseline,
    SUMMARY_SCHEMA_NAME,
    SUMMARY_SCHEMA_VERSION,
)


class IsExactIntTests(unittest.TestCase):
    """_is_exact_int type discrimination."""

    def test_accepts_int(self) -> None:
        self.assertTrue(_is_exact_int(42))

    def test_rejects_bool(self) -> None:
        self.assertFalse(_is_exact_int(True))

    def test_rejects_float(self) -> None:
        self.assertFalse(_is_exact_int(4.2))

    def test_rejects_string(self) -> None:
        self.assertFalse(_is_exact_int("42"))


class RequireMappingTests(unittest.TestCase):
    """_require_mapping validation."""

    def test_accepts_dict(self) -> None:
        result = _require_mapping({"a": 1}, "test")
        self.assertEqual(result["a"], 1)

    def test_rejects_list(self) -> None:
        with self.assertRaises(ExperimentError, msg="must be an object"):
            _require_mapping([1, 2], "test")

    def test_rejects_none(self) -> None:
        with self.assertRaises(ExperimentError, msg="must be an object"):
            _require_mapping(None, "test")


class RejectUnknownKeysTests(unittest.TestCase):
    """_reject_unknown_keys strict key set validation."""

    def test_accepts_expected_keys(self) -> None:
        _reject_unknown_keys({"a": 1, "b": 2}, {"a", "b"}, "test")  # no error

    def test_rejects_unexpected_key(self) -> None:
        with self.assertRaises(ExperimentError, msg="unknown key"):
            _reject_unknown_keys({"a": 1, "z": 2}, {"a", "b"}, "test")

    def test_detects_missing_required_keys(self) -> None:
        with self.assertRaises(ExperimentError, msg="missing required"):
            _reject_unknown_keys({"a": 1}, {"a", "b", "c"}, "test")


class NoDuplicateJsonObjectTests(unittest.TestCase):
    """_no_duplicate_json_object duplicate key detection."""

    def test_accepts_unique_keys(self) -> None:
        result = _no_duplicate_json_object([("a", 1), ("b", 2)])
        self.assertEqual(result, {"a": 1, "b": 2})

    def test_rejects_duplicate_key(self) -> None:
        with self.assertRaises(ExperimentError, msg="duplicate key"):
            _no_duplicate_json_object([("a", 1), ("a", 2)])


class CanonicalJsonBytesTests(unittest.TestCase):
    """_canonical_json_bytes stable serialization."""

    def test_sorts_keys(self) -> None:
        result_a = _canonical_json_bytes({"z": 1, "a": 2})
        result_b = _canonical_json_bytes({"a": 2, "z": 1})
        self.assertEqual(result_a, result_b)

    def test_deterministic(self) -> None:
        self.assertEqual(
            _canonical_json_bytes({"b": 2, "a": 1}),
            _canonical_json_bytes({"a": 1, "b": 2}),
        )


class DigestJsonTests(unittest.TestCase):
    """_digest_json SHA-256 of canonical JSON."""

    def test_deterministic_digest(self) -> None:
        self.assertEqual(
            _digest_json({"a": 1}),
            _digest_json({"a": 1}),
        )

    def test_different_values_differ(self) -> None:
        self.assertNotEqual(
            _digest_json({"a": 1}),
            _digest_json({"a": 2}),
        )


class NormalizeTextTests(unittest.TestCase):
    """_normalize_text CRLF/CR normalization."""

    def test_converts_crlf_to_lf(self) -> None:
        self.assertEqual(_normalize_text("a\r\nb"), "a\nb")

    def test_converts_cr_to_lf(self) -> None:
        self.assertEqual(_normalize_text("a\rb"), "a\nb")

    def test_preserves_lf(self) -> None:
        self.assertEqual(_normalize_text("a\nb"), "a\nb")

    def test_mixed(self) -> None:
        self.assertEqual(_normalize_text("a\r\nb\rc"), "a\nb\nc")


class NormalizeVolatileSnapshotValueTests(unittest.TestCase):
    """_normalize_volatile_snapshot_value drops timestamps."""

    def test_strips_volatile_keys(self) -> None:
        value = {"captured_at": "2024-01-01", "path": "/tmp/x.json", "key": 42}
        result = _normalize_volatile_snapshot_value(value)
        self.assertNotIn("captured_at", result)
        self.assertNotIn("path", result)
        self.assertIn("key", result)

    def test_passes_primitives(self) -> None:
        for v in (None, True, 42, "hello"):
            self.assertEqual(_normalize_volatile_snapshot_value(v), v)


class RequireStringTests(unittest.TestCase):
    """_require_string validation."""

    def test_accepts_nonempty_string(self) -> None:
        self.assertEqual(_require_string("hello", "test"), "hello")

    def test_rejects_empty_string(self) -> None:
        with self.assertRaises(ExperimentError, msg="must be a non-empty string"):
            _require_string("", "test")

    def test_rejects_non_string(self) -> None:
        with self.assertRaises(ExperimentError, msg="must be a string"):
            _require_string(42, "test")


class ValidateCompilerFlagsTests(unittest.TestCase):
    """_validate_compiler_flags acceptance."""

    def test_accepts_valid_flags(self) -> None:
        result = _validate_compiler_flags(["-O4"])
        self.assertEqual(result, ["-O4"])

    def test_rejects_non_list(self) -> None:
        with self.assertRaises(ExperimentError, msg="must be an array"):
            _validate_compiler_flags("-O4")

    def test_rejects_list_with_non_strings(self) -> None:
        with self.assertRaises(ExperimentError, msg="must be strings"):
            _validate_compiler_flags(["-O4", 42])


class FormatCommandTests(unittest.TestCase):
    """_format_command text rendering."""

    def test_simple_command(self) -> None:
        result = _format_command(["gdb", "--batch"])
        self.assertIn("gdb", result)

    def test_path_with_spaces(self) -> None:
        result = _format_command(["Program Files\\gdb.exe"])
        self.assertIn("gdb.exe", result)


class FormatProcessOutputTests(unittest.TestCase):
    """_format_process_output formatting."""

    def test_stdout_only(self) -> None:
        from subprocess import CompletedProcess
        cp = CompletedProcess([], 0, stdout="hello", stderr="")
        result = _format_process_output(cp)
        self.assertIn("hello", result)

    def test_no_output(self) -> None:
        from subprocess import CompletedProcess
        cp = CompletedProcess([], 0, stdout="", stderr="")
        result = _format_process_output(cp)
        self.assertEqual(result, "(no process output)")


class GdbQuoteTests(unittest.TestCase):
    """_gdb_quote delegation."""

    def test_quotes_argument(self) -> None:
        result = _gdb_quote("test")
        self.assertEqual(result, '"test"')


class ExpectSchemaTests(unittest.TestCase):
    """_expect_schema schema validation."""

    def test_accepts_correct_schema(self) -> None:
        payload = {"schema": {"name": "test-schema", "version": 1}}
        _expect_schema(payload, "test-schema", 1, "test")  # no error

    def test_rejects_wrong_name(self) -> None:
        payload = {"schema": {"name": "wrong", "version": 1}}
        with self.assertRaises(ExperimentError, msg="schema.name must be"):
            _expect_schema(payload, "test-schema", 1, "test")

    def test_rejects_wrong_version(self) -> None:
        payload = {"schema": {"name": "test-schema", "version": 2}}
        with self.assertRaises(ExperimentError, msg="schema.version must be"):
            _expect_schema(payload, "test-schema", 1, "test")

    def test_rejects_non_mapping_schema(self) -> None:
        payload = {"schema": "not-a-dict"}
        with self.assertRaises(ExperimentError, msg="must be an object"):
            _expect_schema(payload, "test-schema", 1, "test")


class CompareVariantToBaselineTests(unittest.TestCase):
    """compare_variant_to_baseline comparison logic."""

    def test_identical_returns_equal(self) -> None:
        stage = {
            "stage": "codegen_entry",
            "pcode_text": "same",
            "normalized_graph": {"a": 1},
        }
        baseline = {"stage_order": ["codegen_entry"], "stages": [stage]}
        variant = {"stage_order": ["codegen_entry"], "stages": [stage]}
        result = compare_variant_to_baseline(
            "base", baseline, "var", variant,
            {"object_sha256": "abc"}, {"object_sha256": "abc"},
        )
        self.assertTrue(result["final_object_equal"])
        self.assertIsNone(result["earliest_pcode_divergence"])
        self.assertIsNone(result["earliest_raw_graph_difference"])

    def test_different_pcode_detected(self) -> None:
        baseline = {"stage_order": ["entry"], "stages": [{"stage": "entry", "sequence": 0, "capture_status": "completed", "normalized_stage_sha256": "a", "graph_sha256": "b", "pcode_text_sha256": "c", "pcode_text": "base_text", "normalized_graph": {"a": 1}}]}
        variant = {"stage_order": ["entry"], "stages": [{"stage": "entry", "sequence": 0, "capture_status": "completed", "normalized_stage_sha256": "a", "graph_sha256": "b", "pcode_text_sha256": "d", "pcode_text": "variant_text", "normalized_graph": {"a": 1}}]}
        result = compare_variant_to_baseline(
            "base", baseline, "var", variant,
            {"object_sha256": "abc"}, {"object_sha256": "abc"},
        )
        self.assertIsNotNone(result["earliest_pcode_divergence"])
        self.assertEqual(result["earliest_pcode_divergence"]["reason"], "deterministic_pcode_text_differs")

    def test_different_graph_detected(self) -> None:
        baseline = {"stage_order": ["entry"], "stages": [{"stage": "entry", "sequence": 0, "capture_status": "completed", "normalized_stage_sha256": "a", "graph_sha256": "b", "pcode_text_sha256": "c", "pcode_text": "same", "normalized_graph": {"a": 1}}]}
        variant = {"stage_order": ["entry"], "stages": [{"stage": "entry", "sequence": 0, "capture_status": "completed", "normalized_stage_sha256": "a", "graph_sha256": "d", "pcode_text_sha256": "c", "pcode_text": "same", "normalized_graph": {"a": 2}}]}
        result = compare_variant_to_baseline(
            "base", baseline, "var", variant,
            {"object_sha256": "abc"}, {"object_sha256": "abc"},
        )
        self.assertIsNotNone(result["earliest_raw_graph_difference"])

    def test_missing_stages_reported(self) -> None:
        baseline = {"stage_order": ["entry"], "stages": [{"stage": "entry", "pcode_text": "t", "normalized_graph": {}}]}
        variant = {"stage_order": [], "stages": []}
        result = compare_variant_to_baseline(
            "base", baseline, "var", variant,
            {"object_sha256": "abc"}, {"object_sha256": "def"},
        )
        self.assertGreater(len(result["missing_stages"]), 0)
        self.assertFalse(result["final_object_equal"])

    def test_capture_count_differences_reported(self) -> None:
        baseline = {
            "stage_order": ["entry"],
            "stages": [
                {"stage": "entry", "pcode_text": "t", "normalized_graph": {}},
                {"stage": "entry", "pcode_text": "t2", "normalized_graph": {}},
            ]
        }
        variant = {
            "stage_order": ["entry"],
            "stages": [
                {"stage": "entry", "pcode_text": "t", "normalized_graph": {}},
            ]
        }
        result = compare_variant_to_baseline(
            "base", baseline, "var", variant,
            {"object_sha256": "abc"}, {"object_sha256": "abc"},
        )
        self.assertGreater(len(result["capture_count_differences"]), 0)


if __name__ == "__main__":
    unittest.main()
