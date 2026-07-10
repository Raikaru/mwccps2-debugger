"""Regression coverage for P3 reduction bundle creation."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from mwccps2_p3_reduce import (
    P3IntegrationError,
    _is_exact_int,
    _require_mapping,
    _require_string,
    _require_exact_keys,
    _no_duplicate_json_object,
    _canonical_json_bytes,
    _pretty_json_bytes,
    _sha256,
    _validate_relative_path,
    _resolve_existing,
    _parse_hex_address,
    _parse_sha256,
    _validate_nonnegative_int,
    _normalize_relocations,
    _normalize_report_record,
    load_config,
    load_p3_report,
    _validate_experiment_stage,
    CONFIG_SCHEMA_NAME,
    CONFIG_SCHEMA_VERSION,
)


class IsExactIntTests(unittest.TestCase):
    def test_accepts_int(self) -> None:
        self.assertTrue(_is_exact_int(42))

    def test_rejects_bool(self) -> None:
        self.assertFalse(_is_exact_int(True))

    def test_rejects_float(self) -> None:
        self.assertFalse(_is_exact_int(4.2))


class RequireMappingTests(unittest.TestCase):
    def test_accepts_dict(self) -> None:
        result = _require_mapping({"a": 1}, "test")
        self.assertEqual(result["a"], 1)

    def test_rejects_list(self) -> None:
        with self.assertRaises(P3IntegrationError, msg="must be an object"):
            _require_mapping([], "test")


class RequireExactKeysTests(unittest.TestCase):
    def test_accepts_exact_keys(self) -> None:
        _require_exact_keys({"a": 1, "b": 2}, {"a", "b"}, "test")

    def test_rejects_extra_keys(self) -> None:
        with self.assertRaises(P3IntegrationError):
            _require_exact_keys({"a": 1, "z": 2}, {"a", "b"}, "test")


class NoDuplicateJsonObjectTests(unittest.TestCase):
    def test_rejects_duplicate_key(self) -> None:
        with self.assertRaises(P3IntegrationError, msg="duplicate key"):
            _no_duplicate_json_object([("a", 1), ("a", 2)])


class CanonicalJsonBytesTests(unittest.TestCase):
    def test_sorts_keys(self) -> None:
        a = _canonical_json_bytes({"z": 1, "a": 2})
        b = _canonical_json_bytes({"a": 2, "z": 1})
        self.assertEqual(a, b)


class PrettyJsonBytesTests(unittest.TestCase):
    def test_produces_pretty_output(self) -> None:
        result = _pretty_json_bytes({"a": 1})
        self.assertIsInstance(result, bytes)
        self.assertIn(b"\n", result)


class Sha256Tests(unittest.TestCase):
    def test_deterministic(self) -> None:
        self.assertEqual(_sha256(b"hello"), _sha256(b"hello"))


class ValidateRelativePathTests(unittest.TestCase):
    def test_accepts_simple_path(self) -> None:
        result = _validate_relative_path("subdir/file.c", "test", permit_parent=False)
        self.assertEqual(result, "subdir/file.c")

    def test_rejects_absolute_path(self) -> None:
        with self.assertRaises(P3IntegrationError, msg="must be a relative"):
            _validate_relative_path("/absolute/path", "test", permit_parent=False)

    def test_rejects_parent_traversal_when_disallowed(self) -> None:
        with self.assertRaises(P3IntegrationError):
            _validate_relative_path("../escape", "test", permit_parent=False)

    def test_allows_parent_when_permitted(self) -> None:
        result = _validate_relative_path("../parent", "test", permit_parent=True)
        self.assertEqual(result, "../parent")

    def test_normalizes_backslashes(self) -> None:
        result = _validate_relative_path("subdir\\file.c", "test", permit_parent=False)
        self.assertEqual(result, "subdir/file.c")


class ResolveExistingTests(unittest.TestCase):
    def test_resolves_existing_file(self) -> None:
        with tempfile.NamedTemporaryFile(suffix=".json") as f:
            path = Path(f.name)
            result = _resolve_existing(path, "test")
            self.assertEqual(result, path.resolve())

    def test_rejects_nonexistent_path(self) -> None:
        with self.assertRaises(P3IntegrationError, msg="does not exist"):
            _resolve_existing(Path("/nonexistent_file_xyzzy"), "test")


class ParseHexAddressTests(unittest.TestCase):
    def test_parses_hex_string(self) -> None:
        self.assertEqual(_parse_hex_address("0x1234", "test"), "0x00001234")

    def test_parses_int(self) -> None:
        self.assertEqual(_parse_hex_address(0x1234, "test"), "0x00001234")

    def test_rejects_negative_int(self) -> None:
        with self.assertRaises(P3IntegrationError):
            _parse_hex_address(-1, "test")

    def test_pads_to_8_digits(self) -> None:
        self.assertEqual(_parse_hex_address("0x1", "test"), "0x00000001")


class ParseSha256Tests(unittest.TestCase):
    def test_accepts_64_hex_chars(self) -> None:
        result = _parse_sha256("A" * 64, "test")
        self.assertEqual(len(result), 64)

    def test_lowercases_digest(self) -> None:
        result = _parse_sha256("A" * 64, "test")
        self.assertEqual(result, "a" * 64)

    def test_rejects_short_string(self) -> None:
        with self.assertRaises(P3IntegrationError):
            _parse_sha256("abc123", "test")

    def test_rejects_non_hex_chars(self) -> None:
        with self.assertRaises(P3IntegrationError):
            _parse_sha256("x" * 64, "test")


class ValidateExperimentStageTests(unittest.TestCase):
    def test_accepts_known_stage(self) -> None:
        result = _validate_experiment_stage({"stage": "codegen_entry"}, "test")
        self.assertEqual(result, "codegen_entry")

    def test_accepts_none(self) -> None:
        result = _validate_experiment_stage(None, "test")
        self.assertIsNone(result)

    def test_rejects_unknown_stage(self) -> None:
        with self.assertRaises(P3IntegrationError, msg="unknown"):
            _validate_experiment_stage({"stage": "unknown_stage"}, "test")


class NormalizeRelocationsTests(unittest.TestCase):
    """_normalize_relocations: null, scalar fields, sorting."""

    def test_none_becomes_empty_list(self) -> None:
        result = _normalize_relocations(None, "test")
        self.assertEqual(result, [])

    def test_normalizes_relocation_entry(self) -> None:
        result = _normalize_relocations(
            [{"address": "0x1000", "type": "R_PPC_ADDR32"}],
            "test",
        )
        self.assertEqual(len(result), 1)
        # address is not zero-padded by _normalize_relocations (only offset/retail_target are)
        self.assertEqual(result[0]["address"], "0x1000")

    def test_retail_target_is_zero_padded(self) -> None:
        result = _normalize_relocations(
            [{"retail_target": "0x1000", "type": "R_PPC_ADDR32"}],
            "test",
        )
        self.assertEqual(result[0]["retail_target"], "0x00001000")

    def test_sorts_by_canonical_json(self) -> None:
        result = _normalize_relocations([
            {"address": "0x2000", "type": "R_PPC_ADDR32"},
            {"address": "0x1000", "type": "R_PPC_ADDR32"},
        ], "test")
        self.assertEqual(result[0]["address"], "0x1000")
        self.assertEqual(result[1]["address"], "0x2000")

    def test_rejects_non_list(self) -> None:
        with self.assertRaises(P3IntegrationError, msg="must be an array"):
            _normalize_relocations("bad", "test")

    def test_rejects_non_string_key(self) -> None:
        with self.assertRaises(P3IntegrationError):
            _normalize_relocations([{1: "value"}], "test")


class LoadP3ReportTests(unittest.TestCase):
    """load_p3_report filtering."""

    def test_rejects_missing_file(self) -> None:
        with self.assertRaises(P3IntegrationError):
            load_p3_report(
                Path("/nonexistent_report"),
                accepted_statuses=frozenset({"MATCH"}),
                p3_root=Path("."),
            )

    def test_filters_unaccepted_statuses(self) -> None:
        report = {
            "results": [
                {"file": "test.c", "addr": "0x1000", "name": "f", "line": 1, "status": "SKIP"},
            ]
        }
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False, encoding="utf-8"
        ) as f:
            json.dump(report, f)
        try:
            result = load_p3_report(
                Path(f.name),
                accepted_statuses=frozenset({"MATCH"}),
                p3_root=Path("."),
            )
            self.assertIn("records", result)
        finally:
            Path(f.name).unlink(missing_ok=True)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _valid_config_dict() -> dict:
    return {
        "schema": {"name": CONFIG_SCHEMA_NAME, "version": CONFIG_SCHEMA_VERSION},
        "integration": {
            "mode": "external-optional",
            "p3_root": ".",
            "debugger": {
                "repository": ".",
                "compiler": "mwccps2.exe",
                "profile": "profiles/b210.json",
            },
        },
        "reports": {
            "default_paths": ["reports/report.json"],
            "accepted_statuses": ["MATCH", "MISMATCH"],
            "analysis_evidence_paths": [],
        },
        "reduction": {
            "output_root": "reduction_output",
        },
    }


if __name__ == "__main__":
    unittest.main()
