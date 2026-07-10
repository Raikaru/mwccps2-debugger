"""Regression coverage for capture directory normalization and comparison."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from transports.capture_compare import (
    CAPTURE_COMPARISON_SCHEMA_NAME,
    CAPTURE_COMPARISON_SCHEMA_VERSION,
    _normalize_value,
    normalize_capture_directory,
    compare_capture_directories,
    write_comparison,
    TransportError,
)


class NormalizeValueTests(unittest.TestCase):
    """_normalize_value recursive host-path field stripping."""

    def test_strips_host_path_keys(self) -> None:
        value = {"path": "/home/user/build.o", "name": "stage1"}
        result = _normalize_value(value)
        self.assertNotIn("path", result)
        self.assertIn("name", result)

    def test_recurses_into_nested_dicts(self) -> None:
        value = {"outer": {"path": "/tmp/test", "key": 42}}
        result = _normalize_value(value)
        outer = result["outer"]
        self.assertNotIn("path", outer)
        self.assertEqual(outer["key"], 42)

    def test_recurses_into_lists(self) -> None:
        value = [{"path": "/tmp/a"}, {"path": "/tmp/b", "x": 1}]
        result = _normalize_value(value)
        self.assertEqual(len(result), 2)
        for item in result:
            self.assertNotIn("path", item)

    def test_passes_through_primitives(self) -> None:
        for val in (None, True, "hello", 42, 3.14):
            self.assertEqual(_normalize_value(val), val)

    def test_raises_on_unsupported_types(self) -> None:
        with self.assertRaises(TransportError, msg="unsupported value type"):
            _normalize_value(bytearray(b"test"))

    def test_sorts_dict_keys(self) -> None:
        result = _normalize_value({"z": 1, "a": 2})
        keys = list(result.keys())
        self.assertEqual(keys, ["a", "z"])


class NormalizeCaptureDirectoryTests(unittest.TestCase):
    """normalize_capture_directory with synthesized fixtures."""

    def test_rejects_nonexistent_directory(self) -> None:
        with self.assertRaises(TransportError, msg="cannot resolve"):
            normalize_capture_directory(Path("/nonexistent_capture_dir_xyzzy"))

    def test_rejects_file_instead_of_directory(self) -> None:
        with tempfile.NamedTemporaryFile(suffix=".json") as f:
            with self.assertRaises(TransportError, msg="not a directory"):
                normalize_capture_directory(Path(f.name))

    def test_rejects_directory_without_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(TransportError, msg="member is missing"):
                normalize_capture_directory(Path(tmp))

    def test_rejects_malformed_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, "snapshot-manifest.json").write_text("not json", encoding="utf-8")
            with self.assertRaises(TransportError, msg="not valid JSON"):
                normalize_capture_directory(Path(tmp))

    def test_accepts_empty_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            manifest = {"stages": []}
            Path(tmp, "snapshot-manifest.json").write_text(
                json.dumps(manifest), encoding="utf-8"
            )
            result = normalize_capture_directory(Path(tmp))
            self.assertIn("documents", result)
            self.assertIn("normalization", result)

    def test_accepts_manifest_with_no_stages(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            manifest = {"stages": []}
            Path(tmp, "snapshot-manifest.json").write_text(
                json.dumps(manifest), encoding="utf-8"
            )
            result = normalize_capture_directory(Path(tmp))
            docs = result["documents"]
            self.assertIn("snapshot-manifest.json", docs)

    def test_normalization_info_present(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            manifest = {"stages": []}
            Path(tmp, "snapshot-manifest.json").write_text(
                json.dumps(manifest), encoding="utf-8"
            )
            result = normalize_capture_directory(Path(tmp))
            norm = result["normalization"]
            self.assertIn("host_path_keys_removed", norm)
            self.assertIn("line_endings", norm)

    def test_line_endings_normalized_in_text(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            manifest = {
                "stages": [
                    {
                        "file": "stage1.json",
                        "name": "codegen_entry",
                    }
                ]
            }
            stage = {
                "pcode_text_file": "stage1_pcode.txt",
            }
            Path(tmp, "snapshot-manifest.json").write_text(
                json.dumps(manifest), encoding="utf-8"
            )
            Path(tmp, "stage1.json").write_text(
                json.dumps(stage), encoding="utf-8"
            )
            Path(tmp, "stage1_pcode.txt").write_bytes(b"line1\r\nline2\rline3\n")
            result = normalize_capture_directory(Path(tmp))
            # Verify CR and CRLF normalized to LF
            text = result["documents"]["stage1_pcode.txt"]
            self.assertEqual(text, "line1\nline2\nline3\n")


class CompareCaptureDirectoriesTests(unittest.TestCase):
    """compare_capture_directories between baseline and candidate."""

    def test_identical_normalized_directories(self) -> None:
        manifest = {"stages": []}
        with tempfile.TemporaryDirectory() as baseline, \
             tempfile.TemporaryDirectory() as candidate:
            Path(baseline, "snapshot-manifest.json").write_text(
                json.dumps(manifest), encoding="utf-8"
            )
            Path(candidate, "snapshot-manifest.json").write_text(
                json.dumps(manifest), encoding="utf-8"
            )
            result = compare_capture_directories(
                Path(baseline), Path(candidate)
            )
            self.assertEqual(result["equal"], True)

    def test_different_content_detected(self) -> None:
        with tempfile.TemporaryDirectory() as baseline, \
             tempfile.TemporaryDirectory() as candidate:
            Path(baseline, "snapshot-manifest.json").write_text(
                json.dumps({"stages": []}), encoding="utf-8"
            )
            Path(candidate, "snapshot-manifest.json").write_text(
                json.dumps({"stages": [{"file": "x.json"}]}), encoding="utf-8"
            )
            Path(candidate, "x.json").write_text(
                json.dumps({"pcode_text_file": "x_pcode.txt"}), encoding="utf-8"
            )
            Path(candidate, "x_pcode.txt").write_bytes(b"different\n")
            result = compare_capture_directories(
                Path(baseline), Path(candidate)
            )
            self.assertEqual(result["equal"], False)

    def test_deterministic_result(self) -> None:
        manifest = {"stages": []}
        with tempfile.TemporaryDirectory() as baseline, \
             tempfile.TemporaryDirectory() as candidate:
            Path(baseline, "snapshot-manifest.json").write_text(
                json.dumps(manifest), encoding="utf-8"
            )
            Path(candidate, "snapshot-manifest.json").write_text(
                json.dumps(manifest), encoding="utf-8"
            )
            r1 = compare_capture_directories(Path(baseline), Path(candidate))
            r2 = compare_capture_directories(Path(baseline), Path(candidate))
            self.assertEqual(r1, r2)


class WriteComparisonTests(unittest.TestCase):
    """write_comparison atomic write."""

    def test_writes_valid_json(self) -> None:
        comparison = {
            "schema": {
                "name": CAPTURE_COMPARISON_SCHEMA_NAME,
                "version": CAPTURE_COMPARISON_SCHEMA_VERSION,
            },
            "documents_identical": True,
        }
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "comparison.json"
            write_comparison(path, comparison)
            self.assertTrue(path.exists())
            loaded = json.loads(path.read_text(encoding="utf-8"))
            self.assertTrue(loaded["documents_identical"])


if __name__ == "__main__":
    unittest.main()
