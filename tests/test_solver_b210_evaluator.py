from __future__ import annotations

import json
import tempfile
import unittest
from hashlib import sha256
from pathlib import Path
from unittest.mock import patch

import solver.b210_evaluator as module
from solver.b210_evaluator import B210CandidateEvaluator, B210EvaluatorError, RESULT_FILENAME, compare

D = "c" * 64
SNAPSHOTS = {"stage_order": ["ir", "optional"], "stages": [{"stage": "ir", "sequence": 1, "capture_status": "complete", "normalized_stage_sha256": D, "graph_sha256": D, "pcode_text_sha256": D, "normalized_graph": {}, "pcode_text": "x"}]}


class FakeEvaluator(B210CandidateEvaluator):
    mismatch = False
    def _validate_platform(self): pass
    def _fingerprint(self): return ({"profile": "fake"}, {"exe": "fake"}, {"probe": "fake"})
    def _compile_direct(self, source, object_path, work): return {"object_sha256": D}
    def _compile_with_snapshots(self, source, object_path, work): return ({"object_sha256": "d" * 64 if self.mismatch else D}, SNAPSHOTS)


class B210EvaluatorContractTests(unittest.TestCase):
    def make_evaluator(self, root: Path) -> FakeEvaluator:
        source = root / "source.c"
        source.write_text("int f(void){return 0;}", encoding="utf-8")
        return FakeEvaluator(root / "compiler.exe", root / "gdb.exe", root / "profile.json", (), root / "out", 1, root, source)

    def test_compact_artifact_missing_optional_stage_and_reuse_compare(self) -> None:
        with tempfile.TemporaryDirectory() as directory, patch.object(module._experiment, "BUILD_DIRECTORY", Path(directory)), patch.object(module._experiment, "parse_snapshot_run", return_value=SNAPSHOTS):
            root = Path(directory)
            evaluator = self.make_evaluator(root)
            result = evaluator.evaluate("int f(void){return 0;}", "candidate")
            artifact = next((root / "out").iterdir())
            self.assertLess(len(artifact.name), 40)
            self.assertEqual(result.outcome, "success")
            self.assertEqual(result.stages[1].status, "missing")
            reused = evaluator.evaluate("int f(void){return 0;}", "candidate")
            self.assertEqual(reused.outcome, "success")
            self.assertTrue(compare(result, reused)["final_object_equal"])

    def test_direct_instrumented_drift_is_not_success(self) -> None:
        with tempfile.TemporaryDirectory() as directory, patch.object(module._experiment, "BUILD_DIRECTORY", Path(directory)):
            evaluator = self.make_evaluator(Path(directory))
            evaluator.mismatch = True
            result = evaluator.evaluate("int f(void){return 1;}", "candidate")
            self.assertEqual((result.outcome, result.error_kind), ("object_mismatch", "object_invariant"))

    def test_cached_artifact_tampering_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory, patch.object(module._experiment, "BUILD_DIRECTORY", Path(directory)), patch.object(module._experiment, "parse_snapshot_run", return_value=SNAPSHOTS):
            root = Path(directory)
            evaluator = self.make_evaluator(root)
            source = "int f(void){return 2;}"
            evaluator.evaluate(source, "candidate")
            result_path = next((root / "out").iterdir()) / RESULT_FILENAME
            original_bytes = result_path.read_bytes()
            cases = (
                (lambda value: value.update({"extra": 1}), "invalid field set"),
                (lambda value: value["objects"].update({"direct_sha256": "bad"}), "direct object must be"),
                (lambda value: value.update({"outcome": "success", "objects": {"direct_sha256": D, "instrumented_sha256": "d" * 64}}), "violates object or stage invariants"),
                (lambda value: value["stages"][0].update({"status": "bogus"}), "invalid stage status"),
                (lambda value: value["stages"][0]["occurrences"][0].__setitem__(0, 0), "unordered stage occurrences"),
            )
            for mutate, message in cases:
                with self.subTest(message=message):
                    result_path.write_bytes(original_bytes)
                    value = json.loads(original_bytes)
                    mutate(value)
                    result_path.write_bytes(module._canonical_bytes(value))
                    with self.assertRaisesRegex(B210EvaluatorError, message):
                        evaluator.evaluate(source, "candidate")
            # Duplicate key is caught before JSON decoding can discard evidence.
            # Reparsed snapshots must agree with retained stage summaries.
            other_source = "int f(void){return 3;}"
            evaluator.evaluate(other_source, "other")
            disagreement = json.loads(json.dumps(SNAPSHOTS))
            disagreement["stages"][0]["normalized_stage_sha256"] = "e" * 64
            with patch.object(module._experiment, "parse_snapshot_run", return_value=disagreement):
                with self.assertRaises(B210EvaluatorError):
                    evaluator.evaluate(other_source, "other")
            result_path.write_text('{"schema":{},"schema":{}}\n', encoding="utf-8")
            with self.assertRaisesRegex(B210EvaluatorError, "duplicate JSON keys"):
                evaluator.evaluate(source, "candidate")
