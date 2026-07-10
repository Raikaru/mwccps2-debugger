from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from solver.evidence import (
    EvidenceError, FailureRecord, PortableEvidenceRef, SolverEvidence, StageEvidence,
    load_solver_evidence, write_solver_evidence,
)

D = "b" * 64


class EvidenceArtifactTests(unittest.TestCase):
    def test_strict_round_trip_preserves_only_portable_evidence(self) -> None:
        evidence = SolverEvidence((FailureRecord(D, D, ("swap",), "failed", "direct_mismatch", None, False, None, (StageEvidence("ir", 0, "complete", D),), (PortableEvidenceRef("snapshot", D, "ir.0"),)),))
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "evidence.json"
            write_solver_evidence(path, evidence)
            self.assertEqual(load_solver_evidence(path), evidence)
            self.assertNotIn(directory, path.read_text(encoding="utf-8"))

    def test_duplicate_json_keys_are_rejected_not_last_key_wins(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "evidence.json"
            path.write_text('{"schema":{"name":"mwccps2-solver-evidence","version":1},"failures":[],"failures":[],"capture_gap_requests":[],"capture_gap_rejections":[]}', encoding="utf-8")
            with self.assertRaises(EvidenceError):
                load_solver_evidence(path)

    def test_missing_stage_digest_is_not_promoted_to_observed_equality(self) -> None:
        stage = StageEvidence("ir", 0, "missing")
        self.assertIsNone(stage.normalized_stage_sha256)
