from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from solver.search import (
    CandidateEvaluation, Objective, SearchConfig, SearchStateError, StageObjective,
    StageObservation, load_checkpoint, run_search,
)

D = "a" * 64
CATALOG = ({"id": "swap"},)


class GuidedSearchTests(unittest.TestCase):
    def test_depth_two_search_avoids_reapplying_same_application(self) -> None:
        def enumerate_(source, _catalog, _candidate):
            return ({"spec_id": "swap", "node_id": "left"}, {"spec_id": "swap", "node_id": "right"})
        def apply(source, app):
            return source + app["node_id"]
        result = run_search("base", CATALOG, enumerate_, apply, lambda _: CandidateEvaluation(), config=SearchConfig(max_depth=2))
        self.assertEqual({candidate.source for candidate in result.candidates}, {"base", "baseleft", "baseright", "baseleftright", "baserightleft"})
        self.assertTrue(any(row["outcome"] == "duplicate_application" for row in result.attempts))

    def test_only_complete_digest_mismatch_prunes(self) -> None:
        objective = Objective((StageObjective("ir", D, True),))
        evaluations = {"base": CandidateEvaluation((StageObservation("ir", "partial"),)), "basex": CandidateEvaluation((StageObservation("ir", "complete", D),))}
        result = run_search("base", CATALOG, lambda *_: ({"spec_id": "swap", "node_id": "n"},), lambda source, _: source + "x", lambda candidate: evaluations[candidate.source], objective, SearchConfig(max_depth=1, required_stages=("ir",)))
        self.assertEqual(result.status, "exhausted")
        self.assertEqual(result.best_candidate.source, "basex")
        self.assertFalse(result.candidates[-1].rejections)

    def test_required_missing_stage_blocks_while_optional_missing_does_not(self) -> None:
        evaluator = lambda _: CandidateEvaluation((StageObservation("optional", "missing"),))
        optional = run_search("base", (), lambda *_: (), lambda *_: "", evaluator, config=SearchConfig())
        required = run_search("base", (), lambda *_: (), lambda *_: "", evaluator, config=SearchConfig(required_stages=("required",)))
        self.assertEqual(optional.status, "exhausted")
        self.assertEqual(required.status, "blocked")

    def test_retail_diff_ranks_nearer_nonmatches_before_farther(self) -> None:
        def enum(source, *_):
            return ({"spec_id": "swap", "node_id": source},) if source == "base" else ()
        def apply(source, app):
            return "near" if app["node_id"] == "base" else source
        def evaluate(candidate):
            return CandidateEvaluation(retail_status="NON_MATCH", retail_diff={"base": 9, "near": 2}[candidate.source])
        result = run_search("base", CATALOG, enum, apply, evaluate, config=SearchConfig(max_depth=1))
        self.assertEqual(result.candidates[0].source, "near")

    def test_match_requires_authoritative_p3_and_checkpoint_rejects_drift(self) -> None:
        with self.assertRaises(ValueError):
            CandidateEvaluation(retail_status="MATCH", retail_verifier="fake", retail_authoritative=True)
        with tempfile.TemporaryDirectory() as directory:
            checkpoint = Path(directory) / "state.json"
            result = run_search("base", (), lambda *_: (), lambda *_: "", lambda _: CandidateEvaluation(), checkpoint_path=checkpoint)
            self.assertEqual(result.status, "exhausted")
            with self.assertRaises(SearchStateError):
                load_checkpoint(checkpoint, "changed", (), Objective(), SearchConfig())
            resumed = run_search("base", (), lambda *_: (), lambda *_: "", lambda _: CandidateEvaluation(), checkpoint_path=checkpoint, resume=True)
            self.assertEqual(resumed.status, "exhausted")

    def test_catalog_rejects_nested_absolute_host_path(self) -> None:
        with self.assertRaises(ValueError):
            run_search(
                "base",
                ({"id": "swap", "evidence": {"host": "C:\\Users\\builder\\capture"}},),
                lambda *_: (),
                lambda *_: "",
                lambda _: CandidateEvaluation(),
            )

    def test_rejects_posix_and_unc_host_paths_anywhere_in_durable_inputs(self) -> None:
        for source in ("// /home/builder/private.c", r"// \\server\share\retail.c"):
            with self.subTest(source=source):
                with self.assertRaisesRegex(ValueError, "host paths"):
                    run_search(source, (), lambda *_: (), lambda *_: "", lambda _: CandidateEvaluation())
