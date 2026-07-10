"""Regression coverage for decomp frontend optimization predictions."""

from __future__ import annotations

import json
import unittest

from decomp.frontend_optimizations import (
    FrontendOptimizationModelError,
    predict_variant,
    predict_checked_in_variants,
    canonical_prediction_json,
    _PREDICTIONS,
    _VARIANT_ORDER,
)


class PredictVariantTests(unittest.TestCase):
    """predict_variant per-reducer/per-variant predictions."""

    def test_known_reducer_and_variant_succeeds(self) -> None:
        # Pick the first known reducer and its first variant
        reducer = next(iter(_PREDICTIONS))
        variants = _PREDICTIONS[reducer]
        variant = next(iter(variants))
        result = predict_variant(reducer, variant)
        self.assertIn("schema", result)
        self.assertIn("outcome", result)
        self.assertIn("evidence", result)
        self.assertEqual(result["schema"]["name"], "mwccps2-frontend-optimization-prediction")

    def test_unknown_reducer_raises(self) -> None:
        with self.assertRaises(FrontendOptimizationModelError, msg="unknown reducer"):
            predict_variant("nonexistent_reducer", "variant_a")

    def test_known_reducer_unknown_variant_raises(self) -> None:
        reducer = next(iter(_PREDICTIONS))
        with self.assertRaises(FrontendOptimizationModelError, msg="unknown variant"):
            predict_variant(reducer, "nonexistent_variant")

    def test_all_reducers_have_variants(self) -> None:
        for reducer, variants in _PREDICTIONS.items():
            self.assertGreater(len(variants), 0, f"{reducer} has no variants")

    def test_prediction_has_expected_fields(self) -> None:
        reducer = next(iter(_PREDICTIONS))
        variant = next(iter(_PREDICTIONS[reducer]))
        result = predict_variant(reducer, variant)
        self.assertIn("outcome", result)
        self.assertIn("predicate", result)

    def test_prediction_has_pipeline_owner(self) -> None:
        reducer = next(iter(_PREDICTIONS))
        variant = next(iter(_PREDICTIONS[reducer]))
        result = predict_variant(reducer, variant)
        evidence = result["evidence"]
        self.assertIn("pipeline", result)

    def test_prediction_deterministic(self) -> None:
        reducer = next(iter(_PREDICTIONS))
        variant = next(iter(_PREDICTIONS[reducer]))
        self.assertEqual(
            predict_variant(reducer, variant),
            predict_variant(reducer, variant),
        )


class PredictCheckedInVariantsTests(unittest.TestCase):
    """predict_checked_in_variants produces sorted results."""

    def test_returns_list(self) -> None:
        results = predict_checked_in_variants()
        self.assertIsInstance(results, list)

    def test_all_results_have_schema(self) -> None:
        results = predict_checked_in_variants()
        for r in results:
            self.assertIn("schema", r)
            self.assertEqual(r["schema"]["name"], "mwccps2-frontend-optimization-prediction")

    def test_nonempty(self) -> None:
        results = predict_checked_in_variants()
        self.assertGreater(len(results), 0)

    def test_deterministic_order(self) -> None:
        self.assertEqual(
            predict_checked_in_variants(),
            predict_checked_in_variants(),
        )

    def test_each_result_has_expected_keys(self) -> None:
        results = predict_checked_in_variants()
        for r in results:
            self.assertIn("reducer", r)
            self.assertIn("variant", r)
            self.assertIn("outcome", r)
            self.assertIn("evidence", r)


class CanonicalPredictionJsonTests(unittest.TestCase):
    """canonical_prediction_json produces stable output."""

    def test_produces_valid_json(self) -> None:
        reducer = next(iter(_PREDICTIONS))
        variant = next(iter(_PREDICTIONS[reducer]))
        text = canonical_prediction_json(reducer, variant)
        parsed = json.loads(text)
        self.assertIn("schema", parsed)

    def test_deterministic_output(self) -> None:
        reducer = next(iter(_PREDICTIONS))
        variant = next(iter(_PREDICTIONS[reducer]))
        self.assertEqual(
            canonical_prediction_json(reducer, variant),
            canonical_prediction_json(reducer, variant),
        )


if __name__ == "__main__":
    unittest.main()
