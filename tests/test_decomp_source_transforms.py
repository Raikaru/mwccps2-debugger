from __future__ import annotations

import unittest

from decomp.mwccps2_transforms import apply_candidates, catalog, enumerate_candidates


class Mwccps2CatalogTransformTests(unittest.TestCase):
    def test_disabled_mask_transform_is_not_reachable_by_default(self) -> None:
        source = "int f(unsigned int x) { return x; }"
        default_ids = {app.spec_id for app in enumerate_candidates(source, integer_type="unsigned int")}
        all_ids = {app.spec_id for app in enumerate_candidates(source, include_disabled=True, integer_type="unsigned int")}
        self.assertNotIn("unsigned-mask-insert", default_ids)
        self.assertIn("unsigned-mask-insert", all_ids)
        self.assertTrue(all(spec.evidence["checked_in_reducer"] for spec in catalog()))

    def test_mask_temporary_and_branch_candidates_preserve_assumption_gate(self) -> None:
        source = "int f(int x) { if (x) { return x + 1; } else { return x & 0xFFFFu; } }"
        apps = enumerate_candidates(source, include_disabled=True, integer_type="unsigned int")
        ids = {app.spec_id for app in apps}
        self.assertTrue({"condition-invert-branch-swap", "unsigned-mask-remove"} <= ids)
        branch = next(app for app in apps if app.spec_id == "condition-invert-branch-swap")
        result = apply_candidates(source, (branch,))
        self.assertEqual(result.source, source)
        permitted = apply_candidates(source, (branch,), allow_assumptions=True)
        self.assertIn("if (!(x))", permitted.source)
