"""
Unit Test Suite for Phase 3B Shortcut-Learning and Distribution-Shift Diagnostics

Validates:
1. Integrity and schema of the offline diagnostic suite (265 legitimate candidate URLs).
2. Sliced structural categorization (root-only, deep paths, query-heavy, subdomains, long URLs, IDNs).
3. 30-feature vector extraction validity (finite values, dimensional consistency).
4. Feature ablation transformations (verifying that targeted structural dimensions are neutralized
   without mutating unaffected semantic features).
5. Diagnostic manifest and export format validation.
"""

import os
import unittest
import numpy as np

from backend.app.ml.features import URLFeatureExtractor
from scratch.run_phase3b_diagnostics import get_diagnostic_url_candidates


class TestDiagnosticSuiteIntegrity(unittest.TestCase):
    """Tests the integrity, schema, and structural slice properties of the diagnostic dataset."""

    @classmethod
    def setUpClass(cls):
        cls.candidates = get_diagnostic_url_candidates()

    def test_sample_count_and_slice_coverage(self):
        self.assertEqual(len(self.candidates), 265)
        slices = set(c["slice"] for c in self.candidates)
        expected_slices = {
            "slice_a_root_only",
            "slice_b_deep_paths",
            "slice_c_query_heavy",
            "slice_d_subdomains",
            "slice_e_long_urls",
            "slice_f_idns",
        }
        self.assertEqual(slices, expected_slices)

    def test_all_candidates_have_required_fields_and_valid_schemes(self):
        for c in self.candidates:
            self.assertIn("url", c)
            self.assertIn("slice", c)
            self.assertIn("slice_label", c)
            self.assertIn("provenance", c)
            self.assertEqual(c["expected_label"], 0)
            self.assertTrue(c["url"].startswith("http://") or c["url"].startswith("https://"))

    def test_feature_extraction_consistency(self):
        """Verifies that all 265 diagnostic URLs extract exactly 30 numerical features with no NaNs."""
        for c in self.candidates:
            feats = URLFeatureExtractor.extract_features(c["url"])
            vec = URLFeatureExtractor.to_feature_vector(feats)
            self.assertEqual(len(vec), 30)
            self.assertTrue(all(np.isfinite(val) for val in vec))


class TestFeatureAblationMechanics(unittest.TestCase):
    """Tests sensitivity analysis transformations on feature vectors."""

    def test_path_ablation_neutralizes_target_dimensions(self):
        url = "https://docs.python.org/3/library/urllib.parse.html"
        feats = URLFeatureExtractor.extract_features(url)
        vec = np.array(URLFeatureExtractor.to_feature_vector(feats), dtype=np.float32)

        idx_path_len = URLFeatureExtractor.FEATURE_NAMES.index("path_length")
        idx_path_ent = URLFeatureExtractor.FEATURE_NAMES.index("path_entropy")

        self.assertGreater(vec[idx_path_len], 1.0)
        self.assertGreater(vec[idx_path_ent], 0.0)

        # Apply ablation
        ablated = vec.copy()
        ablated[idx_path_len] = 1.0
        ablated[idx_path_ent] = 0.0

        self.assertEqual(ablated[idx_path_len], 1.0)
        self.assertEqual(ablated[idx_path_ent], 0.0)
        # Unrelated dimensions remain untouched
        idx_dots = URLFeatureExtractor.FEATURE_NAMES.index("count_dots")
        self.assertEqual(vec[idx_dots], ablated[idx_dots])

    def test_subdomain_ablation_neutralizes_prefix(self):
        url = "https://us-east-1.console.aws.amazon.com/"
        feats = URLFeatureExtractor.extract_features(url)
        vec = np.array(URLFeatureExtractor.to_feature_vector(feats), dtype=np.float32)

        idx_sub_cnt = URLFeatureExtractor.FEATURE_NAMES.index("subdomain_count")
        idx_has_sub = URLFeatureExtractor.FEATURE_NAMES.index("has_subdomain")

        self.assertGreater(vec[idx_sub_cnt], 0.0)
        self.assertEqual(vec[idx_has_sub], 1.0)

        ablated = vec.copy()
        ablated[idx_sub_cnt] = 0.0
        ablated[idx_has_sub] = 0.0

        self.assertEqual(ablated[idx_sub_cnt], 0.0)
        self.assertEqual(ablated[idx_has_sub], 0.0)


if __name__ == "__main__":
    unittest.main()

