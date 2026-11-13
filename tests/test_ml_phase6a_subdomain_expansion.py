"""
TrustShield AI - Phase 6A Regression & Verification Test Suite
Validates:
1. Phase 6A dataset integrity, partition counts, and domain isolation.
2. Zero cross-split domain leakage across Train, Cal, and Test.
3. Zero benchmark contamination across all 150 quarantined benchmark domain groups.
4. Phase 6 Future Validation Benchmark availability and disjointness.
5. Feasibility study string algorithms: Levenshtein distance, homoglyph normalization,
   and lexical collision false-positive characteristics.
"""

import csv
import json
import os
import unittest

from backend.app.ml.dataset_importer import DatasetImporter
from scratch.prototype_feature_feasibility import (
    levenshtein_distance,
    normalized_levenshtein_similarity,
    normalize_homoglyphs,
    BrandSimilarityPrototype,
)


class TestPhase6ADatasetIntegrity(unittest.TestCase):
    """Verifies Phase 6A dataset partitioning, provenance, and quarantine isolation."""

    @classmethod
    def setUpClass(cls):
        cls.base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
        cls.curated_dir = os.path.join(cls.base_dir, "data", "curated", "phase6a")
        cls.manifest_path = os.path.join(cls.curated_dir, "dataset_manifest.json")
        cls.train_path = os.path.join(cls.curated_dir, "train_partition.csv")
        cls.cal_path = os.path.join(cls.curated_dir, "cal_partition.csv")
        cls.test_path = os.path.join(cls.curated_dir, "test_partition.csv")
        cls.future_val_path = os.path.join(cls.base_dir, "data", "benchmarks", "phase6_future_validation.csv")

    def test_phase6a_files_exist(self):
        """Verifies that all Phase 6A dataset artifacts exist on disk."""
        self.assertTrue(os.path.exists(self.manifest_path), "Missing dataset_manifest.json")
        self.assertTrue(os.path.exists(self.train_path), "Missing train_partition.csv")
        self.assertTrue(os.path.exists(self.cal_path), "Missing cal_partition.csv")
        self.assertTrue(os.path.exists(self.test_path), "Missing test_partition.csv")
        self.assertTrue(os.path.exists(self.future_val_path), "Missing phase6_future_validation.csv")

    def test_reconciliation_integrity(self):
        """Verifies that the manifest records the verified ground truth of 22/50 (44.0%)."""
        with open(self.manifest_path, "r", encoding="utf-8") as f:
            manifest = json.load(f)

        recon = manifest.get("reconciliation", {})
        self.assertEqual(recon.get("verified_cal_fp"), 22)
        self.assertEqual(recon.get("sample_count"), 50)
        self.assertEqual(recon.get("fpr"), 0.44)
        self.assertEqual(recon.get("threshold"), 0.50)

    def test_zero_cross_partition_domain_leakage(self):
        """Guarantees that no registered domain group appears in more than one partition."""
        def load_domains(csv_path):
            with open(csv_path, "r", encoding="utf-8") as f:
                reader = csv.DictReader(f)
                return {row["domain_group"] for row in reader}

        train_domains = load_domains(self.train_path)
        cal_domains = load_domains(self.cal_path)
        test_domains = load_domains(self.test_path)

        self.assertGreater(len(train_domains), 500)
        self.assertGreater(len(cal_domains), 150)
        self.assertGreater(len(test_domains), 150)

        self.assertEqual(len(train_domains & cal_domains), 0, "Domain leakage between Train and Cal!")
        self.assertEqual(len(train_domains & test_domains), 0, "Domain leakage between Train and Test!")
        self.assertEqual(len(cal_domains & test_domains), 0, "Domain leakage between Cal and Test!")

    def test_zero_benchmark_contamination(self):
        """Verifies that all quarantined benchmark domains are strictly excluded from partitions."""
        with open(self.manifest_path, "r", encoding="utf-8") as f:
            manifest = json.load(f)

        total_quarantined = manifest["quarantined_benchmarks"]["total_quarantined_domains"]
        self.assertEqual(total_quarantined, 150)

        # Load all benchmark domains
        from scratch.run_phase3b_diagnostics import get_diagnostic_url_candidates
        from scratch.acquire_phase5a_dataset import get_phase5_external_validation_candidates
        from scratch.acquire_phase6a_dataset import get_phase6_future_validation_candidates

        p3b = get_diagnostic_url_candidates()
        p5ext = get_phase5_external_validation_candidates()
        p6fut = get_phase6_future_validation_candidates()

        quarantined_domains = (
            {DatasetImporter.extract_domain_group(c["url"]) for c in p3b}
            | {DatasetImporter.extract_domain_group(c["url"]) for c in p5ext}
            | {DatasetImporter.extract_domain_group(c["url"]) for c in p6fut}
        )

        for p_name, path in [("Train", self.train_path), ("Cal", self.cal_path), ("Test", self.test_path)]:
            with open(path, "r", encoding="utf-8") as f:
                reader = csv.DictReader(f)
                part_domains = {r["domain_group"] for r in reader}
            overlap = part_domains & quarantined_domains
            self.assertEqual(len(overlap), 0, f"Benchmark domain contamination in {p_name}: {overlap}")

    def test_benign_subdomain_exposure(self):
        """Verifies that the benign training partition contains real multi-tier subdomains."""
        with open(self.train_path, "r", encoding="utf-8") as f:
            reader = list(csv.DictReader(f))

        benign_rows = [r for r in reader if r["label"] == "0"]
        subdomain_sources = [r for r in benign_rows if "subdomain" in r["source"]]
        self.assertGreater(len(subdomain_sources), 50, "Insufficient subdomain representation in training partition.")


class TestFeatureFeasibilityPrototype(unittest.TestCase):
    """Verifies non-production feasibility prototype algorithms for Phase 6A."""

    def test_levenshtein_distance_exact_and_variations(self):
        """Tests string edit distance calculations."""
        self.assertEqual(levenshtein_distance("paypal", "paypal"), 0)
        self.assertEqual(levenshtein_distance("paypal", "paypa1"), 1)
        self.assertEqual(levenshtein_distance("apple", "appl"), 1)
        self.assertEqual(levenshtein_distance("microsoft", "rnicrosoft"), 2)

    def test_normalized_levenshtein_similarity(self):
        """Tests normalized similarity score bounds and calculations."""
        self.assertEqual(normalized_levenshtein_similarity("paypal", "paypal"), 1.0)
        sim_typo = normalized_levenshtein_similarity("paypa1", "paypal")
        self.assertGreaterEqual(sim_typo, 0.80)
        sim_unrelated = normalized_levenshtein_similarity("wikipedia", "paypal")
        self.assertLess(sim_unrelated, 0.40)

    def test_homoglyph_normalization(self):
        """Verifies Unicode confusable normalization to canonical Latin characters."""
        # Cyrillic small 'а' (U+0430) -> Latin 'a'
        cyrillic_a = "\u0430pple"
        self.assertEqual(normalize_homoglyphs(cyrillic_a), "apple")

        # Two-character confusable 'rn' -> 'm'
        rn_test = "rnicrosoft"
        self.assertEqual(normalize_homoglyphs(rn_test), "microsoft")

        # Leetspeak lookalikes '0' -> 'o', '1' -> 'l'
        self.assertEqual(normalize_homoglyphs("p0rtal"), "portal")
        self.assertEqual(normalize_homoglyphs("paypa1"), "paypal")

    def test_prototype_identifies_lexical_collisions(self):
        """Verifies that prototype empirically flags documented false positive risk tokens."""
        proto = BrandSimilarityPrototype()

        # Legitimate word 'apply' shares 80% similarity with brand 'apple'
        res_apply = proto.evaluate_url("https://apply.berkeley.edu/status")
        self.assertIsNotNone(res_apply["best_match"])
        self.assertEqual(res_apply["best_match"]["brand"], "apple")
        self.assertGreaterEqual(res_apply["best_match"]["similarity"], 0.80)
        # Confirms that naive thresholding creates a false alarm on benign word 'apply'
        self.assertTrue(res_apply["best_match"]["flagged_as_suspicious"])

        # Legitimate company 'chaser' shares 83% similarity with brand 'chase'
        res_chase = proto.evaluate_url("https://chaser-technologies.com/")
        self.assertIsNotNone(res_chase["best_match"])
        self.assertEqual(res_chase["best_match"]["brand"], "chase")
        self.assertGreaterEqual(res_chase["best_match"]["similarity"], 0.80)
        self.assertTrue(res_chase["best_match"]["flagged_as_suspicious"])


if __name__ == "__main__":
    unittest.main()

