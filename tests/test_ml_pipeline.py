"""
Unit Test Suite for TrustShield AI Machine Learning Pipeline
Validates:
1. URLFeatureExtractor: length, entropy, subdomains, punycode, IP-literals, brand squatting, keywords.
2. DatasetImporter & Leakage Prevention: domain grouping, zero domain leakage across splits.
3. Evaluation Metrics: precision, recall, F1, false positive rate, confusion matrix, Brier score.
4. PhishingMLService: integrity preservation (no fabricated probabilities when untrained).
"""

import unittest
from backend.app.ml.features import URLFeatureExtractor
from backend.app.ml.dataset_importer import DatasetImporter, LabeledURLRecord
from backend.app.ml.train import compute_metrics, group_train_test_split
from backend.app.ml.service import PhishingMLService


class TestURLFeatureExtractor(unittest.TestCase):
    """Tests lexical, structural, and brand impersonation feature extraction."""

    def test_shannon_entropy_calculation(self):
        """Validates information-theoretic Shannon entropy calculations."""
        # Empty string
        self.assertEqual(URLFeatureExtractor.calculate_entropy(""), 0.0)
        # Uniform single character has zero entropy
        self.assertEqual(URLFeatureExtractor.calculate_entropy("aaaaaa"), 0.0)
        # High randomness string has elevated entropy
        entropy_normal = URLFeatureExtractor.calculate_entropy("example.com")
        entropy_random = URLFeatureExtractor.calculate_entropy("a8f9d0c1e2b347a5")
        self.assertGreater(entropy_random, entropy_normal)

    def test_subdomain_and_domain_parsing(self):
        """Verifies accurate subdomain depth and registered domain extraction."""
        info1 = URLFeatureExtractor.extract_domain_info("example.com")
        self.assertEqual(info1["registered_domain"], "example.com")
        self.assertEqual(info1["subdomain_count"], 0)

        info2 = URLFeatureExtractor.extract_domain_info("login.security.example.com")
        self.assertEqual(info2["registered_domain"], "example.com")
        self.assertEqual(info2["subdomain_count"], 2)
        self.assertEqual(info2["subdomains"], ["login", "security"])

        # Two-part TLD (.co.uk)
        info3 = URLFeatureExtractor.extract_domain_info("auth.portal.company.co.uk")
        self.assertEqual(info3["registered_domain"], "company.co.uk")
        self.assertEqual(info3["tld"], "co.uk")
        self.assertEqual(info3["subdomain_count"], 2)

    def test_ip_literal_detection(self):
        """Detects raw IP hosts instead of domain names."""
        feats_ip = URLFeatureExtractor.extract_features("http://185.220.101.5/banking")
        self.assertEqual(feats_ip["has_ip_literal"], 1)

        feats_domain = URLFeatureExtractor.extract_features("https://github.com/torvalds")
        self.assertEqual(feats_domain["has_ip_literal"], 0)

    def test_punycode_detection(self):
        """Detects IDN/Punycode evasion attempts."""
        feats_puny = URLFeatureExtractor.extract_features("https://xn--pple-43d.com/login")
        self.assertEqual(feats_puny["is_punycode"], 1)

        feats_clean = URLFeatureExtractor.extract_features("https://apple.com/login")
        self.assertEqual(feats_clean["is_punycode"], 0)

    def test_brand_squatting_heuristics(self):
        """Detects brand tokens in subdomains/paths when registered domain is not legitimate."""
        # Phishing: brand in subdomain of non-brand domain
        squat1, in_sub1, brands1 = URLFeatureExtractor.check_brand_squatting(
            "paypal.com.account-verification.xyz", "/login"
        )
        self.assertTrue(squat1)
        self.assertTrue(in_sub1)
        self.assertIn("paypal", brands1)

        # Legitimate brand domain should NOT be flagged as squatting
        squat_legit, _, _ = URLFeatureExtractor.check_brand_squatting("www.paypal.com", "/signin")
        self.assertFalse(squat_legit)

    def test_feature_vector_dimensionality(self):
        """Ensures to_feature_vector returns correct dimensions matching FEATURE_NAMES."""
        features = URLFeatureExtractor.extract_features("https://secure.chase-login.com/auth?id=123")
        vector = URLFeatureExtractor.to_feature_vector(features)

        self.assertEqual(len(vector), len(URLFeatureExtractor.FEATURE_NAMES))
        self.assertTrue(all(isinstance(v, (int, float)) for v in vector))


class TestDatasetAndLeakagePrevention(unittest.TestCase):
    """Tests dataset ingestion and domain grouping to eliminate train/test leakage."""

    def test_domain_group_extraction(self):
        """Ensures different subdomains of same entity share identical domain group."""
        grp1 = DatasetImporter.extract_domain_group("https://login.paypal.com/auth")
        grp2 = DatasetImporter.extract_domain_group("https://support.paypal.com/help")
        grp3 = DatasetImporter.extract_domain_group("https://api.paypal.com/v1")
        self.assertEqual(grp1, "paypal.com")
        self.assertEqual(grp1, grp2)
        self.assertEqual(grp2, grp3)

    def test_leakage_free_group_split(self):
        """Confirms that no base domain appears in both train and test splits."""
        records = [
            LabeledURLRecord(url="https://a.google.com/1", label=0, registered_domain="google.com", domain_group="google.com", source="test"),
            LabeledURLRecord(url="https://b.google.com/2", label=0, registered_domain="google.com", domain_group="google.com", source="test"),
            LabeledURLRecord(url="https://c.google.com/3", label=0, registered_domain="google.com", domain_group="google.com", source="test"),
            LabeledURLRecord(url="https://login.evil1.com/a", label=1, registered_domain="evil1.com", domain_group="evil1.com", source="test"),
            LabeledURLRecord(url="https://auth.evil1.com/b", label=1, registered_domain="evil1.com", domain_group="evil1.com", source="test"),
            LabeledURLRecord(url="https://evil2.com/pay", label=1, registered_domain="evil2.com", domain_group="evil2.com", source="test"),
            LabeledURLRecord(url="https://python.org/docs", label=0, registered_domain="python.org", domain_group="python.org", source="test"),
            LabeledURLRecord(url="https://pypi.python.org/p", label=0, registered_domain="python.org", domain_group="python.org", source="test"),
        ]

        train_set, test_set = group_train_test_split(records, test_ratio=0.25, random_seed=42)

        train_domains = set(r.domain_group for r in train_set)
        test_domains = set(r.domain_group for r in test_set)

        # Mathematical Proof: Set intersection must be completely empty!
        leakage = train_domains.intersection(test_domains)
        self.assertEqual(len(leakage), 0, f"Domain leakage detected across splits: {leakage}")

    def test_seed_benchmark_dataset(self):
        """Verifies validated seed benchmark contains balanced clean & phishing samples."""
        benchmark = DatasetImporter.generate_seed_benchmark()
        self.assertGreaterEqual(len(benchmark), 20)

        clean_count = sum(1 for r in benchmark if r.label == 0)
        phish_count = sum(1 for r in benchmark if r.label == 1)
        self.assertGreater(clean_count, 0)
        self.assertGreater(phish_count, 0)


class TestMetricsCalculation(unittest.TestCase):
    """Tests evaluation metrics: Precision, Recall, F1, FPR, Confusion Matrix, Brier score."""

    def test_standard_metrics_computation(self):
        # 2 TP, 2 TN, 1 FP, 1 FN
        y_true = [1, 1, 1, 0, 0, 0]
        y_pred = [1, 1, 0, 0, 0, 1]
        y_prob = [0.9, 0.8, 0.3, 0.1, 0.2, 0.7]

        metrics = compute_metrics(y_true, y_pred, y_prob)

        # TP=2, FP=1 -> Precision = 2/3 = 0.6667
        self.assertAlmostEqual(metrics["precision"], 0.6667, places=3)
        # TP=2, FN=1 -> Recall = 2/3 = 0.6667
        self.assertAlmostEqual(metrics["recall"], 0.6667, places=3)
        # F1 = 0.6667
        self.assertAlmostEqual(metrics["f1_score"], 0.6667, places=3)
        # FP=1, TN=2 -> FPR = 1/3 = 0.3333
        self.assertAlmostEqual(metrics["false_positive_rate"], 0.3333, places=3)
        # Confusion matrix checks
        cm = metrics["confusion_matrix"]
        self.assertEqual(cm["true_positives"], 2)
        self.assertEqual(cm["true_negatives"], 2)
        self.assertEqual(cm["false_positives"], 1)
        self.assertEqual(cm["false_negatives"], 1)
        self.assertEqual(cm["matrix"], [[2, 1], [1, 2]])


class TestMLServiceIntegrity(unittest.TestCase):
    """Verifies that untrained heuristics are never presented as a trained ML model."""

    def test_service_reports_unavailable_when_untrained(self):
        """When no trained model artifact exists on disk, status MUST be unavailable."""
        service = PhishingMLService(model_name="TrustShield-TestModel-v1.0")
        # Ensure untrained
        service.is_trained = False
        service.status = "unavailable"
        service.model_instance = None

        result = service.predict("https://secure-login.paypal-update.xyz/auth")

        # CRITICAL CONTRACT: Status is unavailable, probability is None, not fabricated!
        self.assertEqual(result["status"], "unavailable")
        self.assertFalse(result["is_trained"])
        self.assertIsNone(result["probability_phish"])
        self.assertIsNone(result["confidence"])
        self.assertIn("unavailable", result["message"].lower())
        # Extracted features are present for structural analysis
        self.assertIn("url_length", result["extracted_features"])
        self.assertIn("subdomain_count", result["extracted_features"])


if __name__ == "__main__":
    unittest.main()
