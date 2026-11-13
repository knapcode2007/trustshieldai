"""
Unit Test Suite for TrustShield AI Machine Learning Pipeline
Validates:
1. URLFeatureExtractor: length, entropy, subdomains, punycode, IP-literals, brand squatting, keywords.
2. DatasetImporter & Leakage Prevention: domain grouping, zero domain leakage across splits.
3. Evaluation Metrics: precision, recall, F1, false positive rate, confusion matrix, Brier score.
4. PhishingMLService: integrity preservation (no fabricated probabilities when untrained).
"""

import os
import json
import hashlib
import tempfile
import unittest
from backend.app.ml.features import URLFeatureExtractor
from backend.app.ml.dataset_importer import DatasetImporter, LabeledURLRecord
from backend.app.ml.train import (
    compute_metrics,
    group_train_test_split,
    group_train_val_test_split,
    PhishingModelTrainer,
)
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

    def test_idn_unicode_and_punycode_handling(self):
        """Regression test: Verifies sound IDN handling, entropy normalization, and malformed safety."""
        # Legitimate Swiss bookstore IDN (bücher.ch)
        feats_idn = URLFeatureExtractor.extract_features("https://xn--bcher-kva.ch/")
        self.assertEqual(feats_idn["is_punycode"], 1)
        # RFC 3492 ACE protocol prefix 'xn--' must not be flagged as a consecutive-hyphen attack
        self.assertEqual(feats_idn["consecutive_hyphens"], 0)
        # Domain entropy should be calculated on 'bücher.ch' (< 3.0) rather than raw Punycode (> 3.4)
        self.assertLess(feats_idn["domain_entropy"], 3.0)

        # Attack scenario: Phishing domain containing legitimate consecutive hyphens in the payload
        feats_attack = URLFeatureExtractor.extract_features("https://xn--apple--secure-123.com/login")
        self.assertEqual(feats_attack["consecutive_hyphens"], 1)

        # Raw Unicode domain input
        feats_unicode = URLFeatureExtractor.extract_features("https://münchen.de/")
        self.assertEqual(feats_unicode["is_punycode"], 1)

        # Malformed Punycode fails safely without throwing exception
        feats_malformed = URLFeatureExtractor.extract_features("https://xn--!!!invalid.com/")
        self.assertEqual(feats_malformed["is_punycode"], 1)
        self.assertEqual(len(URLFeatureExtractor.to_feature_vector(feats_malformed)), 30)

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

    def test_group_train_val_test_split_pairwise_isolation(self):
        """Verifies pairwise zero domain leakage and class balance across train, cal, and test."""
        benchmark = DatasetImporter.generate_seed_benchmark()
        train_recs, cal_recs, test_recs = group_train_val_test_split(
            benchmark, val_ratio=0.20, test_ratio=0.20, random_seed=42
        )

        train_domains = set(r.domain_group for r in train_recs)
        cal_domains = set(r.domain_group for r in cal_recs)
        test_domains = set(r.domain_group for r in test_recs)

        # Pairwise zero domain overlap
        self.assertTrue(
            train_domains.isdisjoint(cal_domains),
            f"Leakage between train and cal: {train_domains.intersection(cal_domains)}"
        )
        self.assertTrue(
            train_domains.isdisjoint(test_domains),
            f"Leakage between train and test: {train_domains.intersection(test_domains)}"
        )
        self.assertTrue(
            cal_domains.isdisjoint(test_domains),
            f"Leakage between cal and test: {cal_domains.intersection(test_domains)}"
        )

        # Class balance across all three partitions
        for name, partition in [("Train", train_recs), ("Cal", cal_recs), ("Test", test_recs)]:
            labels = set(r.label for r in partition)
            self.assertIn(0, labels, f"{name} partition lacks benign samples")
            self.assertIn(1, labels, f"{name} partition lacks phishing samples")

    def test_group_split_insufficient_domains_raises_value_error(self):
        """Ensures ValueError is raised when dataset lacks domain diversity to balance splits."""
        insufficient_records = [
            LabeledURLRecord(url="https://clean1.com/1", label=0, registered_domain="clean1.com", domain_group="clean1.com", source="t"),
            LabeledURLRecord(url="https://clean2.com/2", label=0, registered_domain="clean2.com", domain_group="clean2.com", source="t"),
            # Only 1 phishing domain
            LabeledURLRecord(url="https://evil.com/1", label=1, registered_domain="evil.com", domain_group="evil.com", source="t"),
            LabeledURLRecord(url="https://evil.com/2", label=1, registered_domain="evil.com", domain_group="evil.com", source="t"),
        ]

        with self.assertRaises(ValueError) as ctx:
            group_train_test_split(insufficient_records, test_ratio=0.25)
        self.assertIn("Insufficient distinct domain groups", str(ctx.exception))

        with self.assertRaises(ValueError) as ctx3:
            group_train_val_test_split(insufficient_records, val_ratio=0.2, test_ratio=0.2)
        self.assertIn("Insufficient distinct domain groups", str(ctx3.exception))


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


class TestArtifactIntegrityAndValidation(unittest.TestCase):
    """Validates SHA-256 integrity, schema conformity, and safe failure modes."""

    def test_tampered_joblib_sha256_mismatch_fails_safely(self):
        """Detects mismatched SHA-256 digests and refuses to deserialize the binary."""
        with tempfile.TemporaryDirectory() as tmpdir:
            joblib_path = os.path.join(tmpdir, "trustshield_rf_v1.joblib")
            json_path = os.path.join(tmpdir, "trustshield_rf_v1.json")

            with open(joblib_path, "wb") as f:
                f.write(b"corrupted_or_altered_binary_content")

            manifest = {
                "model_version": "test-v1",
                "feature_names": URLFeatureExtractor.FEATURE_NAMES,
                "artifact_sha256": "0" * 64,  # Intentionally invalid hash
            }
            with open(json_path, "w", encoding="utf-8") as f:
                json.dump(manifest, f)

            service = PhishingMLService()
            service.models_dir = tmpdir
            service._load_artifact()

            self.assertFalse(service.is_trained)
            self.assertEqual(service.status, "unavailable")
            self.assertIsNone(service.model_instance)
            self.assertIn("SHA-256 mismatch", service.load_error)

    def test_missing_manifest_sha256_fails_safely(self):
        """Fails safely when manifest does not declare an artifact SHA-256 hash."""
        with tempfile.TemporaryDirectory() as tmpdir:
            joblib_path = os.path.join(tmpdir, "trustshield_rf_v1.joblib")
            json_path = os.path.join(tmpdir, "trustshield_rf_v1.json")

            with open(joblib_path, "wb") as f:
                f.write(b"some_bytes")

            manifest = {
                "model_version": "test-v1",
                "feature_names": URLFeatureExtractor.FEATURE_NAMES,
            }
            with open(json_path, "w", encoding="utf-8") as f:
                json.dump(manifest, f)

            service = PhishingMLService()
            service.models_dir = tmpdir
            service._load_artifact()

            self.assertFalse(service.is_trained)
            self.assertEqual(service.status, "unavailable")
            self.assertIn("missing a valid 'artifact_sha256'", service.load_error)

    def test_feature_schema_count_mismatch_fails_safely(self):
        """Fails safely when manifest declares a feature count different from extractor."""
        with tempfile.TemporaryDirectory() as tmpdir:
            joblib_path = os.path.join(tmpdir, "trustshield_rf_v1.joblib")
            json_path = os.path.join(tmpdir, "trustshield_rf_v1.json")

            with open(joblib_path, "wb") as f:
                f.write(b"some_bytes")

            manifest = {
                "model_version": "test-v1",
                "feature_names": URLFeatureExtractor.FEATURE_NAMES[:15],  # Only 15 features
                "artifact_sha256": hashlib.sha256(b"some_bytes").hexdigest(),
            }
            with open(json_path, "w", encoding="utf-8") as f:
                json.dump(manifest, f)

            service = PhishingMLService()
            service.models_dir = tmpdir
            service._load_artifact()

            self.assertFalse(service.is_trained)
            self.assertEqual(service.status, "unavailable")
            self.assertIn("Feature count mismatch", service.load_error)

    def test_feature_schema_names_mismatch_fails_safely(self):
        """Fails safely when feature names or ordering in manifest do not match schema."""
        with tempfile.TemporaryDirectory() as tmpdir:
            joblib_path = os.path.join(tmpdir, "trustshield_rf_v1.joblib")
            json_path = os.path.join(tmpdir, "trustshield_rf_v1.json")

            with open(joblib_path, "wb") as f:
                f.write(b"some_bytes")

            altered_features = list(URLFeatureExtractor.FEATURE_NAMES)
            altered_features[0] = "corrupted_feature_name"

            manifest = {
                "model_version": "test-v1",
                "feature_names": altered_features,
                "artifact_sha256": hashlib.sha256(b"some_bytes").hexdigest(),
            }
            with open(json_path, "w", encoding="utf-8") as f:
                json.dump(manifest, f)

            service = PhishingMLService()
            service.models_dir = tmpdir
            service._load_artifact()

            self.assertFalse(service.is_trained)
            self.assertEqual(service.status, "unavailable")
            self.assertIn("Feature names or order", service.load_error)

    def test_isolated_manifest_or_joblib_fails_safely(self):
        """Fails safely if either .json or .joblib is missing individually."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Only json exists
            json_path = os.path.join(tmpdir, "trustshield_rf_v1.json")
            with open(json_path, "w", encoding="utf-8") as f:
                json.dump({"model_version": "v1"}, f)

            service = PhishingMLService()
            service.models_dir = tmpdir
            service._load_artifact()

            self.assertFalse(service.is_trained)
            self.assertEqual(service.status, "unavailable")
            self.assertIn("binary is missing", service.load_error)

        with tempfile.TemporaryDirectory() as tmpdir2:
            # Only joblib exists
            joblib_path = os.path.join(tmpdir2, "trustshield_rf_v1.joblib")
            with open(joblib_path, "wb") as f:
                f.write(b"bytes")

            service = PhishingMLService()
            service.models_dir = tmpdir2
            service._load_artifact()

            self.assertFalse(service.is_trained)
            self.assertEqual(service.status, "unavailable")
            self.assertIn("manifest JSON is missing", service.load_error)


class TestDefensibleLocalFeatureAttribution(unittest.TestCase):
    """Verifies that local feature attribution relies on normalized signals, not raw unscaled values."""

    def test_ip_literal_is_top_contributing_feature(self):
        """Confirms high-risk binary traits like IP literals properly rank near top of local evidence."""
        url = "http://185.220.101.5/banking/signin.php?action=login"
        extracted = URLFeatureExtractor.extract_features(url)
        vector = URLFeatureExtractor.to_feature_vector(extracted)

        importances = {
            "has_ip_literal": 0.10,
            "auth_keyword_count": 0.08,
            "financial_keyword_count": 0.07,
            "url_length": 0.05,
            "domain_entropy": 0.04,
        }

        contributing, evidence = PhishingMLService.compute_local_evidence(
            extracted, vector, importances
        )

        self.assertIn("has_ip_literal", contributing)
        self.assertAlmostEqual(contributing["has_ip_literal"], 0.10, places=3)
        self.assertIn("auth_keyword_count", contributing)
        self.assertIn("financial_keyword_count", contributing)

        # url_length is 53 chars, which is within normal bounds and should not be flagged as a threat
        self.assertNotIn("url_length", contributing)

    def test_clean_url_does_not_falsely_flag_normal_length(self):
        """Clean standard URLs with benign traits should not attribute normal lengths as malicious."""
        url = "https://example.com/about"
        extracted = URLFeatureExtractor.extract_features(url)
        vector = URLFeatureExtractor.to_feature_vector(extracted)

        importances = {
            "url_length": 0.15,
            "domain_entropy": 0.10,
            "subdomain_count": 0.05,
        }

        contributing, evidence = PhishingMLService.compute_local_evidence(
            extracted, vector, importances
        )

        # example.com/about has 0 active risk signals
        self.assertEqual(len(contributing), 0)
        self.assertEqual(len(evidence), 0)

    def test_punycode_and_brand_squatting_evidence(self):
        """Punycode and brand squatting are appropriately scored with detailed descriptions."""
        url = "https://xn--pple-43d.com/login"
        extracted = URLFeatureExtractor.extract_features(url)
        vector = URLFeatureExtractor.to_feature_vector(extracted)

        importances = {
            "is_punycode": 0.12,
            "auth_keyword_count": 0.06,
        }

        contributing, evidence = PhishingMLService.compute_local_evidence(
            extracted, vector, importances
        )

        self.assertIn("is_punycode", contributing)
        self.assertIn("auth_keyword_count", contributing)
        puny_item = next(e for e in evidence if e["feature"] == "is_punycode")
        self.assertEqual(puny_item["signal_intensity"], 1.0)
        self.assertIn("Punycode", puny_item["description"])


class TestCalibrationAndTrainingIntegration(unittest.TestCase):
    """Verifies separated training/calibration procedure and artifact generation."""

    def test_trainer_executes_separated_calibration_and_exports_valid_artifact(self):
        """Tests end-to-end training, calibration separation, manifest generation, and service loading."""
        with tempfile.TemporaryDirectory() as tmpdir:
            trainer = PhishingModelTrainer()
            trainer.models_dir = tmpdir

            benchmark = DatasetImporter.generate_seed_benchmark()
            result = trainer.train_and_evaluate(
                benchmark, output_name="trustshield_rf_v1", calibrate_probabilities=True
            )

            self.assertTrue(result.get("success"), f"Training failed with: {result}")
            self.assertIn("metrics", result)
            self.assertIn("precision", result["metrics"])

            joblib_path = os.path.join(tmpdir, "trustshield_rf_v1.joblib")
            json_path = os.path.join(tmpdir, "trustshield_rf_v1.json")

            self.assertTrue(os.path.exists(joblib_path))
            self.assertTrue(os.path.exists(json_path))

            # Validate manifest structure and embedded SHA-256
            with open(json_path, "r", encoding="utf-8") as f:
                manifest = json.load(f)

            self.assertEqual(manifest["feature_count"], 30)
            self.assertEqual(len(manifest["feature_names"]), 30)
            self.assertIn("artifact_sha256", manifest)
            self.assertEqual(len(manifest["artifact_sha256"]), 64)

            # Check SHA-256 matches actual file on disk
            hasher = hashlib.sha256()
            with open(joblib_path, "rb") as f:
                while chunk := f.read(65536):
                    hasher.update(chunk)
            self.assertEqual(manifest["artifact_sha256"], hasher.hexdigest())

            # Test that PhishingMLService can load and serve the validated artifact
            service = PhishingMLService()
            service.models_dir = tmpdir
            service._load_artifact()

            self.assertTrue(service.is_trained)
            self.assertEqual(service.status, "operational")
            self.assertIsNone(service.load_error)

            # Test inference on test URLs
            phish_pred = service.predict("https://paypal-security-update.xyz/verify-login")
            self.assertEqual(phish_pred["status"], "operational")
            self.assertTrue(phish_pred["is_trained"])
            self.assertIsInstance(phish_pred["probability_phish"], float)
            self.assertGreaterEqual(phish_pred["probability_phish"], 0.0)
            self.assertLessEqual(phish_pred["probability_phish"], 1.0)
            self.assertEqual(phish_pred["explanation_method"], "normalized_local_risk_attribution")
            self.assertIn("global_feature_importances", phish_pred)
            self.assertIn("contributing_features", phish_pred)

            clean_pred = service.predict("https://example.com/")
            self.assertEqual(clean_pred["status"], "operational")
            self.assertIsInstance(clean_pred["probability_phish"], float)


if __name__ == "__main__":
    unittest.main()
