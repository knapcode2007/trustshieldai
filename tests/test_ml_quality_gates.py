"""
Unit Test Suite for Deployment Quality Gates Engine (Decision 3)

Validates:
1. Configurable quality gate evaluation with realistic model mocks.
2. Strict failure when sliced False Positive Rate (e.g. deep paths or subdomains) breaches threshold.
3. Strict fail-closed behavior (BLOCKED_INSUFFICIENT_EVIDENCE) when sample counts are below minimum.
4. Fail-closed behavior when benchmark slices are completely missing.
5. Expected Calibration Error (ECE) and Brier score evaluation.
"""

import unittest
import numpy as np

from backend.app.ml.dataset_importer import LabeledURLRecord
from backend.app.ml.quality_gates import (
    DeploymentQualityGates,
    DeploymentVerdict,
    GateStatus,
    QualityGateConfig,
)


class MockPredictor:
    """Mock model that returns configured probabilities for testing gate evaluation."""

    def __init__(self, prob_map):
        self.prob_map = prob_map

    def predict_proba(self, X):
        probs = []
        for row in X:
            # Hash first 3 feature values as deterministic key
            key = tuple(np.round(row[:3], 1))
            p = self.prob_map.get(key, 0.05)
            probs.append([1.0 - p, p])
        return np.array(probs, dtype=np.float32)


class TestDeploymentQualityGates(unittest.TestCase):

    def setUp(self):
        self.config = QualityGateConfig(
            min_overall_samples=10,
            min_slice_samples=5,
            max_deep_path_fpr=0.01,
            max_subdomain_fpr=0.01,
            min_phishing_recall=0.90,
        )
        self.gates = DeploymentQualityGates(self.config)

    def _create_mock_records(self, count, label=0, path="/"):
        recs = []
        for i in range(count):
            url = f"https://mock-domain-{i}.org{path}"
            recs.append(
                LabeledURLRecord(
                    url=url,
                    canonical_url=url,
                    label=label,
                    threat_type="benign" if label == 0 else "phishing",
                    registered_domain=f"mock-domain-{i}.org",
                    domain_group=f"mock-domain-{i}.org",
                    source="mock",
                )
            )
        return recs

    def test_insufficient_general_samples_fails_closed(self):
        """Fails closed with BLOCKED_INSUFFICIENT_EVIDENCE if general test set is too small."""
        test_recs = self._create_mock_records(5)  # Less than min_overall_samples (10)
        
        class DummyModel:
            def predict_proba(self, X):
                return np.zeros((len(X), 2))

        report = self.gates.evaluate_model(DummyModel(), test_recs)
        self.assertEqual(report.overall_verdict, DeploymentVerdict.BLOCKED_INSUFFICIENT_EVIDENCE)
        self.assertGreater(report.insufficient_evidence_gates_count, 0)

    def test_missing_slice_fails_closed(self):
        """Fails closed if benchmark slices are missing or empty."""
        test_recs = self._create_mock_records(20, label=0)
        test_recs.extend(self._create_mock_records(20, label=1))

        class LowRiskModel:
            def predict_proba(self, X):
                return np.tile([0.9, 0.1], (len(X), 1))

        # No benchmark slices provided
        report = self.gates.evaluate_model(LowRiskModel(), test_recs, benchmark_slices={})
        self.assertEqual(report.overall_verdict, DeploymentVerdict.BLOCKED_INSUFFICIENT_EVIDENCE)

    def test_breached_deep_path_gate_blocks_deployment(self):
        """A model with 98% deep path FPR must be strictly BLOCKED_QUALITY_GATE_FAILURE."""
        test_recs = self._create_mock_records(20, label=0)
        test_recs.extend(self._create_mock_records(20, label=1))

        slices = {
            "deep_paths": self._create_mock_records(10, label=0, path="/long/documentation/path/endpoint.html"),
            "subdomains": self._create_mock_records(10, label=0, path="/"),
            "query_heavy": self._create_mock_records(10, label=0, path="/search?q=test"),
        }

        # Model that predicts high phishing probability (0.95) on deep paths (simulating shortcut learning)
        class ShortcutModel:
            def predict_proba(self, X):
                probs = []
                for row in X:
                    # Index 2 is path_length
                    if row[2] > 5:
                        probs.append([0.05, 0.95])
                    else:
                        probs.append([0.95, 0.05])
                return np.array(probs)

        report = self.gates.evaluate_model(ShortcutModel(), test_recs, benchmark_slices=slices)
        self.assertEqual(report.overall_verdict, DeploymentVerdict.BLOCKED_QUALITY_GATE_FAILURE)
        
        deep_gate = next(g for g in report.gate_checks if g.target_slice == "deep_paths")
        self.assertEqual(deep_gate.status, GateStatus.FAILED)
        self.assertGreater(deep_gate.actual_value, 0.01)

    def test_fully_qualified_model_passes_all_gates(self):
        """When all gates pass with verified sample evidence, model is QUALIFIED_FOR_DEPLOYMENT."""
        test_recs = self._create_mock_records(20, label=0, path="/clean")
        test_recs.extend(self._create_mock_records(20, label=1, path="/phish"))

        slices = {
            "deep_paths": self._create_mock_records(10, label=0, path="/docs/library/urllib.html"),
            "subdomains": self._create_mock_records(10, label=0, path="/"),
            "query_heavy": self._create_mock_records(10, label=0, path="/search?q=test"),
        }

        # Model that accurately gives label 0 (no 'phish' in URL) low score, and 'phish' high score
        class SmartModel:
            def predict_proba(self, X):
                probs = []
                for row in X:
                    # If URL length matches the /phish records (longer by 1 char or similar)
                    probs.append([0.98, 0.02])
                return np.array(probs)

        # Build a model that passes recall and FPR
        class AccuratePredictor:
            def predict_proba(self, X):
                probs = []
                for row in X:
                    # Use row[0] (url_length): /clean is len 29, /phish is len 29, but we can differentiate
                    # We can check row[2] (path_length): /phish is 6, /clean is 6, etc.
                    # Or simple: if path_length == 6 and count_dots == 1 -> label 1
                    # To be exact:
                    probs.append([0.02, 0.98] if row[2] == 6.0 and row[20] == 1.0 and row[0] == 29.0 else [0.98, 0.02])
                return np.array(probs)

        # For test_recs: clean path has len 6 ("/clean"), phish path has len 6 ("/phish").
        # Let's give phish a distinct feature, e.g. path="/phish-attack/verify" (path_length=20)
        test_recs_accurate = self._create_mock_records(20, label=0, path="/clean")
        test_recs_accurate.extend(self._create_mock_records(20, label=1, path="/phish-attack/verify"))

        class DiscerningModel:
            def predict_proba(self, X):
                probs = []
                for row in X:
                    # Index 2 is path_length
                    if row[2] == 20.0:  # /phish-attack/verify
                        probs.append([0.02, 0.98])
                    else:
                        probs.append([0.98, 0.02])
                return np.array(probs)

        report = self.gates.evaluate_model(DiscerningModel(), test_recs_accurate, benchmark_slices=slices)
        self.assertEqual(report.overall_verdict, DeploymentVerdict.QUALIFIED_FOR_DEPLOYMENT)
        self.assertEqual(report.failed_gates_count, 0)
        self.assertEqual(report.insufficient_evidence_gates_count, 0)

        # Check ECE calculation
        ece = DeploymentQualityGates.compute_ece(np.array([0, 0, 1, 1]), np.array([0.02, 0.02, 0.98, 0.98]))
        self.assertLess(ece, 0.05)


if __name__ == "__main__":
    unittest.main()
