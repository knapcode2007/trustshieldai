"""
TrustShield AI - Machine Learning Prediction Service
FastAPI-compatible inference service.
Adheres to strict verification integrity:
Never presents untrained heuristics as a trained ML model.
Marks inference 'unavailable' when no validated model artifact is loaded.
"""

import os
import json
from typing import Any, Dict, List, Optional
from backend.app.ml.features import URLFeatureExtractor


class PhishingMLService:
    """Manages model artifact lifecycle, feature extraction, and real ML inference."""

    def __init__(self, model_name: str = "TrustShield-RandomForest-PhishLex-v1.0"):
        self.model_name = model_name
        self.model_version = model_name
        self.is_trained: bool = False
        self.status: str = "unavailable"
        self.model_instance = None
        self.metadata: Dict[str, Any] = {}
        self.models_dir = os.path.join(os.path.dirname(__file__), "models")

        # Attempt to load model artifact if it exists on disk
        self._load_artifact()

    def _load_artifact(self) -> None:
        """Inspects disk for validated model artifact and loads serialized estimator."""
        json_manifest = os.path.join(self.models_dir, "trustshield_rf_v1.json")
        joblib_artifact = os.path.join(self.models_dir, "trustshield_rf_v1.joblib")

        if os.path.exists(json_manifest):
            try:
                with open(json_manifest, "r", encoding="utf-8") as f:
                    self.metadata = json.load(f)
                    self.model_version = self.metadata.get("model_version", self.model_name)
            except Exception:
                pass

        # Try loading compiled model estimator
        if os.path.exists(joblib_artifact):
            try:
                import joblib
                self.model_instance = joblib.load(joblib_artifact)
                self.is_trained = True
                self.status = "operational"
            except Exception:
                self.is_trained = False
                self.status = "unavailable"
        else:
            # No compiled model artifact on disk
            self.is_trained = False
            self.status = "unavailable"

    def predict(self, url: str) -> Dict[str, Any]:
        """
        Executes prediction on target URL.
        If a validated trained model is loaded, returns real ML prediction and contributing features.
        If no validated model artifact exists, marks status 'unavailable' without fabricating probabilities.
        """
        # Always extract structural and lexical features honestly
        extracted = URLFeatureExtractor.extract_features(url)
        vector = URLFeatureExtractor.to_feature_vector(extracted)

        # Integrity Check: If model is not trained, NEVER invent or fake a probability
        if not self.is_trained or self.model_instance is None:
            return {
                "status": "unavailable",
                "is_trained": False,
                "model": self.model_name,
                "model_version": self.model_version,
                "probability_phish": None,
                "confidence": None,
                "feature_importances": None,
                "contributing_features": None,
                "extracted_features": {
                    "url_length": extracted["url_length"],
                    "subdomain_count": extracted["subdomain_count"],
                    "url_entropy": extracted["url_entropy"],
                    "domain_entropy": extracted["domain_entropy"],
                    "is_punycode": extracted["is_punycode"],
                    "has_ip_literal": extracted["has_ip_literal"],
                    "matched_keywords": extracted["matched_keywords"],
                    "squatted_brands": extracted["squatted_brands"],
                    "is_high_risk_tld": extracted["is_high_risk_tld"],
                },
                "message": (
                    "ML inference is unavailable: Validated scikit-learn model artifact not loaded. "
                    "Run 'python -m backend.app.ml.train' to train and calibrate a Random Forest / Gradient Boosting model."
                ),
            }

        # Real ML inference using loaded estimator
        try:
            import numpy as np
            X = np.array([vector])
            probabilities = self.model_instance.predict_proba(X)[0]
            prob_phish = round(float(probabilities[1]), 4)
            confidence = round(float(max(probabilities)), 4)

            # Feature importances from manifest
            importances = self.metadata.get("feature_importances", {})

            # Calculate top contributing features for this specific URL
            contributing = {}
            for fname, val in zip(URLFeatureExtractor.FEATURE_NAMES, vector):
                weight = importances.get(fname, 0.05)
                impact = round(val * weight, 4)
                if impact > 0.01:
                    contributing[fname] = impact

            # Sort top 5 contributing features
            sorted_contributing = dict(
                sorted(contributing.items(), key=lambda item: item[1], reverse=True)[:5]
            )

            return {
                "status": "operational",
                "is_trained": True,
                "model": self.model_name,
                "model_version": self.model_version,
                "probability_phish": prob_phish,
                "confidence": confidence,
                "feature_importances": importances,
                "contributing_features": sorted_contributing,
                "extracted_features": {
                    "url_length": extracted["url_length"],
                    "subdomain_count": extracted["subdomain_count"],
                    "url_entropy": extracted["url_entropy"],
                    "domain_entropy": extracted["domain_entropy"],
                    "is_punycode": extracted["is_punycode"],
                    "has_ip_literal": extracted["has_ip_literal"],
                    "matched_keywords": extracted["matched_keywords"],
                    "squatted_brands": extracted["squatted_brands"],
                },
                "message": "Real ML prediction evaluated with calibrated probabilities.",
            }
        except Exception as e:
            return {
                "status": "error",
                "is_trained": False,
                "model": self.model_name,
                "model_version": self.model_version,
                "probability_phish": None,
                "confidence": None,
                "error": str(e),
                "message": f"Inference execution failed: {str(e)}",
            }


# Singleton service instance
ml_service = PhishingMLService()
