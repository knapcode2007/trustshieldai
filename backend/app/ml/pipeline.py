"""
TrustShield AI - Machine Learning Pipeline
Consolidates phishing ML inference strictly through the verified PhishingMLService.
Adheres to strict verification integrity:
Never presents untrained heuristics as a trained ML model.
Marks inference 'unavailable' when no validated model artifact is loaded.
"""

from typing import Any, Dict, Union
from backend.app.ml.features import URLFeatureExtractor
from backend.app.ml.service import ml_service

# Backward-compatibility alias
PhishingFeatureExtractor = URLFeatureExtractor

class PhishingModelPipeline:
    """Consolidated pipeline delegating strictly to the verified PhishingMLService."""

    def __init__(self):
        self.service = ml_service

    @property
    def model_name(self) -> str:
        return self.service.model_version

    @property
    def is_loaded(self) -> bool:
        return self.service.is_trained

    def predict(self, url_or_features: Union[str, Dict[str, Any]]) -> Dict[str, Any]:
        """
        Executes prediction via PhishingMLService.
        Returns explicit 'unavailable' status when no trained model artifact exists.
        Never fabricates probabilities from heuristics.
        """
        if isinstance(url_or_features, str):
            return self.service.predict(url_or_features)
        
        # If passed an extracted features dictionary, retrieve raw URL
        url = url_or_features.get("raw_url") or url_or_features.get("url") or ""
        return self.service.predict(url)

ml_pipeline = PhishingModelPipeline()
