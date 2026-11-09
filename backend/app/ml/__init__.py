"""
TrustShield AI - Machine Learning & Feature Extraction Modules
"""

from backend.app.ml.features import URLFeatureExtractor
from backend.app.ml.dataset_importer import DatasetImporter, LabeledURLRecord
from backend.app.ml.train import PhishingModelTrainer, compute_metrics, group_train_test_split
from backend.app.ml.service import PhishingMLService, ml_service

__all__ = [
    "URLFeatureExtractor",
    "DatasetImporter",
    "LabeledURLRecord",
    "PhishingModelTrainer",
    "compute_metrics",
    "group_train_test_split",
    "PhishingMLService",
    "ml_service",
]
