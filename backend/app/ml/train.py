"""
TrustShield AI - ML Training Pipeline
Trains a Random Forest baseline and compares against Gradient Boosting / Calibrated classifiers.
Guarantees zero domain leakage via GroupKFold on registered domains.
Reports Precision, Recall, F1, Confusion Matrix, and False Positive Rate (FPR).
Outputs versioned model artifact for FastAPI microservice serving.
"""

import argparse
import datetime
import json
import math
import os
import sys
from typing import Any, Dict, List, Optional, Tuple

from backend.app.ml.dataset_importer import DatasetImporter, LabeledURLRecord
from backend.app.ml.features import URLFeatureExtractor


def compute_metrics(y_true: List[int], y_pred: List[int], y_prob: Optional[List[float]] = None) -> Dict[str, Any]:
    """Computes precision, recall, F1, confusion matrix, and false positive rate."""
    tp = sum(1 for yt, yp in zip(y_true, y_pred) if yt == 1 and yp == 1)
    tn = sum(1 for yt, yp in zip(y_true, y_pred) if yt == 0 and yp == 0)
    fp = sum(1 for yt, yp in zip(y_true, y_pred) if yt == 0 and yp == 1)
    fn = sum(1 for yt, yp in zip(y_true, y_pred) if yt == 1 and yp == 0)

    total = len(y_true)
    accuracy = round((tp + tn) / max(1, total), 4)
    precision = round(tp / max(1, tp + fp), 4)
    recall = round(tp / max(1, tp + fn), 4)
    f1 = round(2 * precision * recall / max(1e-6, precision + recall), 4)
    fpr = round(fp / max(1, fp + tn), 4)

    brier_score = None
    if y_prob:
        brier_score = round(sum((p - t) ** 2 for p, t in zip(y_prob, y_true)) / max(1, total), 4)

    return {
        "accuracy": accuracy,
        "precision": precision,
        "recall": recall,
        "f1_score": f1,
        "false_positive_rate": fpr,
        "confusion_matrix": {
            "true_negatives": tn,
            "false_positives": fp,
            "false_negatives": fn,
            "true_positives": tp,
            "matrix": [[tn, fp], [fn, tp]],
        },
        "brier_score": brier_score,
        "sample_count": total,
    }


def group_train_test_split(
    records: List[LabeledURLRecord], test_ratio: float = 0.25, random_seed: int = 42
) -> Tuple[List[LabeledURLRecord], List[LabeledURLRecord]]:
    """
    Splits dataset into train and test sets by registered base domain.
    Eliminates cross-split data leakage (e.g. subdomains of the same domain never appear in both sets).
    """
    import random
    rng = random.Random(random_seed)

    # Group records by domain
    domain_to_records: Dict[str, List[LabeledURLRecord]] = {}
    for r in records:
        domain_to_records.setdefault(r.domain_group, []).append(r)

    domains = sorted(domain_to_records.keys())
    rng.shuffle(domains)

    total_records = len(records)
    target_test_count = int(total_records * test_ratio)

    train_records: List[LabeledURLRecord] = []
    test_records: List[LabeledURLRecord] = []
    current_test_count = 0

    for d in domains:
        recs = domain_to_records[d]
        if current_test_count < target_test_count and len(test_records) < len(records) // 2:
            test_records.extend(recs)
            current_test_count += len(recs)
        else:
            train_records.extend(recs)

    # Ensure both sets have at least some samples
    if not test_records and len(train_records) > 1:
        test_records.append(train_records.pop())

    return train_records, test_records


class PhishingModelTrainer:
    """Manages the training, cross-validation, and export of TrustShield phishing models."""

    def __init__(self, model_version: str = "TrustShield-RandomForest-PhishLex-v1.0"):
        self.model_version = model_version
        self.feature_names = URLFeatureExtractor.FEATURE_NAMES
        self.models_dir = os.path.join(os.path.dirname(__file__), "models")
        os.makedirs(self.models_dir, exist_ok=True)

    def train_and_evaluate(
        self,
        records: List[LabeledURLRecord],
        output_name: str = "trustshield_rf_v1",
        calibrate_probabilities: bool = True,
    ) -> Dict[str, Any]:
        """
        Trains models using scikit-learn when installed.
        Applies GroupKFold / GroupShuffleSplit by registered domain to prevent data leakage.
        """
        try:
            import numpy as np
            from sklearn.calibration import CalibratedClassifierCV
            from sklearn.ensemble import GradientBoostingClassifier, RandomForestClassifier
            from sklearn.metrics import roc_auc_score
            from sklearn.model_selection import GroupKFold
        except ImportError:
            return {
                "success": False,
                "error": "MISSING_DEPENDENCIES",
                "message": (
                    "scikit-learn and numpy are required to fit models. "
                    "Install via 'pip install -r backend/requirements.txt'. "
                    "In the container environment, run the training pipeline after activating the virtual environment."
                ),
            }

        # Extract features
        X_raw, y_raw, groups = DatasetImporter.prepare_feature_dataset(records)
        X = np.array(X_raw)
        y = np.array(y_raw)
        groups = np.array(groups)

        # Baseline: Random Forest
        rf_model = RandomForestClassifier(
            n_estimators=100,
            max_depth=12,
            min_samples_split=2,
            class_weight="balanced",
            random_state=42,
        )

        # Comparison Model: Gradient Boosting
        gb_model = GradientBoostingClassifier(
            n_estimators=100,
            max_depth=5,
            learning_rate=0.1,
            random_state=42,
        )

        # 5-fold cross-validation by domain group
        n_groups = len(set(groups))
        n_splits = min(5, max(2, n_groups // 2))
        gkf = GroupKFold(n_splits=n_splits)

        rf_preds = np.zeros(len(y), dtype=int)
        rf_probs = np.zeros(len(y), dtype=float)
        gb_preds = np.zeros(len(y), dtype=int)
        gb_probs = np.zeros(len(y), dtype=float)

        for train_idx, val_idx in gkf.split(X, y, groups=groups):
            # Fit RF
            rf_model.fit(X[train_idx], y[train_idx])
            rf_probs[val_idx] = rf_model.predict_proba(X[val_idx])[:, 1]
            rf_preds[val_idx] = (rf_probs[val_idx] >= 0.5).astype(int)

            # Fit GB
            gb_model.fit(X[train_idx], y[train_idx])
            gb_probs[val_idx] = gb_model.predict_proba(X[val_idx])[:, 1]
            gb_preds[val_idx] = (gb_probs[val_idx] >= 0.5).astype(int)

        rf_metrics = compute_metrics(y.tolist(), rf_preds.tolist(), rf_probs.tolist())
        gb_metrics = compute_metrics(y.tolist(), gb_preds.tolist(), gb_probs.tolist())

        try:
            rf_metrics["roc_auc"] = round(float(roc_auc_score(y, rf_probs)), 4)
            gb_metrics["roc_auc"] = round(float(roc_auc_score(y, gb_probs)), 4)
        except Exception:
            rf_metrics["roc_auc"] = None
            gb_metrics["roc_auc"] = None

        # Select Best Model based on F1-Score & False Positive Rate
        best_name = "RandomForest" if rf_metrics["f1_score"] >= gb_metrics["f1_score"] else "GradientBoosting"
        best_model = rf_model if best_name == "RandomForest" else gb_model
        best_metrics = rf_metrics if best_name == "RandomForest" else gb_metrics

        # Train final production model on full dataset
        best_model.fit(X, y)

        # Calibrate probabilities if requested
        calibrated_model = best_model
        if calibrate_probabilities and len(y) >= 10:
            calibrator = CalibratedClassifierCV(estimator=best_model, method="sigmoid", cv="prefit")
            calibrator.fit(X, y)
            calibrated_model = calibrator

        # Extract normalized feature importances
        if hasattr(best_model, "feature_importances_"):
            importances = best_model.feature_importances_.tolist()
            feat_imp_dict = {
                name: round(float(val), 4)
                for name, val in sorted(zip(self.feature_names, importances), key=lambda x: x[1], reverse=True)
            }
        else:
            feat_imp_dict = {name: round(1.0 / len(self.feature_names), 4) for name in self.feature_names}

        # Save versioned artifact manifest
        artifact_manifest = {
            "model_version": self.model_version,
            "algorithm": best_name,
            "created_at": datetime.datetime.utcnow().isoformat() + "Z",
            "is_calibrated": calibrate_probabilities,
            "feature_names": self.feature_names,
            "metrics": {
                "selected_model": best_name,
                "rf_comparison": rf_metrics,
                "gb_comparison": gb_metrics,
                "production_metrics": best_metrics,
            },
            "feature_importances": feat_imp_dict,
            "dataset_summary": {
                "total_samples": len(records),
                "phishing_count": sum(1 for r in records if r.label == 1),
                "benign_count": sum(1 for r in records if r.label == 0),
                "unique_domain_groups": len(set(groups)),
                "leakage_prevention": "GroupKFold on registered domain",
            },
        }

        # Write manifest JSON
        json_path = os.path.join(self.models_dir, f"{output_name}.json")
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(artifact_manifest, f, indent=2)

        # Serialize trained estimator if joblib is available
        try:
            import joblib
            joblib_path = os.path.join(self.models_dir, f"{output_name}.joblib")
            joblib.dump(calibrated_model, joblib_path)
            artifact_manifest["artifact_path"] = joblib_path
        except Exception:
            artifact_manifest["artifact_path"] = json_path

        return {
            "success": True,
            "artifact_path": json_path,
            "model_version": self.model_version,
            "metrics": best_metrics,
            "comparison": {
                "random_forest": rf_metrics,
                "gradient_boosting": gb_metrics,
            },
        }


def main():
    parser = argparse.ArgumentParser(description="TrustShield AI Phishing Model Trainer")
    parser.add_argument("--csv", type=str, help="Path to custom labeled CSV dataset")
    parser.add_argument("--url-col", type=str, default="url", help="Column name for target URL")
    parser.add_argument("--label-col", type=str, default="label", help="Column name for label (1/0)")
    parser.add_argument("--use-benchmark", action="store_true", default=True, help="Use validated seed benchmark")
    parser.add_argument("--output", type=str, default="trustshield_rf_v1", help="Output artifact base name")
    args = parser.parse_args()

    print("=" * 60)
    print("TrustShield AI — Phishing Detection ML Training Pipeline")
    print("=" * 60)

    records: List[LabeledURLRecord] = []
    if args.csv and os.path.exists(args.csv):
        print(f"[*] Ingesting custom dataset from: {args.csv}")
        records = DatasetImporter.load_csv(args.csv, url_col=args.url_col, label_col=args.label_col)
    elif args.use_benchmark:
        print("[*] Ingesting validated balanced seed benchmark dataset...")
        records = DatasetImporter.generate_seed_benchmark()
    else:
        print("[!] No dataset provided. Specify --csv <path> or --use-benchmark.")
        sys.exit(1)

    print(f"[*] Total dataset records: {len(records)}")
    unique_domains = len(set(r.domain_group for r in records))
    print(f"[*] Distinct domain groups (for leakage prevention): {unique_domains}")

    trainer = PhishingModelTrainer()
    result = trainer.train_and_evaluate(records, output_name=args.output)

    if result.get("success"):
        print("\n[+] Training completed successfully!")
        print(f"Model Version: {result['model_version']}")
        print(f"Artifact Saved: {result['artifact_path']}")
        metrics = result["metrics"]
        print(f"Accuracy:   {metrics['accuracy']}")
        print(f"Precision:  {metrics['precision']}")
        print(f"Recall:     {metrics['recall']}")
        print(f"F1 Score:   {metrics['f1_score']}")
        print(f"FPR:        {metrics['false_positive_rate']}")
        print(f"Confusion:  {metrics['confusion_matrix']['matrix']}")
    else:
        print(f"\n[!] Notice: {result.get('error')}")
        print(f"Message: {result.get('message')}")


if __name__ == "__main__":
    main()
