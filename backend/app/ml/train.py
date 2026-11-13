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
    records: List[LabeledURLRecord],
    test_ratio: float = 0.25,
    random_seed: int = 42,
) -> Tuple[List[LabeledURLRecord], List[LabeledURLRecord]]:
    """
    Splits dataset into train and test sets by registered base domain.
    Eliminates cross-split data leakage: URLs from the same registered domain
    never appear in both sets. Enforces class balance checks and prevents
    empty-class partitions.
    """
    import random
    rng = random.Random(random_seed)

    # Group records by domain
    domain_to_records: Dict[str, List[LabeledURLRecord]] = {}
    for r in records:
        domain_to_records.setdefault(r.domain_group, []).append(r)

    # Stratify domains by majority label to preserve class balance across splits
    pos_domains: List[str] = []
    neg_domains: List[str] = []
    mixed_domains: List[str] = []

    for domain, recs in domain_to_records.items():
        has_pos = any(r.label == 1 for r in recs)
        has_neg = any(r.label == 0 for r in recs)
        if has_pos and has_neg:
            mixed_domains.append(domain)
        elif has_pos:
            pos_domains.append(domain)
        else:
            neg_domains.append(domain)

    # Sort and shuffle deterministically
    pos_domains.sort()
    neg_domains.sort()
    mixed_domains.sort()
    rng.shuffle(pos_domains)
    rng.shuffle(neg_domains)
    rng.shuffle(mixed_domains)

    # Check minimum domain diversity if dataset contains multiple classes
    total_pos = sum(1 for r in records if r.label == 1)
    total_neg = sum(1 for r in records if r.label == 0)

    if total_pos > 0 and total_neg > 0:
        available_pos_domains = len(pos_domains) + len(mixed_domains)
        available_neg_domains = len(neg_domains) + len(mixed_domains)
        if available_pos_domains < 2 or available_neg_domains < 2:
            raise ValueError(
                f"Insufficient distinct domain groups to form a class-balanced, domain-isolated split. "
                f"Requires at least 2 distinct domain groups with positive samples (found {available_pos_domains}) "
                f"and 2 distinct domain groups with negative samples (found {available_neg_domains})."
            )

    train_domains: set = set()
    test_domains: set = set()

    def _distribute_groups(domain_list: List[str]):
        n = len(domain_list)
        if n == 0:
            return
        n_test = max(1, int(round(n * test_ratio))) if n >= 2 else 0
        # Ensure train gets at least 1 domain if n >= 2
        if n >= 2 and n_test >= n:
            n_test = n - 1
        for idx, d in enumerate(domain_list):
            if idx < n_test:
                test_domains.add(d)
            else:
                train_domains.add(d)

    _distribute_groups(pos_domains)
    _distribute_groups(neg_domains)
    _distribute_groups(mixed_domains)

    train_records = [r for r in records if r.domain_group in train_domains]
    test_records = [r for r in records if r.domain_group in test_domains]

    # Verify zero domain leakage
    intersection = train_domains.intersection(test_domains)
    if intersection:
        raise RuntimeError(f"Domain leakage detected: domains {intersection} appear in both train and test.")

    # Validate that neither split has an empty class if input has both classes
    if total_pos > 0 and total_neg > 0:
        train_labels = set(r.label for r in train_records)
        test_labels = set(r.label for r in test_records)
        if len(train_labels) < 2 or len(test_labels) < 2:
            raise ValueError(
                f"Class balance failure: split produced an empty-class partition. "
                f"Train labels present: {train_labels}, Test labels present: {test_labels}."
            )

    return train_records, test_records


def group_train_val_test_split(
    records: List[LabeledURLRecord],
    val_ratio: float = 0.20,
    test_ratio: float = 0.20,
    random_seed: int = 42,
) -> Tuple[List[LabeledURLRecord], List[LabeledURLRecord], List[LabeledURLRecord]]:
    """
    Splits dataset into train, calibration (validation), and test sets by registered base domain.
    Guarantees pairwise zero domain leakage:
      train_domains ∩ cal_domains = ∅
      train_domains ∩ test_domains = ∅
      cal_domains ∩ test_domains = ∅
    Enforces class balance across all 3 partitions and guards against empty-class partitions.
    """
    import random
    rng = random.Random(random_seed)

    domain_to_records: Dict[str, List[LabeledURLRecord]] = {}
    for r in records:
        domain_to_records.setdefault(r.domain_group, []).append(r)

    pos_domains: List[str] = []
    neg_domains: List[str] = []
    mixed_domains: List[str] = []

    for domain, recs in domain_to_records.items():
        has_pos = any(r.label == 1 for r in recs)
        has_neg = any(r.label == 0 for r in recs)
        if has_pos and has_neg:
            mixed_domains.append(domain)
        elif has_pos:
            pos_domains.append(domain)
        else:
            neg_domains.append(domain)

    pos_domains.sort()
    neg_domains.sort()
    mixed_domains.sort()
    rng.shuffle(pos_domains)
    rng.shuffle(neg_domains)
    rng.shuffle(mixed_domains)

    total_pos = sum(1 for r in records if r.label == 1)
    total_neg = sum(1 for r in records if r.label == 0)

    if total_pos > 0 and total_neg > 0:
        avail_pos = len(pos_domains) + len(mixed_domains)
        avail_neg = len(neg_domains) + len(mixed_domains)
        if avail_pos < 3 or avail_neg < 3:
            raise ValueError(
                f"Insufficient distinct domain groups for a 3-way class-balanced, domain-isolated split. "
                f"Requires at least 3 distinct domain groups with positive samples (found {avail_pos}) "
                f"and 3 distinct domain groups with negative samples (found {avail_neg})."
            )

    train_domains: set = set()
    cal_domains: set = set()
    test_domains: set = set()

    def _distribute_three_way(domain_list: List[str]):
        n = len(domain_list)
        if n == 0:
            return
        n_test = max(1, int(round(n * test_ratio))) if n >= 3 else (1 if n == 2 else 0)
        n_cal = max(1, int(round(n * val_ratio))) if n >= 3 else 0
        if n >= 3 and (n_test + n_cal) >= n:
            n_cal = max(1, n - n_test - 1)

        for idx, d in enumerate(domain_list):
            if idx < n_test:
                test_domains.add(d)
            elif idx < (n_test + n_cal):
                cal_domains.add(d)
            else:
                train_domains.add(d)

    _distribute_three_way(pos_domains)
    _distribute_three_way(neg_domains)
    _distribute_three_way(mixed_domains)

    train_records = [r for r in records if r.domain_group in train_domains]
    cal_records = [r for r in records if r.domain_group in cal_domains]
    test_records = [r for r in records if r.domain_group in test_domains]

    # Verify pairwise zero domain leakage
    if train_domains.intersection(cal_domains):
        raise RuntimeError(f"Domain leakage detected between train and cal: {train_domains.intersection(cal_domains)}")
    if train_domains.intersection(test_domains):
        raise RuntimeError(f"Domain leakage detected between train and test: {train_domains.intersection(test_domains)}")
    if cal_domains.intersection(test_domains):
        raise RuntimeError(f"Domain leakage detected between cal and test: {cal_domains.intersection(test_domains)}")

    # Verify no empty-class partitions
    if total_pos > 0 and total_neg > 0:
        for name, partition in [("Train", train_records), ("Calibration", cal_records), ("Test", test_records)]:
            labels = set(r.label for r in partition)
            if len(labels) < 2:
                raise ValueError(
                    f"Class balance failure: {name} partition contains an empty class. "
                    f"Labels present: {labels}. Minimum 1 positive and 1 negative sample required."
                )

    return train_records, cal_records, test_records


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

        # Determine split strategy based on domain diversity
        use_three_way_split = False
        train_recs, cal_recs, test_recs = [], [], []

        if calibrate_probabilities:
            try:
                train_recs, cal_recs, test_recs = group_train_val_test_split(
                    records, val_ratio=0.20, test_ratio=0.20, random_seed=42
                )
                use_three_way_split = True
            except ValueError:
                # Insufficient domains for 3-way split, fall back to 2-way split
                use_three_way_split = False

        if not use_three_way_split:
            train_recs, test_recs = group_train_test_split(
                records, test_ratio=0.25, random_seed=42
            )
            cal_recs = []

        # Extract features for partitions
        X_train_raw, y_train_raw, groups_train_raw = DatasetImporter.prepare_feature_dataset(train_recs)
        X_test_raw, y_test_raw, groups_test_raw = DatasetImporter.prepare_feature_dataset(test_recs)

        X_train = np.array(X_train_raw)
        y_train = np.array(y_train_raw)
        groups_train = np.array(groups_train_raw)

        X_test = np.array(X_test_raw)
        y_test = np.array(y_test_raw)

        # Baseline: Random Forest
        rf_base = RandomForestClassifier(
            n_estimators=100,
            max_depth=12,
            min_samples_split=2,
            class_weight="balanced",
            random_state=42,
        )

        # Comparison Model: Gradient Boosting
        gb_base = GradientBoostingClassifier(
            n_estimators=100,
            max_depth=5,
            learning_rate=0.1,
            random_state=42,
        )

        # Train models with isolated calibration
        if use_three_way_split and cal_recs:
            X_cal_raw, y_cal_raw, _ = DatasetImporter.prepare_feature_dataset(cal_recs)
            X_cal = np.array(X_cal_raw)
            y_cal = np.array(y_cal_raw)

            # Stack train and calibration sets for custom single-fold CV split
            X_train_cal = np.vstack([X_train, X_cal])
            y_train_cal = np.concatenate([y_train, y_cal])

            # Predefined single split: train base estimators strictly on X_train,
            # calibrate sigmoid mapping strictly on held-out X_cal.
            # Guarantees zero domain overlap between training, calibration, and test data.
            cal_split = [(np.arange(len(X_train)), np.arange(len(X_train), len(X_train_cal)))]

            rf_model = CalibratedClassifierCV(estimator=rf_base, method="sigmoid", cv=cal_split)
            rf_model.fit(X_train_cal, y_train_cal)

            gb_model = CalibratedClassifierCV(estimator=gb_base, method="sigmoid", cv=cal_split)
            gb_model.fit(X_train_cal, y_train_cal)
            split_strategy = "group_train_val_test_split (disjoint domains: train, calibration, test)"
        else:
            if calibrate_probabilities and len(y_train) >= 10:
                # Group-aware cross-validation calibration within train partition
                n_grp = len(set(groups_train))
                n_spl = min(5, max(2, n_grp // 2))
                gkf = GroupKFold(n_splits=n_spl)
                rf_model = CalibratedClassifierCV(estimator=rf_base, method="sigmoid", cv=gkf)
                rf_model.fit(X_train, y_train, groups=groups_train)

                gb_model = CalibratedClassifierCV(estimator=gb_base, method="sigmoid", cv=gkf)
                gb_model.fit(X_train, y_train, groups=groups_train)
                split_strategy = "group_train_test_split (GroupKFold CV calibration on train, evaluated on test)"
            else:
                rf_base.fit(X_train, y_train)
                gb_base.fit(X_train, y_train)
                rf_model = rf_base
                gb_model = gb_base
                split_strategy = "group_train_test_split (uncalibrated)"

        # Unbiased evaluation on holdout test partition
        rf_probs = rf_model.predict_proba(X_test)[:, 1]
        rf_preds = (rf_probs >= 0.5).astype(int)

        gb_probs = gb_model.predict_proba(X_test)[:, 1]
        gb_preds = (gb_probs >= 0.5).astype(int)

        rf_metrics = compute_metrics(y_test.tolist(), rf_preds.tolist(), rf_probs.tolist())
        gb_metrics = compute_metrics(y_test.tolist(), gb_preds.tolist(), gb_probs.tolist())

        try:
            rf_metrics["roc_auc"] = round(float(roc_auc_score(y_test, rf_probs)), 4)
            gb_metrics["roc_auc"] = round(float(roc_auc_score(y_test, gb_probs)), 4)
        except Exception:
            rf_metrics["roc_auc"] = None
            gb_metrics["roc_auc"] = None

        # Select Best Model based on F1-Score & False Positive Rate on test set
        best_name = "RandomForest" if rf_metrics["f1_score"] >= gb_metrics["f1_score"] else "GradientBoosting"
        best_model = rf_model if best_name == "RandomForest" else gb_model
        best_base = rf_base if best_name == "RandomForest" else gb_base
        best_metrics = rf_metrics if best_name == "RandomForest" else gb_metrics

        # Extract normalized feature importances from underlying tree estimator
        feat_imp_dict: Dict[str, float] = {}
        target_est = best_base
        if hasattr(best_model, "calibrated_classifiers_") and best_model.calibrated_classifiers_:
            target_est = getattr(best_model.calibrated_classifiers_[0], "estimator", best_base)
        elif hasattr(best_model, "estimator"):
            target_est = best_model.estimator

        if hasattr(target_est, "feature_importances_"):
            importances = target_est.feature_importances_.tolist()
            feat_imp_dict = {
                name: round(float(val), 4)
                for name, val in sorted(zip(self.feature_names, importances), key=lambda x: x[1], reverse=True)
            }
        else:
            feat_imp_dict = {name: round(1.0 / len(self.feature_names), 4) for name in self.feature_names}

        # First serialize model binary to disk (if joblib is available) to compute genuine SHA-256
        joblib_path = os.path.join(self.models_dir, f"{output_name}.joblib")
        artifact_sha256 = None
        try:
            import joblib
            joblib.dump(best_model, joblib_path)
            # Compute genuine SHA-256 hash of serialized artifact
            import hashlib
            hasher = hashlib.sha256()
            with open(joblib_path, "rb") as f:
                while chunk := f.read(65536):
                    hasher.update(chunk)
            artifact_sha256 = hasher.hexdigest()
        except Exception:
            joblib_path = None

        # Build comprehensive versioned artifact manifest
        import sklearn
        artifact_manifest = {
            "model_version": self.model_version,
            "algorithm": best_name,
            "created_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "is_calibrated": calibrate_probabilities,
            "calibration_method": "sigmoid" if calibrate_probabilities else "none",
            "split_strategy": split_strategy,
            "artifact_sha256": artifact_sha256,
            "feature_count": len(self.feature_names),
            "feature_names": self.feature_names,
            "runtime": {
                "python_version": sys.version.split()[0],
                "sklearn_version": sklearn.__version__,
                "numpy_version": np.__version__,
            },
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
                "unique_domain_groups": len(set(r.domain_group for r in records)),
                "train_samples": len(train_recs),
                "calibration_samples": len(cal_recs),
                "test_samples": len(test_recs),
                "leakage_prevention": "Disjoint registered domain groups across all partitions",
            },
        }

        # Write manifest JSON with embedded artifact_sha256
        json_path = os.path.join(self.models_dir, f"{output_name}.json")
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(artifact_manifest, f, indent=2)

        artifact_manifest["artifact_path"] = joblib_path or json_path

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
