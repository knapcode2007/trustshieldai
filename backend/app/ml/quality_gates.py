"""
TrustShield AI - ML Deployment Quality Gates Engine
Decision 3: Configurable, independent benchmark quality gates for model qualification.

Guarantees:
1. Independent threshold enforcement on critical error modes:
   - False Positive Rate on Deep-Path Documentation (< 1.0% target)
   - False Positive Rate on Multi-Tier Subdomains (< 1.0% target)
   - False Positive Rate on Query-Heavy Endpoints (< 1.5% target)
   - Overall Phishing Recall (>= 95.0% target)
   - False Negative Rate (< 5.0% target)
   - Expected Calibration Error (ECE <= 0.05 target)
   - Brier Score (<= 0.05 target)
2. Statistical Confidence Guardrails:
   - Rejects claims of statistical confidence when sample counts per slice are below required thresholds.
   - Fails closed (status='INSUFFICIENT_EVIDENCE' / 'BLOCKED') when benchmark evidence is insufficient.
3. Separation of Concerns:
   - Quality gate logic is completely decoupled from model training, evaluating models as black-box predictors.
"""

from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Tuple
import numpy as np
from sklearn.metrics import (
    confusion_matrix,
    precision_score,
    recall_score,
    f1_score,
    accuracy_score,
    brier_score_loss,
)

from backend.app.ml.features import URLFeatureExtractor


class GateStatus(str, Enum):
    PASSED = "PASSED"
    FAILED = "FAILED"
    INSUFFICIENT_EVIDENCE = "INSUFFICIENT_EVIDENCE"


class DeploymentVerdict(str, Enum):
    QUALIFIED_FOR_DEPLOYMENT = "QUALIFIED_FOR_DEPLOYMENT"
    BLOCKED_QUALITY_GATE_FAILURE = "BLOCKED_QUALITY_GATE_FAILURE"
    BLOCKED_INSUFFICIENT_EVIDENCE = "BLOCKED_INSUFFICIENT_EVIDENCE"


@dataclass
class QualityGateConfig:
    """Configurable threshold parameters for model qualification."""
    max_overall_fpr: float = 0.010  # <= 1.0%
    max_deep_path_fpr: float = 0.010  # <= 1.0%
    max_subdomain_fpr: float = 0.010  # <= 1.0%
    max_query_heavy_fpr: float = 0.015  # <= 1.5%
    min_phishing_recall: float = 0.950  # >= 95.0%
    max_false_negative_rate: float = 0.050  # <= 5.0%
    min_f1_score: float = 0.900  # >= 0.90
    max_brier_score: float = 0.050  # <= 0.05
    max_expected_calibration_error: float = 0.050  # <= 0.05
    min_overall_samples: int = 100
    min_slice_samples: int = 15  # Minimum sample count per slice to assert statistical confidence
    decision_threshold: float = 0.50


@dataclass
class SingleGateCheck:
    """Telemetry for an individual gate criterion."""
    gate_name: str
    target_metric: str
    target_slice: str
    actual_value: Optional[float]
    threshold_value: float
    comparator: str  # "<=" or ">="
    sample_count: int
    status: GateStatus
    confidence_established: bool
    notes: str


@dataclass
class QualityGateEvaluationReport:
    """Comprehensive qualification report evaluating a candidate model against deployment gates."""
    overall_verdict: DeploymentVerdict
    passed_gates_count: int
    failed_gates_count: int
    insufficient_evidence_gates_count: int
    total_gates_count: int
    gate_checks: List[SingleGateCheck]
    sliced_metrics: Dict[str, Any]
    summary_notes: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "overall_verdict": self.overall_verdict.value,
            "summary": {
                "passed": self.passed_gates_count,
                "failed": self.failed_gates_count,
                "insufficient_evidence": self.insufficient_evidence_gates_count,
                "total": self.total_gates_count,
            },
            "gate_checks": [
                {
                    "gate_name": c.gate_name,
                    "target_metric": c.target_metric,
                    "target_slice": c.target_slice,
                    "actual_value": c.actual_value,
                    "threshold_value": c.threshold_value,
                    "comparator": c.comparator,
                    "sample_count": c.sample_count,
                    "status": c.status.value,
                    "confidence_established": c.confidence_established,
                    "notes": c.notes,
                }
                for c in self.gate_checks
            ],
            "sliced_metrics": self.sliced_metrics,
            "summary_notes": self.summary_notes,
        }


class DeploymentQualityGates:
    """Evaluates candidate models against strict deployment qualification gates."""

    def __init__(self, config: Optional[QualityGateConfig] = None):
        self.config = config or QualityGateConfig()

    @staticmethod
    def compute_ece(y_true: np.ndarray, y_prob: np.ndarray, n_bins: int = 10) -> float:
        """Computes Expected Calibration Error (ECE) across probability deciles."""
        bin_edges = np.linspace(0.0, 1.0, n_bins + 1)
        ece = 0.0
        total_samples = len(y_true)
        if total_samples == 0:
            return 0.0

        for i in range(n_bins):
            bin_lower = bin_edges[i]
            bin_upper = bin_edges[i + 1]
            if i == n_bins - 1:
                in_bin = (y_prob >= bin_lower) & (y_prob <= bin_upper)
            else:
                in_bin = (y_prob >= bin_lower) & (y_prob < bin_upper)

            bin_count = int(np.sum(in_bin))
            if bin_count > 0:
                bin_acc = float(np.mean(y_true[in_bin]))
                bin_conf = float(np.mean(y_prob[in_bin]))
                ece += (bin_count / total_samples) * abs(bin_acc - bin_conf)

        return round(float(ece), 4)

    def evaluate_model(
        self,
        model: Any,
        test_records: List[Any],
        benchmark_slices: Optional[Dict[str, List[Any]]] = None,
    ) -> QualityGateEvaluationReport:
        """
        Evaluates a candidate model against holdout test records and optional structural benchmark slices.
        Fails closed if evidence is missing, inadequate, or if any quality threshold is breached.
        """
        gate_checks: List[SingleGateCheck] = []
        sliced_metrics: Dict[str, Any] = {}

        # 1. Feature extraction and prediction on general test set
        X_test_list = []
        y_test_list = []
        for r in test_records:
            url = getattr(r, "canonical_url", None) or getattr(r, "url", "")
            feats = URLFeatureExtractor.extract_features(url)
            X_test_list.append(URLFeatureExtractor.to_feature_vector(feats))
            y_test_list.append(r.label)

        X_test = np.array(X_test_list, dtype=np.float32)
        y_test = np.array(y_test_list, dtype=np.int32)
        n_test = len(y_test)

        # Baseline predictions
        probs = model.predict_proba(X_test)[:, 1]
        preds = (probs >= self.config.decision_threshold).astype(int)

        # Compute general metrics
        tn, fp, fn, tp = confusion_matrix(y_test, preds, labels=[0, 1]).ravel()
        recall = float(recall_score(y_test, preds, zero_division=0))
        precision = float(precision_score(y_test, preds, zero_division=0))
        f1 = float(f1_score(y_test, preds, zero_division=0))
        overall_fpr = float(fp / max(1, fp + tn))
        fnr = float(fn / max(1, fn + tp))
        brier = float(brier_score_loss(y_test, probs))
        ece = self.compute_ece(y_test, probs)

        sliced_metrics["general_test"] = {
            "sample_count": n_test,
            "tp": int(tp), "tn": int(tn), "fp": int(fp), "fn": int(fn),
            "precision": round(precision, 4),
            "recall": round(recall, 4),
            "f1": round(f1, 4),
            "fpr": round(overall_fpr, 4),
            "fnr": round(fnr, 4),
            "brier_score": round(brier, 4),
            "ece": round(ece, 4),
        }

        # Check Gate: Minimum Overall Sample Count
        overall_sample_conf = n_test >= self.config.min_overall_samples
        gate_checks.append(
            SingleGateCheck(
                gate_name="Overall Test Sample Size",
                target_metric="sample_count",
                target_slice="general_test",
                actual_value=float(n_test),
                threshold_value=float(self.config.min_overall_samples),
                comparator=">=",
                sample_count=n_test,
                status=GateStatus.PASSED if overall_sample_conf else GateStatus.INSUFFICIENT_EVIDENCE,
                confidence_established=overall_sample_conf,
                notes="Verified minimum general holdout volume." if overall_sample_conf else "Insufficient general test sample size to establish statistical validity.",
            )
        )

        # Check Gate: Phishing Recall
        recall_passed = recall >= self.config.min_phishing_recall
        gate_checks.append(
            SingleGateCheck(
                gate_name="Phishing Recall (Min Sensitivity)",
                target_metric="recall",
                target_slice="general_test",
                actual_value=round(recall, 4) if overall_sample_conf else None,
                threshold_value=self.config.min_phishing_recall,
                comparator=">=",
                sample_count=n_test,
                status=GateStatus.PASSED if (overall_sample_conf and recall_passed) else (GateStatus.INSUFFICIENT_EVIDENCE if not overall_sample_conf else GateStatus.FAILED),
                confidence_established=overall_sample_conf,
                notes=f"Recall {recall:.1%} meets target {self.config.min_phishing_recall:.1%}." if (overall_sample_conf and recall_passed) else (
                    "Insufficient sample count to evaluate recall with confidence." if not overall_sample_conf else f"Recall {recall:.1%} breaches minimum {self.config.min_phishing_recall:.1%}."
                ),
            )
        )

        # Check Gate: False Negative Rate
        fnr_passed = fnr <= self.config.max_false_negative_rate
        gate_checks.append(
            SingleGateCheck(
                gate_name="Phishing False Negative Rate (Max Missed)",
                target_metric="false_negative_rate",
                target_slice="general_test",
                actual_value=round(fnr, 4) if overall_sample_conf else None,
                threshold_value=self.config.max_false_negative_rate,
                comparator="<=",
                sample_count=n_test,
                status=GateStatus.PASSED if (overall_sample_conf and fnr_passed) else (GateStatus.INSUFFICIENT_EVIDENCE if not overall_sample_conf else GateStatus.FAILED),
                confidence_established=overall_sample_conf,
                notes=f"FNR {fnr:.1%} meets target {self.config.max_false_negative_rate:.1%}." if (overall_sample_conf and fnr_passed) else (
                    "Insufficient sample count to evaluate FNR with confidence." if not overall_sample_conf else f"FNR {fnr:.1%} breaches ceiling {self.config.max_false_negative_rate:.1%}."
                ),
            )
        )

        # Check Gate: Overall False Positive Rate
        overall_fpr_passed = overall_fpr <= self.config.max_overall_fpr
        gate_checks.append(
            SingleGateCheck(
                gate_name="General False Positive Rate (Max Clean False Alarms)",
                target_metric="false_positive_rate",
                target_slice="general_test",
                actual_value=round(overall_fpr, 4) if overall_sample_conf else None,
                threshold_value=self.config.max_overall_fpr,
                comparator="<=",
                sample_count=n_test,
                status=GateStatus.PASSED if (overall_sample_conf and overall_fpr_passed) else (GateStatus.INSUFFICIENT_EVIDENCE if not overall_sample_conf else GateStatus.FAILED),
                confidence_established=overall_sample_conf,
                notes=f"FPR {overall_fpr:.1%} meets ceiling {self.config.max_overall_fpr:.1%}." if (overall_sample_conf and overall_fpr_passed) else (
                    "Insufficient sample count to evaluate general FPR with confidence." if not overall_sample_conf else f"FPR {overall_fpr:.1%} breaches ceiling {self.config.max_overall_fpr:.1%}."
                ),
            )
        )

        # Check Gate: Probability Calibration (Brier Score & ECE)
        brier_passed = brier <= self.config.max_brier_score
        gate_checks.append(
            SingleGateCheck(
                gate_name="Probability Calibration (Brier Score)",
                target_metric="brier_score",
                target_slice="general_test",
                actual_value=round(brier, 4) if overall_sample_conf else None,
                threshold_value=self.config.max_brier_score,
                comparator="<=",
                sample_count=n_test,
                status=GateStatus.PASSED if (overall_sample_conf and brier_passed) else (GateStatus.INSUFFICIENT_EVIDENCE if not overall_sample_conf else GateStatus.FAILED),
                confidence_established=overall_sample_conf,
                notes=f"Brier score {brier:.4f} meets target {self.config.max_brier_score:.4f}." if (overall_sample_conf and brier_passed) else (
                    "Insufficient sample count to evaluate Brier score with confidence." if not overall_sample_conf else f"Brier score {brier:.4f} breaches ceiling {self.config.max_brier_score:.4f}."
                ),
            )
        )

        ece_passed = ece <= self.config.max_expected_calibration_error
        gate_checks.append(
            SingleGateCheck(
                gate_name="Expected Calibration Error (ECE)",
                target_metric="expected_calibration_error",
                target_slice="general_test",
                actual_value=round(ece, 4) if overall_sample_conf else None,
                threshold_value=self.config.max_expected_calibration_error,
                comparator="<=",
                sample_count=n_test,
                status=GateStatus.PASSED if (overall_sample_conf and ece_passed) else (GateStatus.INSUFFICIENT_EVIDENCE if not overall_sample_conf else GateStatus.FAILED),
                confidence_established=overall_sample_conf,
                notes=f"ECE {ece:.4f} meets target {self.config.max_expected_calibration_error:.4f}." if (overall_sample_conf and ece_passed) else (
                    "Insufficient sample count to evaluate ECE with confidence." if not overall_sample_conf else f"ECE {ece:.4f} breaches ceiling {self.config.max_expected_calibration_error:.4f}."
                ),
            )
        )

        # 2. Evaluate Sliced Benchmarks (Deep-Path, Subdomain, Query-Heavy)
        slices = benchmark_slices or {}
        slice_threshold_mapping = {
            "deep_paths": ("Deep-Path Documentation FPR", self.config.max_deep_path_fpr),
            "subdomains": ("Multi-Tier Subdomains FPR", self.config.max_subdomain_fpr),
            "query_heavy": ("Query-Heavy Endpoints FPR", self.config.max_query_heavy_fpr),
        }

        for s_key, (gate_name, threshold) in slice_threshold_mapping.items():
            records_in_slice = slices.get(s_key, [])
            n_slice = len(records_in_slice)

            if n_slice == 0:
                gate_checks.append(
                    SingleGateCheck(
                        gate_name=gate_name,
                        target_metric="false_positive_rate",
                        target_slice=s_key,
                        actual_value=None,
                        threshold_value=threshold,
                        comparator="<=",
                        sample_count=0,
                        status=GateStatus.INSUFFICIENT_EVIDENCE,
                        confidence_established=False,
                        notes=f"FAIL-CLOSED: Benchmark slice '{s_key}' contains 0 samples. Deployment blocked without verified slice evidence.",
                    )
                )
                continue

            has_slice_conf = n_slice >= self.config.min_slice_samples
            X_slice_list = []
            for rec in records_in_slice:
                u = getattr(rec, "canonical_url", None) or getattr(rec, "url", "")
                f_dict = URLFeatureExtractor.extract_features(u)
                X_slice_list.append(URLFeatureExtractor.to_feature_vector(f_dict))

            X_slice = np.array(X_slice_list, dtype=np.float32)
            s_probs = model.predict_proba(X_slice)[:, 1]
            s_preds = (s_probs >= self.config.decision_threshold).astype(int)

            # All diagnostic benchmark slice items are assumed legitimate (y=0)
            fp_count = int(np.sum(s_preds == 1))
            slice_fpr = float(fp_count / n_slice)

            sliced_metrics[s_key] = {
                "sample_count": n_slice,
                "false_positive_count": fp_count,
                "false_positive_rate": round(slice_fpr, 4),
                "mean_probability": round(float(np.mean(s_probs)), 4),
                "confidence_established": has_slice_conf,
            }

            if not has_slice_conf:
                status = GateStatus.INSUFFICIENT_EVIDENCE
                note = f"FAIL-CLOSED: Slice '{s_key}' has only {n_slice} samples (minimum {self.config.min_slice_samples} required for confidence)."
            elif slice_fpr <= threshold:
                status = GateStatus.PASSED
                note = f"Slice FPR {slice_fpr:.1%} meets target {threshold:.1%} on {n_slice} verified samples."
            else:
                status = GateStatus.FAILED
                note = f"SHORTCUT FAILURE: Slice FPR {slice_fpr:.1%} breaches ceiling {threshold:.1%} ({fp_count}/{n_slice} legitimate endpoints flagged)."

            gate_checks.append(
                SingleGateCheck(
                    gate_name=gate_name,
                    target_metric="false_positive_rate",
                    target_slice=s_key,
                    actual_value=round(slice_fpr, 4),
                    threshold_value=threshold,
                    comparator="<=",
                    sample_count=n_slice,
                    status=status,
                    confidence_established=has_slice_conf,
                    notes=note,
                )
            )

        # 3. Compute Overall Deployment Verdict
        failed_count = sum(1 for g in gate_checks if g.status == GateStatus.FAILED)
        insufficient_count = sum(1 for g in gate_checks if g.status == GateStatus.INSUFFICIENT_EVIDENCE)
        passed_count = sum(1 for g in gate_checks if g.status == GateStatus.PASSED)
        total_count = len(gate_checks)

        summary_notes = []
        if insufficient_count > 0:
            overall_verdict = DeploymentVerdict.BLOCKED_INSUFFICIENT_EVIDENCE
            summary_notes.append(f"Model BLOCKED (Fail-Closed): {insufficient_count} gate(s) lack sufficient sample evidence to establish statistical confidence.")
            if failed_count > 0:
                summary_notes.append(f"Additionally, {failed_count} quality gate(s) breached threshold ceiling.")
        elif failed_count > 0:
            overall_verdict = DeploymentVerdict.BLOCKED_QUALITY_GATE_FAILURE
            summary_notes.append(f"Model REJECTED for deployment: {failed_count} quality gate(s) breached.")
        else:
            overall_verdict = DeploymentVerdict.QUALIFIED_FOR_DEPLOYMENT
            summary_notes.append("All deployment quality gates and sliced benchmark criteria PASSED with verified statistical evidence.")

        return QualityGateEvaluationReport(
            overall_verdict=overall_verdict,
            passed_gates_count=passed_count,
            failed_gates_count=failed_count,
            insufficient_evidence_gates_count=insufficient_count,
            total_gates_count=total_count,
            gate_checks=gate_checks,
            sliced_metrics=sliced_metrics,
            summary_notes=summary_notes,
        )
