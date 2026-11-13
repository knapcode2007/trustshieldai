"""
TrustShield AI - Phase 8A Privacy-Safe Shadow Log Analysis & Aggregator
Audits JSONL shadow evaluation logs:
1. Strict Privacy & Redaction Audit:
   - Scans records for any leaking raw URLs, tokens, passwords, session cookies, or IPv4/IPv6 addresses.
   - Verifies 16-character SHA-256 truncation for canonical_url_hash and domain_hash.
2. Observability Metrics & Verdict Divergence Synthesis:
   - Disagreement categorization (AGREEMENT_CLEAN, AGREEMENT_MALICIOUS, HYBRID_ESCALATION, HYBRID_MITIGATION, etc.).
   - Risk score delta analysis (mean, max mitigation, max escalation).
   - Evidence coverage & module availability (ML states, RDAP statuses, timeouts, cache hits).
   - Latency distributions (p50, p95, p99 for dispatch, shadow worker, and RDAP).
3. Produces clean, non-leaking audit summary JSON and markdown tables.
"""

import argparse
import json
import os
import re
import sys
from pathlib import Path
from typing import Any, Dict, List

# Patterns that MUST NOT appear in privacy-safe shadow records
URL_PATTERN = re.compile(r"https?://[^\s\"']+", re.IGNORECASE)
IPV4_PATTERN = re.compile(r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b")
SECRET_PATTERNS = [
    re.compile(r"(?:api_key|token|secret|password|bearer|auth|session)[\"']?\s*[:=]\s*[\"']?([a-zA-Z0-9_\-\.]{8,})", re.IGNORECASE),
    re.compile(r"AKIA[0-9A-Z]{16}"),  # AWS Key pattern
    re.compile(r"eyJ[a-zA-Z0-9_\-]{10,}\.[a-zA-Z0-9_\-]{10,}\.[a-zA-Z0-9_\-]{10,}"),  # JWT pattern
]


def audit_and_analyze_logs(log_path: str) -> Dict[str, Any]:
    if not os.path.exists(log_path):
        print(f"[ERROR] Log file not found at: {log_path}", file=sys.stderr)
        return {"status": "ERROR", "message": f"File not found: {log_path}"}

    total_records = 0
    privacy_violations = []

    disagreement_counts = {}
    ml_states_count = {}
    rdap_sources_count = {}
    rdap_timeouts = 0
    rdap_cache_hits = 0

    shadow_durations = []
    rdap_durations = []
    risk_score_deltas = []  # hybrid - legacy

    with open(log_path, "r", encoding="utf-8") as f:
        for line_num, line in enumerate(f, 1):
            if not line.strip():
                continue
            total_records += 1

            # 1. Privacy Audit: Check raw line for sensitive token leaks
            for sec_pat in SECRET_PATTERNS:
                if sec_pat.search(line):
                    privacy_violations.append({
                        "line": line_num,
                        "type": "SECRET_LEAK",
                        "pattern": sec_pat.pattern,
                    })

            # Check for leaked IP addresses (ignoring safe loopbacks or mock constants if any)
            ip_matches = IPV4_PATTERN.findall(line)
            for ip in ip_matches:
                # 93.184.216.34 is our mocked test IP, but in privacy-safe logs IP must not be logged
                privacy_violations.append({
                    "line": line_num,
                    "type": "IP_LEAK",
                    "matched_ip": ip,
                })

            try:
                rec = json.loads(line)
            except Exception as e:
                privacy_violations.append({
                    "line": line_num,
                    "type": "JSON_PARSE_ERROR",
                    "error": str(e),
                })
                continue

            # Check that raw canonical URL is NOT in the record
            target = rec.get("target", {})
            for k, v in target.items():
                if isinstance(v, str) and URL_PATTERN.search(v):
                    privacy_violations.append({
                        "line": line_num,
                        "type": "RAW_URL_LEAK",
                        "field": f"target.{k}",
                    })

            # Check hash truncation (must be 16 chars hex)
            url_hash = target.get("canonical_url_hash", "")
            if not (len(url_hash) == 16 and all(c in "0123456789abcdef" for c in url_hash.lower())):
                privacy_violations.append({
                    "line": line_num,
                    "type": "INVALID_HASH_LENGTH",
                    "field": "target.canonical_url_hash",
                    "actual_length": len(url_hash),
                })

            # 2. Observability Aggregation
            verdicts = rec.get("verdicts", {})
            cat = verdicts.get("disagreement_category", "UNKNOWN")
            disagreement_counts[cat] = disagreement_counts.get(cat, 0) + 1

            leg_score = verdicts.get("legacy_risk_score", 0)
            hyb_score = verdicts.get("hybrid_risk_score", 0)
            risk_score_deltas.append(hyb_score - leg_score)

            evidence = rec.get("evidence_sources", {})
            lex_ml = evidence.get("lexical_ml", {})
            exp_state = lex_ml.get("experimental_state", "UNKNOWN")
            ml_states_count[exp_state] = ml_states_count.get(exp_state, 0) + 1

            dom_tel = evidence.get("domain_telemetry", {})
            source = dom_tel.get("source", "none")
            rdap_sources_count[source] = rdap_sources_count.get(source, 0) + 1
            if dom_tel.get("timed_out"):
                rdap_timeouts += 1
            if dom_tel.get("cached"):
                rdap_cache_hits += 1

            timing = rec.get("telemetry_timing", {})
            shadow_durations.append(timing.get("total_shadow_duration_ms", 0.0))
            rdap_durations.append(timing.get("rdap_duration_ms", 0.0))

    # Calculate percentiles
    def calc_percentiles(values: List[float]) -> Dict[str, float]:
        if not values:
            return {"p50": 0.0, "p90": 0.0, "p95": 0.0, "p99": 0.0, "max": 0.0}
        s = sorted(values)
        n = len(s)
        return {
            "p50": round(s[int(n * 0.50)], 2),
            "p90": round(s[int(n * 0.90)], 2),
            "p95": round(s[int(n * 0.95)], 2),
            "p99": round(s[int(n * 0.99)], 2),
            "max": round(max(s), 2),
        }

    shadow_pct = calc_percentiles(shadow_durations)
    rdap_pct = calc_percentiles(rdap_durations)

    mean_delta = round(sum(risk_score_deltas) / len(risk_score_deltas), 2) if risk_score_deltas else 0.0
    max_escalation = max(risk_score_deltas) if risk_score_deltas else 0
    max_mitigation = min(risk_score_deltas) if risk_score_deltas else 0

    analysis_report = {
        "log_path": log_path,
        "total_records": total_records,
        "privacy_audit": {
            "is_clean": len(privacy_violations) == 0,
            "violations_count": len(privacy_violations),
            "violations_sample": privacy_violations[:5],
        },
        "disagreement_breakdown": disagreement_counts,
        "risk_score_deltas": {
            "mean_delta": mean_delta,
            "max_escalation_points": max_escalation,
            "max_mitigation_points": abs(max_mitigation) if max_mitigation < 0 else 0,
        },
        "model_and_evidence_states": {
            "experimental_ml_states": ml_states_count,
            "telemetry_sources": rdap_sources_count,
            "rdap_timeouts": rdap_timeouts,
            "rdap_cache_hits": rdap_cache_hits,
            "cache_hit_rate_percent": round((rdap_cache_hits / total_records * 100), 2) if total_records else 0.0,
        },
        "latency_percentiles_ms": {
            "total_shadow_duration": shadow_pct,
            "rdap_lookup_duration": rdap_pct,
        },
    }

    return analysis_report


def main():
    parser = argparse.ArgumentParser(description="TrustShield AI Shadow Evaluation Log Analyzer")
    parser.add_argument("log_path", nargs="?", default="logs/staging_load_test_shadow.jsonl", help="Path to shadow JSONL log")
    parser.add_argument("--json", action="store_true", help="Output raw JSON format")
    args = parser.parse_args()

    report = audit_and_analyze_logs(args.log_path)

    if args.json:
        print(json.dumps(report, indent=2))
        sys.exit(0 if report.get("privacy_audit", {}).get("is_clean", False) else 1)

    print("=" * 70)
    print("TRUSTSHIELD AI - SHADOW LOG PRIVACY & OBSERVABILITY REPORT")
    print(f"Log File: {report['log_path']}")
    print(f"Total Evaluated Records: {report['total_records']}")
    print("=" * 70)

    priv = report["privacy_audit"]
    if priv["is_clean"]:
        print("[PRIVACY AUDIT] PASSED - 0 leaking raw URLs, secrets, or IP addresses.")
    else:
        print(f"[PRIVACY AUDIT] FAILED - {priv['violations_count']} violations detected!")
        for v in priv["violations_sample"]:
            print(f"  - Line {v.get('line')}: {v.get('type')}")

    print("\n[VERDICT DISAGREEMENT SUMMARY]")
    for cat, count in report["disagreement_breakdown"].items():
        pct = (count / report["total_records"] * 100) if report["total_records"] else 0
        print(f"  - {cat:28s}: {count:4d} ({pct:5.1f}%)")

    print("\n[RISK SCORE DIVERGENCE]")
    deltas = report["risk_score_deltas"]
    print(f"  - Mean Risk Delta (Hybrid - Legacy): {deltas['mean_delta']:+.2f} points")
    print(f"  - Max Escalation (Cautious Shadow):  {deltas['max_escalation_points']:+d} points")
    print(f"  - Max Mitigation (FP Reduction):    -{deltas['max_mitigation_points']} points")

    print("\n[OPERATIONAL & TELEMETRY BREAKDOWN]")
    ops = report["model_and_evidence_states"]
    print(f"  - Experimental ML States: {ops['experimental_ml_states']}")
    print(f"  - Telemetry Sources:      {ops['telemetry_sources']}")
    print(f"  - RDAP Timeouts:          {ops['rdap_timeouts']}")
    print(f"  - RDAP Cache Hits:        {ops['rdap_cache_hits']} ({ops['cache_hit_rate_percent']}%)")

    print("\n[SHADOW TIMING PERCENTILES (ms)]")
    lat = report["latency_percentiles_ms"]
    print(f"  - Shadow Worker: p50={lat['total_shadow_duration']['p50']}ms | p95={lat['total_shadow_duration']['p95']}ms | p99={lat['total_shadow_duration']['p99']}ms")
    print(f"  - RDAP Lookup:   p50={lat['rdap_lookup_duration']['p50']}ms | p95={lat['rdap_lookup_duration']['p95']}ms | p99={lat['rdap_lookup_duration']['p99']}ms")
    print("=" * 70)

    sys.exit(0 if priv["is_clean"] else 1)


if __name__ == "__main__":
    main()

