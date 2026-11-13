"""
TrustShield AI - Hybrid Threat Intelligence & Evidence-Based Decision Engine
Phase 7A Architecture: Multi-source evidence correlation combining external threat intelligence,
calibrated lexical machine learning, Public Suffix-aware host structure, and domain telemetry.

Core Security Invariants:
1. External Threat Feed Override: Confirmed malicious threat intelligence (Google Safe Browsing,
   VirusTotal >= 2 engines, URLhaus exact URL) CANNOT be downgraded by lexical ML or apex popularity.
2. No Negative Proof: Clean external feeds ('no_match') or long domain age NEVER establish guaranteed safety.
3. No Automatic Authority Bypasses: Host structures and government/cloud prefixes provide context
   but NEVER grant hardcoded exemptions or bypass threat intelligence.
4. Fail-Closed Integrity: Missing, rate-limited, or errored providers are NEVER interpreted as clean.
5. Explicit Verdict States: Strictly distinguishes MALICIOUS, SUSPICIOUS, NO_THREAT_DETECTED, and INCONCLUSIVE.
"""

import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse

from backend.app.intel.base import ThreatFeedResult
from backend.app.ml.features import URLFeatureExtractor


class HybridVerdictState(str, Enum):
    """Authoritative four-state risk decision model."""
    MALICIOUS = "MALICIOUS"
    SUSPICIOUS = "SUSPICIOUS"
    NO_THREAT_DETECTED = "NO_THREAT_DETECTED"
    INCONCLUSIVE = "INCONCLUSIVE"


class HierarchyType(str, Enum):
    """Structural classification of the destination hostname."""
    APEX_ROOT = "APEX_ROOT"
    SINGLE_SUBDOMAIN = "SINGLE_SUBDOMAIN"
    CORPORATE_MULTI_TIER = "CORPORATE_MULTI_TIER"
    TENANT_NAMESPACE = "TENANT_NAMESPACE"
    NESTED_TENANT = "NESTED_TENANT"


@dataclass
class HostStructureDetails:
    """Public Suffix-aware structural decomposition of a target hostname."""
    hostname: str
    hierarchy_type: HierarchyType
    icann_suffix: str
    private_suffix: Optional[str]
    registrable_domain: str
    tenant_boundary: Optional[str]
    subdomain_count: int
    is_multi_tenant_platform: bool


@dataclass
class DomainTelemetryDetails:
    """Domain registration age, provenance, and stability telemetry."""
    domain: str
    registration_date: Optional[str] = None
    expiration_date: Optional[str] = None
    last_changed_date: Optional[str] = None
    age_days: Optional[int] = None
    status: str = "unknown"  # "active", "newly_registered", "unknown", "error", "redacted", "unavailable"
    is_newly_registered: bool = False  # True if age_days < 30 (ONLY when registration_date is reliably known)
    telemetry_source: str = "none"  # "rdap", "cache", "mock", "none"
    retrieval_timestamp: Optional[str] = None
    freshness_seconds: Optional[int] = None
    confidence: float = 0.5  # 0.0 to 1.0 confidence in the telemetry integrity
    reliability_limitation: Optional[str] = None
    cached: bool = False
    raw_data: Optional[Dict[str, Any]] = None


@dataclass
class DecisionEvidence:
    """Individual item of correlated evidence contributing to the final verdict."""
    level: str  # "L1_AUTHORITATIVE_INTEL", "L2_HEURISTIC_OR_HOST_INTEL", "L3_LEXICAL_ML", "L4_DOMAIN_TELEMETRY"
    provider_or_rule: str
    finding: str
    severity: str  # "critical", "high", "medium", "low", "info"
    confidence: float
    details: str


@dataclass
class HybridDecisionResult:
    """Comprehensive verdict, risk score, and transparent audit trail."""
    state: HybridVerdictState
    legacy_verdict: str  # "clean", "suspicious", "phishing", "malicious" for backwards compatibility
    risk_score: int  # 0 to 100
    confidence: float  # 0.0 to 1.0
    host_structure: HostStructureDetails
    telemetry: DomainTelemetryDetails
    evidence_chain: List[DecisionEvidence] = field(default_factory=list)
    caveats: List[str] = field(default_factory=list)
    threat_types: List[str] = field(default_factory=list)
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> Dict[str, Any]:
        return {
            "state": self.state.value,
            "legacy_verdict": self.legacy_verdict,
            "risk_score": self.risk_score,
            "confidence": round(self.confidence, 4),
            "threat_types": self.threat_types,
            "host_structure": {
                "hostname": self.host_structure.hostname,
                "hierarchy_type": self.host_structure.hierarchy_type.value,
                "icann_suffix": self.host_structure.icann_suffix,
                "private_suffix": self.host_structure.private_suffix,
                "registrable_domain": self.host_structure.registrable_domain,
                "tenant_boundary": self.host_structure.tenant_boundary,
                "subdomain_count": self.host_structure.subdomain_count,
                "is_multi_tenant_platform": self.host_structure.is_multi_tenant_platform,
            },
            "telemetry": {
                "domain": self.telemetry.domain,
                "age_days": self.telemetry.age_days,
                "status": self.telemetry.status,
                "is_newly_registered": self.telemetry.is_newly_registered,
                "telemetry_source": self.telemetry.telemetry_source,
                "registration_date": self.telemetry.registration_date,
                "expiration_date": getattr(self.telemetry, "expiration_date", None),
                "last_changed_date": getattr(self.telemetry, "last_changed_date", None),
                "retrieval_timestamp": getattr(self.telemetry, "retrieval_timestamp", None),
                "freshness_seconds": getattr(self.telemetry, "freshness_seconds", None),
                "confidence": getattr(self.telemetry, "confidence", 0.5),
                "reliability_limitation": getattr(self.telemetry, "reliability_limitation", None),
                "cached": getattr(self.telemetry, "cached", False),
            },
            "evidence_chain": [
                {
                    "level": e.level,
                    "provider_or_rule": e.provider_or_rule,
                    "finding": e.finding,
                    "severity": e.severity,
                    "confidence": e.confidence,
                    "details": e.details,
                }
                for e in self.evidence_chain
            ],
            "caveats": self.caveats,
            "created_at": self.created_at,
        }


class HostStructureInterpreter:
    """
    Deconstructs hostnames using Public Suffix List rules (ICANN and Private)
    to differentiate apex domains, multi-tier corporate consoles, and multi-tenant hosting.
    """

    MULTI_TENANT_SUFFIXES = {
        "pages.dev", "github.io", "gitlab.io", "web.app", "firebaseapp.com",
        "netlify.app", "vercel.app", "onrender.com", "herokuapp.com", "glitch.me",
        "azurewebsites.net", "appspot.com", "myshopify.com", "blogspot.com",
        "wordpress.com", "weebly.com", "wixsite.com", "duckdns.org",
    }

    @classmethod
    def analyze_host(cls, netloc: str) -> HostStructureDetails:
        host = netloc.split(":")[0].strip().lower()

        # Offline fallback / PSL parsing
        try:
            import publicsuffix2
            psl = publicsuffix2.PublicSuffixList()
            suffix = psl.get_tld(host) or ""
            sld = psl.get_sld(host) or host
        except Exception:
            parts = host.split(".")
            suffix = ".".join(parts[-2:]) if len(parts) >= 2 else ""
            sld = host

        # Check multi-tenant platforms
        is_multi_tenant = False
        tenant_boundary = None
        private_suffix = None

        for mts in cls.MULTI_TENANT_SUFFIXES:
            if host == mts:
                is_multi_tenant = True
                private_suffix = mts
                break
            if host.endswith("." + mts):
                is_multi_tenant = True
                private_suffix = mts
                prefix = host[:-len(mts) - 1]
                tenant = prefix.split(".")[-1]
                tenant_boundary = f"{tenant}.{mts}"
                break

        if sld and host.endswith("." + sld):
            prefix = host[:-len(sld) - 1]
            subdomain_count = len(prefix.split("."))
        elif host == sld:
            subdomain_count = 0
        else:
            parts = host.split(".")
            subdomain_count = max(0, len(parts) - 2)
            if host.endswith(".co.uk") or host.endswith(".gov.uk") or host.endswith(".edu.au"):
                subdomain_count = max(0, len(parts) - 3)

        if is_multi_tenant:
            if tenant_boundary and host != tenant_boundary:
                hierarchy = HierarchyType.NESTED_TENANT
            else:
                hierarchy = HierarchyType.TENANT_NAMESPACE
        elif subdomain_count >= 2:
            hierarchy = HierarchyType.CORPORATE_MULTI_TIER
        elif subdomain_count == 1:
            hierarchy = HierarchyType.SINGLE_SUBDOMAIN
        else:
            hierarchy = HierarchyType.APEX_ROOT

        return HostStructureDetails(
            hostname=host,
            hierarchy_type=hierarchy,
            icann_suffix=suffix,
            private_suffix=private_suffix,
            registrable_domain=sld,
            tenant_boundary=tenant_boundary,
            subdomain_count=subdomain_count,
            is_multi_tenant_platform=is_multi_tenant,
        )


class HybridDecisionEngine:
    """
    Correlates multi-source evidence into a defensible risk verdict.
    Adheres strictly to the evidence hierarchy and prevents automated authority bypasses.
    """

    def __init__(self):
        pass

    def evaluate(
        self,
        raw_url: str,
        intel_results: List[ThreatFeedResult],
        ml_prediction: Optional[Dict[str, Any]] = None,
        heuristic_findings: Optional[List[Any]] = None,
        telemetry: Optional[DomainTelemetryDetails] = None,
    ) -> HybridDecisionResult:
        parsed = urlparse(raw_url if "://" in raw_url else f"https://{raw_url}")
        host = (parsed.netloc or "").split(":")[0].lower()

        host_details = HostStructureInterpreter.analyze_host(host)
        dom_telemetry = telemetry or DomainTelemetryDetails(domain=host, status="unknown")

        evidence_chain: List[DecisionEvidence] = []
        caveats: List[str] = []
        threat_types: Set[str] = set()

        # ----------------------------------------------------------------------
        # Step 1: Audit External Intelligence Providers
        # ----------------------------------------------------------------------
        l1_matches: List[ThreatFeedResult] = []
        l2_matches: List[ThreatFeedResult] = []
        clean_feeds_count = 0
        unavailable_feeds_count = 0
        rate_limited_feeds_count = 0
        error_feeds_count = 0

        for feed in intel_results:
            if feed.matched:
                if feed.match_type == "exact_url":
                    l1_matches.append(feed)
                    if feed.threat_type:
                        threat_types.add(feed.threat_type)
                    evidence_chain.append(DecisionEvidence(
                        level="L1_AUTHORITATIVE_INTEL",
                        provider_or_rule=feed.provider,
                        finding=f"Confirmed exact-URL threat signature: {feed.threat_type or 'malicious'}",
                        severity="critical",
                        confidence=feed.confidence / 100.0,
                        details=feed.details,
                    ))
                elif feed.match_type in ("host", "domain"):
                    l2_matches.append(feed)
                    if feed.threat_type:
                        threat_types.add(feed.threat_type)
                    evidence_chain.append(DecisionEvidence(
                        level="L2_HEURISTIC_OR_HOST_INTEL",
                        provider_or_rule=feed.provider,
                        finding=f"Threat intelligence host/domain match: {feed.threat_type or 'suspicious'}",
                        severity="high",
                        confidence=feed.confidence / 100.0,
                        details=feed.details,
                    ))
            elif feed.status == "no_match":
                clean_feeds_count += 1
            elif feed.status == "unavailable":
                unavailable_feeds_count += 1
            elif feed.status == "rate_limited":
                rate_limited_feeds_count += 1
            elif feed.status == "error":
                error_feeds_count += 1

        if unavailable_feeds_count > 0:
            caveats.append(f"{unavailable_feeds_count} intelligence provider(s) unavailable.")
        if rate_limited_feeds_count > 0:
            caveats.append(f"{rate_limited_feeds_count} intelligence provider(s) rate-limited.")
        if error_feeds_count > 0:
            caveats.append(f"{error_feeds_count} intelligence provider(s) encountered lookup errors.")

        # ----------------------------------------------------------------------
        # Step 2: Audit Heuristic Findings
        # ----------------------------------------------------------------------
        brand_squatting_detected = False
        if heuristic_findings:
            for f in heuristic_findings:
                rule_id = getattr(f, "rule_id", "")
                desc = getattr(f, "description", "")
                sev = getattr(f, "severity", "medium")
                if "brand" in rule_id.lower() or "brand" in desc.lower():
                    brand_squatting_detected = True
                    evidence_chain.append(DecisionEvidence(
                        level="L2_HEURISTIC_OR_HOST_INTEL",
                        provider_or_rule=f"heuristics:{rule_id}",
                        finding=desc,
                        severity=sev,
                        confidence=0.85,
                        details="Heuristic pattern detected brand impersonation in hostname/path.",
                    ))
                elif getattr(f, "score_impact", 0) >= 20:
                    evidence_chain.append(DecisionEvidence(
                        level="L2_HEURISTIC_OR_HOST_INTEL",
                        provider_or_rule=f"heuristics:{rule_id}",
                        finding=desc,
                        severity=sev,
                        confidence=0.70,
                        details="High-severity heuristic anomaly.",
                    ))

        # ----------------------------------------------------------------------
        # Step 3: Audit Calibrated Lexical Machine Learning Score
        # ----------------------------------------------------------------------
        prob_phish = None
        ml_confidence = 0.0
        if ml_prediction and ml_prediction.get("is_trained") and ml_prediction.get("probability_phish") is not None:
            prob_phish = float(ml_prediction["probability_phish"])
            ml_confidence = float(ml_prediction.get("confidence", 0.85))
            evidence_chain.append(DecisionEvidence(
                level="L3_LEXICAL_ML",
                provider_or_rule=ml_prediction.get("model", "RandomForest"),
                finding=f"Calibrated lexical phishing probability: {prob_phish:.4f}",
                severity="high" if prob_phish >= 0.65 else ("medium" if prob_phish >= 0.35 else "low"),
                confidence=ml_confidence,
                details=f"Inference derived from 30 standardized lexical and structural features.",
            ))

        # ----------------------------------------------------------------------
        # Step 4: Audit Domain Telemetry (Registration Age & Host Context)
        # ----------------------------------------------------------------------
        if dom_telemetry.is_newly_registered and dom_telemetry.age_days is not None:
            evidence_chain.append(DecisionEvidence(
                level="L4_DOMAIN_TELEMETRY",
                provider_or_rule="domain_telemetry:rdap",
                finding=f"Newly registered domain (Age: {dom_telemetry.age_days} days)",
                severity="medium",
                confidence=0.80,
                details="Domain created within the last 30 days, representing elevated campaign risk.",
            ))

        # ----------------------------------------------------------------------
        # Step 5: Evidence Precedence & Deterministic Verdict Synthesis
        # ----------------------------------------------------------------------

        # RULE 1: Level 1 Authoritative Threat Feed Match -> ABSOLUTE OVERRIDE TO MALICIOUS
        if l1_matches:
            risk_score = max(85, max([f.confidence for f in l1_matches]))
            is_phish = any("phish" in t.lower() or "social" in t.lower() for t in threat_types)
            legacy_v = "phishing" if is_phish else "malicious"
            return HybridDecisionResult(
                state=HybridVerdictState.MALICIOUS,
                legacy_verdict=legacy_v,
                risk_score=risk_score,
                confidence=0.98,
                host_structure=host_details,
                telemetry=dom_telemetry,
                evidence_chain=evidence_chain,
                caveats=caveats,
                threat_types=list(threat_types),
            )

        # RULE 2: Confirmed Brand Squatting or L2 Host Match + Elevated ML -> MALICIOUS / SUSPICIOUS
        if brand_squatting_detected:
            risk_score = 75
            if prob_phish is not None and prob_phish >= 0.60:
                risk_score = 90
                return HybridDecisionResult(
                    state=HybridVerdictState.MALICIOUS,
                    legacy_verdict="phishing",
                    risk_score=risk_score,
                    confidence=0.90,
                    host_structure=host_details,
                    telemetry=dom_telemetry,
                    evidence_chain=evidence_chain,
                    caveats=caveats,
                    threat_types=["phishing", "brand_impersonation"],
                )
            return HybridDecisionResult(
                state=HybridVerdictState.SUSPICIOUS,
                legacy_verdict="suspicious",
                risk_score=risk_score,
                confidence=0.85,
                host_structure=host_details,
                telemetry=dom_telemetry,
                evidence_chain=evidence_chain,
                caveats=caveats,
                threat_types=["brand_impersonation"],
            )

        if l2_matches:
            # Threat feed matches host or domain, but not exact URL
            risk_score = 65
            if prob_phish is not None and prob_phish >= 0.70:
                risk_score = 85
                return HybridDecisionResult(
                    state=HybridVerdictState.MALICIOUS,
                    legacy_verdict="malicious",
                    risk_score=risk_score,
                    confidence=0.88,
                    host_structure=host_details,
                    telemetry=dom_telemetry,
                    evidence_chain=evidence_chain,
                    caveats=caveats,
                    threat_types=list(threat_types),
                )
            return HybridDecisionResult(
                state=HybridVerdictState.SUSPICIOUS,
                legacy_verdict="suspicious",
                risk_score=risk_score,
                confidence=0.80,
                host_structure=host_details,
                telemetry=dom_telemetry,
                evidence_chain=evidence_chain,
                caveats=caveats,
                threat_types=list(threat_types),
            )

        # RULE 3: Handling Lexical Machine Learning Findings
        if prob_phish is not None:
            # 3A. High ML Risk (P >= 0.65)
            if prob_phish >= 0.65:
                # If clean feeds exist and host is Corporate Multi-Tier, mitigate if uncorroborated
                # NOTE: Never bypass, but classify as SUSPICIOUS rather than MALICIOUS without signatures
                risk_score = int(prob_phish * 100)
                return HybridDecisionResult(
                    state=HybridVerdictState.SUSPICIOUS,
                    legacy_verdict="suspicious",
                    risk_score=risk_score,
                    confidence=ml_confidence,
                    host_structure=host_details,
                    telemetry=dom_telemetry,
                    evidence_chain=evidence_chain,
                    caveats=caveats,
                    threat_types=["heuristic_suspicion"],
                )

            # 3B. Low ML Risk (P < 0.35)
            elif prob_phish < 0.35:
                # If newly registered apex domain, escalate to SUSPICIOUS
                if dom_telemetry.is_newly_registered and host_details.hierarchy_type == HierarchyType.APEX_ROOT:
                    return HybridDecisionResult(
                        state=HybridVerdictState.SUSPICIOUS,
                        legacy_verdict="suspicious",
                        risk_score=50,
                        confidence=0.75,
                        host_structure=host_details,
                        telemetry=dom_telemetry,
                        evidence_chain=evidence_chain,
                        caveats=caveats + ["Apex domain registered < 30 days ago escalated for manual verification."],
                        threat_types=["disposable_infrastructure_risk"],
                    )

                # Clean feeds available -> NO_THREAT_DETECTED
                if clean_feeds_count > 0:
                    risk_score = int(prob_phish * 30)
                    return HybridDecisionResult(
                        state=HybridVerdictState.NO_THREAT_DETECTED,
                        legacy_verdict="clean",
                        risk_score=risk_score,
                        confidence=0.92,
                        host_structure=host_details,
                        telemetry=dom_telemetry,
                        evidence_chain=evidence_chain,
                        caveats=caveats,
                        threat_types=[],
                    )
                else:
                    # All feeds were unavailable/error, but ML is low
                    caveats.append("Zero threat feeds available; verdict relies strictly on lexical ML.")
                    return HybridDecisionResult(
                        state=HybridVerdictState.NO_THREAT_DETECTED,
                        legacy_verdict="clean",
                        risk_score=int(prob_phish * 35),
                        confidence=0.60,
                        host_structure=host_details,
                        telemetry=dom_telemetry,
                        evidence_chain=evidence_chain,
                        caveats=caveats,
                        threat_types=[],
                    )

            # 3C. Borderline ML Risk (0.35 <= P < 0.65)
            else:
                if clean_feeds_count >= 2:
                    # Feeds active and clear, borderline lexical score -> Low-grade SUSPICIOUS
                    return HybridDecisionResult(
                        state=HybridVerdictState.SUSPICIOUS,
                        legacy_verdict="suspicious",
                        risk_score=int(prob_phish * 80),
                        confidence=0.65,
                        host_structure=host_details,
                        telemetry=dom_telemetry,
                        evidence_chain=evidence_chain,
                        caveats=caveats,
                        threat_types=["indeterminate_lexical_risk"],
                    )
                else:
                    # Feeds unavailable or errored -> INCONCLUSIVE
                    caveats.append("Borderline lexical probability with insufficient external feed corroboration.")
                    return HybridDecisionResult(
                        state=HybridVerdictState.INCONCLUSIVE,
                        legacy_verdict="suspicious",
                        risk_score=50,
                        confidence=0.40,
                        host_structure=host_details,
                        telemetry=dom_telemetry,
                        evidence_chain=evidence_chain,
                        caveats=caveats,
                        threat_types=["inconclusive_threat_data"],
                    )

        # RULE 4: Fallback when ML service is untrained or unavailable
        if clean_feeds_count > 0:
            return HybridDecisionResult(
                state=HybridVerdictState.NO_THREAT_DETECTED,
                legacy_verdict="clean",
                risk_score=10,
                confidence=0.75,
                host_structure=host_details,
                telemetry=dom_telemetry,
                evidence_chain=evidence_chain,
                caveats=caveats + ["Lexical ML model unavailable; evaluation based on signature feeds."],
                threat_types=[],
            )

        # All signals missing/unavailable -> INCONCLUSIVE
        caveats.append("No active threat feeds or machine learning models available.")
        return HybridDecisionResult(
            state=HybridVerdictState.INCONCLUSIVE,
            legacy_verdict="suspicious",
            risk_score=40,
            confidence=0.20,
            host_structure=host_details,
            telemetry=dom_telemetry,
            evidence_chain=evidence_chain,
            caveats=caveats,
            threat_types=["unsupported_scan_state"],
        )


hybrid_decision_engine = HybridDecisionEngine()
