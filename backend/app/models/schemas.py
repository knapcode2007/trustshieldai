from datetime import datetime
from typing import Any, Dict, List, Literal, Optional

try:
    from pydantic import BaseModel, Field
except ImportError:
    class BaseModel:
        def __init__(self, **kwargs):
            for cls_item in reversed(self.__class__.__mro__):
                if hasattr(cls_item, "__annotations__"):
                    for k in cls_item.__annotations__:
                        if hasattr(cls_item, k):
                            val = getattr(cls_item, k)
                            setattr(self, k, val() if callable(val) else val)
            for k, v in kwargs.items():
                setattr(self, k, v)

        def model_dump(self):
            return {k: (v.model_dump() if hasattr(v, "model_dump") else v) for k, v in self.__dict__.items()}

        def __repr__(self):
            return f"{self.__class__.__name__}({self.__dict__})"

    def Field(*args, default=None, default_factory=None, **kwargs):
        if default_factory is not None:
            return default_factory
        return default

# --- Health Schemas ---
class SubsystemHealth(BaseModel):
    status: Literal["online", "ready", "configured", "degraded", "offline"]
    details: Optional[str] = None
    latency_ms: Optional[float] = None
    version: Optional[str] = None
    provider: Optional[str] = None

class HealthResponse(BaseModel):
    status: Literal["healthy", "degraded", "unhealthy"]
    app_name: str
    version: str
    environment: str
    request_id: Optional[str] = None
    ssrf_protection: Literal["active", "disabled"] = "active"
    timestamp: str
    subsystems: Dict[str, SubsystemHealth]

# --- Scan & Inspection Options ---
class ScanOptions(BaseModel):
    run_ml: bool = True
    inspect_tls: bool = True
    inspect_headers: bool = True
    follow_redirects: bool = True
    save_scan: bool = True

class ScanCreateRequest(BaseModel):
    url: str = Field(..., description="Destination target URL or domain")
    force_fresh: bool = Field(default=False, description="Bypass cache and force immediate re-scan")
    options: Optional[ScanOptions] = Field(default_factory=ScanOptions)

# Backward compatibility alias
ScanRequest = ScanCreateRequest

class ModuleStatusDetail(BaseModel):
    status: Literal["idle", "running", "completed", "partial", "failed", "skipped"]
    started_at: Optional[str] = None
    completed_at: Optional[str] = None
    error: Optional[str] = None

class HeuristicFinding(BaseModel):
    rule_id: str
    category: str
    severity: Literal["low", "medium", "high", "critical"]
    description: str
    score_impact: int

class HeuristicResults(BaseModel):
    suspicious_keywords: List[str] = []
    has_ip_in_url: bool = False
    subdomain_count: int = 0
    url_entropy: float = 0.0
    detected_brand_squats: List[str] = []
    findings: List[HeuristicFinding] = []

class MlPrediction(BaseModel):
    status: Literal["operational", "unavailable", "error"] = "unavailable"
    is_trained: bool = False
    model: str = "TrustShield-RandomForest-PhishLex-v1.0"
    model_version: Optional[str] = "TrustShield-RandomForest-PhishLex-v1.0"
    probability_phish: Optional[float] = None
    confidence: Optional[float] = None
    feature_importances: Optional[Dict[str, float]] = None
    contributing_features: Optional[Dict[str, float]] = None
    extracted_features: Optional[Dict[str, Any]] = None
    message: Optional[str] = None

class TlsSummary(BaseModel):
    valid: bool
    issuer: Optional[str] = None
    subject: Optional[str] = None
    days_remaining: Optional[int] = None
    is_expired: bool = False
    is_self_signed: bool = False
    protocol_version: Optional[str] = None
    cipher_suite: Optional[str] = None
    grade: Optional[str] = None

class SecurityHeaderItem(BaseModel):
    name: str
    value: Optional[str] = None
    present: bool
    status: Literal["pass", "warn", "fail"]
    description: str
    recommendation: Optional[str] = None

class SecurityHeadersSummary(BaseModel):
    evaluated: bool = True
    score: int = 0
    grade: str = "N/A"
    headers: List[SecurityHeaderItem] = []
    missing_critical_count: int = 0
    target_url: Optional[str] = None
    final_url: Optional[str] = None
    https_available: bool = True
    redirect_chain: List[Dict[str, Any]] = []
    cookie_security: List[Dict[str, Any]] = []
    weaknesses: List[Dict[str, Any]] = []
    verdict_separation_note: Optional[str] = None
    notes: List[str] = []

class AnalysisCoverage(BaseModel):
    lexical: int
    ml: int
    tls: int
    headers: int
    threat_feeds: int
    overall: int

class ThreatFeedMatch(BaseModel):
    provider: Optional[str] = None
    provider_name: Optional[str] = None
    feed_name: Optional[str] = None
    status: Literal["available", "no_match", "unavailable", "rate_limited", "error"] = "no_match"
    matched: bool = False
    match_type: Literal["exact_url", "host", "domain", "none"] = "none"
    threat_type: Optional[str] = None
    confidence: Optional[int] = 0
    details: Optional[str] = None
    reference_url: Optional[str] = None
    reference_id: Optional[str] = None
    attribution: Optional[str] = None
    checked_at: Optional[str] = None
    cached: Optional[bool] = False
    rate_limited: Optional[bool] = False
    query_sanitized: Optional[bool] = False
    redacted_params: Optional[List[str]] = []
    raw_evidence: Optional[Dict[str, Any]] = None

class EvidenceItem(BaseModel):
    category: str
    key: str
    value: str
    significance: str

class Recommendation(BaseModel):
    id: str
    title: str
    description: str
    severity: Literal["low", "medium", "high", "critical"]
    category: str

class ScanResponse(BaseModel):
    scan_id: str
    url: str
    normalized_url: str
    domain: str
    verdict: Literal["clean", "suspicious", "phishing", "malicious"]
    risk_score: int = Field(..., ge=0, le=100)
    confidence: float = Field(..., ge=0.0, le=1.0)
    heuristics: HeuristicResults
    ml_prediction: Optional[MlPrediction] = None
    tls_summary: Optional[TlsSummary] = None
    security_headers: Optional[SecurityHeadersSummary] = None
    analysis_coverage: Optional[AnalysisCoverage] = None
    threat_feed_matches: Optional[List[ThreatFeedMatch]] = None
    threat_intel_summary: Optional[Dict[str, Any]] = None
    evidence: Optional[List[EvidenceItem]] = None
    recommendations: Optional[List[Recommendation]] = None
    created_at: str

class ScanJobStateResponse(BaseModel):
    scan_id: str
    request_id: str
    raw_url: str
    canonical_url: str
    domain: str
    state: Literal["queued", "running", "completed", "partial", "failed"]
    progress_percent: int
    module_statuses: Dict[str, ModuleStatusDetail]
    timestamps: Dict[str, Optional[str]]
    error: Optional[Dict[str, Any]] = None
    result: Optional[ScanResponse] = None

class ScanHistoryResponse(BaseModel):
    items: List[ScanJobStateResponse]
    total: int
    limit: int
    offset: int

# --- TLS Inspection & Certificate Intelligence Schemas ---
class CertificateChainItem(BaseModel):
    subject: str
    issuer: str
    is_root: bool = False
    is_intermediate: bool = False
    is_leaf: bool = False
    valid_from: Optional[str] = None
    valid_to: Optional[str] = None
    days_remaining: Optional[int] = None
    sha256_fingerprint: Optional[str] = None
    trusted: bool = True

class TlsAnomaly(BaseModel):
    code: str
    severity: Literal["low", "medium", "high", "critical"]
    title: str
    description: str

class CertificateTransparencyEvidence(BaseModel):
    status: Literal["verified_embedded_scts", "public_log_matched", "unavailable", "none"] = "unavailable"
    sct_count: int = 0
    operators: List[str] = []
    details: str = "CT log lookup completed"
    is_verified: bool = False

class CertificateValidityDetails(BaseModel):
    valid_dates: bool = True
    hostname_matches: bool = True
    chain_trusted: bool = True
    is_self_signed: bool = False
    is_expired: bool = False
    is_not_yet_valid: bool = False
    days_remaining: Optional[int] = None

class TlsSecurityPosture(BaseModel):
    grade: str = "A"
    protocol_version: str = "TLSv1.3"
    cipher_suite: str = "TLS_AES_256_GCM_SHA384"
    key_algorithm: str = "RSA"
    key_size: int = 2048
    signature_algorithm: str = "sha256WithRSAEncryption"
    has_pfs: bool = True

class TlsInspectRequest(BaseModel):
    hostname: str
    port: int = 443

class TlsInspectResponse(BaseModel):
    hostname: str
    port: int
    connected: bool
    subject: Optional[str] = None
    issuer: Optional[str] = None
    valid_from: Optional[str] = None
    valid_to: Optional[str] = None
    days_remaining: Optional[int] = None
    is_expired: bool = False
    is_self_signed: bool = False
    sha256_fingerprint: Optional[str] = None
    sha1_fingerprint: Optional[str] = None
    key_algorithm: Optional[str] = "RSA"
    key_size: Optional[int] = 2048
    signature_algorithm: Optional[str] = "sha256WithRSAEncryption"
    cipher_suite: Optional[str] = None
    protocol_version: Optional[str] = None
    subject_alt_names: List[str] = []
    hostname_matches: bool = True
    hostname_match_details: Optional[str] = None
    grade: str = "A"
    certificate_validity: Optional[CertificateValidityDetails] = None
    security_posture: Optional[TlsSecurityPosture] = None
    certificate_chain: List[CertificateChainItem] = []
    certificate_transparency: Optional[CertificateTransparencyEvidence] = None
    anomalies: List[TlsAnomaly] = []
    phishing_risk_note: str = (
        "Transport encryption (HTTPS) confirms confidential socket transit and domain validation, "
        "not website trustworthiness. Modern phishing campaigns frequently acquire valid certificates."
    )
    evaluated_at: str
    notes: List[str] = []

# --- Threat Intelligence Schemas ---
class ThreatIndicatorCreate(BaseModel):
    indicator_value: str
    indicator_type: Literal["url", "domain", "ip", "sha256"]
    threat_category: str
    severity: Literal["low", "medium", "high", "critical"]
    confidence: int = Field(default=80, ge=0, le=100)
    tags: List[str] = []

class ThreatIndicator(BaseModel):
    id: str
    indicator_value: str
    indicator_type: Literal["url", "domain", "ip", "sha256"]
    threat_category: str
    severity: Literal["low", "medium", "high", "critical"]
    confidence: int
    source: str
    tags: List[str] = []
    is_verified: bool
    created_at: str

# --- Authorized Domain Testing Schemas ---
class AuthorizedScanChallengeRequest(BaseModel):
    domain: str
    owner_email: str

class AuthorizedScanChallengeResponse(BaseModel):
    domain: str
    challenge_token: str
    txt_record_name: str
    txt_record_value: str
    http_challenge_path: str
    http_challenge_content: str
    instructions: str
    expires_at: str

class AuthorizedScanVerifyRequest(BaseModel):
    domain: str
    method: Literal["dns_txt", "http_challenge"] = "dns_txt"

class AuthorizedScanVerifyResponse(BaseModel):
    domain: str
    verified: bool
    verification_token: Optional[str] = None
    message: str
    timestamp: str

class AuthorizedScanDispatchRequest(BaseModel):
    domain: str
    verification_token: str
    scan_policy: Literal["passive_baseline", "active_zap_crawl", "full_authenticated"] = "passive_baseline"

class AuthorizedScanDispatchResponse(BaseModel):
    domain: str
    status: Literal["rejected", "scheduled", "disabled"]
    message: str
    zap_integration_status: str
    authorized: bool = False
    verified_owner: Optional[str] = None
