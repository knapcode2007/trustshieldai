export type RiskVerdict = "clean" | "suspicious" | "phishing" | "malicious";
export type SeverityLevel = "low" | "medium" | "high" | "critical";
export type SubsystemStatus = "online" | "ready" | "configured" | "degraded" | "offline";

export interface SubsystemHealth {
  status: SubsystemStatus;
  details?: string;
  latency_ms?: number;
  version?: string;
  provider?: string;
}

export interface HealthResponse {
  status: "healthy" | "degraded" | "unhealthy";
  app_name: string;
  version: string;
  environment: string;
  timestamp: string;
  subsystems: {
    api_gateway: SubsystemHealth;
    fastapi_service: SubsystemHealth;
    ml_engine: SubsystemHealth;
    database: SubsystemHealth;
    tls_validator: SubsystemHealth;
  };
}

export interface HeuristicFinding {
  rule_id: string;
  category: string;
  severity: SeverityLevel;
  description: string;
  score_impact: number;
}

export interface HeuristicResults {
  suspicious_keywords: string[];
  has_ip_in_url: boolean;
  subdomain_count: number;
  url_entropy: number;
  detected_brand_squats: string[];
  findings: HeuristicFinding[];
}

export interface MlPrediction {
  status?: "operational" | "unavailable" | "error";
  is_trained?: boolean;
  model: string;
  model_version?: string;
  probability_phish?: number | null;
  confidence?: number | null;
  feature_importances?: Record<string, number> | null;
  contributing_features?: Record<string, number> | null;
  extracted_features?: Record<string, any> | null;
  message?: string;
}

export interface TlsSummary {
  valid: boolean;
  issuer?: string;
  subject?: string;
  days_remaining?: number | null;
  is_expired?: boolean;
  is_self_signed?: boolean;
  protocol_version?: string;
  cipher_suite?: string;
  grade?: string;
}

export interface SecurityHeaderItem {
  name: string;
  value: string | null;
  present: boolean;
  status: "pass" | "warn" | "fail";
  description: string;
  recommendation?: string;
}

export interface CookieSecurityItem {
  name: string;
  is_secure: boolean;
  is_http_only: boolean;
  same_site: "Strict" | "Lax" | "None" | "Unspecified" | string;
}

export interface SecurityWeakness {
  code: string;
  severity: SeverityLevel;
  title: string;
  description: string;
  remediation: string;
}

export interface RedirectHop {
  hop: number;
  url: string;
  status_code: number;
  is_https: boolean;
}

export interface SecurityHeadersSummary {
  evaluated: boolean;
  score: number;
  grade: string;
  headers: SecurityHeaderItem[];
  missing_critical_count: number;
  target_url?: string;
  final_url?: string;
  https_available?: boolean;
  redirect_chain?: RedirectHop[];
  cookie_security?: CookieSecurityItem[];
  weaknesses?: SecurityWeakness[];
  verdict_separation_note?: string;
  notes?: string[];
}

export interface AnalysisCoverage {
  lexical: number;
  ml: number;
  tls: number;
  headers: number;
  threat_feeds: number;
  overall: number;
}

export interface ThreatFeedMatch {
  provider?: string;
  provider_name?: string;
  feed_name?: string;
  status: "available" | "no_match" | "unavailable" | "rate_limited" | "error";
  matched: boolean;
  match_type: "exact_url" | "host" | "domain" | "none";
  threat_type?: string | null;
  confidence?: number;
  details?: string;
  reference_url?: string | null;
  reference_id?: string | null;
  attribution?: string;
  checked_at?: string;
  cached?: boolean;
  rate_limited?: boolean;
  query_sanitized?: boolean;
  redacted_params?: string[];
  raw_evidence?: Record<string, any> | null;
}

export interface ThreatIntelSummary {
  total_providers: number;
  operational_count: number;
  matched_count: number;
  rate_limited_count: number;
  unavailable_count: number;
  error_count: number;
  has_exact_url_match: boolean;
  has_host_match: boolean;
  max_confidence: number;
  threat_types: string[];
  results?: ThreatFeedMatch[];
}

export interface EvidenceItem {
  category: string;
  key: string;
  value: string;
  significance: string;
}

export interface Recommendation {
  id: string;
  title: string;
  description: string;
  severity: SeverityLevel;
  category: string;
}

export interface ScanResponse {
  scan_id: string;
  url: string;
  normalized_url: string;
  domain: string;
  verdict: RiskVerdict;
  risk_score: number;
  confidence: number;
  heuristics: HeuristicResults;
  ml_prediction?: MlPrediction;
  tls_summary?: TlsSummary | null;
  security_headers?: SecurityHeadersSummary;
  analysis_coverage?: AnalysisCoverage;
  threat_feed_matches?: ThreatFeedMatch[];
  threat_intel_summary?: ThreatIntelSummary;
  evidence?: EvidenceItem[];
  recommendations?: Recommendation[];
  created_at: string;
}

export interface ScanOptions {
  run_ml?: boolean;
  inspect_tls?: boolean;
  inspect_headers?: boolean;
  follow_redirects?: boolean;
  save_scan?: boolean;
}

export type ScanJobState = "queued" | "running" | "completed" | "partial" | "failed";

export interface ModuleStatusDetail {
  status: "idle" | "running" | "completed" | "partial" | "failed" | "skipped";
  started_at?: string | null;
  completed_at?: string | null;
  error?: string | null;
}

export interface ScanJobStateResponse {
  scan_id: string;
  request_id: string;
  raw_url: string;
  canonical_url: string;
  domain: string;
  state: ScanJobState;
  progress_percent: number;
  module_statuses: {
    lexical: ModuleStatusDetail;
    ml: ModuleStatusDetail;
    tls: ModuleStatusDetail;
    headers: ModuleStatusDetail;
    threat_intel: ModuleStatusDetail;
    [key: string]: ModuleStatusDetail;
  };
  timestamps: {
    queued_at: string;
    started_at?: string | null;
    completed_at?: string | null;
  };
  error?: {
    code: string;
    message: string;
    details?: any;
  } | null;
  result?: ScanResponse | null;
}

export interface ScanHistoryResponse {
  items: ScanJobStateResponse[];
  total: number;
  limit: number;
  offset: number;
}

export interface CertificateChainItem {
  subject: string;
  issuer: string;
  is_root: boolean;
  is_intermediate: boolean;
  is_leaf: boolean;
  valid_from?: string;
  valid_to?: string;
  days_remaining?: number | null;
  sha256_fingerprint?: string;
  trusted: boolean;
}

export interface TlsAnomaly {
  code: string;
  severity: SeverityLevel;
  title: string;
  description: string;
}

export interface CertificateTransparencyEvidence {
  status: "verified_embedded_scts" | "public_log_matched" | "unavailable" | "none";
  sct_count: number;
  operators: string[];
  details: string;
  is_verified: boolean;
}

export interface CertificateValidityDetails {
  valid_dates: boolean;
  hostname_matches: boolean;
  chain_trusted: boolean;
  is_self_signed: boolean;
  is_expired: boolean;
  is_not_yet_valid: boolean;
  days_remaining?: number | null;
}

export interface TlsSecurityPosture {
  grade: string;
  protocol_version: string;
  cipher_suite: string;
  key_algorithm: string;
  key_size: number;
  signature_algorithm: string;
  has_pfs: boolean;
}

export interface TlsInspectResponse {
  hostname: string;
  port: number;
  connected: boolean;
  subject?: string;
  issuer?: string;
  valid_from?: string;
  valid_to?: string;
  days_remaining?: number | null;
  is_expired: boolean;
  is_self_signed: boolean;
  sha256_fingerprint?: string;
  sha1_fingerprint?: string;
  key_algorithm?: string;
  key_size?: number;
  signature_algorithm?: string;
  cipher_suite?: string;
  protocol_version?: string;
  subject_alt_names: string[];
  hostname_matches?: boolean;
  hostname_match_details?: string;
  grade: string;
  certificate_validity?: CertificateValidityDetails;
  security_posture?: TlsSecurityPosture;
  certificate_chain?: CertificateChainItem[];
  certificate_transparency?: CertificateTransparencyEvidence;
  anomalies?: TlsAnomaly[];
  phishing_risk_note?: string;
  evaluated_at: string;
  notes: string[];
}

export interface ThreatIndicator {
  id: string;
  indicator_value: string;
  indicator_type: "url" | "domain" | "ip" | "sha256";
  threat_category: string;
  severity: SeverityLevel;
  confidence: number;
  source: string;
  tags: string[];
  is_verified: boolean;
  created_at: string;
}

export interface ThreatIndicatorCreate {
  indicator_value: string;
  indicator_type: "url" | "domain" | "ip" | "sha256";
  threat_category: string;
  severity: SeverityLevel;
  confidence: number;
  tags: string[];
}

export interface CommunityReport {
  id: string;
  target_url: string;
  domain: string;
  threat_type: string;
  targeted_brand?: string;
  description: string;
  reporter_handle?: string;
  severity: SeverityLevel;
  status: "pending" | "verified" | "dismissed";
  confirmations_count: number;
  created_at: string;
  moderated_at?: string;
  moderator_note?: string;
}

export interface CommunityReportCreate {
  target_url: string;
  threat_type: string;
  targeted_brand?: string;
  description: string;
  reporter_handle?: string;
  severity: SeverityLevel;
}

export interface WatchlistItem {
  id: string;
  target: string;
  domain: string;
  label: string;
  added_at: string;
  last_scanned_at?: string;
  last_risk_score?: number;
  last_verdict?: RiskVerdict;
  alert_threshold: number;
  status: "active" | "paused";
}

export interface WatchlistItemCreate {
  target: string;
  label: string;
  alert_threshold?: number;
}

export interface AdminAuditEntry {
  id: string;
  action: string;
  target_type: "indicator" | "report" | "watchlist";
  target_id: string;
  target_value: string;
  decision: "approved" | "rejected" | "modified";
  timestamp: string;
  actor: string;
  reason?: string;
}

export interface ApiErrorDetail {
  code: string;
  message: string;
  details?: any;
}

export interface ApiErrorResponse {
  success: false;
  error: ApiErrorDetail;
  timestamp: string;
}

export interface AuthorizedScanChallengeRequest {
  domain: string;
  owner_email: string;
}

export interface AuthorizedScanChallengeResponse {
  domain: string;
  challenge_token: string;
  txt_record_name: string;
  txt_record_value: string;
  http_challenge_path: string;
  http_challenge_content: string;
  instructions: string;
  expires_at: string;
}

export interface AuthorizedScanVerifyRequest {
  domain: string;
  method?: "dns_txt" | "http_challenge";
}

export interface AuthorizedScanVerifyResponse {
  domain: string;
  verified: boolean;
  verification_token?: string | null;
  message: string;
  timestamp: string;
}

export interface AuthorizedScanDispatchRequest {
  domain: string;
  verification_token: string;
  scan_policy?: "passive_baseline" | "active_zap_crawl" | "full_authenticated";
}

export interface AuthorizedScanDispatchResponse {
  domain: string;
  status: "rejected" | "scheduled" | "disabled";
  message: string;
  zap_integration_status: string;
  authorized: boolean;
  verified_owner?: string | null;
}

