import {
  HealthResponse,
  ScanResponse,
  ScanOptions,
  ScanJobStateResponse,
  ScanHistoryResponse,
  TlsInspectResponse,
  ThreatIndicator,
  ThreatIndicatorCreate,
  CommunityReport,
  CommunityReportCreate,
  WatchlistItem,
  WatchlistItemCreate,
  AdminAuditEntry,
  ApiErrorResponse,
  AuthorizedScanChallengeRequest,
  AuthorizedScanChallengeResponse,
  AuthorizedScanVerifyRequest,
  AuthorizedScanVerifyResponse,
  AuthorizedScanDispatchRequest,
  AuthorizedScanDispatchResponse,
} from "./types";

export class ApiClientError extends Error {
  code: string;
  statusCode: number;
  details?: any;

  constructor(message: string, code = "API_CLIENT_ERROR", statusCode = 500, details?: any) {
    super(message);
    this.name = "ApiClientError";
    this.code = code;
    this.statusCode = statusCode;
    this.details = details;
  }
}

class TrustShieldApiClient {
  private baseUrl: string;
  private defaultTimeoutMs: number;

  constructor() {
    this.baseUrl = (import.meta.env.VITE_API_BASE_URL || "/api").replace(/\/+$/, "");
    this.defaultTimeoutMs = 15000;
  }

  private async request<T>(
    endpoint: string,
    options: RequestInit = {},
    customSignal?: AbortSignal,
    retries = 1
  ): Promise<T> {
    const url = `${this.baseUrl}${endpoint.startsWith("/") ? endpoint : `/${endpoint}`}`;
    const internalController = new AbortController();
    const timeout = setTimeout(() => internalController.abort(), this.defaultTimeoutMs);

    // Combine custom signal (for cancellation support) with internal timeout
    const signal = customSignal || internalController.signal;
    if (customSignal) {
      customSignal.addEventListener("abort", () => internalController.abort());
    }

    const headers: Record<string, string> = {
      "Content-Type": "application/json",
      Accept: "application/json",
      ...(options.headers as Record<string, string>),
    };

    try {
      const response = await fetch(url, {
        ...options,
        headers,
        signal,
      });

      clearTimeout(timeout);

      const contentType = response.headers.get("content-type") || "";
      let responseData: any = null;
      if (contentType.includes("application/json")) {
        responseData = await response.json();
      } else {
        responseData = await response.text();
      }

      if (!response.ok) {
        if (responseData && typeof responseData === "object" && responseData.error) {
          const errPayload = responseData as ApiErrorResponse;
          throw new ApiClientError(
            errPayload.error.message || `Request failed with status ${response.status}`,
            errPayload.error.code || `HTTP_${response.status}`,
            response.status,
            errPayload.error.details
          );
        }
        throw new ApiClientError(
          typeof responseData === "string" ? responseData : `HTTP error ${response.status}`,
          `HTTP_${response.status}`,
          response.status
        );
      }

      return responseData as T;
    } catch (err: any) {
      clearTimeout(timeout);

      if (err.name === "AbortError") {
        if (customSignal?.aborted) {
          throw new ApiClientError("Analysis was cancelled by the user", "USER_ABORTED", 499);
        }
        throw new ApiClientError("Request timed out while contacting TrustShield backend", "REQUEST_TIMEOUT", 408);
      }

      if (err instanceof ApiClientError) {
        throw err;
      }

      // Retry for network failures
      if (retries > 0 && !customSignal?.aborted) {
        await new Promise((resolve) => setTimeout(resolve, 300));
        return this.request<T>(endpoint, options, customSignal, retries - 1);
      }

      throw new ApiClientError(
        err.message || "Failed to communicate with TrustShield backend service",
        "NETWORK_ERROR",
        0,
        err
      );
    }
  }

  // Health
  public async getHealth(): Promise<HealthResponse> {
    return this.request<HealthResponse>("/v1/health");
  }

  // 1. Submit Scan Job (POST /api/v1/scans - returns 202 Accepted with job state)
  public async submitScanJob(
    url: string,
    force_fresh = false,
    options: ScanOptions = {},
    signal?: AbortSignal
  ): Promise<ScanJobStateResponse> {
    return this.request<ScanJobStateResponse>(
      "/v1/scans",
      {
        method: "POST",
        body: JSON.stringify({ url, force_fresh, options }),
      },
      signal
    );
  }

  // 2. Poll Scan Job State (GET /api/v1/scans/:id)
  public async getScanJob(id: string, signal?: AbortSignal): Promise<ScanJobStateResponse> {
    return this.request<ScanJobStateResponse>(`/v1/scans/${id}`, {}, signal);
  }

  // 3. Retrieve Forensic Report (GET /api/v1/reports/:id)
  public async getReport(id: string, signal?: AbortSignal): Promise<ScanResponse> {
    return this.request<ScanResponse>(`/v1/reports/${id}`, {}, signal);
  }

  // 4. Polling orchestrator with progress callback and timeout
  public async pollScanJob(
    jobId: string,
    onProgress?: (job: ScanJobStateResponse) => void,
    signal?: AbortSignal,
    intervalMs = 250,
    maxWaitMs = 30000
  ): Promise<ScanResponse> {
    const startTime = Date.now();

    while (true) {
      if (signal?.aborted) {
        throw new ApiClientError("Analysis was cancelled by the user", "USER_ABORTED", 499);
      }

      if (Date.now() - startTime > maxWaitMs) {
        throw new ApiClientError("Scan timed out waiting for background engine to complete", "SCAN_TIMEOUT", 408);
      }

      const job = await this.getScanJob(jobId, signal);
      if (onProgress) {
        onProgress(job);
      }

      if (job.state === "completed" || job.state === "partial") {
        if (job.result) {
          return job.result;
        }
        // Fallback to fetch report directly
        return await this.getReport(jobId, signal);
      }

      if (job.state === "failed") {
        const errMsg = job.error?.message || "Scan engine encountered an unrecoverable failure.";
        const errCode = job.error?.code || "SCAN_EXECUTION_FAILED";
        throw new ApiClientError(errMsg, errCode, 422, job.error?.details);
      }

      // Wait interval before next poll
      await new Promise((resolve) => setTimeout(resolve, intervalMs));
    }
  }

  // 5. Synchronous or Asynchronous Scan wrapper
  public async scanUrl(
    url: string,
    options: ScanOptions = {},
    signal?: AbortSignal,
    onProgress?: (job: ScanJobStateResponse) => void
  ): Promise<ScanResponse> {
    try {
      // First try standard asynchronous job queue + poll
      const submitted = await this.submitScanJob(url, false, options, signal);
      if (onProgress) onProgress(submitted);
      return await this.pollScanJob(submitted.scan_id, onProgress, signal);
    } catch (err: any) {
      // If client abort, rethrow directly
      if (err.code === "USER_ABORTED" || signal?.aborted) {
        throw err;
      }
      // If validation error (SSRF, malformed URL), throw immediately without fallback
      if (err.statusCode === 400 || err.code?.startsWith("SSRF_") || err.code?.startsWith("URL_")) {
        throw err;
      }
      // Direct fallback to synchronous endpoint
      return this.request<ScanResponse>(
        "/v1/scan",
        {
          method: "POST",
          body: JSON.stringify({ url, options }),
        },
        signal
      );
    }
  }

  // 6. Paginated Scan History (GET /api/v1/history)
  public async getHistory(params?: { limit?: number; offset?: number; verdict?: string }): Promise<ScanHistoryResponse> {
    const query = new URLSearchParams();
    if (params?.limit) query.set("limit", String(params.limit));
    if (params?.offset) query.set("offset", String(params.offset));
    if (params?.verdict && params.verdict !== "all") query.set("verdict", params.verdict);
    const qs = query.toString();
    return this.request<ScanHistoryResponse>(`/v1/history${qs ? `?${qs}` : ""}`);
  }

  // Legacy Scan History list helper
  public async getScansHistory(params?: { limit?: number; verdict?: string }): Promise<ScanResponse[]> {
    const query = new URLSearchParams();
    if (params?.limit) query.set("limit", String(params.limit));
    if (params?.verdict && params.verdict !== "all") query.set("verdict", params.verdict);
    const qs = query.toString();
    return this.request<ScanResponse[]>(`/v1/scans${qs ? `?${qs}` : ""}`);
  }

  public async getScanReport(id: string): Promise<ScanResponse> {
    return this.request<ScanResponse>(`/v1/reports/${id}`);
  }

  public async deleteScan(id: string): Promise<{ success: boolean; message: string }> {
    return this.request<{ success: boolean; message: string }>(`/v1/scans/${id}`, {
      method: "DELETE",
    });
  }

  public async clearScansHistory(): Promise<{ success: boolean; message: string }> {
    return this.request<{ success: boolean; message: string }>("/v1/scans", {
      method: "DELETE",
    });
  }

  // Dedicated TLS Inspector
  public async inspectTls(hostname: string, port = 443): Promise<TlsInspectResponse> {
    return this.request<TlsInspectResponse>("/v1/tls/inspect", {
      method: "POST",
      body: JSON.stringify({ hostname, port }),
    });
  }

  // Threat Indicators (CTI)
  public async getThreatIndicators(params?: {
    type?: string;
    severity?: string;
    search?: string;
  }): Promise<ThreatIndicator[]> {
    const query = new URLSearchParams();
    if (params?.type && params.type !== "all") query.set("type", params.type);
    if (params?.severity && params.severity !== "all") query.set("severity", params.severity);
    if (params?.search) query.set("search", params.search);
    const qs = query.toString();
    return this.request<ThreatIndicator[]>(`/v1/intel/indicators${qs ? `?${qs}` : ""}`);
  }

  public async submitThreatIndicator(indicator: ThreatIndicatorCreate): Promise<ThreatIndicator> {
    return this.request<ThreatIndicator>("/v1/intel/indicators", {
      method: "POST",
      body: JSON.stringify(indicator),
    });
  }

  public async verifyThreatIndicator(id: string, is_verified: boolean, reason?: string): Promise<ThreatIndicator> {
    return this.request<ThreatIndicator>(`/v1/intel/indicators/${id}/verify`, {
      method: "PATCH",
      body: JSON.stringify({ is_verified, reason }),
    });
  }

  // Community Reports
  public async getCommunityReports(params?: { status?: string; search?: string }): Promise<CommunityReport[]> {
    const query = new URLSearchParams();
    if (params?.status && params.status !== "all") query.set("status", params.status);
    if (params?.search) query.set("search", params.search);
    const qs = query.toString();
    return this.request<CommunityReport[]>(`/v1/community/reports${qs ? `?${qs}` : ""}`);
  }

  public async submitCommunityReport(report: CommunityReportCreate): Promise<CommunityReport> {
    return this.request<CommunityReport>("/v1/community/reports", {
      method: "POST",
      body: JSON.stringify(report),
    });
  }

  public async voteCommunityReport(id: string): Promise<CommunityReport> {
    return this.request<CommunityReport>(`/v1/community/reports/${id}/vote`, {
      method: "PATCH",
    });
  }

  public async moderateCommunityReport(
    id: string,
    status: "verified" | "dismissed",
    moderator_note?: string
  ): Promise<CommunityReport> {
    return this.request<CommunityReport>(`/v1/community/reports/${id}/moderate`, {
      method: "PATCH",
      body: JSON.stringify({ status, moderator_note }),
    });
  }

  // Watchlist
  public async getWatchlist(): Promise<WatchlistItem[]> {
    return this.request<WatchlistItem[]>("/v1/watchlist");
  }

  public async addToWatchlist(item: WatchlistItemCreate): Promise<WatchlistItem> {
    return this.request<WatchlistItem>("/v1/watchlist", {
      method: "POST",
      body: JSON.stringify(item),
    });
  }

  public async removeFromWatchlist(id: string): Promise<{ success: boolean; message: string }> {
    return this.request<{ success: boolean; message: string }>(`/v1/watchlist/${id}`, {
      method: "DELETE",
    });
  }

  // Admin Audit Logs
  public async getAdminAuditLogs(): Promise<AdminAuditEntry[]> {
    return this.request<AdminAuditEntry[]>("/v1/admin/audit-logs");
  }

  // Authorized Domain Security Testing (OWASP ZAP)
  public async createAuthorizedScanChallenge(req: AuthorizedScanChallengeRequest): Promise<AuthorizedScanChallengeResponse> {
    return this.request<AuthorizedScanChallengeResponse>("/v1/authorized-scan/challenge", {
      method: "POST",
      body: JSON.stringify(req),
    });
  }

  public async verifyDomainOwnership(req: AuthorizedScanVerifyRequest): Promise<AuthorizedScanVerifyResponse> {
    return this.request<AuthorizedScanVerifyResponse>("/v1/authorized-scan/verify", {
      method: "POST",
      body: JSON.stringify(req),
    });
  }

  public async dispatchAuthorizedScan(req: AuthorizedScanDispatchRequest): Promise<AuthorizedScanDispatchResponse> {
    return this.request<AuthorizedScanDispatchResponse>("/v1/authorized-scan/dispatch", {
      method: "POST",
      body: JSON.stringify(req),
    });
  }
}

export const apiClient = new TrustShieldApiClient();

