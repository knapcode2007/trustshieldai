import React, { useState, useEffect, useRef } from "react";
import {
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  Lock,
  Cpu,
  Search,
  ExternalLink,
  Copy,
  CheckCircle2,
  XCircle,
  FileText,
  RefreshCw,
  Sliders,
  ChevronDown,
  ChevronUp,
  X,
  Radio,
  FileCode,
  ArrowRight,
  Database,
} from "lucide-react";
import { Card, CardHeader, CardTitle, CardDescription, CardContent, CardFooter } from "../ui/card";
import { Button } from "../ui/button";
import { Input } from "../ui/input";
import { Badge } from "../ui/badge";
import { Alert, AlertTitle, AlertDescription } from "../ui/alert";
import { apiClient, ApiClientError } from "../../services/apiClient";
import { ScanResponse, ScanOptions } from "../../services/types";

interface ScanViewProps {
  initialUrl?: string;
  onClearInitialUrl?: () => void;
  onViewReport: (scan: ScanResponse) => void;
}

export const ScanView: React.FC<ScanViewProps> = ({
  initialUrl,
  onClearInitialUrl,
  onViewReport,
}) => {
  const [targetUrl, setTargetUrl] = useState<string>(initialUrl || "");
  const [urlValidationError, setUrlValidationError] = useState<string | null>(null);
  const [options, setOptions] = useState<ScanOptions>({
    run_ml: true,
    inspect_tls: true,
    inspect_headers: true,
    follow_redirects: true,
    save_scan: true,
  });
  const [showAdvanced, setShowAdvanced] = useState<boolean>(false);

  // Scanning Lifecycle & Progress
  const [isScanning, setIsScanning] = useState<boolean>(false);
  const [progressPercent, setProgressPercent] = useState<number>(0);
  const [currentStageName, setCurrentStageName] = useState<string>("");
  const [moduleStatuses, setModuleStatuses] = useState<{
    lexical: "idle" | "running" | "completed" | "skipped" | "partial" | "failed";
    ml: "idle" | "running" | "completed" | "skipped" | "partial" | "failed";
    tls: "idle" | "running" | "completed" | "skipped" | "partial" | "failed";
    headers: "idle" | "running" | "completed" | "skipped" | "partial" | "failed";
    threat_intel: "idle" | "running" | "completed" | "skipped" | "partial" | "failed";
  }>({
    lexical: "idle",
    ml: "idle",
    tls: "idle",
    headers: "idle",
    threat_intel: "idle",
  });

  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<ScanResponse | null>(null);
  const abortControllerRef = useRef<AbortController | null>(null);
  const progressTimerRef = useRef<NodeJS.Timeout | null>(null);

  // Client-side URL validator
  const validateUrl = (input: string): boolean => {
    if (!input || !input.trim()) {
      setUrlValidationError("URL cannot be empty.");
      return false;
    }
    const clean = input.trim();
    if (clean.includes(" ") || clean.includes("\t")) {
      setUrlValidationError("URL cannot contain whitespace characters.");
      return false;
    }
    // Check for basic domain or IP structure
    const toTest = clean.includes("://") ? clean : `https://${clean}`;
    try {
      const u = new URL(toTest);
      if (!u.hostname || u.hostname.length < 3 || !u.hostname.includes(".")) {
        setUrlValidationError("Please enter a valid domain name (e.g. example.com or 192.168.1.1).");
        return false;
      }
      setUrlValidationError(null);
      return true;
    } catch {
      setUrlValidationError("Malformed URL format. Ensure protocol and host are valid.");
      return false;
    }
  };

  // If initialUrl passed from header/dashboard, auto-run scan
  useEffect(() => {
    if (initialUrl) {
      setTargetUrl(initialUrl);
      executeScan(initialUrl);
      if (onClearInitialUrl) onClearInitialUrl();
    }
  }, [initialUrl]);

  // Clean up timers on unmount
  useEffect(() => {
    return () => {
      if (progressTimerRef.current) clearInterval(progressTimerRef.current);
      if (abortControllerRef.current) abortControllerRef.current.abort();
    };
  }, []);

  const handleCancelScan = () => {
    if (abortControllerRef.current) {
      abortControllerRef.current.abort();
      abortControllerRef.current = null;
    }
    if (progressTimerRef.current) {
      clearInterval(progressTimerRef.current);
      progressTimerRef.current = null;
    }
    setIsScanning(false);
    setProgressPercent(0);
    setCurrentStageName("Scan cancelled by user");
    setModuleStatuses({
      lexical: "idle",
      ml: "idle",
      tls: "idle",
      headers: "idle",
      threat_intel: "idle",
    });
    setError("Analysis was cancelled by user.");
  };

  const executeScan = async (urlToScan: string) => {
    if (!validateUrl(urlToScan)) {
      return;
    }

    // Reset states
    setIsScanning(true);
    setError(null);
    setResult(null);
    setProgressPercent(10);
    setCurrentStageName("Submitting target and validating against SSRF firewall...");
    setModuleStatuses({
      lexical: "idle",
      ml: "idle",
      tls: "idle",
      headers: "idle",
      threat_intel: "idle",
    });

    const abortCtrl = new AbortController();
    abortControllerRef.current = abortCtrl;

    try {
      const data = await apiClient.scanUrl(
        urlToScan.trim(),
        options,
        abortCtrl.signal,
        (jobState) => {
          if (abortCtrl.signal.aborted) return;
          if (jobState.progress_percent !== undefined) {
            setProgressPercent(jobState.progress_percent);
          }

          // Update module statuses directly from the backend
          if (jobState.module_statuses) {
            const ms = jobState.module_statuses;
            setModuleStatuses({
              lexical: (ms.lexical?.status || "idle") as any,
              ml: (ms.ml?.status || "idle") as any,
              tls: (ms.tls?.status || "idle") as any,
              headers: (ms.headers?.status || "idle") as any,
              threat_intel: (ms.threat_intel?.status || "idle") as any,
            });

            if (ms.threat_intel?.status === "running" || ms.headers?.status === "running") {
              setCurrentStageName("Auditing defensive HTTP security headers & querying threat intelligence...");
            } else if (ms.tls?.status === "running") {
              setCurrentStageName("Auditing TLS handshake, cipher suites and SAN certificates...");
            } else if (ms.ml?.status === "running") {
              setCurrentStageName("Evaluating RandomForest PhishLex model & feature importances...");
            } else if (ms.lexical?.status === "running") {
              setCurrentStageName("Extracting lexical tokens, Shannon entropy & brand spoof heuristics...");
            } else if (jobState.state === "completed" || jobState.state === "partial") {
              setCurrentStageName(jobState.state === "partial" ? "Analysis completed with partial telemetry" : "All modules evaluated successfully");
            }
          }
        }
      );

      setProgressPercent(100);
      setCurrentStageName("Analysis completed successfully");
      setModuleStatuses({
        lexical: "completed",
        ml: "completed",
        tls: "completed",
        headers: "completed",
        threat_intel: "completed",
      });
      setResult(data);
    } catch (err: any) {
      if (abortCtrl.signal.aborted) {
        return; // Handled in handleCancelScan
      }
      console.error("[ScanView Error]", err);
      if (err instanceof ApiClientError) {
        setError(`[${err.code}] ${err.message}`);
      } else {
        setError(err.message || "Failed to complete security scan.");
      }
    } finally {
      setIsScanning(false);
      abortControllerRef.current = null;
    }
  };

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    executeScan(targetUrl);
  };

  const getVerdictBadge = (verdict: string) => {
    switch (verdict) {
      case "clean":
        return <Badge variant="clean">CLEAN / BENIGN</Badge>;
      case "suspicious":
        return <Badge variant="suspicious">SUSPICIOUS</Badge>;
      case "phishing":
        return <Badge variant="phishing">PHISHING DETECTED</Badge>;
      case "malicious":
        return <Badge variant="malicious">CRITICAL MALICIOUS</Badge>;
      default:
        return <Badge variant="outline">{verdict.toUpperCase()}</Badge>;
    }
  };

  return (
    <div className="space-y-6 max-w-5xl mx-auto">
      {/* Scan Input Header */}
      <Card className="border-slate-800 bg-slate-900/70 shadow-xl">
        <CardHeader>
          <div className="flex items-center justify-between">
            <CardTitle className="text-lg text-white flex items-center gap-2">
              <ShieldAlert className="w-5 h-5 text-cyan-400" />
              <span>Target Analysis & Phishing Engine</span>
            </CardTitle>
            <span className="text-xs text-slate-400 font-mono">
              Engine: Heuristics + scikit-learn + TLS
            </span>
          </div>
          <CardDescription className="text-xs">
            Enter a destination website, domain, or raw IP to run lexical extraction, brand impersonation inspection,
            ML phishing scoring, and live TLS cryptographic audit.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <form onSubmit={handleSubmit} className="space-y-4">
            <div>
              <div className="flex flex-col sm:flex-row gap-2">
                <div className="relative flex-1">
                  <Search className="absolute left-3.5 top-3 h-4 w-4 text-slate-500" />
                  <Input
                    type="text"
                    value={targetUrl}
                    onChange={(e) => {
                      setTargetUrl(e.target.value);
                      if (urlValidationError) validateUrl(e.target.value);
                    }}
                    placeholder="https://example.com/login or secure-banking-update.xyz"
                    className="pl-10 h-11 text-sm font-mono text-white placeholder:text-slate-500 border-slate-700 bg-slate-950/90"
                    disabled={isScanning}
                  />
                </div>

                {isScanning ? (
                  <Button
                    type="button"
                    variant="destructive"
                    onClick={handleCancelScan}
                    className="h-11 px-5 font-semibold text-xs flex items-center gap-2"
                  >
                    <X className="w-4 h-4" />
                    <span>Cancel Scan</span>
                  </Button>
                ) : (
                  <Button
                    type="submit"
                    variant="default"
                    className="h-11 px-6 font-semibold bg-cyan-600 hover:bg-cyan-700 text-white"
                  >
                    <ShieldAlert className="w-4 h-4 mr-2" />
                    <span>Run Deep Scan</span>
                  </Button>
                )}
              </div>

              {urlValidationError && (
                <p className="text-xs text-red-400 font-mono mt-1.5 flex items-center gap-1">
                  <AlertTriangle className="w-3.5 h-3.5" />
                  <span>{urlValidationError}</span>
                </p>
              )}
            </div>

            {/* Quick Benchmark Chips */}
            <div className="flex flex-wrap items-center gap-2 text-xs text-slate-400">
              <span className="text-slate-500">Quick tests:</span>
              <button
                type="button"
                onClick={() => {
                  setTargetUrl("https://github.com");
                  setUrlValidationError(null);
                }}
                className="px-2 py-0.5 rounded bg-slate-800 text-slate-300 hover:text-white font-mono text-[11px]"
              >
                github.com (Safe)
              </button>
              <button
                type="button"
                onClick={() => {
                  setTargetUrl("https://secure-login.paypal-update-account.com/auth");
                  setUrlValidationError(null);
                }}
                className="px-2 py-0.5 rounded bg-slate-800 text-slate-300 hover:text-white font-mono text-[11px]"
              >
                paypal-update (Phishing)
              </button>
              <button
                type="button"
                onClick={() => {
                  setTargetUrl("http://185.220.101.5/banking");
                  setUrlValidationError(null);
                }}
                className="px-2 py-0.5 rounded bg-slate-800 text-slate-300 hover:text-white font-mono text-[11px]"
              >
                185.220.101.5 (IP Host)
              </button>
            </div>

            {/* Advanced Options Toggle */}
            <div className="pt-2 border-t border-slate-800/80">
              <button
                type="button"
                onClick={() => setShowAdvanced(!showAdvanced)}
                className="text-xs text-slate-400 hover:text-cyan-400 flex items-center gap-1 font-mono transition-colors"
              >
                <Sliders className="w-3.5 h-3.5" />
                <span>Analysis Parameters & Engine Modules</span>
                {showAdvanced ? <ChevronUp className="w-3.5 h-3.5" /> : <ChevronDown className="w-3.5 h-3.5" />}
              </button>

              {showAdvanced && (
                <div className="mt-3 p-3.5 rounded-lg border border-slate-800 bg-slate-950/60 grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-3 text-xs">
                  <label className="flex items-center gap-2 cursor-pointer text-slate-300">
                    <input
                      type="checkbox"
                      checked={options.run_ml}
                      onChange={(e) => setOptions({ ...options, run_ml: e.target.checked })}
                      className="rounded border-slate-700 text-cyan-500 focus:ring-cyan-500"
                    />
                    <span>Run scikit-learn ML Classifier</span>
                  </label>
                  <label className="flex items-center gap-2 cursor-pointer text-slate-300">
                    <input
                      type="checkbox"
                      checked={options.inspect_tls}
                      onChange={(e) => setOptions({ ...options, inspect_tls: e.target.checked })}
                      className="rounded border-slate-700 text-cyan-500 focus:ring-cyan-500"
                    />
                    <span>Inspect TLS Certificate & Cipher</span>
                  </label>
                  <label className="flex items-center gap-2 cursor-pointer text-slate-300">
                    <input
                      type="checkbox"
                      checked={options.inspect_headers}
                      onChange={(e) => setOptions({ ...options, inspect_headers: e.target.checked })}
                      className="rounded border-slate-700 text-cyan-500 focus:ring-cyan-500"
                    />
                    <span>Audit HTTP Security Headers</span>
                  </label>
                </div>
              )}
            </div>
          </form>
        </CardContent>
      </Card>

      {/* Real-time Scan Progress with Per-Module Status */}
      {isScanning && (
        <Card className="border-cyan-500/30 bg-slate-900/90 shadow-2xl animate-in fade-in">
          <CardHeader className="pb-3">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2 text-sm font-semibold text-white">
                <RefreshCw className="w-4 h-4 animate-spin text-cyan-400" />
                <span>Multi-Stage Target Assessment in Progress</span>
              </div>
              <span className="font-mono text-xs font-bold text-cyan-400">{progressPercent}%</span>
            </div>
            <CardDescription className="text-xs text-slate-400 font-mono">
              {currentStageName}
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            {/* Progress Bar */}
            <div className="w-full bg-slate-950 rounded-full h-2 overflow-hidden border border-slate-800">
              <div
                className="bg-gradient-to-r from-blue-600 via-cyan-500 to-teal-400 h-2 rounded-full transition-all duration-300"
                style={{ width: `${progressPercent}%` }}
              />
            </div>

            {/* Per-Module Status Pills */}
            {/* Per-Module Status Pills */}
            <div className="grid grid-cols-2 sm:grid-cols-5 gap-2 pt-1 text-[11px] font-mono">
              {[
                { name: "1. Lexical", status: moduleStatuses.lexical },
                { name: "2. ML PhishLex", status: moduleStatuses.ml },
                { name: "3. TLS Socket", status: moduleStatuses.tls },
                { name: "4. Headers", status: moduleStatuses.headers },
                { name: "5. Threat CTI", status: moduleStatuses.threat_intel },
              ].map((m) => (
                <div key={m.name} className="p-2 rounded border border-slate-800 bg-slate-950/70 flex flex-col justify-between">
                  <span className="text-slate-400">{m.name}</span>
                  <span
                    className={
                      m.status === "completed"
                        ? "text-emerald-400 font-semibold"
                        : m.status === "running"
                        ? "text-cyan-400 animate-pulse font-semibold"
                        : m.status === "skipped"
                        ? "text-amber-400 font-semibold"
                        : m.status === "failed"
                        ? "text-red-400 font-semibold"
                        : "text-slate-500"
                    }
                  >
                    {m.status.toUpperCase()}
                  </span>
                </div>
              ))}
            </div>

            <div className="flex justify-end pt-2">
              <Button
                type="button"
                size="sm"
                variant="outline"
                onClick={handleCancelScan}
                className="text-xs text-red-400 border-red-900/50 hover:bg-red-950/30"
              >
                Cancel Evaluation
              </Button>
            </div>
          </CardContent>
        </Card>
      )}

      {/* Error State */}
      {error && (
        <Alert variant="destructive">
          <AlertTriangle className="h-4 w-4" />
          <AlertTitle>Scan Request Fault</AlertTitle>
          <AlertDescription>{error}</AlertDescription>
        </Alert>
      )}

      {/* Scan Results Summary & Deep Report Launcher */}
      {result && (
        <div className="space-y-6">
          <Card className="border-slate-800 bg-slate-900/80 shadow-2xl">
            <CardHeader className="pb-4">
              <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
                <div>
                  <div className="flex items-center gap-3">
                    <h2 className="text-xl font-bold text-white font-mono break-all">
                      {result.domain}
                    </h2>
                    {getVerdictBadge(result.verdict)}
                  </div>
                  <p className="text-xs text-slate-400 mt-1 font-mono break-all">
                    {result.normalized_url}
                  </p>
                </div>

                <div className="flex items-center gap-4">
                  <div className="text-right">
                    <span className="text-[10px] text-slate-400 font-mono uppercase block">
                      Risk Score
                    </span>
                    <span
                      className={`text-2xl font-black font-mono ${
                        result.risk_score >= 70
                          ? "text-red-400"
                          : result.risk_score >= 35
                          ? "text-amber-400"
                          : "text-emerald-400"
                      }`}
                    >
                      {result.risk_score}
                      <span className="text-xs font-normal text-slate-500">/100</span>
                    </span>
                  </div>

                  <Button
                    onClick={() => onViewReport(result)}
                    className="bg-cyan-600 hover:bg-cyan-700 text-white font-semibold text-xs flex items-center gap-1.5"
                  >
                    <span>View Detailed Report</span>
                    <ArrowRight className="w-4 h-4" />
                  </Button>
                </div>
              </div>
            </CardHeader>

            <CardContent className="space-y-4 pt-2">
              {/* Findings Summary Strip */}
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-xs">
                <div className="p-3 rounded-lg border border-slate-800 bg-slate-950/60 font-mono">
                  <span className="text-slate-500 block text-[10px] uppercase">Confidence</span>
                  <span className="text-white font-bold">{(result.confidence * 100).toFixed(1)}%</span>
                </div>
                <div className="p-3 rounded-lg border border-slate-800 bg-slate-950/60 font-mono">
                  <span className="text-slate-500 block text-[10px] uppercase">Entropy</span>
                  <span className="text-cyan-300 font-bold">{result.heuristics.url_entropy.toFixed(2)}</span>
                </div>
                <div className="p-3 rounded-lg border border-slate-800 bg-slate-950/60 font-mono">
                  <span className="text-slate-500 block text-[10px] uppercase">TLS Certificate</span>
                  <span className={result.tls_summary?.valid ? "text-emerald-400 font-bold" : "text-red-400 font-bold"}>
                    {result.tls_summary?.valid ? "Valid" : "Invalid / Expired"}
                  </span>
                </div>
                <div className="p-3 rounded-lg border border-slate-800 bg-slate-950/60 font-mono">
                  <span className="text-slate-500 block text-[10px] uppercase">Security Headers</span>
                  <span className="text-white font-bold">
                    Grade {result.security_headers?.grade || "N/A"}
                  </span>
                </div>
              </div>

              {/* Top Findings Snippet */}
              <div>
                <h4 className="text-xs font-semibold uppercase text-slate-300 font-mono mb-2">
                  Immediate Findings ({result.heuristics.findings.length})
                </h4>
                {result.heuristics.findings.length === 0 ? (
                  <p className="text-xs text-emerald-400 bg-emerald-950/20 p-3 rounded border border-emerald-900/40">
                    No heuristic threats or suspicious evasion techniques flagged for this target.
                  </p>
                ) : (
                  <div className="space-y-1.5">
                    {result.heuristics.findings.slice(0, 3).map((f, idx) => (
                      <div
                        key={idx}
                        className="p-2.5 rounded border border-slate-800 bg-slate-950/70 text-xs flex items-center justify-between"
                      >
                        <div className="flex items-center gap-2">
                          <span className="text-red-400 font-mono font-bold text-[11px]">
                            [{f.rule_id}]
                          </span>
                          <span className="text-slate-300">{f.description}</span>
                        </div>
                        <span className="font-mono text-red-400 text-xs shrink-0 font-semibold">
                          +{f.score_impact} pts
                        </span>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </CardContent>
          </Card>
        </div>
      )}
    </div>
  );
};
