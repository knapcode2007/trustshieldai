import React, { useState, useEffect } from "react";
import {
  ShieldAlert,
  ShieldCheck,
  Lock,
  Database,
  ArrowRight,
  TrendingUp,
  AlertTriangle,
  Zap,
  Globe,
  Radio,
  Eye,
  RefreshCw,
  Search,
  ExternalLink,
} from "lucide-react";
import { Card, CardHeader, CardTitle, CardDescription, CardContent } from "../ui/card";
import { Button } from "../ui/button";
import { Badge } from "../ui/badge";
import { useSystemHealth } from "../../hooks/useSystemHealth";
import { apiClient } from "../../services/apiClient";
import { ScanResponse, WatchlistItem } from "../../services/types";

interface DashboardViewProps {
  onNavigate: (tab: string) => void;
  onRunScan: (url: string) => void;
  onViewReport: (scan: ScanResponse) => void;
}

export const DashboardView: React.FC<DashboardViewProps> = ({
  onNavigate,
  onRunScan,
  onViewReport,
}) => {
  const { health } = useSystemHealth();
  const [scans, setScans] = useState<ScanResponse[]>([]);
  const [watchlist, setWatchlist] = useState<WatchlistItem[]>([]);
  const [isLoading, setIsLoading] = useState<boolean>(true);

  const loadDashboardData = async () => {
    setIsLoading(true);
    try {
      const [scansData, watchlistData] = await Promise.all([
        apiClient.getScansHistory({ limit: 10 }),
        apiClient.getWatchlist(),
      ]);
      setScans(scansData || []);
      setWatchlist(watchlistData || []);
    } catch (err) {
      console.warn("[DashboardView] Failed to load telemetry data:", err);
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    loadDashboardData();
  }, []);

  // Compute real metrics from actual scan data
  const totalScans = scans.length;
  const cleanCount = scans.filter((s) => s.verdict === "clean").length;
  const suspiciousCount = scans.filter((s) => s.verdict === "suspicious").length;
  const phishingCount = scans.filter((s) => s.verdict === "phishing" || s.verdict === "malicious").length;
  const avgRiskScore = totalScans > 0 ? Math.round(scans.reduce((acc, s) => acc + s.risk_score, 0) / totalScans) : 0;

  const sampleTargets = [
    {
      title: "Legitimate Corporate Service",
      url: "https://github.com",
      description: "Standard HTTPS service with valid certificate authority",
    },
    {
      title: "Simulated Brand Squatting",
      url: "https://secure-login.paypal-update-account.com/auth",
      description: "Heuristic and lexical triggers for brand impersonation",
    },
    {
      title: "Raw IP Endpoint with Auth Path",
      url: "http://185.220.101.5/banking/signin.php",
      description: "Evasion via direct IPv4 address bypass",
    },
  ];

  return (
    <div className="space-y-8 max-w-6xl mx-auto">
      {/* Hero Welcome / Platform Overview */}
      <div className="relative overflow-hidden rounded-2xl border border-slate-800 bg-gradient-to-br from-slate-900 via-slate-900/95 to-slate-950 p-6 md:p-8 shadow-2xl">
        <div className="relative z-10 max-w-3xl">
          <div className="flex items-center gap-2 text-xs font-mono text-cyan-400 mb-3">
            <span className="h-2 w-2 rounded-full bg-cyan-400 animate-pulse" />
            <span>OPERATIONAL TELEMETRY · DEFENSE IN DEPTH</span>
          </div>
          <h1 className="text-2xl sm:text-3xl font-extrabold tracking-tight text-white">
            TrustShield AI Security Operations Center
          </h1>
          <p className="mt-2 text-sm text-slate-300 leading-relaxed max-w-2xl">
            Automated intelligence framework combining lexical feature extraction,
            scikit-learn machine learning classifiers, live TLS cryptographic handshake verification,
            and collaborative Threat Intelligence.
          </p>
          <div className="mt-6 flex flex-wrap gap-3">
            <Button
              variant="default"
              size="lg"
              onClick={() => onNavigate("scan")}
              className="font-medium bg-cyan-600 hover:bg-cyan-700 text-white"
            >
              <ShieldAlert className="w-4 h-4 mr-1.5" />
              Scan Target Website
            </Button>
            <Button
              variant="outline"
              size="lg"
              onClick={() => onNavigate("intel")}
              className="border-slate-700 text-slate-200 hover:bg-slate-800"
            >
              <Database className="w-4 h-4 mr-1.5 text-cyan-400" />
              Threat Intelligence (CTI)
            </Button>
            <Button
              variant="secondary"
              size="lg"
              onClick={() => onNavigate("watchlist")}
              className="bg-slate-800 text-slate-200 hover:bg-slate-700"
            >
              <Eye className="w-4 h-4 mr-1.5 text-purple-400" />
              Watchlist ({watchlist.length})
            </Button>
          </div>
        </div>

        {/* Ambient subtle glow */}
        <div className="absolute right-0 top-0 -mt-16 -mr-16 w-80 h-80 rounded-full bg-cyan-500/10 blur-3xl pointer-events-none" />
      </div>

      {/* Honest Real Metrics Row */}
      <div>
        <div className="flex items-center justify-between mb-3">
          <h2 className="text-xs font-semibold uppercase tracking-wider text-slate-400 font-mono">
            Platform Metrics (Live Session)
          </h2>
          <button
            onClick={loadDashboardData}
            disabled={isLoading}
            className="text-xs text-slate-400 hover:text-cyan-400 flex items-center gap-1 font-mono transition-colors"
          >
            <RefreshCw className={`w-3 h-3 ${isLoading ? "animate-spin" : ""}`} />
            <span>Refresh</span>
          </button>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
          <Card className="border-slate-800 bg-slate-900/60">
            <CardHeader className="pb-2">
              <CardDescription className="text-xs uppercase font-mono tracking-wider text-slate-400">
                Audited Targets
              </CardDescription>
              <CardTitle className="text-2xl font-mono text-white">
                {totalScans}
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="text-xs text-slate-400">
                {totalScans === 0 ? "No scans recorded yet" : `${totalScans} scan(s) performed in this session`}
              </div>
            </CardContent>
          </Card>

          <Card className="border-slate-800 bg-slate-900/60">
            <CardHeader className="pb-2">
              <CardDescription className="text-xs uppercase font-mono tracking-wider text-slate-400">
                Threat Breakdown
              </CardDescription>
              <CardTitle className="text-2xl font-mono text-white flex items-center gap-2">
                <span className="text-red-400">{phishingCount}</span>
                <span className="text-xs text-slate-500 font-normal">phish</span>
                <span className="text-slate-600">/</span>
                <span className="text-amber-400">{suspiciousCount}</span>
                <span className="text-xs text-slate-500 font-normal">susp</span>
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="text-xs text-slate-400">
                {totalScans > 0 ? `${cleanCount} safe target(s)` : "Awaiting scan execution"}
              </div>
            </CardContent>
          </Card>

          <Card className="border-slate-800 bg-slate-900/60">
            <CardHeader className="pb-2">
              <CardDescription className="text-xs uppercase font-mono tracking-wider text-slate-400">
                Average Target Risk
              </CardDescription>
              <CardTitle className="text-2xl font-mono text-white">
                {totalScans > 0 ? (
                  <span className={avgRiskScore > 50 ? "text-red-400" : "text-emerald-400"}>
                    {avgRiskScore}
                    <span className="text-xs font-normal text-slate-500">/100</span>
                  </span>
                ) : (
                  <span className="text-slate-500">N/A</span>
                )}
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="text-xs text-slate-400">
                {totalScans > 0 ? "Weighted composite score" : "Requires active scan history"}
              </div>
            </CardContent>
          </Card>

          <Card className="border-slate-800 bg-slate-900/60">
            <CardHeader className="pb-2">
              <CardDescription className="text-xs uppercase font-mono tracking-wider text-slate-400">
                Monitored Watchlist
              </CardDescription>
              <CardTitle className="text-2xl font-mono text-white">
                {watchlist.length}
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="text-xs text-slate-400 flex items-center justify-between">
                <span>Targets under active watch</span>
                <button
                  onClick={() => onNavigate("watchlist")}
                  className="text-cyan-400 hover:underline"
                >
                  Manage
                </button>
              </div>
            </CardContent>
          </Card>
        </div>
      </div>

      {/* Recent Scans Section or Honest Empty State */}
      <Card className="border-slate-800 bg-slate-900/70 shadow-xl">
        <CardHeader className="pb-3 border-b border-slate-800/80 flex flex-row items-center justify-between">
          <div>
            <CardTitle className="text-base text-white flex items-center gap-2">
              <TrendingUp className="w-4 h-4 text-cyan-400" />
              <span>Recent Scan History</span>
            </CardTitle>
            <CardDescription className="text-xs">
              Live audit logs from the target analysis engine.
            </CardDescription>
          </div>
          {scans.length > 0 && (
            <Button
              variant="outline"
              size="sm"
              onClick={() => onNavigate("history")}
              className="text-xs"
            >
              <span>View All History</span>
              <ArrowRight className="w-3.5 h-3.5 ml-1" />
            </Button>
          )}
        </CardHeader>
        <CardContent className="p-0">
          {totalScans === 0 ? (
            <div className="py-12 px-6 text-center">
              <div className="w-12 h-12 mx-auto mb-3 rounded-full bg-slate-800/80 flex items-center justify-center text-slate-400">
                <ShieldCheck className="w-6 h-6 text-slate-500" />
              </div>
              <h3 className="text-sm font-semibold text-slate-200">No Audits Recorded in Current Session</h3>
              <p className="mt-1 text-xs text-slate-400 max-w-md mx-auto">
                TrustShield AI only displays real data from your actual scans.
                Launch your first security scan below or choose one of the benchmark scenarios.
              </p>
              <div className="mt-4">
                <Button
                  size="sm"
                  variant="cyber"
                  onClick={() => onNavigate("scan")}
                  className="text-xs"
                >
                  Start First Scan
                </Button>
              </div>
            </div>
          ) : (
            <div className="divide-y divide-slate-800/80">
              {scans.slice(0, 5).map((scan) => (
                <div
                  key={scan.scan_id}
                  className="p-4 hover:bg-slate-850/50 transition-colors flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3"
                >
                  <div className="space-y-1 min-w-0 flex-1">
                    <div className="flex items-center gap-2.5">
                      <span className="font-mono text-sm font-semibold text-white truncate">
                        {scan.domain}
                      </span>
                      <Badge
                        variant={
                          scan.verdict === "clean"
                            ? "clean"
                            : scan.verdict === "suspicious"
                            ? "suspicious"
                            : scan.verdict === "phishing"
                            ? "phishing"
                            : "malicious"
                        }
                        className="text-[10px]"
                      >
                        {scan.verdict.toUpperCase()}
                      </Badge>
                    </div>
                    <div className="flex items-center gap-3 text-xs text-slate-400">
                      <span className="truncate max-w-sm">{scan.normalized_url}</span>
                      <span>·</span>
                      <span>{new Date(scan.created_at).toLocaleTimeString()}</span>
                    </div>
                  </div>

                  <div className="flex items-center gap-3 shrink-0">
                    <div className="text-right">
                      <span className="text-[10px] text-slate-400 font-mono block">Risk</span>
                      <span
                        className={`text-sm font-bold font-mono ${
                          scan.risk_score >= 70
                            ? "text-red-400"
                            : scan.risk_score >= 35
                            ? "text-amber-400"
                            : "text-emerald-400"
                        }`}
                      >
                        {scan.risk_score}/100
                      </span>
                    </div>
                    <Button
                      size="sm"
                      variant="outline"
                      onClick={() => onViewReport(scan)}
                      className="text-xs"
                    >
                      <span>Report</span>
                      <ArrowRight className="w-3.5 h-3.5 ml-1" />
                    </Button>
                  </div>
                </div>
              ))}
            </div>
          )}
        </CardContent>
      </Card>

      {/* Target Benchmark Scenarios */}
      <Card className="border-slate-800 bg-slate-900/60">
        <CardHeader>
          <CardTitle className="text-base text-slate-100 flex items-center gap-2">
            <ShieldAlert className="w-4 h-4 text-cyan-400" />
            <span>Benchmark Verification Targets</span>
          </CardTitle>
          <CardDescription className="text-xs">
            Select a verified scenario to test lexical heuristics, brand squatting, and cryptographic TLS inspection.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
            {sampleTargets.map((item, idx) => (
              <div
                key={idx}
                className="rounded-lg border border-slate-800 bg-slate-950/70 p-4 hover:border-slate-700 transition-all flex flex-col justify-between gap-3"
              >
                <div>
                  <h4 className="text-xs font-semibold text-slate-200 mb-1">{item.title}</h4>
                  <p className="text-[11px] text-slate-400 mb-2 leading-relaxed">{item.description}</p>
                  <p className="font-mono text-xs text-cyan-300 break-all bg-slate-900/90 p-1.5 rounded border border-slate-800">
                    {item.url}
                  </p>
                </div>
                <Button
                  size="sm"
                  variant="secondary"
                  onClick={() => onRunScan(item.url)}
                  className="w-full text-xs"
                >
                  <span>Analyze This Target</span>
                  <ArrowRight className="w-3.5 h-3.5 ml-1" />
                </Button>
              </div>
            ))}
          </div>
        </CardContent>
      </Card>
    </div>
  );
};
