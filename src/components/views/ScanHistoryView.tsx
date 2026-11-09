import React, { useState, useEffect } from "react";
import {
  FileText,
  Search,
  Filter,
  Trash2,
  RefreshCw,
  Download,
  ArrowRight,
  ShieldCheck,
  ShieldAlert,
  Calendar,
  Clock,
} from "lucide-react";
import { Card, CardHeader, CardTitle, CardDescription, CardContent } from "../ui/card";
import { Button } from "../ui/button";
import { Input } from "../ui/input";
import { Badge } from "../ui/badge";
import { apiClient } from "../../services/apiClient";
import { ScanResponse } from "../../services/types";

interface ScanHistoryViewProps {
  onNavigate: (tab: string) => void;
  onViewReport: (scan: ScanResponse) => void;
  onRunScan: (url: string) => void;
}

export const ScanHistoryView: React.FC<ScanHistoryViewProps> = ({
  onNavigate,
  onViewReport,
  onRunScan,
}) => {
  const [scans, setScans] = useState<ScanResponse[]>([]);
  const [filterVerdict, setFilterVerdict] = useState<string>("all");
  const [searchQuery, setSearchQuery] = useState<string>("");
  const [isLoading, setIsLoading] = useState<boolean>(true);

  const fetchScans = async () => {
    setIsLoading(true);
    try {
      const data = await apiClient.getScansHistory({ verdict: filterVerdict });
      setScans(data || []);
    } catch (err) {
      console.warn("Error fetching scan history:", err);
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    fetchScans();
  }, [filterVerdict]);

  const handleDeleteScan = async (id: string, e: React.MouseEvent) => {
    e.stopPropagation();
    try {
      await apiClient.deleteScan(id);
      setScans(scans.filter((s) => s.scan_id !== id));
    } catch (err) {
      console.warn("Error deleting scan:", err);
    }
  };

  const handleClearAll = async () => {
    if (window.confirm("Are you sure you want to clear all audit scan history?")) {
      await apiClient.clearScansHistory();
      setScans([]);
    }
  };

  const handleExportJson = () => {
    const jsonStr = JSON.stringify(scans, null, 2);
    const blob = new Blob([jsonStr], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = `trustshield-scan-history-${new Date().toISOString().slice(0, 10)}.json`;
    link.click();
    URL.revokeObjectURL(url);
  };

  const filteredScans = scans.filter((s) => {
    if (!searchQuery) return true;
    const q = searchQuery.toLowerCase();
    return s.domain.toLowerCase().includes(q) || s.url.toLowerCase().includes(q);
  });

  const getVerdictBadge = (verdict: string) => {
    switch (verdict) {
      case "clean":
        return <Badge variant="clean">CLEAN</Badge>;
      case "suspicious":
        return <Badge variant="suspicious">SUSPICIOUS</Badge>;
      case "phishing":
        return <Badge variant="phishing">PHISHING</Badge>;
      case "malicious":
        return <Badge variant="malicious">MALICIOUS</Badge>;
      default:
        return <Badge variant="outline">{verdict.toUpperCase()}</Badge>;
    }
  };

  return (
    <div className="space-y-6 max-w-6xl mx-auto">
      {/* Header */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
        <div>
          <h2 className="text-xl font-bold text-white flex items-center gap-2">
            <FileText className="w-5 h-5 text-cyan-400" />
            <span>Target Scan History</span>
          </h2>
          <p className="text-xs text-slate-400 mt-1">
            Historical audit logs of inspected websites, risk scores, and cryptographic findings.
          </p>
        </div>

        <div className="flex items-center gap-2">
          {scans.length > 0 && (
            <>
              <Button
                size="sm"
                variant="outline"
                onClick={handleExportJson}
                className="text-xs"
              >
                <Download className="w-3.5 h-3.5 mr-1" />
                <span>Export JSON</span>
              </Button>
              <Button
                size="sm"
                variant="destructive"
                onClick={handleClearAll}
                className="text-xs"
              >
                <Trash2 className="w-3.5 h-3.5 mr-1" />
                <span>Clear History</span>
              </Button>
            </>
          )}
          <Button
            size="sm"
            variant="default"
            onClick={() => onNavigate("scan")}
            className="text-xs bg-cyan-600 hover:bg-cyan-700 text-white"
          >
            <span>New Scan</span>
          </Button>
        </div>
      </div>

      {/* Filter and Search Bar */}
      <Card className="border-slate-800 bg-slate-900/60">
        <CardContent className="p-3.5 flex flex-col md:flex-row items-center gap-3">
          <div className="relative flex-1 w-full">
            <Search className="absolute left-3 top-2.5 h-4 w-4 text-slate-500" />
            <Input
              type="text"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              placeholder="Filter by domain or URL..."
              className="pl-9 h-9 text-xs font-mono bg-slate-950/80 border-slate-800"
            />
          </div>

          {/* Segmented Filter Buttons */}
          <div className="flex items-center gap-1 p-1 bg-slate-950/80 border border-slate-800 rounded-lg text-xs font-mono overflow-x-auto w-full md:w-auto">
            {["all", "clean", "suspicious", "phishing", "malicious"].map((v) => (
              <button
                key={v}
                onClick={() => setFilterVerdict(v)}
                className={`px-3 py-1 rounded-md capitalize transition-colors cursor-pointer ${
                  filterVerdict === v
                    ? "bg-slate-800 text-white font-semibold"
                    : "text-slate-400 hover:text-white"
                }`}
              >
                {v}
              </button>
            ))}
          </div>
        </CardContent>
      </Card>

      {/* History List Table / Empty State */}
      <Card className="border-slate-800 bg-slate-900/80 shadow-xl overflow-hidden">
        <CardHeader className="py-3 px-4 border-b border-slate-800/80 flex flex-row items-center justify-between">
          <span className="text-xs font-mono uppercase text-slate-400">
            Recorded Scans ({filteredScans.length})
          </span>
          <button
            onClick={fetchScans}
            className="text-slate-400 hover:text-cyan-400 text-xs flex items-center gap-1 font-mono transition-colors"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${isLoading ? "animate-spin" : ""}`} />
            <span>Refresh</span>
          </button>
        </CardHeader>
        <CardContent className="p-0">
          {isLoading ? (
            <div className="p-12 text-center text-xs text-slate-400 font-mono">
              <RefreshCw className="w-6 h-6 mx-auto mb-2 animate-spin text-cyan-400" />
              Loading scan history records...
            </div>
          ) : filteredScans.length === 0 ? (
            <div className="p-12 text-center text-xs text-slate-400">
              <FileText className="w-8 h-8 mx-auto mb-3 text-slate-600" />
              <p className="font-semibold text-slate-300">No Scans Recorded in History</p>
              <p className="mt-1 max-w-sm mx-auto text-slate-500">
                Any targets you analyze will be catalogued here with full telemetry and report snapshots.
              </p>
              <div className="mt-4">
                <Button
                  size="sm"
                  variant="outline"
                  onClick={() => onNavigate("scan")}
                  className="text-xs"
                >
                  Analyze a Target Now
                </Button>
              </div>
            </div>
          ) : (
            <div className="divide-y divide-slate-800/80">
              {filteredScans.map((scan) => (
                <div
                  key={scan.scan_id}
                  onClick={() => onViewReport(scan)}
                  className="p-4 hover:bg-slate-850/60 transition-colors cursor-pointer flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3"
                >
                  <div className="space-y-1 min-w-0 flex-1">
                    <div className="flex items-center gap-2.5">
                      <span className="font-mono text-sm font-semibold text-white truncate">
                        {scan.domain}
                      </span>
                      {getVerdictBadge(scan.verdict)}
                    </div>
                    <p className="text-xs text-slate-400 font-mono truncate max-w-lg">
                      {scan.normalized_url}
                    </p>
                    <div className="flex items-center gap-4 text-[11px] font-mono text-slate-500 pt-0.5">
                      <span>{new Date(scan.created_at).toLocaleString()}</span>
                      <span>·</span>
                      <span>Confidence: {(scan.confidence * 100).toFixed(0)}%</span>
                      {scan.tls_summary && (
                        <>
                          <span>·</span>
                          <span className={scan.tls_summary.valid ? "text-emerald-400" : "text-red-400"}>
                            {scan.tls_summary.valid ? "TLS Valid" : "TLS Untrusted"}
                          </span>
                        </>
                      )}
                    </div>
                  </div>

                  <div className="flex items-center gap-4 shrink-0">
                    <div className="text-right">
                      <span className="text-[10px] text-slate-400 font-mono block">Score</span>
                      <span
                        className={`text-base font-bold font-mono ${
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

                    <div className="flex items-center gap-1.5" onClick={(e) => e.stopPropagation()}>
                      <Button
                        size="sm"
                        variant="outline"
                        onClick={() => onViewReport(scan)}
                        className="text-xs h-8"
                      >
                        <span>Report</span>
                        <ArrowRight className="w-3.5 h-3.5 ml-1" />
                      </Button>
                      <Button
                        size="sm"
                        variant="ghost"
                        onClick={() => onRunScan(scan.url)}
                        title="Re-scan this target"
                        className="text-xs h-8 px-2 text-slate-400 hover:text-cyan-400"
                      >
                        <RefreshCw className="w-3.5 h-3.5" />
                      </Button>
                      <Button
                        size="sm"
                        variant="ghost"
                        onClick={(e) => handleDeleteScan(scan.scan_id, e)}
                        title="Delete from history"
                        className="text-xs h-8 px-2 text-slate-400 hover:text-red-400"
                      >
                        <Trash2 className="w-3.5 h-3.5" />
                      </Button>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
};
