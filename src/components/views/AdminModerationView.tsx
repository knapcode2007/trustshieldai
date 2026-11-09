import React, { useState, useEffect } from "react";
import {
  ShieldCheck,
  ShieldAlert,
  CheckCircle2,
  XCircle,
  AlertTriangle,
  RefreshCw,
  Search,
  Filter,
  Clock,
  UserCheck,
  FileText,
  ThumbsUp,
  Tag,
  ArrowRight,
} from "lucide-react";
import { Card, CardHeader, CardTitle, CardDescription, CardContent } from "../ui/card";
import { Button } from "../ui/button";
import { Input } from "../ui/input";
import { Badge } from "../ui/badge";
import { Alert, AlertTitle, AlertDescription } from "../ui/alert";
import { apiClient } from "../../services/apiClient";
import { CommunityReport, ThreatIndicator, AdminAuditEntry } from "../../services/types";

interface AdminModerationViewProps {
  onRunScan: (url: string) => void;
}

export const AdminModerationView: React.FC<AdminModerationViewProps> = ({ onRunScan }) => {
  const [activeQueue, setActiveQueue] = useState<"reports" | "indicators" | "audit">("reports");
  const [reports, setReports] = useState<CommunityReport[]>([]);
  const [indicators, setIndicators] = useState<ThreatIndicator[]>([]);
  const [auditLogs, setAuditLogs] = useState<AdminAuditEntry[]>([]);
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [moderatorNotes, setModeratorNotes] = useState<Record<string, string>>({});
  const [actionSuccess, setActionSuccess] = useState<string | null>(null);

  const loadData = async () => {
    setIsLoading(true);
    try {
      const [reps, iocs, logs] = await Promise.all([
        apiClient.getCommunityReports({ status: "all" }),
        apiClient.getThreatIndicators(),
        apiClient.getAdminAuditLogs(),
      ]);
      setReports(reps || []);
      setIndicators(iocs || []);
      setAuditLogs(logs || []);
    } catch (err) {
      console.warn("Failed to load moderation queue:", err);
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    loadData();
  }, [activeQueue]);

  const handleModerateReport = async (id: string, status: "verified" | "dismissed") => {
    const note = moderatorNotes[id] || `Action: marked as ${status} by admin`;
    try {
      const updated = await apiClient.moderateCommunityReport(id, status, note);
      setReports(reports.map((r) => (r.id === id ? updated : r)));
      setActionSuccess(`Report ${id} successfully marked as ${status.toUpperCase()}.`);
      setTimeout(() => setActionSuccess(null), 3000);
      // Reload logs
      apiClient.getAdminAuditLogs().then(setAuditLogs);
    } catch (err) {
      console.warn("Moderation error:", err);
    }
  };

  const handleVerifyIndicator = async (id: string, is_verified: boolean) => {
    try {
      const updated = await apiClient.verifyThreatIndicator(
        id,
        is_verified,
        is_verified ? "Verified by SOC analyst review" : "Revoked by admin"
      );
      setIndicators(indicators.map((i) => (i.id === id ? updated : i)));
      setActionSuccess(`Threat indicator ${updated.indicator_value} updated.`);
      setTimeout(() => setActionSuccess(null), 3000);
      apiClient.getAdminAuditLogs().then(setAuditLogs);
    } catch (err) {
      console.warn("Verification error:", err);
    }
  };

  const pendingReports = reports.filter((r) => r.status === "pending");

  return (
    <div className="space-y-6 max-w-6xl mx-auto">
      {/* Header */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
        <div>
          <h2 className="text-xl font-bold text-white flex items-center gap-2">
            <UserCheck className="w-5 h-5 text-cyan-400" />
            <span>SOC Admin & Threat Moderation</span>
          </h2>
          <p className="text-xs text-slate-400 mt-1">
            Review crowdsourced threat reports, verify collaborative Indicators of Compromise (IOCs), and inspect audit trails.
          </p>
        </div>

        {/* Tab Switcher */}
        <div className="flex items-center gap-1 p-1 bg-slate-900 border border-slate-800 rounded-lg text-xs font-mono">
          <button
            onClick={() => setActiveQueue("reports")}
            className={`px-3 py-1.5 rounded-md transition-colors cursor-pointer ${
              activeQueue === "reports"
                ? "bg-slate-800 text-white font-semibold"
                : "text-slate-400 hover:text-white"
            }`}
          >
            Community Reports ({pendingReports.length})
          </button>
          <button
            onClick={() => setActiveQueue("indicators")}
            className={`px-3 py-1.5 rounded-md transition-colors cursor-pointer ${
              activeQueue === "indicators"
                ? "bg-slate-800 text-white font-semibold"
                : "text-slate-400 hover:text-white"
            }`}
          >
            Threat IOCs ({indicators.length})
          </button>
          <button
            onClick={() => setActiveQueue("audit")}
            className={`px-3 py-1.5 rounded-md transition-colors cursor-pointer ${
              activeQueue === "audit"
                ? "bg-slate-800 text-white font-semibold"
                : "text-slate-400 hover:text-white"
            }`}
          >
            Audit Log ({auditLogs.length})
          </button>
        </div>
      </div>

      {actionSuccess && (
        <Alert variant="success">
          <CheckCircle2 className="h-4 w-4" />
          <AlertTitle>Moderation Recorded</AlertTitle>
          <AlertDescription>{actionSuccess}</AlertDescription>
        </Alert>
      )}

      {/* Main Queue Panels */}
      {activeQueue === "reports" && (
        <Card className="border-slate-800 bg-slate-900/80 shadow-xl overflow-hidden">
          <CardHeader className="py-3 px-4 border-b border-slate-800/80 flex flex-row items-center justify-between">
            <span className="text-xs font-mono uppercase text-slate-400">
              Pending Community Reports ({pendingReports.length})
            </span>
            <button
              onClick={loadData}
              className="text-slate-400 hover:text-cyan-400 text-xs flex items-center gap-1 font-mono transition-colors"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${isLoading ? "animate-spin" : ""}`} />
              <span>Refresh Queue</span>
            </button>
          </CardHeader>
          <CardContent className="p-0">
            {pendingReports.length === 0 ? (
              <div className="p-12 text-center text-xs text-slate-400">
                <CheckCircle2 className="w-8 h-8 mx-auto mb-3 text-emerald-500" />
                <p className="font-semibold text-slate-200">Moderation Queue is Clear</p>
                <p className="mt-1 text-slate-500">All submitted community threat sightings have been audited.</p>
              </div>
            ) : (
              <div className="divide-y divide-slate-800/80">
                {pendingReports.map((report) => (
                  <div key={report.id} className="p-5 space-y-3">
                    <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-3">
                      <div>
                        <div className="flex items-center gap-2">
                          <span className="font-mono text-sm font-semibold text-white break-all">
                            {report.target_url}
                          </span>
                          <Badge variant="suspicious">PENDING REVIEW</Badge>
                          <Badge variant="destructive">{report.severity.toUpperCase()}</Badge>
                        </div>
                        <p className="text-xs text-slate-300 mt-1 max-w-3xl leading-relaxed">
                          {report.description}
                        </p>
                      </div>

                      <Button
                        size="sm"
                        variant="outline"
                        onClick={() => onRunScan(report.target_url)}
                        className="text-xs shrink-0"
                      >
                        <span>Audit Target</span>
                        <ArrowRight className="w-3.5 h-3.5 ml-1" />
                      </Button>
                    </div>

                    <div className="flex flex-wrap items-center gap-4 text-[11px] font-mono text-slate-400">
                      <span>Threat: <strong className="text-slate-200">{report.threat_type}</strong></span>
                      {report.targeted_brand && (
                        <span>Brand Spoofed: <strong className="text-cyan-400">{report.targeted_brand}</strong></span>
                      )}
                      <span>Reporter: @{report.reporter_handle || "anonymous"}</span>
                      <span>Sightings: <strong>{report.confirmations_count}</strong></span>
                    </div>

                    {/* Moderator Decision Row */}
                    <div className="pt-2 border-t border-slate-800/60 flex flex-col sm:flex-row items-stretch sm:items-center gap-2">
                      <Input
                        type="text"
                        placeholder="Add rationale or forensic note..."
                        value={moderatorNotes[report.id] || ""}
                        onChange={(e) =>
                          setModeratorNotes({ ...moderatorNotes, [report.id]: e.target.value })
                        }
                        className="h-8 text-xs bg-slate-950 font-mono flex-1"
                      />

                      <div className="flex gap-2">
                        <Button
                          size="sm"
                          onClick={() => handleModerateReport(report.id, "verified")}
                          className="h-8 text-xs bg-emerald-600 hover:bg-emerald-700 text-white font-semibold"
                        >
                          <CheckCircle2 className="w-3.5 h-3.5 mr-1" />
                          <span>Approve & Verify</span>
                        </Button>

                        <Button
                          size="sm"
                          variant="destructive"
                          onClick={() => handleModerateReport(report.id, "dismissed")}
                          className="h-8 text-xs"
                        >
                          <XCircle className="w-3.5 h-3.5 mr-1" />
                          <span>Dismiss</span>
                        </Button>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </CardContent>
        </Card>
      )}

      {activeQueue === "indicators" && (
        <Card className="border-slate-800 bg-slate-900/80 shadow-xl overflow-hidden">
          <CardHeader className="py-3 px-4 border-b border-slate-800/80">
            <span className="text-xs font-mono uppercase text-slate-400">
              Collaborative Threat Indicators ({indicators.length})
            </span>
          </CardHeader>
          <CardContent className="p-0">
            <div className="divide-y divide-slate-800/80">
              {indicators.map((ioc) => (
                <div
                  key={ioc.id}
                  className="p-4 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 text-xs"
                >
                  <div className="space-y-1">
                    <div className="flex items-center gap-2">
                      <span className="font-mono font-semibold text-white break-all">
                        {ioc.indicator_value}
                      </span>
                      <Badge variant="outline" className="text-[10px] uppercase font-mono">
                        {ioc.indicator_type}
                      </Badge>
                      <Badge variant={ioc.is_verified ? "clean" : "suspicious"}>
                        {ioc.is_verified ? "VERIFIED" : "COMMUNITY SUBMISSION"}
                      </Badge>
                    </div>
                    <div className="flex items-center gap-3 text-slate-400 font-mono text-[11px]">
                      <span>Category: {ioc.threat_category}</span>
                      <span>·</span>
                      <span>Source: {ioc.source}</span>
                      <span>·</span>
                      <span>Confidence: {ioc.confidence}%</span>
                    </div>
                  </div>

                  <div className="flex items-center gap-2 shrink-0">
                    {ioc.is_verified ? (
                      <Button
                        size="sm"
                        variant="outline"
                        onClick={() => handleVerifyIndicator(ioc.id, false)}
                        className="text-xs text-amber-400 border-amber-900/40 hover:bg-amber-950/40"
                      >
                        Revoke Verification
                      </Button>
                    ) : (
                      <Button
                        size="sm"
                        onClick={() => handleVerifyIndicator(ioc.id, true)}
                        className="text-xs bg-emerald-600 hover:bg-emerald-700 text-white"
                      >
                        <CheckCircle2 className="w-3.5 h-3.5 mr-1" />
                        <span>Mark Verified</span>
                      </Button>
                    )}
                  </div>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      )}

      {activeQueue === "audit" && (
        <Card className="border-slate-800 bg-slate-900/80 shadow-xl overflow-hidden">
          <CardHeader className="py-3 px-4 border-b border-slate-800/80">
            <span className="text-xs font-mono uppercase text-slate-400">
              SOC Moderation Audit Trail ({auditLogs.length})
            </span>
          </CardHeader>
          <CardContent className="p-0">
            <div className="overflow-x-auto">
              <table className="w-full text-xs font-mono text-left">
                <thead>
                  <tr className="border-b border-slate-800 bg-slate-950/60 text-slate-400">
                    <th className="py-2.5 px-4 font-semibold">Timestamp</th>
                    <th className="py-2.5 px-4 font-semibold">Action</th>
                    <th className="py-2.5 px-4 font-semibold">Target Value</th>
                    <th className="py-2.5 px-4 font-semibold">Decision</th>
                    <th className="py-2.5 px-4 font-semibold">Actor / Reason</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60 text-slate-300">
                  {auditLogs.map((log) => (
                    <tr key={log.id} className="hover:bg-slate-850/40">
                      <td className="py-2.5 px-4 text-slate-400">
                        {new Date(log.timestamp).toLocaleTimeString()}
                      </td>
                      <td className="py-2.5 px-4 text-cyan-400 font-semibold">{log.action}</td>
                      <td className="py-2.5 px-4 text-white max-w-xs truncate">{log.target_value}</td>
                      <td className="py-2.5 px-4">
                        <Badge variant={log.decision === "approved" ? "clean" : "destructive"}>
                          {log.decision.toUpperCase()}
                        </Badge>
                      </td>
                      <td className="py-2.5 px-4 text-slate-400 text-[11px]">
                        <strong>{log.actor}:</strong> {log.reason || "Approved"}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  );
};
