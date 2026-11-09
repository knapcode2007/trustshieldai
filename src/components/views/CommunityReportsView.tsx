import React, { useState, useEffect } from "react";
import {
  Users,
  Search,
  Plus,
  ShieldAlert,
  CheckCircle2,
  ThumbsUp,
  AlertTriangle,
  RefreshCw,
  ExternalLink,
  Tag,
  Clock,
  X,
  ArrowRight,
} from "lucide-react";
import { Card, CardHeader, CardTitle, CardDescription, CardContent } from "../ui/card";
import { Button } from "../ui/button";
import { Input } from "../ui/input";
import { Badge } from "../ui/badge";
import { Alert, AlertTitle, AlertDescription } from "../ui/alert";
import { apiClient } from "../../services/apiClient";
import { CommunityReport, CommunityReportCreate, SeverityLevel } from "../../services/types";

interface CommunityReportsViewProps {
  onRunScan: (url: string) => void;
}

export const CommunityReportsView: React.FC<CommunityReportsViewProps> = ({ onRunScan }) => {
  const [reports, setReports] = useState<CommunityReport[]>([]);
  const [filterStatus, setFilterStatus] = useState<string>("all");
  const [searchQuery, setSearchQuery] = useState<string>("");
  const [isLoading, setIsLoading] = useState<boolean>(true);

  // Submission Modal State
  const [isModalOpen, setIsModalOpen] = useState<boolean>(false);
  const [isSubmitting, setIsSubmitting] = useState<boolean>(false);
  const [submitSuccess, setSubmitSuccess] = useState<boolean>(false);
  const [newReport, setNewReport] = useState<CommunityReportCreate>({
    target_url: "",
    threat_type: "Phishing / Credential Harvesting",
    targeted_brand: "",
    description: "",
    reporter_handle: "",
    severity: "high",
  });

  const fetchReports = async () => {
    setIsLoading(true);
    try {
      const data = await apiClient.getCommunityReports({
        status: filterStatus,
        search: searchQuery,
      });
      setReports(data || []);
    } catch (err) {
      console.warn("Error fetching community reports:", err);
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    fetchReports();
  }, [filterStatus]);

  const handleSearch = (e: React.FormEvent) => {
    e.preventDefault();
    fetchReports();
  };

  const handleVote = async (id: string, e: React.MouseEvent) => {
    e.stopPropagation();
    try {
      const updated = await apiClient.voteCommunityReport(id);
      setReports(reports.map((r) => (r.id === id ? updated : r)));
    } catch (err) {
      console.warn("Error confirming report sighting:", err);
    }
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newReport.target_url.trim()) return;

    setIsSubmitting(true);
    try {
      const created = await apiClient.submitCommunityReport(newReport);
      setReports([created, ...reports]);
      setSubmitSuccess(true);
      setTimeout(() => {
        setSubmitSuccess(false);
        setIsModalOpen(false);
        setNewReport({
          target_url: "",
          threat_type: "Phishing / Credential Harvesting",
          targeted_brand: "",
          description: "",
          reporter_handle: "",
          severity: "high",
        });
      }, 1500);
    } catch (err) {
      console.warn("Error submitting community report:", err);
    } finally {
      setIsSubmitting(false);
    }
  };

  const getStatusBadge = (status: string) => {
    switch (status) {
      case "verified":
        return <Badge variant="clean">VERIFIED THREAT</Badge>;
      case "dismissed":
        return <Badge variant="outline">DISMISSED</Badge>;
      default:
        return <Badge variant="suspicious">PENDING REVIEW</Badge>;
    }
  };

  const getSeverityBadge = (severity: SeverityLevel) => {
    switch (severity) {
      case "critical":
        return <Badge variant="malicious">CRITICAL</Badge>;
      case "high":
        return <Badge variant="phishing">HIGH</Badge>;
      case "medium":
        return <Badge variant="suspicious">MEDIUM</Badge>;
      default:
        return <Badge variant="outline">LOW</Badge>;
    }
  };

  return (
    <div className="space-y-6 max-w-6xl mx-auto">
      {/* Header */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
        <div>
          <h2 className="text-xl font-bold text-white flex items-center gap-2">
            <Users className="w-5 h-5 text-cyan-400" />
            <span>Community Threat Reports</span>
          </h2>
          <p className="text-xs text-slate-400 mt-1">
            Crowdsourced telemetry from security researchers and frontline users spotting active phishing campaigns.
          </p>
        </div>

        <Button
          onClick={() => setIsModalOpen(true)}
          className="bg-cyan-600 hover:bg-cyan-700 text-white font-medium text-xs flex items-center gap-1.5"
        >
          <Plus className="w-4 h-4" />
          <span>Report Suspicious Site</span>
        </Button>
      </div>

      {/* Filter and Search Bar */}
      <Card className="border-slate-800 bg-slate-900/60">
        <CardContent className="p-3.5 flex flex-col md:flex-row items-center gap-3">
          <form onSubmit={handleSearch} className="relative flex-1 w-full">
            <Search className="absolute left-3 top-2.5 h-4 w-4 text-slate-500" />
            <Input
              type="text"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              placeholder="Search reports by URL, domain, brand or threat type..."
              className="pl-9 h-9 text-xs font-mono bg-slate-950/80 border-slate-800"
            />
          </form>

          {/* Segmented Filter Buttons */}
          <div className="flex items-center gap-1 p-1 bg-slate-950/80 border border-slate-800 rounded-lg text-xs font-mono overflow-x-auto w-full md:w-auto">
            {["all", "pending", "verified", "dismissed"].map((s) => (
              <button
                key={s}
                onClick={() => setFilterStatus(s)}
                className={`px-3 py-1 rounded-md capitalize transition-colors cursor-pointer ${
                  filterStatus === s
                    ? "bg-slate-800 text-white font-semibold"
                    : "text-slate-400 hover:text-white"
                }`}
              >
                {s === "all" ? "All Reports" : s}
              </button>
            ))}
          </div>
        </CardContent>
      </Card>

      {/* Reports List */}
      <Card className="border-slate-800 bg-slate-900/80 shadow-xl overflow-hidden">
        <CardHeader className="py-3 px-4 border-b border-slate-800/80 flex flex-row items-center justify-between">
          <span className="text-xs font-mono uppercase text-slate-400">
            Reports Feed ({reports.length})
          </span>
          <button
            onClick={fetchReports}
            className="text-slate-400 hover:text-cyan-400 text-xs flex items-center gap-1 font-mono transition-colors"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${isLoading ? "animate-spin" : ""}`} />
            <span>Reload</span>
          </button>
        </CardHeader>
        <CardContent className="p-0">
          {isLoading ? (
            <div className="p-12 text-center text-xs text-slate-400 font-mono">
              <RefreshCw className="w-6 h-6 mx-auto mb-2 animate-spin text-cyan-400" />
              Loading community threat submissions...
            </div>
          ) : reports.length === 0 ? (
            <div className="p-12 text-center text-xs text-slate-400">
              <Users className="w-8 h-8 mx-auto mb-3 text-slate-600" />
              <p className="font-semibold text-slate-300">No Reports Found</p>
              <p className="mt-1 text-slate-500">No community sightings matching the current query filter.</p>
            </div>
          ) : (
            <div className="divide-y divide-slate-800/80">
              {reports.map((item) => (
                <div
                  key={item.id}
                  className="p-5 hover:bg-slate-850/50 transition-colors flex flex-col md:flex-row items-start md:items-center justify-between gap-4"
                >
                  <div className="space-y-2 flex-1 min-w-0">
                    <div className="flex flex-wrap items-center gap-2">
                      <span className="font-mono text-sm font-semibold text-white break-all">
                        {item.target_url}
                      </span>
                      {getStatusBadge(item.status)}
                      {getSeverityBadge(item.severity)}
                      {item.targeted_brand && (
                        <span className="text-[11px] font-mono px-2 py-0.5 rounded bg-blue-950/60 border border-blue-800/50 text-blue-300">
                          Brand: {item.targeted_brand}
                        </span>
                      )}
                    </div>

                    <p className="text-xs text-slate-300 leading-relaxed max-w-2xl">
                      {item.description}
                    </p>

                    <div className="flex flex-wrap items-center gap-4 text-[11px] font-mono text-slate-400 pt-1">
                      <span>Threat: <strong className="text-slate-200">{item.threat_type}</strong></span>
                      <span>·</span>
                      <span>Reported by: <span className="text-cyan-400">@{item.reporter_handle || "anonymous"}</span></span>
                      <span>·</span>
                      <span>{new Date(item.created_at).toLocaleDateString()}</span>
                    </div>

                    {item.moderator_note && (
                      <div className="p-2.5 rounded bg-slate-950/80 border border-slate-800 text-[11px] text-slate-300 font-mono">
                        <strong className="text-cyan-400">Moderator Note:</strong> {item.moderator_note}
                      </div>
                    )}
                  </div>

                  <div className="flex items-center gap-2 shrink-0">
                    <Button
                      size="sm"
                      variant="outline"
                      onClick={(e) => handleVote(item.id, e)}
                      title="Confirm this threat sighting"
                      className="text-xs h-9 flex items-center gap-1.5 border-slate-700 hover:border-cyan-500"
                    >
                      <ThumbsUp className="w-3.5 h-3.5 text-cyan-400" />
                      <span>Confirm Sighting</span>
                      <span className="font-mono font-bold ml-1 text-cyan-300">
                        ({item.confirmations_count})
                      </span>
                    </Button>

                    <Button
                      size="sm"
                      variant="default"
                      onClick={() => onRunScan(item.target_url)}
                      className="text-xs h-9 bg-cyan-600 hover:bg-cyan-700 text-white flex items-center gap-1"
                    >
                      <span>Scan Target</span>
                      <ArrowRight className="w-3.5 h-3.5" />
                    </Button>
                  </div>
                </div>
              ))}
            </div>
          )}
        </CardContent>
      </Card>

      {/* Submission Modal */}
      {isModalOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm">
          <div className="relative w-full max-w-lg rounded-xl border border-slate-800 bg-slate-900 p-6 shadow-2xl space-y-4">
            <div className="flex items-center justify-between pb-3 border-b border-slate-800">
              <h3 className="text-base font-semibold text-white flex items-center gap-2">
                <ShieldAlert className="w-5 h-5 text-cyan-400" />
                <span>Submit Suspicious Website Report</span>
              </h3>
              <button
                onClick={() => setIsModalOpen(false)}
                className="text-slate-400 hover:text-white"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            {submitSuccess && (
              <Alert variant="success">
                <CheckCircle2 className="h-4 w-4" />
                <AlertTitle>Report Logged</AlertTitle>
                <AlertDescription>
                  Your community sighting was recorded and queued for SOC moderation review.
                </AlertDescription>
              </Alert>
            )}

            <form onSubmit={handleSubmit} className="space-y-3 text-xs">
              <div>
                <label className="block text-slate-300 mb-1 font-medium">Target URL *</label>
                <Input
                  type="text"
                  required
                  value={newReport.target_url}
                  onChange={(e) => setNewReport({ ...newReport, target_url: e.target.value })}
                  placeholder="https://fake-login-service.xyz/verify"
                  className="bg-slate-950 font-mono"
                />
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-slate-300 mb-1 font-medium">Targeted Brand</label>
                  <Input
                    type="text"
                    value={newReport.targeted_brand || ""}
                    onChange={(e) => setNewReport({ ...newReport, targeted_brand: e.target.value })}
                    placeholder="e.g. Netflix, Microsoft, Google"
                    className="bg-slate-950"
                  />
                </div>

                <div>
                  <label className="block text-slate-300 mb-1 font-medium">Threat Severity</label>
                  <select
                    value={newReport.severity}
                    onChange={(e: any) => setNewReport({ ...newReport, severity: e.target.value })}
                    className="w-full h-10 rounded-md border border-slate-700 bg-slate-950 px-3 py-1 text-xs text-slate-200 font-mono"
                  >
                    <option value="critical">Critical</option>
                    <option value="high">High</option>
                    <option value="medium">Medium</option>
                    <option value="low">Low</option>
                  </select>
                </div>
              </div>

              <div>
                <label className="block text-slate-300 mb-1 font-medium">Threat Type</label>
                <select
                  value={newReport.threat_type}
                  onChange={(e) => setNewReport({ ...newReport, threat_type: e.target.value })}
                  className="w-full h-10 rounded-md border border-slate-700 bg-slate-950 px-3 py-1 text-xs text-slate-200"
                >
                  <option value="Phishing / Credential Harvesting">Phishing / Credential Harvesting</option>
                  <option value="SMS / Smishing Campaign">SMS / Smishing Campaign</option>
                  <option value="Banking & Financial Fraud">Banking & Financial Fraud</option>
                  <option value="Web3 / Cryptocurrency Drainer">Web3 / Cryptocurrency Drainer</option>
                  <option value="Malware / Dropper Delivery">Malware / Dropper Delivery</option>
                  <option value="Brand Impersonation / Fake Store">Brand Impersonation / Fake Store</option>
                </select>
              </div>

              <div>
                <label className="block text-slate-300 mb-1 font-medium">Lure Description & Evidence *</label>
                <textarea
                  required
                  rows={3}
                  value={newReport.description}
                  onChange={(e) => setNewReport({ ...newReport, description: e.target.value })}
                  placeholder="Describe the attack vector (e.g. Received email claiming account was locked, page replicates corporate login form...)"
                  className="w-full rounded-md border border-slate-700 bg-slate-950 p-2.5 text-xs text-slate-200 placeholder:text-slate-500 focus:outline-none focus:ring-1 focus:ring-cyan-500"
                />
              </div>

              <div>
                <label className="block text-slate-300 mb-1 font-medium">Your Handle / Pseudonym</label>
                <Input
                  type="text"
                  value={newReport.reporter_handle || ""}
                  onChange={(e) => setNewReport({ ...newReport, reporter_handle: e.target.value })}
                  placeholder="e.g. sec_researcher_01"
                  className="bg-slate-950 font-mono"
                />
              </div>

              <div className="flex justify-end gap-2 pt-4 border-t border-slate-800">
                <Button
                  type="button"
                  variant="outline"
                  onClick={() => setIsModalOpen(false)}
                >
                  Cancel
                </Button>
                <Button
                  type="submit"
                  disabled={isSubmitting}
                  className="bg-cyan-600 hover:bg-cyan-700 text-white"
                >
                  {isSubmitting ? "Submitting..." : "Submit Report"}
                </Button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};
