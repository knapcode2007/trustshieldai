import React, { useState, useEffect } from "react";
import {
  Database,
  Search,
  Filter,
  Plus,
  ShieldAlert,
  CheckCircle2,
  Clock,
  Tag,
  Download,
  AlertTriangle,
  RefreshCw,
  X,
} from "lucide-react";
import { Card, CardHeader, CardTitle, CardDescription, CardContent } from "../ui/card";
import { Button } from "../ui/button";
import { Input } from "../ui/input";
import { Badge } from "../ui/badge";
import { Alert, AlertTitle, AlertDescription } from "../ui/alert";
import { apiClient } from "../../services/apiClient";
import { ThreatIndicator, ThreatIndicatorCreate, SeverityLevel } from "../../services/types";

export const ThreatIntelView: React.FC = () => {
  const [indicators, setIndicators] = useState<ThreatIndicator[]>([]);
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  // Filters
  const [filterType, setFilterType] = useState<string>("all");
  const [filterSeverity, setFilterSeverity] = useState<string>("all");
  const [searchQuery, setSearchQuery] = useState<string>("");

  // Modal State
  const [isSubmitOpen, setIsSubmitOpen] = useState<boolean>(false);
  const [isSubmitting, setIsSubmitting] = useState<boolean>(false);
  const [newIndicator, setNewIndicator] = useState<ThreatIndicatorCreate>({
    indicator_value: "",
    indicator_type: "domain",
    threat_category: "Phishing Portal",
    severity: "high",
    confidence: 85,
    tags: ["phishing", "community-report"],
  });
  const [tagInput, setTagInput] = useState<string>("");
  const [submitSuccess, setSubmitSuccess] = useState<boolean>(false);

  const fetchIndicators = async () => {
    setIsLoading(true);
    setError(null);
    try {
      const data = await apiClient.getThreatIndicators({
        type: filterType,
        severity: filterSeverity,
        search: searchQuery,
      });
      setIndicators(data);
    } catch (err: any) {
      setError(err.message || "Failed to load threat intelligence feed.");
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    fetchIndicators();
  }, [filterType, filterSeverity]);

  const handleSearch = (e: React.FormEvent) => {
    e.preventDefault();
    fetchIndicators();
  };

  const handleAddTag = () => {
    if (!tagInput.trim()) return;
    if (!newIndicator.tags.includes(tagInput.trim().toLowerCase())) {
      setNewIndicator({
        ...newIndicator,
        tags: [...newIndicator.tags, tagInput.trim().toLowerCase()],
      });
    }
    setTagInput("");
  };

  const handleRemoveTag = (tagToRemove: string) => {
    setNewIndicator({
      ...newIndicator,
      tags: newIndicator.tags.filter((t) => t !== tagToRemove),
    });
  };

  const handleSubmitIndicator = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newIndicator.indicator_value.trim()) return;

    setIsSubmitting(true);
    try {
      const created = await apiClient.submitThreatIndicator(newIndicator);
      setIndicators([created, ...indicators]);
      setSubmitSuccess(true);
      setTimeout(() => {
        setSubmitSuccess(false);
        setIsSubmitOpen(false);
        setNewIndicator({
          indicator_value: "",
          indicator_type: "domain",
          threat_category: "Phishing Portal",
          severity: "high",
          confidence: 85,
          tags: ["phishing", "community-report"],
        });
      }, 1500);
    } catch (err: any) {
      setError(err.message || "Failed to submit threat indicator.");
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleExportJson = () => {
    const jsonStr = JSON.stringify(indicators, null, 2);
    const blob = new Blob([jsonStr], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = `trustshield-iocs-${new Date().toISOString().slice(0, 10)}.json`;
    link.click();
    URL.revokeObjectURL(url);
  };

  const getSeverityBadge = (severity: SeverityLevel) => {
    switch (severity) {
      case "critical":
        return <Badge variant="malicious">CRITICAL</Badge>;
      case "high":
        return <Badge variant="phishing">HIGH</Badge>;
      case "medium":
        return <Badge variant="suspicious">MEDIUM</Badge>;
      case "low":
        return <Badge variant="outline">LOW</Badge>;
      default:
        return <Badge variant="outline">{severity}</Badge>;
    }
  };

  return (
    <div className="space-y-6 max-w-6xl mx-auto">
      {/* Top Header Card */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
        <div>
          <h2 className="text-xl font-bold text-white flex items-center gap-2">
            <Database className="w-5 h-5 text-cyan-400" />
            <span>Collaborative Threat Intelligence (CTI)</span>
          </h2>
          <p className="text-xs text-slate-400 mt-1">
            Crowdsourced and research-verified Indicators of Compromise (IOCs) stored with Supabase PostgreSQL schema.
          </p>
        </div>

        <div className="flex items-center gap-2">
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
            variant="default"
            onClick={() => setIsSubmitOpen(true)}
            className="text-xs bg-cyan-600 hover:bg-cyan-700 text-white font-medium"
          >
            <Plus className="w-3.5 h-3.5 mr-1" />
            <span>Report Indicator</span>
          </Button>
        </div>
      </div>

      {/* Filter and Search Bar */}
      <Card className="border-slate-800 bg-slate-900/60">
        <CardContent className="p-4">
          <form
            onSubmit={handleSearch}
            className="flex flex-col md:flex-row items-center gap-3"
          >
            {/* Search Input */}
            <div className="relative flex-1 w-full">
              <Search className="absolute left-3 top-2.5 h-4 w-4 text-slate-500" />
              <Input
                type="text"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                placeholder="Search indicators, domains, IPs, or tags..."
                className="pl-9 h-9 text-xs font-mono bg-slate-950/80 border-slate-800"
              />
            </div>

            {/* Type Selector */}
            <div className="flex items-center gap-2 w-full md:w-auto">
              <span className="text-xs text-slate-400 hidden sm:inline">Type:</span>
              <select
                value={filterType}
                onChange={(e) => setFilterType(e.target.value)}
                className="h-9 rounded-md border border-slate-800 bg-slate-950 px-3 py-1 text-xs text-slate-200 focus:outline-none focus:ring-1 focus:ring-cyan-500 font-mono"
              >
                <option value="all">All Types</option>
                <option value="domain">Domain</option>
                <option value="url">URL</option>
                <option value="ip">IPv4 Address</option>
                <option value="sha256">SHA256 Hash</option>
              </select>

              {/* Severity Selector */}
              <span className="text-xs text-slate-400 hidden sm:inline">Severity:</span>
              <select
                value={filterSeverity}
                onChange={(e) => setFilterSeverity(e.target.value)}
                className="h-9 rounded-md border border-slate-800 bg-slate-950 px-3 py-1 text-xs text-slate-200 focus:outline-none focus:ring-1 focus:ring-cyan-500 font-mono"
              >
                <option value="all">All Severities</option>
                <option value="critical">Critical</option>
                <option value="high">High</option>
                <option value="medium">Medium</option>
                <option value="low">Low</option>
              </select>

              <Button type="submit" size="sm" variant="secondary" className="h-9 text-xs">
                Filter
              </Button>
            </div>
          </form>
        </CardContent>
      </Card>

      {/* Error state */}
      {error && (
        <Alert variant="destructive">
          <AlertTriangle className="h-4 w-4" />
          <AlertTitle>Threat Feed Error</AlertTitle>
          <AlertDescription>{error}</AlertDescription>
        </Alert>
      )}

      {/* IOC Table / List */}
      <Card className="border-slate-800 bg-slate-900/80 shadow-xl overflow-hidden">
        <CardHeader className="py-3 px-4 border-b border-slate-800/80 flex flex-row items-center justify-between">
          <span className="text-xs font-mono uppercase text-slate-400">
            Active Indicators ({indicators.length})
          </span>
          <button
            onClick={fetchIndicators}
            className="text-slate-400 hover:text-cyan-400 text-xs flex items-center gap-1 font-mono transition-colors"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${isLoading ? "animate-spin" : ""}`} />
            <span>Reload Feed</span>
          </button>
        </CardHeader>
        <CardContent className="p-0">
          {isLoading ? (
            <div className="p-12 text-center text-xs text-slate-400 font-mono">
              <RefreshCw className="w-6 h-6 mx-auto mb-2 animate-spin text-cyan-400" />
              Loading Threat Intelligence repository...
            </div>
          ) : indicators.length === 0 ? (
            <div className="p-12 text-center text-xs text-slate-400 font-mono">
              No matching indicators found for current query.
            </div>
          ) : (
            <div className="divide-y divide-slate-800/80">
              {indicators.map((ioc) => (
                <div
                  key={ioc.id}
                  className="p-4 hover:bg-slate-850/50 transition-colors flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3"
                >
                  <div className="space-y-1.5 flex-1 min-w-0">
                    <div className="flex flex-wrap items-center gap-2">
                      <span className="font-mono text-sm font-semibold text-white break-all">
                        {ioc.indicator_value}
                      </span>
                      <Badge variant="outline" className="text-[10px] uppercase font-mono">
                        {ioc.indicator_type}
                      </Badge>
                      {getSeverityBadge(ioc.severity)}
                      {ioc.is_verified && (
                        <span className="inline-flex items-center gap-1 text-[11px] text-emerald-400 font-mono">
                          <CheckCircle2 className="w-3 h-3" />
                          <span>Verified</span>
                        </span>
                      )}
                    </div>
                    <div className="flex flex-wrap items-center gap-3 text-xs text-slate-400">
                      <span>Category: <strong className="text-slate-200">{ioc.threat_category}</strong></span>
                      <span>Source: <strong className="text-slate-300">{ioc.source}</strong></span>
                      <span>Confidence: <strong className="text-cyan-400 font-mono">{ioc.confidence}%</strong></span>
                    </div>
                    {ioc.tags && ioc.tags.length > 0 && (
                      <div className="flex flex-wrap gap-1 pt-1">
                        {ioc.tags.map((tag, tIdx) => (
                          <span
                            key={tIdx}
                            className="inline-flex items-center text-[10px] font-mono px-2 py-0.5 rounded bg-slate-800/80 text-slate-300 border border-slate-700/60"
                          >
                            #{tag}
                          </span>
                        ))}
                      </div>
                    )}
                  </div>

                  <div className="text-right shrink-0 text-[11px] font-mono text-slate-500">
                    <span className="flex items-center gap-1">
                      <Clock className="w-3 h-3" />
                      {new Date(ioc.created_at).toLocaleDateString()}
                    </span>
                  </div>
                </div>
              ))}
            </div>
          )}
        </CardContent>
      </Card>

      {/* Submission Modal */}
      {isSubmitOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm">
          <div className="relative w-full max-w-lg rounded-xl border border-slate-800 bg-slate-900 p-6 shadow-2xl space-y-4">
            <div className="flex items-center justify-between pb-3 border-b border-slate-800">
              <h3 className="text-base font-semibold text-white flex items-center gap-2">
                <ShieldAlert className="w-5 h-5 text-cyan-400" />
                <span>Report Threat Indicator (IOC)</span>
              </h3>
              <button
                onClick={() => setIsSubmitOpen(false)}
                className="text-slate-400 hover:text-white"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            {submitSuccess && (
              <Alert variant="success">
                <CheckCircle2 className="h-4 w-4" />
                <AlertTitle>Success</AlertTitle>
                <AlertDescription>
                  Indicator submitted to threat intelligence registry successfully.
                </AlertDescription>
              </Alert>
            )}

            <form onSubmit={handleSubmitIndicator} className="space-y-3 text-xs">
              <div>
                <label className="block text-slate-300 mb-1 font-medium">
                  Indicator Value (Domain, URL, IP, or Hash) *
                </label>
                <Input
                  type="text"
                  required
                  value={newIndicator.indicator_value}
                  onChange={(e) =>
                    setNewIndicator({ ...newIndicator, indicator_value: e.target.value })
                  }
                  placeholder="e.g. evil-phishing-bank.xyz"
                  className="bg-slate-950 font-mono"
                />
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-slate-300 mb-1 font-medium">Type</label>
                  <select
                    value={newIndicator.indicator_type}
                    onChange={(e: any) =>
                      setNewIndicator({ ...newIndicator, indicator_type: e.target.value })
                    }
                    className="w-full h-10 rounded-md border border-slate-700 bg-slate-950 px-3 py-1 text-xs text-slate-200 font-mono"
                  >
                    <option value="domain">Domain</option>
                    <option value="url">URL</option>
                    <option value="ip">IPv4 Address</option>
                    <option value="sha256">SHA256 Hash</option>
                  </select>
                </div>

                <div>
                  <label className="block text-slate-300 mb-1 font-medium">Severity</label>
                  <select
                    value={newIndicator.severity}
                    onChange={(e: any) =>
                      setNewIndicator({ ...newIndicator, severity: e.target.value })
                    }
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
                <label className="block text-slate-300 mb-1 font-medium">
                  Threat Category
                </label>
                <Input
                  type="text"
                  value={newIndicator.threat_category}
                  onChange={(e) =>
                    setNewIndicator({ ...newIndicator, threat_category: e.target.value })
                  }
                  placeholder="e.g. Credential Harvester, C2 Node, Spearphishing"
                  className="bg-slate-950"
                />
              </div>

              <div>
                <label className="block text-slate-300 mb-1 font-medium">
                  Tags (Press Add)
                </label>
                <div className="flex gap-2">
                  <Input
                    type="text"
                    value={tagInput}
                    onChange={(e) => setTagInput(e.target.value)}
                    onKeyDown={(e) => {
                      if (e.key === "Enter") {
                        e.preventDefault();
                        handleAddTag();
                      }
                    }}
                    placeholder="e.g. paypal, scam, office365"
                    className="bg-slate-950 font-mono text-xs"
                  />
                  <Button type="button" size="sm" variant="secondary" onClick={handleAddTag}>
                    Add
                  </Button>
                </div>
                <div className="flex flex-wrap gap-1.5 mt-2">
                  {newIndicator.tags.map((tag) => (
                    <span
                      key={tag}
                      className="inline-flex items-center gap-1 text-[11px] font-mono px-2 py-0.5 rounded bg-slate-800 text-cyan-300"
                    >
                      #{tag}
                      <button
                        type="button"
                        onClick={() => handleRemoveTag(tag)}
                        className="hover:text-red-400"
                      >
                        ×
                      </button>
                    </span>
                  ))}
                </div>
              </div>

              <div className="flex justify-end gap-2 pt-4 border-t border-slate-800">
                <Button
                  type="button"
                  variant="outline"
                  onClick={() => setIsSubmitOpen(false)}
                >
                  Cancel
                </Button>
                <Button
                  type="submit"
                  disabled={isSubmitting}
                  className="bg-cyan-600 hover:bg-cyan-700 text-white"
                >
                  {isSubmitting ? "Submitting..." : "Submit Indicator"}
                </Button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};
