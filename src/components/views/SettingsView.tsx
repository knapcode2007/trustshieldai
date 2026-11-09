import React, { useState, useEffect } from "react";
import {
  Settings,
  Sliders,
  Database,
  Key,
  Shield,
  Palette,
  Download,
  Trash2,
  CheckCircle2,
  AlertTriangle,
  Server,
  Globe,
} from "lucide-react";
import { Card, CardHeader, CardTitle, CardDescription, CardContent } from "../ui/card";
import { Button } from "../ui/button";
import { Input } from "../ui/input";
import { Badge } from "../ui/badge";
import { Alert, AlertTitle, AlertDescription } from "../ui/alert";
import { getSupabaseStatus } from "../../services/supabaseClient";
import { apiClient } from "../../services/apiClient";

export const SettingsView: React.FC = () => {
  const [fastApiUrl, setFastApiUrl] = useState<string>("http://127.0.0.1:8000");
  const [virusTotalKey, setVirusTotalKey] = useState<string>("");
  const [safeBrowsingKey, setSafeBrowsingKey] = useState<string>("");
  const [timeoutSec, setTimeoutSec] = useState<number>(15);
  const [highContrast, setHighContrast] = useState<boolean>(false);
  const [saveSuccess, setSaveSuccess] = useState<boolean>(false);

  const supabaseStatus = getSupabaseStatus();

  useEffect(() => {
    // Load from localStorage if present
    const savedVt = localStorage.getItem("trustshield_vt_key") || "";
    const savedGsb = localStorage.getItem("trustshield_gsb_key") || "";
    const savedTimeout = localStorage.getItem("trustshield_timeout") || "15";
    const savedHc = localStorage.getItem("trustshield_high_contrast") === "true";

    setVirusTotalKey(savedVt);
    setSafeBrowsingKey(savedGsb);
    setTimeoutSec(Number(savedTimeout) || 15);
    setHighContrast(savedHc);
  }, []);

  const handleSave = (e: React.FormEvent) => {
    e.preventDefault();
    localStorage.setItem("trustshield_vt_key", virusTotalKey.trim());
    localStorage.setItem("trustshield_gsb_key", safeBrowsingKey.trim());
    localStorage.setItem("trustshield_timeout", String(timeoutSec));
    localStorage.setItem("trustshield_high_contrast", String(highContrast));

    setSaveSuccess(true);
    setTimeout(() => setSaveSuccess(false), 3000);
  };

  const handleExportAll = async () => {
    try {
      const [scans, iocs, reports, watchlist] = await Promise.all([
        apiClient.getScansHistory(),
        apiClient.getThreatIndicators(),
        apiClient.getCommunityReports(),
        apiClient.getWatchlist(),
      ]);

      const bundle = {
        exported_at: new Date().toISOString(),
        version: "1.0.0",
        scans,
        threat_indicators: iocs,
        community_reports: reports,
        watchlist,
      };

      const jsonStr = JSON.stringify(bundle, null, 2);
      const blob = new Blob([jsonStr], { type: "application/json" });
      const url = URL.createObjectURL(blob);
      const link = document.createElement("a");
      link.href = url;
      link.download = `trustshield-full-export-${new Date().toISOString().slice(0, 10)}.json`;
      link.click();
      URL.revokeObjectURL(url);
    } catch (err) {
      console.warn("Export failed:", err);
    }
  };

  const handleResetData = async () => {
    if (window.confirm("Are you sure you want to clear all local audit history and settings?")) {
      await apiClient.clearScansHistory();
      localStorage.clear();
      window.location.reload();
    }
  };

  return (
    <div className="space-y-6 max-w-4xl mx-auto">
      {/* Header */}
      <div>
        <h2 className="text-xl font-bold text-white flex items-center gap-2">
          <Settings className="w-5 h-5 text-cyan-400" />
          <span>Platform Settings & Integrations</span>
        </h2>
        <p className="text-xs text-slate-400 mt-1">
          Configure security scanner parameters, external API keys, database synchronization, and local storage.
        </p>
      </div>

      {saveSuccess && (
        <Alert variant="success">
          <CheckCircle2 className="h-4 w-4" />
          <AlertTitle>Preferences Saved</AlertTitle>
          <AlertDescription>
            Engine parameters and integration keys were persisted successfully.
          </AlertDescription>
        </Alert>
      )}

      <form onSubmit={handleSave} className="space-y-6">
        {/* Scanner Engine Options */}
        <Card className="border-slate-800 bg-slate-900/70">
          <CardHeader className="pb-3 border-b border-slate-800/80">
            <CardTitle className="text-sm font-semibold text-white flex items-center gap-2">
              <Sliders className="w-4 h-4 text-cyan-400" />
              <span>Scanning Engine Parameters</span>
            </CardTitle>
            <CardDescription className="text-xs">
              Execution boundaries for live network probes and algorithmic evaluation.
            </CardDescription>
          </CardHeader>
          <CardContent className="p-4 space-y-4 text-xs">
            <div>
              <label className="block text-slate-300 font-medium mb-1">
                Network Request Timeout (Seconds)
              </label>
              <Input
                type="number"
                min={5}
                max={60}
                value={timeoutSec}
                onChange={(e) => setTimeoutSec(Number(e.target.value) || 15)}
                className="w-48 bg-slate-950 font-mono"
              />
              <p className="text-[11px] text-slate-500 mt-1">
                Maximum duration allowed for target TLS handshakes and HTTP header probes.
              </p>
            </div>
          </CardContent>
        </Card>

        {/* External Threat Feeds */}
        <Card className="border-slate-800 bg-slate-900/70">
          <CardHeader className="pb-3 border-b border-slate-800/80">
            <CardTitle className="text-sm font-semibold text-white flex items-center gap-2">
              <Key className="w-4 h-4 text-amber-400" />
              <span>External Threat Feed Integrations</span>
            </CardTitle>
            <CardDescription className="text-xs">
              Optional external enrichment feeds. Leave blank to utilize built-in collaborative telemetry.
            </CardDescription>
          </CardHeader>
          <CardContent className="p-4 space-y-4 text-xs">
            <div>
              <label className="block text-slate-300 font-medium mb-1">
                VirusTotal API Key (Optional)
              </label>
              <Input
                type="password"
                value={virusTotalKey}
                onChange={(e) => setVirusTotalKey(e.target.value)}
                placeholder="Enter 64-character VirusTotal v3 API key..."
                className="bg-slate-950 font-mono"
              />
              <p className="text-[11px] text-slate-500 mt-1">
                Used to enrich domain reputation across 70+ third-party antimalware scanners.
              </p>
            </div>

            <div>
              <label className="block text-slate-300 font-medium mb-1">
                Google Safe Browsing API Key (Optional)
              </label>
              <Input
                type="password"
                value={safeBrowsingKey}
                onChange={(e) => setSafeBrowsingKey(e.target.value)}
                placeholder="Enter Google Cloud Safe Browsing API key..."
                className="bg-slate-950 font-mono"
              />
            </div>
          </CardContent>
        </Card>

        {/* Database & Microservice Connection */}
        <Card className="border-slate-800 bg-slate-900/70">
          <CardHeader className="pb-3 border-b border-slate-800/80">
            <CardTitle className="text-sm font-semibold text-white flex items-center gap-2">
              <Database className="w-4 h-4 text-emerald-400" />
              <span>Backend & Database Connectivity</span>
            </CardTitle>
          </CardHeader>
          <CardContent className="p-4 space-y-3 text-xs font-mono">
            <div className="flex items-center justify-between p-3 rounded-lg border border-slate-800 bg-slate-950/70">
              <div>
                <span className="font-semibold text-white block">Supabase PostgreSQL</span>
                <span className="text-[11px] text-slate-400">
                  {supabaseStatus.url ? supabaseStatus.url : "Configurable via VITE_SUPABASE_URL"}
                </span>
              </div>
              <Badge variant={supabaseStatus.isConfigured ? "clean" : "suspicious"}>
                {supabaseStatus.isConfigured ? "CONNECTED" : "LOCAL CACHE READY"}
              </Badge>
            </div>

            <div className="flex items-center justify-between p-3 rounded-lg border border-slate-800 bg-slate-950/70">
              <div>
                <span className="font-semibold text-white block">FastAPI Microservice Binding</span>
                <span className="text-[11px] text-slate-400">{fastApiUrl}</span>
              </div>
              <Badge variant="outline">PORT 8000</Badge>
            </div>
          </CardContent>
        </Card>

        {/* Data & Storage Actions */}
        <Card className="border-slate-800 bg-slate-900/70">
          <CardHeader className="pb-3 border-b border-slate-800/80">
            <CardTitle className="text-sm font-semibold text-white flex items-center gap-2">
              <Download className="w-4 h-4 text-cyan-400" />
              <span>Data Export & Maintenance</span>
            </CardTitle>
          </CardHeader>
          <CardContent className="p-4 flex flex-wrap items-center gap-3">
            <Button
              type="button"
              variant="outline"
              onClick={handleExportAll}
              className="text-xs"
            >
              <Download className="w-3.5 h-3.5 mr-1.5" />
              <span>Export Complete Data Bundle (JSON)</span>
            </Button>

            <Button
              type="button"
              variant="destructive"
              onClick={handleResetData}
              className="text-xs"
            >
              <Trash2 className="w-3.5 h-3.5 mr-1.5" />
              <span>Reset Local Telemetry & Cache</span>
            </Button>
          </CardContent>
        </Card>

        <div className="flex justify-end gap-3 pt-2">
          <Button
            type="submit"
            className="bg-cyan-600 hover:bg-cyan-700 text-white text-xs px-6"
          >
            Save All Preferences
          </Button>
        </div>
      </form>
    </div>
  );
};
