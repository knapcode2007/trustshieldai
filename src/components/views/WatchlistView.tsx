import React, { useState, useEffect } from "react";
import {
  Eye,
  Plus,
  Search,
  ShieldCheck,
  ShieldAlert,
  AlertTriangle,
  RefreshCw,
  Trash2,
  ArrowRight,
  Clock,
  ExternalLink,
  X,
  Bell,
} from "lucide-react";
import { Card, CardHeader, CardTitle, CardDescription, CardContent } from "../ui/card";
import { Button } from "../ui/button";
import { Input } from "../ui/input";
import { Badge } from "../ui/badge";
import { Alert, AlertTitle, AlertDescription } from "../ui/alert";
import { apiClient } from "../../services/apiClient";
import { WatchlistItem, WatchlistItemCreate, ScanResponse } from "../../services/types";

interface WatchlistViewProps {
  onRunScan: (url: string) => void;
  onViewReport: (scan: ScanResponse) => void;
}

export const WatchlistView: React.FC<WatchlistViewProps> = ({ onRunScan, onViewReport }) => {
  const [items, setItems] = useState<WatchlistItem[]>([]);
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [scanningId, setScanningId] = useState<string | null>(null);

  // Add Item Modal
  const [isModalOpen, setIsModalOpen] = useState<boolean>(false);
  const [isSubmitting, setIsSubmitting] = useState<boolean>(false);
  const [newItem, setNewItem] = useState<WatchlistItemCreate>({
    target: "",
    label: "",
    alert_threshold: 40,
  });

  const fetchWatchlist = async () => {
    setIsLoading(true);
    try {
      const data = await apiClient.getWatchlist();
      setItems(data || []);
    } catch (err) {
      console.warn("Error loading watchlist:", err);
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    fetchWatchlist();
  }, []);

  const handleScanItem = async (item: WatchlistItem) => {
    setScanningId(item.id);
    try {
      const scanResult = await apiClient.scanUrl(item.target);
      // Update local item stats
      setItems(
        items.map((it) =>
          it.id === item.id
            ? {
                ...it,
                last_risk_score: scanResult.risk_score,
                last_verdict: scanResult.verdict,
                last_scanned_at: scanResult.created_at,
              }
            : it
        )
      );
    } catch (err) {
      console.warn("Scan failed for watchlist item:", err);
    } finally {
      setScanningId(null);
    }
  };

  const handleRemove = async (id: string) => {
    try {
      await apiClient.removeFromWatchlist(id);
      setItems(items.filter((it) => it.id !== id));
    } catch (err) {
      console.warn("Error removing watchlist item:", err);
    }
  };

  const handleAddSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newItem.target.trim()) return;

    setIsSubmitting(true);
    try {
      const created = await apiClient.addToWatchlist(newItem);
      setItems([created, ...items]);
      setIsModalOpen(false);
      setNewItem({ target: "", label: "", alert_threshold: 40 });
    } catch (err) {
      console.warn("Error adding to watchlist:", err);
    } finally {
      setIsSubmitting(false);
    }
  };

  const getVerdictBadge = (verdict?: string) => {
    if (!verdict) return <Badge variant="outline">NOT AUDITED</Badge>;
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
            <Eye className="w-5 h-5 text-purple-400" />
            <span>Monitored Target Watchlist</span>
          </h2>
          <p className="text-xs text-slate-400 mt-1">
            Continuous posture tracking for brand portals, partner domains, and high-value single sign-on endpoints.
          </p>
        </div>

        <Button
          onClick={() => setIsModalOpen(true)}
          className="bg-purple-600 hover:bg-purple-700 text-white font-medium text-xs flex items-center gap-1.5"
        >
          <Plus className="w-4 h-4" />
          <span>Add Target to Watchlist</span>
        </Button>
      </div>

      {/* Main Table / Empty State */}
      <Card className="border-slate-800 bg-slate-900/80 shadow-xl overflow-hidden">
        <CardHeader className="py-3 px-4 border-b border-slate-800/80 flex flex-row items-center justify-between">
          <span className="text-xs font-mono uppercase text-slate-400">
            Active Watchlist Targets ({items.length})
          </span>
          <button
            onClick={fetchWatchlist}
            className="text-slate-400 hover:text-cyan-400 text-xs flex items-center gap-1 font-mono transition-colors"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${isLoading ? "animate-spin" : ""}`} />
            <span>Reload</span>
          </button>
        </CardHeader>
        <CardContent className="p-0">
          {isLoading ? (
            <div className="p-12 text-center text-xs text-slate-400 font-mono">
              <RefreshCw className="w-6 h-6 mx-auto mb-2 animate-spin text-purple-400" />
              Loading watchlist targets...
            </div>
          ) : items.length === 0 ? (
            <div className="p-12 text-center text-xs text-slate-400">
              <Eye className="w-8 h-8 mx-auto mb-3 text-slate-600" />
              <p className="font-semibold text-slate-300">Watchlist is Empty</p>
              <p className="mt-1 text-slate-500">
                Add corporate login pages or partner domains to track their risk posture and certificate health.
              </p>
              <div className="mt-4">
                <Button
                  size="sm"
                  variant="outline"
                  onClick={() => setIsModalOpen(true)}
                  className="text-xs"
                >
                  Add Your First Monitored Domain
                </Button>
              </div>
            </div>
          ) : (
            <div className="divide-y divide-slate-800/80">
              {items.map((item) => (
                <div
                  key={item.id}
                  className="p-5 hover:bg-slate-850/50 transition-colors flex flex-col md:flex-row items-start md:items-center justify-between gap-4"
                >
                  <div className="space-y-1.5 min-w-0 flex-1">
                    <div className="flex flex-wrap items-center gap-2.5">
                      <span className="font-mono text-sm font-semibold text-white truncate">
                        {item.domain}
                      </span>
                      {getVerdictBadge(item.last_verdict)}
                      <span className="text-[11px] font-mono px-2 py-0.5 rounded bg-slate-800 text-slate-300 border border-slate-700">
                        {item.label}
                      </span>
                      {item.last_risk_score !== undefined && item.last_risk_score >= item.alert_threshold && (
                        <span className="inline-flex items-center gap-1 text-[11px] font-mono text-red-400 bg-red-950/60 px-2 py-0.5 rounded border border-red-800/60 font-bold">
                          <AlertTriangle className="w-3 h-3" />
                          <span>EXCEEDS THRESHOLD ({item.alert_threshold})</span>
                        </span>
                      )}
                    </div>

                    <p className="text-xs text-slate-400 font-mono truncate max-w-lg">
                      {item.target}
                    </p>

                    <div className="flex flex-wrap items-center gap-4 text-[11px] font-mono text-slate-500 pt-0.5">
                      <span>Added: {new Date(item.added_at).toLocaleDateString()}</span>
                      <span>·</span>
                      <span>
                        Last Scan:{" "}
                        {item.last_scanned_at ? (
                          new Date(item.last_scanned_at).toLocaleString()
                        ) : (
                          <span className="text-slate-500">Pending initial audit</span>
                        )}
                      </span>
                      <span>·</span>
                      <span>Alert Threshold: Risk &gt; {item.alert_threshold}</span>
                    </div>
                  </div>

                  <div className="flex items-center gap-4 shrink-0">
                    {item.last_risk_score !== undefined && (
                      <div className="text-right">
                        <span className="text-[10px] text-slate-400 font-mono block">Risk</span>
                        <span
                          className={`text-base font-bold font-mono ${
                            item.last_risk_score >= 70
                              ? "text-red-400"
                              : item.last_risk_score >= 35
                              ? "text-amber-400"
                              : "text-emerald-400"
                          }`}
                        >
                          {item.last_risk_score}/100
                        </span>
                      </div>
                    )}

                    <div className="flex items-center gap-2">
                      <Button
                        size="sm"
                        variant="default"
                        disabled={scanningId === item.id}
                        onClick={() => handleScanItem(item)}
                        className="text-xs h-8 bg-cyan-600 hover:bg-cyan-700 text-white flex items-center gap-1"
                      >
                        <RefreshCw className={`w-3.5 h-3.5 ${scanningId === item.id ? "animate-spin" : ""}`} />
                        <span>{scanningId === item.id ? "Scanning..." : "Audit Now"}</span>
                      </Button>

                      <Button
                        size="sm"
                        variant="ghost"
                        onClick={() => handleRemove(item.id)}
                        title="Remove from watchlist"
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

      {/* Add Target Modal */}
      {isModalOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm">
          <div className="relative w-full max-w-md rounded-xl border border-slate-800 bg-slate-900 p-6 shadow-2xl space-y-4">
            <div className="flex items-center justify-between pb-3 border-b border-slate-800">
              <h3 className="text-base font-semibold text-white flex items-center gap-2">
                <Eye className="w-5 h-5 text-purple-400" />
                <span>Add Target to Watchlist</span>
              </h3>
              <button
                onClick={() => setIsModalOpen(false)}
                className="text-slate-400 hover:text-white"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            <form onSubmit={handleAddSubmit} className="space-y-3 text-xs">
              <div>
                <label className="block text-slate-300 mb-1 font-medium">Destination URL or Domain *</label>
                <Input
                  type="text"
                  required
                  value={newItem.target}
                  onChange={(e) => setNewItem({ ...newItem, target: e.target.value })}
                  placeholder="https://auth.company.com or partner-gateway.net"
                  className="bg-slate-950 font-mono"
                />
              </div>

              <div>
                <label className="block text-slate-300 mb-1 font-medium">Classification Label</label>
                <Input
                  type="text"
                  value={newItem.label}
                  onChange={(e) => setNewItem({ ...newItem, label: e.target.value })}
                  placeholder="e.g. SSO IdP, Vendor Portal, Egress API"
                  className="bg-slate-950"
                />
              </div>

              <div>
                <label className="block text-slate-300 mb-1 font-medium">
                  Alert Risk Threshold (0–100)
                </label>
                <Input
                  type="number"
                  min={1}
                  max={99}
                  value={newItem.alert_threshold}
                  onChange={(e) =>
                    setNewItem({ ...newItem, alert_threshold: Number(e.target.value) || 40 })
                  }
                  className="bg-slate-950 font-mono"
                />
                <p className="text-[11px] text-slate-500 mt-1">
                  Alert triggers when an audit score exceeds this value. Default: 40.
                </p>
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
                  className="bg-purple-600 hover:bg-purple-700 text-white"
                >
                  {isSubmitting ? "Adding..." : "Add Target"}
                </Button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};
