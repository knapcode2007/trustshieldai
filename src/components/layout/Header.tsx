import React, { useState } from "react";
import { Shield, Search, Menu, X, ShieldAlert, Eye, Settings } from "lucide-react";
import { Button } from "../ui/button";

interface HeaderProps {
  activeTab: string;
  onNavigate: (tab: string) => void;
  onQuickScan: (url: string) => void;
  onToggleMobileMenu?: () => void;
  isMobileMenuOpen?: boolean;
}

export const Header: React.FC<HeaderProps> = ({
  activeTab,
  onNavigate,
  onQuickScan,
  onToggleMobileMenu,
  isMobileMenuOpen,
}) => {
  const [quickUrl, setQuickUrl] = useState("");

  const handleQuickSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!quickUrl.trim()) return;
    onQuickScan(quickUrl.trim());
    setQuickUrl("");
  };

  return (
    <header className="sticky top-0 z-40 w-full border-b border-slate-800 bg-slate-950/85 backdrop-blur-md">
      <div className="max-w-7xl mx-auto flex h-16 items-center justify-between px-4 sm:px-6">
        {/* Brand / Logo + Mobile Menu Toggle */}
        <div className="flex items-center gap-3">
          {onToggleMobileMenu && (
            <button
              onClick={onToggleMobileMenu}
              className="md:hidden p-1.5 rounded text-slate-400 hover:text-white hover:bg-slate-900 transition-colors"
              aria-label="Toggle navigation menu"
            >
              {isMobileMenuOpen ? <X className="w-5 h-5" /> : <Menu className="w-5 h-5" />}
            </button>
          )}

          <div
            onClick={() => onNavigate("dashboard")}
            className="flex items-center gap-2.5 cursor-pointer group select-none"
          >
            <div className="relative flex items-center justify-center w-9 h-9 rounded-lg bg-gradient-to-br from-blue-600 via-cyan-600 to-teal-700 text-white shadow-lg shadow-cyan-950/40 group-hover:scale-105 transition-transform">
              <Shield className="w-5 h-5 text-white" />
              <div className="absolute inset-0 rounded-lg ring-1 ring-inset ring-white/20" />
            </div>
            <div>
              <div className="flex items-center gap-1.5">
                <span className="font-bold text-base tracking-tight text-white font-mono">
                  TrustShield<span className="text-cyan-400">.AI</span>
                </span>
                <span className="rounded bg-cyan-950/80 border border-cyan-800/60 px-1 py-0.2 text-[9px] font-mono text-cyan-300 font-semibold uppercase">
                  v1.0
                </span>
              </div>
              <p className="text-[10px] text-slate-400 hidden sm:block">
                Phishing Detection & Threat Intelligence Platform
              </p>
            </div>
          </div>
        </div>

        {/* Global Quick Target Analysis Input */}
        <form
          onSubmit={handleQuickSubmit}
          className="hidden md:flex items-center flex-1 max-w-md mx-6"
        >
          <div className="relative w-full">
            <Search className="absolute left-3 top-2.5 h-4 w-4 text-slate-500" />
            <input
              type="text"
              value={quickUrl}
              onChange={(e) => setQuickUrl(e.target.value)}
              placeholder="Quick target analysis (e.g. secure-login.bank.com)..."
              className="w-full rounded-md border border-slate-800 bg-slate-900/90 pl-9 pr-24 py-1.5 text-xs text-slate-200 placeholder:text-slate-500 focus:outline-none focus:ring-1 focus:ring-cyan-500 focus:border-cyan-500 font-mono"
            />
            <Button
              type="submit"
              size="sm"
              className="absolute right-1 top-1 h-7 text-[11px] px-2.5 bg-cyan-600 hover:bg-cyan-700 text-white font-medium"
            >
              Analyze
            </Button>
          </div>
        </form>

        {/* Action Controls */}
        <div className="flex items-center gap-2">
          <Button
            variant={activeTab === "scan" ? "default" : "outline"}
            size="sm"
            onClick={() => onNavigate("scan")}
            className="text-xs items-center gap-1.5"
          >
            <ShieldAlert className="w-3.5 h-3.5 text-cyan-400" />
            <span className="hidden sm:inline">Scan Website</span>
          </Button>

          <Button
            variant={activeTab === "watchlist" ? "secondary" : "ghost"}
            size="sm"
            onClick={() => onNavigate("watchlist")}
            className="text-xs items-center gap-1.5 text-slate-300 hover:text-white"
          >
            <Eye className="w-3.5 h-3.5 text-purple-400" />
            <span className="hidden md:inline">Watchlist</span>
          </Button>

          <Button
            variant={activeTab === "settings" ? "secondary" : "ghost"}
            size="sm"
            onClick={() => onNavigate("settings")}
            title="Settings"
            className="text-xs px-2 text-slate-300 hover:text-white"
          >
            <Settings className="w-4 h-4" />
          </Button>
        </div>
      </div>
    </header>
  );
};
