import React, { useState } from "react";
import { Header } from "./Header";
import { StatusBanner } from "./StatusBanner";
import { Sidebar } from "./Sidebar";

interface AppShellProps {
  activeTab: string;
  onNavigate: (tab: string) => void;
  onQuickScan: (url: string) => void;
  children: React.ReactNode;
}

export const AppShell: React.FC<AppShellProps> = ({
  activeTab,
  onNavigate,
  onQuickScan,
  children,
}) => {
  const [isMobileMenuOpen, setIsMobileMenuOpen] = useState(false);

  const handleMobileNavigate = (tab: string) => {
    setIsMobileMenuOpen(false);
    onNavigate(tab);
  };

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col antialiased selection:bg-cyan-500/30 selection:text-cyan-200">
      {/* Top Header */}
      <Header
        activeTab={activeTab}
        onNavigate={onNavigate}
        onQuickScan={onQuickScan}
        isMobileMenuOpen={isMobileMenuOpen}
        onToggleMobileMenu={() => setIsMobileMenuOpen(!isMobileMenuOpen)}
      />

      {/* Real-time Subsystem Status & Environment Banner */}
      <StatusBanner />

      {/* Mobile Drawer Backdrop */}
      {isMobileMenuOpen && (
        <div
          className="fixed inset-0 z-40 bg-black/80 backdrop-blur-sm md:hidden"
          onClick={() => setIsMobileMenuOpen(false)}
        />
      )}

      {/* Mobile Drawer Content */}
      {isMobileMenuOpen && (
        <div className="fixed inset-y-0 left-0 z-50 w-72 bg-slate-950 border-r border-slate-800 p-4 shadow-2xl md:hidden overflow-y-auto">
          <Sidebar activeTab={activeTab} onNavigate={handleMobileNavigate} />
        </div>
      )}

      {/* Main Body Area: Sidebar + Active View */}
      <div className="flex-1 flex max-w-7xl w-full mx-auto">
        <div className="hidden md:block">
          <Sidebar activeTab={activeTab} onNavigate={onNavigate} />
        </div>

        <main className="flex-1 p-4 sm:p-6 lg:p-8 overflow-y-auto">
          {children}
        </main>
      </div>

      {/* Global Security Footer */}
      <footer className="border-t border-slate-900 bg-slate-950/90 py-3.5 px-6 text-center text-xs text-slate-400 print:hidden">
        <div className="max-w-7xl mx-auto flex flex-col sm:flex-row items-center justify-between gap-2">
          <span>TrustShield AI — Phishing Detection & Threat Intelligence Platform</span>
          <span className="font-mono text-slate-500 text-[11px]">
            FastAPI · scikit-learn · Supabase PostgreSQL · React 19
          </span>
        </div>
      </footer>
    </div>
  );
};
