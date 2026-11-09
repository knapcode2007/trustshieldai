/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useState, useEffect } from "react";
import { AppShell } from "./components/layout/AppShell";
import { DashboardView } from "./components/views/DashboardView";
import { ScanView } from "./components/views/ScanView";
import { ScanHistoryView } from "./components/views/ScanHistoryView";
import { ReportView } from "./components/views/ReportView";
import { TlsView } from "./components/views/TlsView";
import { ThreatIntelView } from "./components/views/ThreatIntelView";
import { CommunityReportsView } from "./components/views/CommunityReportsView";
import { WatchlistView } from "./components/views/WatchlistView";
import { SettingsView } from "./components/views/SettingsView";
import { AdminModerationView } from "./components/views/AdminModerationView";
import { ScanResponse } from "./services/types";

export default function App() {
  const [activeTab, setActiveTab] = useState<string>(() => {
    const hash = window.location.hash.replace("#", "");
    const validTabs = [
      "dashboard",
      "scan",
      "history",
      "report",
      "tls",
      "intel",
      "community",
      "watchlist",
      "settings",
      "admin",
    ];
    return validTabs.includes(hash) ? hash : "dashboard";
  });

  const [pendingScanUrl, setPendingScanUrl] = useState<string>("");
  const [currentReport, setCurrentReport] = useState<ScanResponse | null>(null);

  // Sync state to URL hash
  useEffect(() => {
    const handleHashChange = () => {
      const hash = window.location.hash.replace("#", "");
      const validTabs = [
        "dashboard",
        "scan",
        "history",
        "report",
        "tls",
        "intel",
        "community",
        "watchlist",
        "settings",
        "admin",
      ];
      if (validTabs.includes(hash)) {
        setActiveTab(hash);
      }
    };

    window.addEventListener("hashchange", handleHashChange);
    return () => window.removeEventListener("hashchange", handleHashChange);
  }, []);

  const navigateTo = (tab: string) => {
    setActiveTab(tab);
    window.location.hash = tab;
    window.scrollTo({ top: 0, behavior: "smooth" });
  };

  const handleQuickScan = (url: string) => {
    setPendingScanUrl(url);
    navigateTo("scan");
  };

  const handleViewReport = (report: ScanResponse) => {
    setCurrentReport(report);
    navigateTo("report");
  };

  const renderActiveView = () => {
    switch (activeTab) {
      case "dashboard":
        return (
          <DashboardView
            onNavigate={navigateTo}
            onRunScan={handleQuickScan}
            onViewReport={handleViewReport}
          />
        );
      case "scan":
        return (
          <ScanView
            initialUrl={pendingScanUrl}
            onClearInitialUrl={() => setPendingScanUrl("")}
            onViewReport={handleViewReport}
          />
        );
      case "history":
        return (
          <ScanHistoryView
            onNavigate={navigateTo}
            onViewReport={handleViewReport}
            onRunScan={handleQuickScan}
          />
        );
      case "report":
        return (
          <ReportView
            currentReport={currentReport}
            onNavigate={navigateTo}
            onRunScan={handleQuickScan}
            onSelectReport={(rep) => setCurrentReport(rep)}
          />
        );
      case "tls":
        return <TlsView />;
      case "intel":
        return <ThreatIntelView />;
      case "community":
        return <CommunityReportsView onRunScan={handleQuickScan} />;
      case "watchlist":
        return (
          <WatchlistView
            onRunScan={handleQuickScan}
            onViewReport={handleViewReport}
          />
        );
      case "settings":
        return <SettingsView />;
      case "admin":
        return <AdminModerationView onRunScan={handleQuickScan} />;
      default:
        return (
          <DashboardView
            onNavigate={navigateTo}
            onRunScan={handleQuickScan}
            onViewReport={handleViewReport}
          />
        );
    }
  };

  return (
    <AppShell
      activeTab={activeTab}
      onNavigate={navigateTo}
      onQuickScan={handleQuickScan}
    >
      {renderActiveView()}
    </AppShell>
  );
}
