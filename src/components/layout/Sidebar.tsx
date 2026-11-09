import React from "react";
import {
  LayoutDashboard,
  ShieldAlert,
  FileText,
  Lock,
  Database,
  Users,
  Eye,
  Settings,
  UserCheck,
  ShieldCheck,
} from "lucide-react";
import { Badge } from "../ui/badge";

interface SidebarProps {
  activeTab: string;
  onNavigate: (tab: string) => void;
  pendingReportsCount?: number;
}

export const Sidebar: React.FC<SidebarProps> = ({
  activeTab,
  onNavigate,
  pendingReportsCount = 2,
}) => {
  const sections = [
    {
      group: "Analysis & Detection",
      items: [
        {
          id: "dashboard",
          label: "Dashboard",
          icon: LayoutDashboard,
        },
        {
          id: "scan",
          label: "Scan Website",
          icon: ShieldAlert,
        },
        {
          id: "history",
          label: "Scan History",
          icon: FileText,
        },
        {
          id: "report",
          label: "Detailed Security Report",
          icon: ShieldCheck,
        },
      ],
    },
    {
      group: "Threat Intelligence",
      items: [
        {
          id: "tls",
          label: "Certificate Intelligence",
          icon: Lock,
        },
        {
          id: "intel",
          label: "Threat Intelligence",
          icon: Database,
        },
        {
          id: "community",
          label: "Community Reports",
          icon: Users,
        },
        {
          id: "watchlist",
          label: "Watchlist",
          icon: Eye,
        },
      ],
    },
    {
      group: "Operations & Admin",
      items: [
        {
          id: "settings",
          label: "Settings",
          icon: Settings,
        },
        {
          id: "admin",
          label: "Admin Moderation",
          icon: UserCheck,
          badge: pendingReportsCount > 0 ? `${pendingReportsCount}` : undefined,
          badgeVariant: "phishing" as const,
        },
      ],
    },
  ];

  return (
    <aside className="w-full md:w-64 shrink-0 border-r border-slate-800 bg-slate-950/70 p-4 flex flex-col justify-between">
      <div className="space-y-6">
        {sections.map((sec, secIdx) => (
          <div key={secIdx}>
            <h4 className="px-3 text-[11px] font-semibold uppercase tracking-wider text-slate-500 mb-2 font-mono">
              {sec.group}
            </h4>
            <nav className="space-y-1">
              {sec.items.map((item) => {
                const Icon = item.icon;
                const isActive = activeTab === item.id;
                return (
                  <button
                    key={item.id}
                    onClick={() => onNavigate(item.id)}
                    className={`w-full flex items-center justify-between px-3 py-2 rounded-lg text-xs font-medium transition-all text-left cursor-pointer ${
                      isActive
                        ? "bg-slate-900 text-cyan-300 font-semibold shadow-sm border-l-2 border-cyan-400"
                        : "text-slate-400 hover:text-slate-100 hover:bg-slate-900/60"
                    }`}
                  >
                    <div className="flex items-center gap-2.5 truncate">
                      <Icon
                        className={`w-4 h-4 shrink-0 ${
                          isActive ? "text-cyan-400" : "text-slate-500"
                        }`}
                      />
                      <span className="truncate">{item.label}</span>
                    </div>
                    {item.badge && (
                      <Badge
                        variant={item.badgeVariant}
                        className="text-[10px] px-1.5 py-0 h-4 font-mono font-normal"
                      >
                        {item.badge}
                      </Badge>
                    )}
                  </button>
                );
              })}
            </nav>
          </div>
        ))}
      </div>

      {/* Footer System Status in Sidebar */}
      <div className="pt-4 border-t border-slate-800/80 text-[11px] text-slate-500 flex flex-col gap-1 font-mono">
        <div className="flex items-center justify-between">
          <span>Security Engine</span>
          <span className="text-emerald-400 font-semibold">Active</span>
        </div>
        <div className="flex items-center justify-between">
          <span>Classifier</span>
          <span className="text-cyan-400">PhishLex v1.0</span>
        </div>
      </div>
    </aside>
  );
};
