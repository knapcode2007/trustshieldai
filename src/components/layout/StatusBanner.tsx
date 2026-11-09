import React from "react";
import { useSystemHealth } from "../../hooks/useSystemHealth";
import { ShieldCheck, AlertTriangle, RefreshCw, Cpu, Database, Lock, Server } from "lucide-react";
import { Badge } from "../ui/badge";

export const StatusBanner: React.FC = () => {
  const { health, isLoading, error, refresh } = useSystemHealth(20000);

  const isHealthy = health?.status === "healthy";
  const isDegraded = health?.status === "degraded" || !!error;

  return (
    <div className="w-full bg-slate-950/90 border-b border-slate-800/80 px-4 py-2 text-xs">
      <div className="max-w-7xl mx-auto flex flex-wrap items-center justify-between gap-3">
        {/* Left: Overall Health & Telemetry State */}
        <div className="flex items-center gap-2.5">
          <span className="relative flex h-2.5 w-2.5">
            <span
              className={`animate-ping absolute inline-flex h-full w-full rounded-full opacity-75 ${
                isHealthy ? "bg-emerald-400" : isDegraded ? "bg-amber-400" : "bg-red-400"
              }`}
            />
            <span
              className={`relative inline-flex rounded-full h-2.5 w-2.5 ${
                isHealthy ? "bg-emerald-500" : isDegraded ? "bg-amber-500" : "bg-red-500"
              }`}
            />
          </span>

          <div className="flex items-center gap-2">
            <span className="font-semibold text-slate-200 uppercase tracking-wider text-[11px]">
              Engine Status:
            </span>
            <span
              className={`font-mono font-medium ${
                isHealthy ? "text-emerald-400" : "text-amber-400"
              }`}
            >
              {health?.status ? health.status.toUpperCase() : isLoading ? "INITIALIZING..." : "STANDBY"}
            </span>
          </div>

          <span className="text-slate-600 hidden sm:inline">|</span>

          {/* Subsystems pills */}
          <div className="hidden md:flex items-center gap-3 text-slate-400">
            <span className="flex items-center gap-1.5" title="FastAPI Microservice Engine">
              <Server className="w-3.5 h-3.5 text-blue-400" />
              <span>FastAPI:</span>
              <span className="font-mono text-slate-200">
                {health?.subsystems?.fastapi_service?.status === "online" ? "Online" : "Ready"}
              </span>
            </span>

            <span className="flex items-center gap-1.5" title="Scikit-Learn Phishing Model">
              <Cpu className="w-3.5 h-3.5 text-cyan-400" />
              <span>ML Classifier:</span>
              <span className="font-mono text-emerald-400">Active</span>
            </span>

            <span className="flex items-center gap-1.5" title="Supabase PostgreSQL Store">
              <Database className="w-3.5 h-3.5 text-emerald-400" />
              <span>Supabase:</span>
              <span className="font-mono text-slate-200">
                {health?.subsystems?.database?.status === "online" ? "Connected" : "Standby"}
              </span>
            </span>

            <span className="flex items-center gap-1.5" title="Native TLS Socket Inspector">
              <Lock className="w-3.5 h-3.5 text-purple-400" />
              <span>TLS Socket:</span>
              <span className="font-mono text-emerald-400">Ready</span>
            </span>
          </div>
        </div>

        {/* Right: Environment & Refresh Button */}
        <div className="flex items-center gap-3 ml-auto">
          <Badge variant="outline" className="font-mono text-[10px] bg-slate-900 border-slate-700 text-slate-300">
            ENV: {health?.environment || "development"}
          </Badge>

          {health?.subsystems?.api_gateway?.latency_ms !== undefined && (
            <span className="text-slate-500 font-mono text-[11px] hidden lg:inline">
              {health.subsystems.api_gateway.latency_ms}ms
            </span>
          )}

          <button
            onClick={() => refresh()}
            disabled={isLoading}
            title="Refresh System Telemetry"
            className="p-1 rounded text-slate-400 hover:text-slate-100 hover:bg-slate-800 transition-colors disabled:opacity-50"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${isLoading ? "animate-spin text-cyan-400" : ""}`} />
          </button>
        </div>
      </div>
    </div>
  );
};
