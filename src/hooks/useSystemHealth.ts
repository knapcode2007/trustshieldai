import { useState, useEffect, useCallback } from "react";
import { apiClient } from "../services/apiClient";
import { HealthResponse } from "../services/types";

export interface UseSystemHealthReturn {
  health: HealthResponse | null;
  isLoading: boolean;
  error: string | null;
  lastChecked: Date | null;
  refresh: () => Promise<void>;
}

export function useSystemHealth(autoRefreshIntervalMs = 25000): UseSystemHealthReturn {
  const [health, setHealth] = useState<HealthResponse | null>(null);
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);
  const [lastChecked, setLastChecked] = useState<Date | null>(null);

  const fetchHealth = useCallback(async () => {
    try {
      setIsLoading(true);
      setError(null);
      const data = await apiClient.getHealth();
      setHealth(data);
      setLastChecked(new Date());
    } catch (err: any) {
      console.warn("[useSystemHealth] Health check error:", err);
      setError(err.message || "Failed to contact TrustShield health endpoint");
    } finally {
      setIsLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchHealth();
    if (autoRefreshIntervalMs > 0) {
      const interval = setInterval(fetchHealth, autoRefreshIntervalMs);
      return () => clearInterval(interval);
    }
  }, [fetchHealth, autoRefreshIntervalMs]);

  return {
    health,
    isLoading,
    error,
    lastChecked,
    refresh: fetchHealth,
  };
}
