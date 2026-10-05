import React from 'react';
import { useQuery } from '@tanstack/react-query';
import { Activity, CheckCircle2, AlertTriangle, XCircle } from 'lucide-react';

interface HealthData {
  status: 'ok' | 'degraded' | 'error';
  version: string;
  uptime: number;
  services: {
    database: 'up' | 'down' | 'degraded';
  };
}

export const HealthBadge: React.FC = () => {
  const { data, status } = useQuery<HealthData>({
    queryKey: ['controller-health'],
    queryFn: async () => {
      const apiUrl = import.meta.env.VITE_API_URL || 'http://localhost:4000';
      const res = await fetch(`${apiUrl}/health`);
      if (!res.ok) throw new Error('Health check failed');
      return res.json();
    },
    refetchInterval: 10000,
    retry: 1,
  });

  if (status === 'pending') {
    return (
      <div className="flex items-center space-x-2 text-xs text-muted-foreground px-3 py-1.5 rounded-full bg-accent border border-border">
        <Activity className="w-3.5 h-3.5 animate-spin text-blue-400" />
        <span>Connecting controller...</span>
      </div>
    );
  }

  if (status === 'error' || !data) {
    return (
      <div className="flex items-center space-x-2 text-xs text-red-400 px-3 py-1.5 rounded-full bg-red-950/40 border border-red-800/50">
        <XCircle className="w-3.5 h-3.5" />
        <span>Controller Offline</span>
      </div>
    );
  }

  const isHealthy = data.status === 'ok';

  return (
    <div
      className={`flex items-center space-x-2 text-xs px-3 py-1.5 rounded-full border ${
        isHealthy
          ? 'text-emerald-400 bg-emerald-950/40 border-emerald-800/50'
          : 'text-amber-400 bg-amber-950/40 border-amber-800/50'
      }`}
    >
      {isHealthy ? (
        <CheckCircle2 className="w-3.5 h-3.5" />
      ) : (
        <AlertTriangle className="w-3.5 h-3.5" />
      )}
      <span>Controller: {data.status}</span>
      <span className="text-muted-foreground font-mono text-[10px]">v{data.version}</span>
    </div>
  );
};
