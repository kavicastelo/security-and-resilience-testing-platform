import React, { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import {
  ShieldAlert,
  ShieldCheck,
  Plus,
  Play,
  Lock,
  Globe,
  Radio,
} from 'lucide-react';

interface TargetScope {
  allowedHosts: string[];
  allowedPorts: number[];
  excludedPaths: string[];
  testing: {
    activeScanning: boolean;
    loadTesting: boolean;
    chaosTesting: boolean;
  };
  limits: {
    maxRps: number;
    maxConcurrency: number;
    maxDuration: string;
  };
}

interface Target {
  id: string;
  projectId: string;
  name: string;
  baseUrl: string;
  scope: TargetScope;
  createdAt: string;
}

interface ScopeValidationResponse {
  valid: boolean;
  violations: string[];
  matchedHost?: string;
  normalizedUrl?: string;
}

export const TargetsView: React.FC = () => {
  const queryClient = useQueryClient();
  const apiUrl = import.meta.env.VITE_API_URL || 'http://localhost:4000';

  // Target list query
  const { data: targets = [], isLoading } = useQuery<Target[]>({
    queryKey: ['targets'],
    queryFn: async () => {
      const res = await fetch(`${apiUrl}/api/v1/targets`);
      if (!res.ok) throw new Error('Failed to fetch targets');
      const json = await res.json();
      return json.data || [];
    },
  });

  // Scope validation playground state
  const [selectedTargetId, setSelectedTargetId] = useState<string>('');
  const [testUrl, setTestUrl] = useState<string>('https://staging.example.com/api/v1/users');
  const [testCapability, setTestCapability] = useState<'passive' | 'activeScanning' | 'loadTesting'>('passive');
  const [validationResult, setValidationResult] = useState<ScopeValidationResponse | null>(null);

  // New target modal state
  const [isCreating, setIsCreating] = useState(false);
  const [newTargetName, setNewTargetName] = useState('');
  const [newTargetUrl, setNewTargetUrl] = useState('');
  const [newTargetHosts, setNewTargetHosts] = useState('');
  const [newTargetPorts, setNewTargetPorts] = useState('80, 443');
  const [activeScanningOpt, setActiveScanningOpt] = useState(false);
  const [loadTestingOpt, setLoadTestingOpt] = useState(false);
  const [creationError, setCreationError] = useState<string | null>(null);

  // Scope validation mutation
  const validateMutation = useMutation({
    mutationFn: async () => {
      if (!selectedTargetId) throw new Error('Select a target');
      const res = await fetch(`${apiUrl}/api/v1/targets/${selectedTargetId}/validate-scope`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          candidateUrl: testUrl,
          capability: testCapability === 'passive' ? undefined : testCapability,
        }),
      });
      const json = await res.json();
      if (!res.ok) throw new Error(json.error?.message || 'Validation request failed');
      return json.data as ScopeValidationResponse;
    },
    onSuccess: (data) => {
      setValidationResult(data);
    },
    onError: (err: unknown) => {
      const msg = err instanceof Error ? err.message : String(err);
      setValidationResult({
        valid: false,
        violations: [msg],
      });
    },
  });

  // Target creation mutation
  const createTargetMutation = useMutation({
    mutationFn: async () => {
      setCreationError(null);
      // Fetch or create default project first
      const projRes = await fetch(`${apiUrl}/api/v1/projects`);
      const projJson = await projRes.json();
      let projectId = projJson.data?.[0]?.id;

      if (!projectId) {
        const createProj = await fetch(`${apiUrl}/api/v1/projects`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ name: 'Default Enterprise Project' }),
        });
        const createdProjJson = await createProj.json();
        projectId = createdProjJson.data.id;
      }

      const hosts = newTargetHosts.split(',').map((h) => h.trim());
      const ports = newTargetPorts.split(',').map((p) => parseInt(p.trim(), 10));

      const res = await fetch(`${apiUrl}/api/v1/projects/${projectId}/targets`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          name: newTargetName,
          baseUrl: newTargetUrl,
          allowedHosts: hosts,
          allowedPorts: ports,
          testing: {
            activeScanning: activeScanningOpt,
            loadTesting: loadTestingOpt,
            chaosTesting: false,
          },
        }),
      });

      const json = await res.json();
      if (!res.ok) throw new Error(json.error?.message || 'Failed to create target');
      return json.data;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['targets'] });
      setIsCreating(false);
      setNewTargetName('');
      setNewTargetUrl('');
      setNewTargetHosts('');
    },
    onError: (err: unknown) => {
      const msg = err instanceof Error ? err.message : String(err);
      setCreationError(msg);
    },
  });

  return (
    <div className="space-y-8">
      {/* Header section */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <h2 className="text-xl font-bold tracking-tight text-foreground flex items-center space-x-2">
            <Lock className="w-5 h-5 text-blue-500" />
            <span>Target Scopes & Security Boundaries</span>
          </h2>
          <p className="text-sm text-muted-foreground">
            Defensive authorization boundaries: only registered hosts, ports, and permitted capabilities are testable.
          </p>
        </div>
        <button
          onClick={() => setIsCreating(true)}
          className="inline-flex items-center space-x-2 px-3.5 py-2 rounded-lg bg-primary hover:bg-primary/90 text-white text-xs font-semibold shadow-md transition-colors"
        >
          <Plus className="w-4 h-4" />
          <span>Register New Target</span>
        </button>
      </div>

      {/* Target Registration Form Modal */}
      {isCreating && (
        <div className="p-6 rounded-xl border border-primary/30 bg-card/90 space-y-4">
          <div className="flex items-center justify-between">
            <h3 className="text-sm font-semibold text-foreground">Register Authorized Target</h3>
            <button
              onClick={() => setIsCreating(false)}
              className="text-xs text-muted-foreground hover:text-foreground"
            >
              Cancel
            </button>
          </div>

          {creationError && (
            <div className="p-3 text-xs bg-red-950/40 border border-red-800/40 text-red-400 rounded-lg">
              {creationError}
            </div>
          )}

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
            <div>
              <label className="block text-muted-foreground mb-1">Target Name</label>
              <input
                type="text"
                placeholder="e.g. Staging Customer API"
                value={newTargetName}
                onChange={(e) => setNewTargetName(e.target.value)}
                className="w-full px-3 py-2 rounded-md bg-accent border border-border text-foreground focus:outline-none focus:ring-1 focus:ring-primary"
              />
            </div>
            <div>
              <label className="block text-muted-foreground mb-1">Base URL</label>
              <input
                type="text"
                placeholder="https://staging.example.com"
                value={newTargetUrl}
                onChange={(e) => setNewTargetUrl(e.target.value)}
                className="w-full px-3 py-2 rounded-md bg-accent border border-border text-foreground focus:outline-none focus:ring-1 focus:ring-primary"
              />
            </div>
            <div>
              <label className="block text-muted-foreground mb-1">Allowed Hosts (comma-separated)</label>
              <input
                type="text"
                placeholder="staging.example.com, api-staging.example.com"
                value={newTargetHosts}
                onChange={(e) => setNewTargetHosts(e.target.value)}
                className="w-full px-3 py-2 rounded-md bg-accent border border-border text-foreground focus:outline-none focus:ring-1 focus:ring-primary"
              />
            </div>
            <div>
              <label className="block text-muted-foreground mb-1">Allowed Ports</label>
              <input
                type="text"
                value={newTargetPorts}
                onChange={(e) => setNewTargetPorts(e.target.value)}
                className="w-full px-3 py-2 rounded-md bg-accent border border-border text-foreground focus:outline-none focus:ring-1 focus:ring-primary"
              />
            </div>
          </div>

          <div className="flex items-center space-x-6 pt-2 text-xs">
            <label className="flex items-center space-x-2 cursor-pointer">
              <input
                type="checkbox"
                checked={activeScanningOpt}
                onChange={(e) => setActiveScanningOpt(e.target.checked)}
                className="rounded border-border text-primary"
              />
              <span className="text-foreground">Authorize Active Scanning</span>
            </label>
            <label className="flex items-center space-x-2 cursor-pointer">
              <input
                type="checkbox"
                checked={loadTestingOpt}
                onChange={(e) => setLoadTestingOpt(e.target.checked)}
                className="rounded border-border text-primary"
              />
              <span className="text-foreground">Authorize Load/Resilience Testing</span>
            </label>
          </div>

          <div className="flex justify-end space-x-3 pt-2">
            <button
              onClick={() => setIsCreating(false)}
              className="px-3 py-1.5 rounded text-xs text-muted-foreground hover:bg-accent"
            >
              Cancel
            </button>
            <button
              onClick={() => createTargetMutation.mutate()}
              disabled={createTargetMutation.isPending || !newTargetName || !newTargetUrl || !newTargetHosts}
              className="px-4 py-1.5 rounded text-xs bg-primary text-white font-medium hover:bg-primary/90 disabled:opacity-50"
            >
              {createTargetMutation.isPending ? 'Saving...' : 'Register Target'}
            </button>
          </div>
        </div>
      )}

      {/* Target Scope Cards */}
      <div className="space-y-4">
        <h3 className="text-sm font-semibold uppercase tracking-wider text-muted-foreground">
          Active Registered Targets ({targets.length})
        </h3>

        {isLoading ? (
          <div className="p-8 text-center text-xs text-muted-foreground">Loading targets...</div>
        ) : targets.length === 0 ? (
          <div className="p-8 border border-dashed border-border rounded-xl text-center text-xs text-muted-foreground space-y-2">
            <p>No target scopes registered yet.</p>
            <p>Register your first target above or run: <code>security-lab target create</code></p>
          </div>
        ) : (
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
            {targets.map((target) => (
              <div
                key={target.id}
                className="p-5 rounded-xl border border-border bg-card space-y-4 hover:border-primary/40 transition-colors"
              >
                <div className="flex items-start justify-between">
                  <div className="space-y-1">
                    <div className="flex items-center space-x-2">
                      <h4 className="font-semibold text-foreground text-sm">{target.name}</h4>
                      <span className="text-[10px] font-mono bg-accent px-1.5 py-0.5 rounded text-muted-foreground">
                        {target.id.slice(0, 8)}...
                      </span>
                    </div>
                    <div className="flex items-center space-x-1.5 text-xs text-primary font-mono">
                      <Globe className="w-3.5 h-3.5" />
                      <span>{target.baseUrl}</span>
                    </div>
                  </div>
                  <button
                    onClick={() => {
                      setSelectedTargetId(target.id);
                      setTestUrl(`${target.baseUrl}/api/v1/health`);
                    }}
                    className="text-[11px] font-medium text-blue-400 hover:text-blue-300 bg-blue-950/30 border border-blue-800/40 px-2.5 py-1 rounded-md"
                  >
                    Test Scope
                  </button>
                </div>

                {/* Boundaries */}
                <div className="space-y-2 text-xs">
                  <div>
                    <span className="text-muted-foreground block text-[11px] uppercase tracking-wider mb-1">
                      Allowed Hosts:
                    </span>
                    <div className="flex flex-wrap gap-1.5">
                      {target.scope.allowedHosts.map((h) => (
                        <span
                          key={h}
                          className="font-mono text-[11px] bg-accent/80 px-2 py-0.5 rounded text-foreground border border-border"
                        >
                          {h}
                        </span>
                      ))}
                    </div>
                  </div>

                  <div className="flex items-center space-x-4 pt-1">
                    <div>
                      <span className="text-muted-foreground text-[11px]">Ports: </span>
                      <span className="font-mono text-foreground">{target.scope.allowedPorts.join(', ')}</span>
                    </div>
                    <div>
                      <span className="text-muted-foreground text-[11px]">Max RPS: </span>
                      <span className="font-mono text-foreground">{target.scope.limits.maxRps}</span>
                    </div>
                    <div>
                      <span className="text-muted-foreground text-[11px]">Max Concurrency: </span>
                      <span className="font-mono text-foreground">{target.scope.limits.maxConcurrency}</span>
                    </div>
                  </div>
                </div>

                {/* Capability Badges */}
                <div className="flex items-center space-x-2 pt-2 border-t border-border/40 text-[11px]">
                  <span className="text-muted-foreground">Capabilities:</span>
                  <span
                    className={`px-2 py-0.5 rounded-full font-medium ${
                      target.scope.testing.activeScanning
                        ? 'bg-emerald-950/40 text-emerald-400 border border-emerald-800/40'
                        : 'bg-muted text-muted-foreground'
                    }`}
                  >
                    Active Scanning: {target.scope.testing.activeScanning ? 'ON' : 'OFF'}
                  </span>
                  <span
                    className={`px-2 py-0.5 rounded-full font-medium ${
                      target.scope.testing.loadTesting
                        ? 'bg-indigo-950/40 text-indigo-400 border border-indigo-800/40'
                        : 'bg-muted text-muted-foreground'
                    }`}
                  >
                    Load Testing: {target.scope.testing.loadTesting ? 'ON' : 'OFF'}
                  </span>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Interactive Scope Boundary Playground */}
      <div className="p-6 rounded-xl border border-blue-900/40 bg-card/60 space-y-4">
        <div className="flex items-center space-x-2 text-foreground font-semibold text-sm">
          <Radio className="w-4 h-4 text-blue-400" />
          <span>Security Scope Validator Playground</span>
        </div>
        <p className="text-xs text-muted-foreground">
          Simulate a test request to verify whether candidate endpoints pass defensive scope allowlists,
          SSRF defenses, and capability authorizations before dispatch.
        </p>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-xs">
          <div>
            <label className="block text-muted-foreground mb-1">Target</label>
            <select
              value={selectedTargetId}
              onChange={(e) => setSelectedTargetId(e.target.value)}
              className="w-full px-3 py-2 rounded-md bg-accent border border-border text-foreground"
            >
              <option value="">Select target...</option>
              {targets.map((t) => (
                <option key={t.id} value={t.id}>
                  {t.name} ({t.baseUrl})
                </option>
              ))}
            </select>
          </div>

          <div className="md:col-span-2">
            <label className="block text-muted-foreground mb-1">Candidate Execution URL</label>
            <input
              type="text"
              value={testUrl}
              onChange={(e) => setTestUrl(e.target.value)}
              placeholder="https://staging.example.com/api/v1/health"
              className="w-full px-3 py-2 rounded-md bg-accent border border-border text-foreground font-mono"
            />
          </div>
        </div>

        <div className="flex flex-wrap items-center justify-between gap-4 pt-2">
          <div className="flex items-center space-x-4 text-xs">
            <span className="text-muted-foreground">Test Capability Mode:</span>
            <label className="flex items-center space-x-1.5 cursor-pointer">
              <input
                type="radio"
                name="cap"
                checked={testCapability === 'passive'}
                onChange={() => setTestCapability('passive')}
              />
              <span>Passive Only</span>
            </label>
            <label className="flex items-center space-x-1.5 cursor-pointer">
              <input
                type="radio"
                name="cap"
                checked={testCapability === 'activeScanning'}
                onChange={() => setTestCapability('activeScanning')}
              />
              <span>Active Fuzzing / Probing</span>
            </label>
            <label className="flex items-center space-x-1.5 cursor-pointer">
              <input
                type="radio"
                name="cap"
                checked={testCapability === 'loadTesting'}
                onChange={() => setTestCapability('loadTesting')}
              />
              <span>Stress / Load</span>
            </label>
          </div>

          <button
            onClick={() => validateMutation.mutate()}
            disabled={!selectedTargetId || !testUrl || validateMutation.isPending}
            className="inline-flex items-center space-x-2 px-4 py-2 rounded-lg bg-blue-600 hover:bg-blue-500 disabled:opacity-50 text-white font-medium text-xs shadow-md transition-colors"
          >
            <Play className="w-3.5 h-3.5" />
            <span>{validateMutation.isPending ? 'Evaluating...' : 'Evaluate Boundary'}</span>
          </button>
        </div>

        {/* Validation Verdict Display */}
        {validationResult && (
          <div
            className={`p-4 rounded-xl border mt-4 text-xs space-y-2 ${
              validationResult.valid
                ? 'bg-emerald-950/40 border-emerald-800/50 text-emerald-300'
                : 'bg-red-950/40 border-red-800/50 text-red-300'
            }`}
          >
            <div className="flex items-center space-x-2 font-semibold">
              {validationResult.valid ? (
                <>
                  <ShieldCheck className="w-4 h-4 text-emerald-400" />
                  <span>BOUNDARY CHECK PASSED: Execution Authorized</span>
                </>
              ) : (
                <>
                  <ShieldAlert className="w-4 h-4 text-red-400" />
                  <span>BOUNDARY VIOLATION: Execution Blocked</span>
                </>
              )}
            </div>

            {validationResult.valid ? (
              <p className="text-emerald-300/80 leading-relaxed">
                Candidate URL is within scope allowed hosts ({validationResult.matchedHost}) and complies with target
                safety constraints.
              </p>
            ) : (
              <div className="space-y-1">
                <p className="font-medium text-red-200">Defensive boundary violations detected:</p>
                <ul className="list-disc list-inside space-y-0.5 text-red-300/90 font-mono text-[11px]">
                  {validationResult.violations.map((violation, i) => (
                    <li key={i}>{violation}</li>
                  ))}
                </ul>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
};
