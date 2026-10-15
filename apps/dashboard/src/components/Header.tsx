import React from 'react';
import { useQuery } from '@tanstack/react-query';
import {
  Shield,
  Terminal,
  Menu,
  X,
  Key,
  Search,
  Zap,
  Sparkles,
} from 'lucide-react';
import { HealthBadge } from './HealthBadge.js';
import { WorkspaceSwitcher } from './WorkspaceSwitcher.js';
import { useAppStore } from '../store/useAppStore.js';
import { authFetch } from '../api/client.js';

export const Header: React.FC = () => {
  const {
    isMobileMenuOpen,
    setIsMobileMenuOpen,
    setIsAuthModalOpen,
    setIsCommandPaletteOpen,
    apiKey,
    setActiveTab,
    currentWorkspaceId,
  } = useAppStore();

  // Query active running tests for the persistent telemetry strip
  const { data: activeRunsCount = 0 } = useQuery<number>({
    queryKey: ['active-runs-count'],
    queryFn: async () => {
      try {
        const res = await authFetch('/api/v1/test-runs?limit=50');
        if (!res.ok) return 0;
        const json = await res.json();
        const runs = Array.isArray(json.data) ? json.data : [];
        return runs.filter((r: { status: string }) => r.status === 'running').length;
      } catch {
        return 0;
      }
    },
    refetchInterval: 5000,
  });

  // Query to detect if workspace contains demo data
  const { data: hasDemoProjects = false } = useQuery<boolean>({
    queryKey: ['has-demo-projects', currentWorkspaceId],
    queryFn: async () => {
      try {
        const res = await authFetch('/api/v1/projects');
        if (!res.ok) return false;
        const json = await res.json();
        const projects = Array.isArray(json.data) ? json.data : (Array.isArray(json) ? json : []);
        return projects.some((p: { name?: string }) => typeof p?.name === 'string' && p.name.includes('(Demo'));
      } catch {
        return false;
      }
    },
    refetchInterval: 10000,
  });

  return (
    <header className="h-16 border-b border-border bg-card/75 backdrop-blur-md px-3 sm:px-6 flex items-center justify-between sticky top-0 z-40 glass-panel">
      {/* Left: Mobile Toggle & Brand & Workspace */}
      <div className="flex items-center space-x-3 sm:space-x-4">
        <button
          type="button"
          onClick={() => setIsMobileMenuOpen(!isMobileMenuOpen)}
          className="md:hidden p-2 rounded-lg bg-accent/60 text-muted-foreground hover:text-foreground hover:bg-accent focus:outline-none transition-colors"
          aria-label="Toggle Navigation Menu"
        >
          {isMobileMenuOpen ? <X className="w-5 h-5 text-blue-400" /> : <Menu className="w-5 h-5" />}
        </button>

        <div
          onClick={() => setActiveTab('overview')}
          className="flex items-center space-x-3 cursor-pointer group"
        >
          <div className="p-2 rounded-xl bg-gradient-to-br from-blue-500/20 to-cyan-500/10 border border-blue-500/30 group-hover:border-blue-400/50 transition-colors shadow-sm">
            <Shield className="w-5 h-5 text-blue-400 group-hover:text-cyan-400 transition-colors" />
          </div>
          <div>
            <div className="flex items-center space-x-2">
              <span className="font-bold text-sm tracking-tight text-foreground group-hover:text-blue-300 transition-colors">
                Security Lab
              </span>
              <span className="text-[10px] font-mono uppercase bg-primary/20 text-blue-400 px-1.5 py-0.2 rounded border border-primary/30">
                SOC
              </span>
            </div>
            <p className="text-[11px] text-muted-foreground hidden lg:block leading-tight">
              Continuous QA & Resilience
            </p>
          </div>
        </div>

        <div className="h-6 w-px bg-border/60 hidden sm:block" />

        {/* Multi-Tenant Workspace Selector */}
        <WorkspaceSwitcher />
      </div>

      {/* Center: Command Palette Trigger Button */}
      <div className="hidden md:flex flex-1 max-w-xs mx-4">
        <button
          type="button"
          onClick={() => setIsCommandPaletteOpen(true)}
          className="w-full flex items-center justify-between px-3 py-1.5 rounded-xl bg-accent/30 border border-border/80 text-xs text-muted-foreground hover:bg-accent/60 hover:text-foreground hover:border-border transition-all duration-150 shadow-inner group"
        >
          <div className="flex items-center space-x-2 truncate">
            <Search className="w-3.5 h-3.5 text-blue-400 group-hover:text-cyan-400 transition-colors" />
            <span className="truncate">Search commands, targets, runs...</span>
          </div>
          <div className="flex items-center space-x-1 shrink-0 ml-2">
            <kbd>⌘K</kbd>
          </div>
        </button>
      </div>

      {/* Right: Telemetry & Actions */}
      <div className="flex items-center space-x-2 sm:space-x-3">
        {/* Active Runs Live Indicator */}
        {activeRunsCount > 0 && (
          <button
            type="button"
            onClick={() => setActiveTab('runs')}
            className="flex items-center space-x-1.5 px-2 py-1 rounded-lg bg-emerald-500/10 border border-emerald-500/25 text-emerald-400 text-xs font-mono animate-pulse-glow"
            title={`${activeRunsCount} active test executions`}
          >
            <Zap className="w-3 h-3 text-emerald-400 animate-spin" />
            <span className="hidden sm:inline">{activeRunsCount} Running</span>
          </button>
        )}

        {/* Demo Mode Active Indicator Badge */}
        {hasDemoProjects && (
          <button
            type="button"
            onClick={() => setActiveTab('management')}
            className="flex items-center space-x-1.5 px-2.5 py-1 rounded-lg bg-amber-500/15 border border-amber-500/30 text-amber-400 text-xs font-semibold hover:bg-amber-500/25 transition-all shadow-sm"
            title="This workspace contains synthetic demonstration records. You can purge them at any time in Management Settings."
          >
            <Sparkles className="w-3.5 h-3.5 text-amber-400" />
            <span className="font-mono text-[11px] tracking-wide uppercase">DEMO MODE ACTIVE</span>
          </button>
        )}

        {/* Quick CLI info */}
        <div className="hidden xl:flex items-center space-x-1.5 text-xs text-muted-foreground bg-accent/40 px-2.5 py-1.5 rounded-lg border border-border/80">
          <Terminal className="w-3.5 h-3.5 text-blue-400" />
          <span className="font-mono text-[11px]">security-lab</span>
        </div>

        {/* Mobile Search Button */}
        <button
          type="button"
          onClick={() => setIsCommandPaletteOpen(true)}
          className="md:hidden p-2 rounded-lg bg-accent/50 text-muted-foreground hover:text-foreground hover:bg-accent border border-border/70"
          aria-label="Open Command Palette"
        >
          <Search className="w-4 h-4 text-blue-400" />
        </button>

        {/* Auth / API Key Button */}
        <button
          type="button"
          onClick={() => setIsAuthModalOpen(true)}
          className={`flex items-center space-x-1.5 text-xs px-2.5 py-1.5 rounded-lg border transition-all duration-150 ${
            apiKey
              ? 'bg-blue-500/10 text-blue-400 border-blue-500/20 hover:bg-blue-500/20'
              : 'bg-amber-500/10 text-amber-400 border-amber-500/20 hover:bg-amber-500/20 animate-pulse'
          }`}
          title={apiKey ? 'API Key Configured' : 'API Key Missing - Click to configure'}
        >
          <Key className="w-3.5 h-3.5" />
          <span className="hidden sm:inline">{apiKey ? 'Auth: Active' : 'Set Key'}</span>
        </button>

        {/* Controller Health Indicator */}
        <HealthBadge />
      </div>
    </header>
  );
};
