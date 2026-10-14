import React, { useState, useEffect, useRef } from 'react';
import {
  Search,
  LayoutDashboard,
  Target,
  PlayCircle,
  AlertOctagon,
  Scale,
  Sliders,
  ShieldCheck,
  FileCode2,
  KeyRound,
  Grid,
  Zap,
  Gauge,
  Boxes,
  Radio,
  FileSpreadsheet,
  GitBranch,
  Key,
  X,
  ArrowRight,
} from 'lucide-react';
import { useAppStore, NavTab } from '../store/useAppStore.js';

interface CommandItem {
  id: string;
  title: string;
  description: string;
  category: 'Navigation' | 'Actions' | 'Testing Lab';
  icon: React.ElementType;
  tab?: NavTab;
  action?: () => void;
  badge?: string;
  shortcut?: string;
}

export const CommandPalette: React.FC = () => {
  const {
    isCommandPaletteOpen,
    setIsCommandPaletteOpen,
    setActiveTab,
    setIsAuthModalOpen,
  } = useAppStore();

  const [query, setQuery] = useState('');
  const [selectedIndex, setSelectedIndex] = useState(0);
  const inputRef = useRef<HTMLInputElement>(null);
  const listRef = useRef<HTMLDivElement>(null);

  const commandItems: CommandItem[] = [
    // Core Navigation
    {
      id: 'nav-overview',
      title: 'Platform Overview',
      description: 'System health, global risk scores, and active run summary',
      category: 'Navigation',
      icon: LayoutDashboard,
      tab: 'overview',
      shortcut: 'G O',
    },
    {
      id: 'nav-targets',
      title: 'Target Scopes & Verification',
      description: 'Authorized hosts, DNS pinning, and safety budgets',
      category: 'Navigation',
      icon: Target,
      tab: 'targets',
      shortcut: 'G T',
    },
    {
      id: 'nav-runs',
      title: 'Test Runs & Executions',
      description: 'Active test executions, live logs, and history',
      category: 'Navigation',
      icon: PlayCircle,
      tab: 'runs',
      shortcut: 'G R',
    },
    {
      id: 'nav-findings',
      title: 'Findings & Risk Triage',
      description: 'Vulnerability catalog, forensic evidence, and SLA waivers',
      category: 'Navigation',
      icon: AlertOctagon,
      tab: 'findings',
      shortcut: 'G F',
    },
    {
      id: 'nav-policies',
      title: 'Release Gates & Policies',
      description: 'Security thresholds, pass/fail rules, and CI gates',
      category: 'Navigation',
      icon: Scale,
      tab: 'policies',
      shortcut: 'G P',
    },
    {
      id: 'nav-management',
      title: 'Universal Operations Hub',
      description: 'System metrics, telemetry, maintenance, and database stats',
      category: 'Navigation',
      icon: Sliders,
      tab: 'management',
      badge: 'Admin',
      shortcut: 'G M',
    },

    // Security & Resilience Lab Workbenches
    {
      id: 'lab-api',
      title: 'API & GraphQL Security Explorer',
      description: 'OpenAPI 3.0 catalog, circular depth, and field suggestions',
      category: 'Testing Lab',
      icon: FileCode2,
      tab: 'api-security',
      badge: 'Engine',
    },
    {
      id: 'lab-auth',
      title: 'Stateful Auth & Secrets Vault',
      description: 'Multi-step login flows, TOTP simulator, and encrypted credentials',
      category: 'Testing Lab',
      icon: KeyRound,
      tab: 'auth-vault',
      badge: 'AES-256',
    },
    {
      id: 'lab-authz',
      title: 'BOLA & BFLA Access Matrix',
      description: 'Dual-identity access graph and privilege escalation heatmaps',
      category: 'Testing Lab',
      icon: Grid,
      tab: 'authz-matrix',
      badge: 'IDOR',
    },
    {
      id: 'lab-chaos',
      title: 'Chaos MITM & Business Logic',
      description: 'Fault injection, circuit breaker trips, and state machine bypasses',
      category: 'Testing Lab',
      icon: Zap,
      tab: 'resilience',
      badge: 'Chaos',
    },
    {
      id: 'lab-performance',
      title: 'Native Performance & Capacity Studio',
      description: 'Percentile latency histograms, RPS waterfalls, and saturation knees',
      category: 'Testing Lab',
      icon: Gauge,
      tab: 'performance',
      badge: 'Benchmarking',
    },
    {
      id: 'lab-infra',
      title: 'Kubernetes Audit & SBOM Supply Chain',
      description: 'Pod Security Standards, CycloneDX dependencies, and smuggling desync',
      category: 'Testing Lab',
      icon: Boxes,
      tab: 'infra-supply-chain',
      badge: 'Cloud',
    },
    {
      id: 'lab-agent',
      title: 'Distributed Agent Fleet Radar',
      description: 'Private worker topologies, mTLS attestation, and heartbeat telemetry',
      category: 'Testing Lab',
      icon: Radio,
      tab: 'agent-fleet',
      badge: 'mTLS',
    },
    {
      id: 'lab-compliance',
      title: 'Compliance Center & Reports Hub',
      description: 'OWASP Top 10, ASVS 4.0 scorecards, and PDF/HTML report exports',
      category: 'Testing Lab',
      icon: FileSpreadsheet,
      tab: 'compliance',
      badge: 'PDF',
    },
    {
      id: 'lab-governance',
      title: 'Workspaces, SSO & Governance',
      description: 'Multi-tenant hierarchy, SAML/OIDC SSO, SCIM sync, and Stripe quotas',
      category: 'Testing Lab',
      icon: ShieldCheck,
      tab: 'governance',
      badge: 'SSO',
    },
    {
      id: 'lab-integrations',
      title: 'CI/CD Integrations & Webhooks',
      description: 'HMAC-SHA256 webhooks, GitHub/Jira sync, and pipeline generators',
      category: 'Testing Lab',
      icon: GitBranch,
      tab: 'integrations',
      badge: 'CI/CD',
    },

    // Quick Actions
    {
      id: 'action-credentials',
      title: 'Configure Platform API Key',
      description: 'Set controller bearer token and administrative authentication credentials',
      category: 'Actions',
      icon: Key,
      action: () => setIsAuthModalOpen(true),
      shortcut: 'Alt+K',
    },
    {
      id: 'action-new-target',
      title: 'Register New Target Scope',
      description: 'Add an authorized domain, CIDR, or API endpoint to the testing catalog',
      category: 'Actions',
      icon: Target,
      tab: 'targets',
    },
    {
      id: 'action-new-run',
      title: 'Execute New Test Run',
      description: 'Trigger targeted security scans, load tests, or resilience scenarios',
      category: 'Actions',
      icon: PlayCircle,
      tab: 'runs',
    },
  ];

  const filteredItems = commandItems.filter((item) => {
    const q = query.toLowerCase().trim();
    if (!q) return true;
    return (
      item.title.toLowerCase().includes(q) ||
      item.description.toLowerCase().includes(q) ||
      item.category.toLowerCase().includes(q) ||
      (item.badge && item.badge.toLowerCase().includes(q))
    );
  });

  useEffect(() => {
    setSelectedIndex(0);
  }, [query]);

  useEffect(() => {
    if (isCommandPaletteOpen) {
      setQuery('');
      setSelectedIndex(0);
      setTimeout(() => inputRef.current?.focus(), 50);
    }
  }, [isCommandPaletteOpen]);

  const handleSelect = (item: CommandItem) => {
    setIsCommandPaletteOpen(false);
    if (item.action) {
      item.action();
    } else if (item.tab) {
      setActiveTab(item.tab);
    }
  };

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === 'ArrowDown') {
      e.preventDefault();
      setSelectedIndex((prev) => (prev + 1) % (filteredItems.length || 1));
    } else if (e.key === 'ArrowUp') {
      e.preventDefault();
      setSelectedIndex((prev) => (prev - 1 + filteredItems.length) % (filteredItems.length || 1));
    } else if (e.key === 'Enter') {
      e.preventDefault();
      if (filteredItems[selectedIndex]) {
        handleSelect(filteredItems[selectedIndex]);
      }
    } else if (e.key === 'Escape') {
      e.preventDefault();
      setIsCommandPaletteOpen(false);
    }
  };

  if (!isCommandPaletteOpen) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-start justify-center pt-16 sm:pt-24 p-4 animate-fade-in">
      {/* Backdrop */}
      <div
        className="fixed inset-0 bg-black/80 backdrop-blur-md transition-opacity"
        onClick={() => setIsCommandPaletteOpen(false)}
      />

      {/* Palette Container */}
      <div className="relative w-full max-w-2xl bg-card border border-border/80 shadow-2xl rounded-2xl overflow-hidden glass-panel glow-blue flex flex-col max-h-[80vh]">
        {/* Search Input Bar */}
        <div className="flex items-center px-4 py-3.5 border-b border-border/80 bg-accent/30">
          <Search className="w-5 h-5 text-blue-400 shrink-0 mr-3" />
          <input
            ref={inputRef}
            type="text"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            onKeyDown={handleKeyDown}
            placeholder="Type a command, search targets, or jump to view..."
            className="w-full bg-transparent text-sm sm:text-base text-foreground placeholder-muted-foreground focus:outline-none"
          />
          {query && (
            <button
              type="button"
              onClick={() => setQuery('')}
              className="text-muted-foreground hover:text-foreground p-1 rounded-md"
            >
              <X className="w-4 h-4" />
            </button>
          )}
          <kbd className="ml-2 hidden sm:inline-flex">ESC</kbd>
        </div>

        {/* Results List */}
        <div
          ref={listRef}
          className="flex-1 overflow-y-auto p-2 space-y-1 divide-y divide-border/30 max-h-[55vh]"
        >
          {filteredItems.length === 0 ? (
            <div className="py-12 text-center text-muted-foreground">
              <Search className="w-8 h-8 mx-auto mb-2 opacity-40 text-blue-400" />
              <p className="text-sm">No commands or views matching "{query}"</p>
              <p className="text-xs text-muted-foreground/70 mt-1">
                Try searching for "API", "Targets", "Chaos", or "Reports"
              </p>
            </div>
          ) : (
            filteredItems.map((item, index) => {
              const Icon = item.icon;
              const isSelected = index === selectedIndex;
              return (
                <div
                  key={item.id}
                  onClick={() => handleSelect(item)}
                  onMouseEnter={() => setSelectedIndex(index)}
                  className={`flex items-center justify-between px-3 py-2.5 rounded-xl cursor-pointer transition-colors duration-150 ${
                    isSelected
                      ? 'bg-primary/20 text-foreground border border-primary/30'
                      : 'text-muted-foreground hover:bg-accent/50 hover:text-foreground border border-transparent'
                  }`}
                >
                  <div className="flex items-center space-x-3 min-w-0">
                    <div
                      className={`p-2 rounded-lg shrink-0 ${
                        isSelected
                          ? 'bg-blue-500/20 text-blue-400'
                          : 'bg-accent/80 text-muted-foreground'
                      }`}
                    >
                      <Icon className="w-4 h-4" />
                    </div>
                    <div className="min-w-0">
                      <div className="flex items-center space-x-2">
                        <span className="text-sm font-medium truncate text-foreground">
                          {item.title}
                        </span>
                        {item.badge && (
                          <span className="text-[10px] uppercase font-mono px-1.5 py-0.5 rounded bg-blue-500/10 text-blue-400 border border-blue-500/20">
                            {item.badge}
                          </span>
                        )}
                      </div>
                      <p className="text-xs text-muted-foreground truncate">{item.description}</p>
                    </div>
                  </div>

                  <div className="flex items-center space-x-2 shrink-0 ml-3">
                    <span className="text-[10px] text-muted-foreground uppercase tracking-wider hidden sm:inline">
                      {item.category}
                    </span>
                    {item.shortcut ? (
                      <kbd className="hidden sm:inline-flex">{item.shortcut}</kbd>
                    ) : (
                      <ArrowRight
                        className={`w-4 h-4 transition-transform ${
                          isSelected ? 'translate-x-0.5 text-blue-400' : 'opacity-0'
                        }`}
                      />
                    )}
                  </div>
                </div>
              );
            })
          )}
        </div>

        {/* Footer Navigation Hints */}
        <div className="px-4 py-2.5 border-t border-border/80 bg-accent/20 flex items-center justify-between text-xs text-muted-foreground">
          <div className="flex items-center space-x-3">
            <span className="flex items-center space-x-1">
              <kbd>↑</kbd> <kbd>↓</kbd> <span>Navigate</span>
            </span>
            <span className="flex items-center space-x-1">
              <kbd>↵</kbd> <span>Select</span>
            </span>
            <span className="flex items-center space-x-1">
              <kbd>ESC</kbd> <span>Close</span>
            </span>
          </div>
          <span className="font-mono text-[11px] text-blue-400">Security Lab SOC Shell</span>
        </div>
      </div>
    </div>
  );
};
