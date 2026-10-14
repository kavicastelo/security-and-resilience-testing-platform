import React from 'react';
import { useAppStore, NavTab } from '../store/useAppStore.js';
import {
  LayoutDashboard,
  Target,
  PlayCircle,
  AlertOctagon,
  Scale,
  Sliders,
  FileCode2,
  KeyRound,
  Grid,
  Zap,
  Gauge,
  Boxes,
  Radio,
  FileSpreadsheet,
  ShieldCheck,
  GitBranch,
  X,
  Keyboard,
  ShieldAlert,
} from 'lucide-react';

interface NavItem {
  id: NavTab;
  label: string;
  icon: React.ElementType;
  badge?: string;
  badgeColor?: string;
}

interface NavSection {
  title: string;
  items: NavItem[];
}

const navSections: NavSection[] = [
  {
    title: 'Core Operations',
    items: [
      { id: 'overview', label: 'Platform Overview', icon: LayoutDashboard },
      { id: 'targets', label: 'Target Scopes', icon: Target },
      { id: 'runs', label: 'Test Executions', icon: PlayCircle },
      { id: 'findings', label: 'Findings & Risks', icon: AlertOctagon },
      { id: 'policies', label: 'Release Gates', icon: Scale },
      { id: 'management', label: 'Universal Hub', icon: Sliders, badge: 'Admin' },
    ],
  },
  {
    title: 'Security & API Lab',
    items: [
      { id: 'api-security', label: 'API & GraphQL', icon: FileCode2, badge: 'New', badgeColor: 'bg-cyan-500/15 text-cyan-400 border-cyan-500/30' },
      { id: 'auth-vault', label: 'Auth & Secrets Vault', icon: KeyRound },
      { id: 'authz-matrix', label: 'BOLA / BFLA Matrix', icon: Grid },
    ],
  },
  {
    title: 'Resilience & Infra',
    items: [
      { id: 'resilience', label: 'Chaos & Recovery', icon: Zap },
      { id: 'performance', label: 'Performance Studio', icon: Gauge },
      { id: 'infra-supply-chain', label: 'K8s & SBOM Feeds', icon: Boxes },
      { id: 'agent-fleet', label: 'Agent Fleet Radar', icon: Radio },
    ],
  },
  {
    title: 'Governance & CI/CD',
    items: [
      { id: 'compliance', label: 'Compliance Hub', icon: FileSpreadsheet, badge: 'OWASP', badgeColor: 'bg-emerald-500/15 text-emerald-400 border-emerald-500/30' },
      { id: 'governance', label: 'RBAC, SSO & SCIM', icon: ShieldCheck },
      { id: 'integrations', label: 'CI/CD & Webhooks', icon: GitBranch, badge: 'HMAC', badgeColor: 'bg-cyan-500/15 text-cyan-400 border-cyan-500/30' },
    ],
  },
];

export const Sidebar: React.FC = () => {
  const {
    activeTab,
    setActiveTab,
    isMobileMenuOpen,
    setIsMobileMenuOpen,
    setIsCommandPaletteOpen,
  } = useAppStore();

  const renderNavContent = () => (
    <div className="flex flex-col h-full justify-between">
      {/* Scrollable Navigation Groups */}
      <div className="space-y-5 overflow-y-auto pr-1">
        <div className="flex items-center justify-between px-2 pt-1 text-[11px] font-bold uppercase tracking-wider text-muted-foreground">
          <span>Operations Center</span>
          <button
            type="button"
            onClick={() => setIsMobileMenuOpen(false)}
            className="md:hidden p-1 rounded-md text-muted-foreground hover:text-foreground hover:bg-accent"
            aria-label="Close Navigation"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {navSections.map((section) => (
          <div key={section.title} className="space-y-1">
            <div className="px-2 text-[10px] font-bold uppercase tracking-wider text-muted-foreground/70">
              {section.title}
            </div>
            <nav className="space-y-0.5">
              {section.items.map((item) => {
                const Icon = item.icon;
                const isActive = activeTab === item.id;
                return (
                  <button
                    key={item.id}
                    onClick={() => {
                      setActiveTab(item.id);
                      setIsMobileMenuOpen(false);
                    }}
                    className={`w-full flex items-center justify-between px-2.5 py-2 rounded-xl text-xs font-medium transition-all duration-150 ${
                      isActive
                        ? 'bg-primary/20 text-blue-300 font-semibold border border-primary/30 shadow-sm'
                        : 'text-muted-foreground hover:bg-accent/60 hover:text-foreground border border-transparent'
                    }`}
                  >
                    <div className="flex items-center space-x-2.5 truncate">
                      <Icon
                        className={`w-4 h-4 shrink-0 transition-colors ${
                          isActive ? 'text-blue-400' : 'text-muted-foreground'
                        }`}
                      />
                      <span className="truncate">{item.label}</span>
                    </div>
                    {item.badge && (
                      <span
                        className={`text-[9px] font-mono px-1.5 py-0.2 rounded border ${
                          item.badgeColor || 'bg-accent text-muted-foreground border-border'
                        }`}
                      >
                        {item.badge}
                      </span>
                    )}
                  </button>
                );
              })}
            </nav>
          </div>
        ))}
      </div>

      {/* Bottom Command Hint Card */}
      <div className="pt-3 border-t border-border/70 mt-3 space-y-2">
        <button
          type="button"
          onClick={() => {
            setIsMobileMenuOpen(false);
            setIsCommandPaletteOpen(true);
          }}
          className="w-full flex items-center justify-between p-2.5 rounded-xl bg-accent/40 border border-border/80 text-xs text-muted-foreground hover:text-foreground hover:bg-accent hover:border-border transition-all duration-150"
        >
          <div className="flex items-center space-x-2">
            <Keyboard className="w-3.5 h-3.5 text-blue-400" />
            <span className="font-medium">Quick Command</span>
          </div>
          <kbd>⌘K</kbd>
        </button>

        <div className="p-2.5 rounded-xl bg-gradient-to-br from-card to-accent/30 border border-border/60 text-[11px] text-muted-foreground flex items-center space-x-2">
          <ShieldAlert className="w-4 h-4 text-emerald-400 shrink-0" />
          <span className="truncate">Local-First Sandbox Active</span>
        </div>
      </div>
    </div>
  );

  return (
    <>
      {/* Desktop Sidebar */}
      <aside className="hidden md:flex w-64 border-r border-border bg-card/40 backdrop-blur-md flex-col justify-between p-3.5 h-[calc(100vh-4rem)] sticky top-16 shrink-0 glass-panel">
        {renderNavContent()}
      </aside>

      {/* Mobile Drawer Overlay */}
      {isMobileMenuOpen && (
        <div className="fixed inset-0 z-50 md:hidden flex animate-fade-in">
          <div
            className="fixed inset-0 bg-black/80 backdrop-blur-md"
            onClick={() => setIsMobileMenuOpen(false)}
          />
          <aside className="relative w-72 bg-card border-r border-border p-4 flex flex-col justify-between z-10 shadow-2xl h-full glass-panel">
            {renderNavContent()}
          </aside>
        </div>
      )}
    </>
  );
};
