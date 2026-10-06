import React from 'react';
import { useAppStore, AppState } from '../store/useAppStore.js';
import {
  LayoutDashboard,
  Target,
  PlayCircle,
  AlertOctagon,
  Scale,
  FileCode,
  X,
} from 'lucide-react';

interface NavItem {
  id: AppState['activeTab'];
  label: string;
  icon: React.ElementType;
  badge?: string;
}

const navItems: NavItem[] = [
  { id: 'overview', label: 'Platform Overview', icon: LayoutDashboard },
  { id: 'targets', label: 'Target Scopes', icon: Target },
  { id: 'runs', label: 'Test Executions', icon: PlayCircle },
  { id: 'findings', label: 'Findings & Risks', icon: AlertOctagon },
  { id: 'policies', label: 'Release Gates', icon: Scale },
];

export const Sidebar: React.FC = () => {
  const { activeTab, setActiveTab, isMobileMenuOpen, setIsMobileMenuOpen } = useAppStore();

  const renderNavContent = () => (
    <>
      <div className="space-y-1">
        <div className="flex items-center justify-between px-3 py-2 text-[11px] font-semibold uppercase tracking-wider text-muted-foreground">
          <span>Core Navigation</span>
          <button
            type="button"
            onClick={() => setIsMobileMenuOpen(false)}
            className="md:hidden p-1 rounded-md text-muted-foreground hover:text-foreground hover:bg-accent"
            aria-label="Close Navigation"
          >
            <X className="w-4 h-4" />
          </button>
        </div>
        <nav className="space-y-1">
          {navItems.map((item) => {
            const Icon = item.icon;
            const isActive = activeTab === item.id;
            return (
              <button
                key={item.id}
                onClick={() => {
                  setActiveTab(item.id);
                  setIsMobileMenuOpen(false);
                }}
                className={`w-full flex items-center justify-between px-3 py-2.5 rounded-lg text-sm transition-all duration-150 ${
                  isActive
                    ? 'bg-primary/15 text-blue-400 font-medium border border-primary/25 shadow-sm'
                    : 'text-muted-foreground hover:bg-accent/70 hover:text-foreground'
                }`}
              >
                <div className="flex items-center space-x-3">
                  <Icon className={`w-4 h-4 ${isActive ? 'text-blue-400' : 'text-muted-foreground'}`} />
                  <span>{item.label}</span>
                </div>
                {item.badge && (
                  <span className="text-[10px] bg-accent px-1.5 py-0.5 rounded text-muted-foreground">
                    {item.badge}
                  </span>
                )}
              </button>
            );
          })}
        </nav>
      </div>

      <div className="p-3.5 rounded-xl bg-accent/40 border border-border/70 text-xs space-y-2">
        <div className="flex items-center space-x-2 text-foreground font-medium">
          <FileCode className="w-4 h-4 text-blue-400" />
          <span>Architecture Mode</span>
        </div>
        <p className="text-[11px] text-muted-foreground leading-relaxed">
          Modular monolith with isolated execution container boundaries. Local-first security QA laboratory.
        </p>
      </div>
    </>
  );

  return (
    <>
      {/* Desktop Sidebar */}
      <aside className="hidden md:flex w-64 border-r border-border bg-card/30 flex-col justify-between p-4 h-[calc(100vh-4rem)] sticky top-16 shrink-0">
        {renderNavContent()}
      </aside>

      {/* Mobile Drawer Overlay */}
      {isMobileMenuOpen && (
        <div className="fixed inset-0 z-50 md:hidden flex animate-fade-in">
          <div
            className="fixed inset-0 bg-black/70 backdrop-blur-sm"
            onClick={() => setIsMobileMenuOpen(false)}
          />
          <aside className="relative w-72 bg-card border-r border-border p-4 flex flex-col justify-between z-10 shadow-2xl h-full">
            {renderNavContent()}
          </aside>
        </div>
      )}
    </>
  );
};
