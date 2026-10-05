import React from 'react';
import { useAppStore, AppState } from '../store/useAppStore.js';
import {
  LayoutDashboard,
  Target,
  PlayCircle,
  AlertOctagon,
  Scale,
  FileCode,
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
  const { activeTab, setActiveTab } = useAppStore();

  return (
    <aside className="w-64 border-r border-border bg-card/30 flex flex-col justify-between p-4 h-[calc(100vh-4rem)]">
      <div className="space-y-1">
        <div className="px-3 py-2 text-[11px] font-semibold uppercase tracking-wider text-muted-foreground">
          Core Navigation
        </div>
        <nav className="space-y-1">
          {navItems.map((item) => {
            const Icon = item.icon;
            const isActive = activeTab === item.id;
            return (
              <button
                key={item.id}
                onClick={() => setActiveTab(item.id)}
                className={`w-full flex items-center justify-between px-3 py-2 rounded-lg text-sm transition-colors ${
                  isActive
                    ? 'bg-primary/15 text-blue-400 font-medium border border-primary/20'
                    : 'text-muted-foreground hover:bg-accent hover:text-foreground'
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

      <div className="p-3 rounded-lg bg-accent/40 border border-border/60 text-xs space-y-2">
        <div className="flex items-center space-x-2 text-foreground font-medium">
          <FileCode className="w-4 h-4 text-blue-400" />
          <span>Architecture Mode</span>
        </div>
        <p className="text-[11px] text-muted-foreground leading-relaxed">
          Modular monolith with isolated execution container boundaries. Local-first security QA laboratory.
        </p>
      </div>
    </aside>
  );
};
