import React, { useState } from 'react';
import {
  Users,
  ShieldCheck,
  RefreshCw,
  CreditCard,
  FileText,
  Building2,
} from 'lucide-react';
import { TeamManagementTab } from './governance/TeamManagementTab.js';
import { SsoConfigTab } from './governance/SsoConfigTab.js';
import { ScimSyncTab } from './governance/ScimSyncTab.js';
import { BillingQuotasTab } from './governance/BillingQuotasTab.js';
import { AuditLogTab } from './governance/AuditLogTab.js';
import { useAppStore } from '../store/useAppStore.js';

type GovernanceSubTab = 'team' | 'sso' | 'scim' | 'billing' | 'audit';

export const GovernanceView: React.FC = () => {
  const [activeSubTab, setActiveSubTab] = useState<GovernanceSubTab>('team');
  const { currentWorkspaceId, currentTenantId } = useAppStore();

  const tabs: Array<{
    id: GovernanceSubTab;
    label: string;
    icon: React.ElementType;
    badge?: string;
  }> = [
    { id: 'team', label: 'Workspaces & Members', icon: Users },
    { id: 'sso', label: 'Enterprise SSO', icon: ShieldCheck, badge: 'SAML/OIDC' },
    { id: 'scim', label: 'Directory Sync', icon: RefreshCw, badge: 'SCIM 2.0' },
    { id: 'billing', label: 'Usage & Quotas', icon: CreditCard },
    { id: 'audit', label: 'Audit Trail', icon: FileText },
  ];

  return (
    <div className="space-y-6 animate-fade-in">
      {/* Header Banner */}
      <div className="p-6 rounded-2xl bg-card border border-border glass-panel glow-blue relative overflow-hidden">
        <div className="absolute right-0 top-0 translate-x-8 -translate-y-8 w-64 h-64 bg-blue-500/10 rounded-full blur-3xl pointer-events-none" />
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 relative z-10">
          <div className="flex items-center space-x-3">
            <div className="p-3 rounded-2xl bg-primary/20 border border-primary/30 text-blue-400">
              <Building2 className="w-6 h-6" />
            </div>
            <div>
              <div className="flex items-center space-x-2">
                <h1 className="text-xl sm:text-2xl font-bold text-foreground tracking-tight">
                  Governance & Access Management
                </h1>
                <span className="text-[10px] font-mono uppercase bg-primary/20 text-blue-300 border border-primary/30 px-2 py-0.5 rounded-full">
                  Enterprise Control Plane
                </span>
              </div>
              <p className="text-xs text-muted-foreground mt-0.5">
                Multi-tenant isolation, RBAC role assignments, SAML/OIDC SSO, SCIM sync, and Stripe quotas.
              </p>
            </div>
          </div>

          <div className="flex items-center space-x-2 font-mono text-xs">
            <span className="px-2.5 py-1 rounded-lg bg-accent/60 text-muted-foreground border border-border">
              Tenant: <span className="text-blue-300 font-bold">{currentTenantId}</span>
            </span>
            <span className="px-2.5 py-1 rounded-lg bg-accent/60 text-muted-foreground border border-border">
              Workspace: <span className="text-blue-300 font-bold">{currentWorkspaceId}</span>
            </span>
          </div>
        </div>
      </div>

      {/* Tab Navigation Navigation Bar */}
      <div className="flex items-center space-x-2 border-b border-border/80 pb-2 overflow-x-auto">
        {tabs.map((tab) => {
          const Icon = tab.icon;
          const isActive = activeSubTab === tab.id;
          return (
            <button
              key={tab.id}
              type="button"
              onClick={() => setActiveSubTab(tab.id)}
              className={`flex items-center space-x-2 px-3.5 py-2 rounded-xl text-xs font-medium transition-all duration-150 shrink-0 ${
                isActive
                  ? 'bg-primary/20 text-blue-400 font-semibold border border-primary/30 shadow-sm'
                  : 'text-muted-foreground hover:bg-accent/60 hover:text-foreground border border-transparent'
              }`}
            >
              <Icon className={`w-4 h-4 ${isActive ? 'text-blue-400' : 'text-muted-foreground'}`} />
              <span>{tab.label}</span>
              {tab.badge && (
                <span className="text-[9px] font-mono px-1.5 py-0.2 rounded bg-accent text-muted-foreground border border-border">
                  {tab.badge}
                </span>
              )}
            </button>
          );
        })}
      </div>

      {/* Tab Contents */}
      <div>
        {activeSubTab === 'team' && <TeamManagementTab />}
        {activeSubTab === 'sso' && <SsoConfigTab />}
        {activeSubTab === 'scim' && <ScimSyncTab />}
        {activeSubTab === 'billing' && <BillingQuotasTab />}
        {activeSubTab === 'audit' && <AuditLogTab />}
      </div>
    </div>
  );
};
