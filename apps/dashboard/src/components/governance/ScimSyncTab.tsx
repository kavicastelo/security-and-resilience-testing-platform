import React, { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import {
  RefreshCw,
  Copy,
  Check,
  CheckCircle2,
  Users,
  Eye,
  EyeOff,
} from 'lucide-react';
import { governanceApi, ScimUserRecord } from '../../api/governance.js';
import { useAppStore } from '../../store/useAppStore.js';

export const ScimSyncTab: React.FC = () => {
  const { currentWorkspaceId, apiKey, showToast } = useAppStore();
  const [copiedField, setCopiedField] = useState<string | null>(null);
  const [showToken, setShowToken] = useState(false);

  const hostUrl = typeof window !== 'undefined' ? window.location.origin : 'https://security-lab.local';
  const scimBaseUrl = `${hostUrl}/scim/v2`;

  const { data: scimUsers = [], isLoading, refetch, isFetching } = useQuery<ScimUserRecord[]>({
    queryKey: ['scim-users', currentWorkspaceId],
    queryFn: () => governanceApi.getScimUsers(currentWorkspaceId),
    enabled: !!currentWorkspaceId,
  });

  const handleCopy = (text: string, field: string) => {
    navigator.clipboard.writeText(text);
    setCopiedField(field);
    showToast('Copied to clipboard', 'info');
    setTimeout(() => setCopiedField(null), 2000);
  };

  return (
    <div className="space-y-6 animate-fade-in max-w-4xl">
      {/* Overview Card */}
      <div className="p-4 rounded-xl bg-card border border-border/70 glass-card flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h2 className="text-sm font-semibold text-foreground flex items-center space-x-2">
            <RefreshCw className="w-4 h-4 text-blue-400" />
            <span>Automated SCIM 2.0 Directory Synchronization</span>
          </h2>
          <p className="text-xs text-muted-foreground mt-0.5">
            Synchronize enterprise employees and groups from Okta, Azure AD, or OneLogin in real-time.
          </p>
        </div>

        <button
          type="button"
          onClick={() => refetch()}
          disabled={isFetching}
          className="flex items-center space-x-1.5 px-3 py-1.5 rounded-lg bg-accent hover:bg-accent/80 text-muted-foreground hover:text-foreground text-xs font-medium transition-colors border border-border self-start sm:self-auto"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${isFetching ? 'animate-spin text-blue-400' : ''}`} />
          <span>Refresh Sync</span>
        </button>
      </div>

      {/* SCIM Credentials & Setup Card */}
      <div className="p-5 rounded-xl bg-card border border-border/70 glass-card space-y-4">
        <h3 className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">
          Directory Provider Configuration
        </h3>

        <div className="space-y-3">
          <div>
            <label className="block text-xs font-medium text-foreground mb-1">
              SCIM 2.0 Base URL (Endpoint)
            </label>
            <div className="flex items-center space-x-2">
              <input
                type="text"
                readOnly
                value={scimBaseUrl}
                className="w-full px-3 py-2 rounded-lg bg-accent/60 border border-border text-xs font-mono text-blue-300 select-all"
              />
              <button
                type="button"
                onClick={() => handleCopy(scimBaseUrl, 'url')}
                className="p-2 rounded-lg bg-accent hover:bg-accent/80 text-muted-foreground hover:text-foreground transition-colors shrink-0"
                title="Copy Base URL"
              >
                {copiedField === 'url' ? <Check className="w-4 h-4 text-emerald-400" /> : <Copy className="w-4 h-4" />}
              </button>
            </div>
          </div>

          <div>
            <label className="block text-xs font-medium text-foreground mb-1">
              SCIM Authorization Bearer Token
            </label>
            <div className="flex items-center space-x-2">
              <div className="relative w-full">
                <input
                  type={showToken ? 'text' : 'password'}
                  readOnly
                  value={apiKey || 'sec_lab_workspace_scim_token_••••••••'}
                  className="w-full px-3 py-2 rounded-lg bg-accent/60 border border-border text-xs font-mono text-foreground pr-9 select-all"
                />
                <button
                  type="button"
                  onClick={() => setShowToken(!showToken)}
                  className="absolute right-2.5 top-2.5 text-muted-foreground hover:text-foreground"
                >
                  {showToken ? <EyeOff className="w-3.5 h-3.5" /> : <Eye className="w-3.5 h-3.5" />}
                </button>
              </div>
              <button
                type="button"
                onClick={() => handleCopy(apiKey || '', 'token')}
                className="p-2 rounded-lg bg-accent hover:bg-accent/80 text-muted-foreground hover:text-foreground transition-colors shrink-0"
                title="Copy Token"
              >
                {copiedField === 'token' ? <Check className="w-4 h-4 text-emerald-400" /> : <Copy className="w-4 h-4" />}
              </button>
            </div>
            <p className="text-[11px] text-muted-foreground mt-1">
              Enter this bearer token into the "API Token" field of your identity provider's SCIM provisioning application.
            </p>
          </div>
        </div>

        {/* Feature Matrix Badges */}
        <div className="pt-2 border-t border-border/70">
          <div className="text-[11px] font-semibold uppercase tracking-wider text-muted-foreground mb-2">
            Supported SCIM 2.0 Core Features
          </div>
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-2">
            {[
              'User Provisioning',
              'User Deprovisioning',
              'Group Sync',
              'Role Attribution',
            ].map((feat) => (
              <div
                key={feat}
                className="flex items-center space-x-1.5 p-2 rounded-lg bg-accent/40 border border-border text-xs text-foreground"
              >
                <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400 shrink-0" />
                <span className="truncate">{feat}</span>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Synced Users Table */}
      <div className="rounded-xl border border-border/70 bg-card overflow-hidden glass-panel space-y-2">
        <div className="p-4 border-b border-border/70 flex items-center justify-between">
          <h3 className="text-xs font-semibold text-foreground flex items-center space-x-2">
            <Users className="w-4 h-4 text-blue-400" />
            <span>Provisioned SCIM Identities ({scimUsers.length})</span>
          </h3>
          <span className="text-[11px] text-muted-foreground font-mono">RFC 7643 / RFC 7644</span>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-accent/40 border-b border-border text-muted-foreground uppercase text-[10px] font-semibold">
              <tr>
                <th className="px-4 py-2.5">User Name / Email</th>
                <th className="px-4 py-2.5">Display Name</th>
                <th className="px-4 py-2.5">Assigned Role</th>
                <th className="px-4 py-2.5 text-right">Status</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border/40">
              {isLoading ? (
                <tr>
                  <td colSpan={4} className="px-4 py-6 text-center text-muted-foreground">
                    Fetching synced directory identities...
                  </td>
                </tr>
              ) : scimUsers.length === 0 ? (
                <tr>
                  <td colSpan={4} className="px-4 py-6 text-center text-muted-foreground">
                    <p className="text-xs font-medium">No SCIM users provisioned yet</p>
                    <p className="text-[11px] text-muted-foreground/70 mt-0.5">
                      Configure your enterprise IdP with the Base URL and Token above to begin synchronization.
                    </p>
                  </td>
                </tr>
              ) : (
                scimUsers.map((user) => (
                  <tr key={user.id} className="hover:bg-accent/20">
                    <td className="px-4 py-2.5 font-mono text-blue-300">{user.userName}</td>
                    <td className="px-4 py-2.5 text-foreground">{user.name?.formatted || user.userName}</td>
                    <td className="px-4 py-2.5">
                      <span className="text-[10px] font-mono px-1.5 py-0.2 rounded bg-primary/20 text-blue-300 border border-primary/30">
                        {user.roles?.[0]?.value || 'ENGINEER'}
                      </span>
                    </td>
                    <td className="px-4 py-2.5 text-right">
                      <span
                        className={`text-[10px] font-mono px-2 py-0.5 rounded border uppercase ${
                          user.active !== false
                            ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20'
                            : 'bg-red-500/10 text-red-400 border-red-500/20'
                        }`}
                      >
                        {user.active !== false ? 'Active' : 'Suspended'}
                      </span>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
