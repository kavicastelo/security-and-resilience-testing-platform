import React, { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import {
  Users,
  UserPlus,
  Shield,
  Trash2,
  Mail,
  Calendar,
  Check,
  X,
} from 'lucide-react';
import { governanceApi, WorkspaceMember } from '../../api/governance.js';
import { useAppStore } from '../../store/useAppStore.js';

const roleColorMap: Record<string, string> = {
  OWNER: 'bg-purple-500/15 text-purple-300 border-purple-500/30',
  ADMIN: 'bg-blue-500/15 text-blue-300 border-blue-500/30',
  ENGINEER: 'bg-emerald-500/15 text-emerald-300 border-emerald-500/30',
  AUDITOR: 'bg-amber-500/15 text-amber-300 border-amber-500/30',
};

const permissionsMatrix = [
  { feature: 'View Dashboard & Telemetry', owner: true, admin: true, engineer: true, auditor: true },
  { feature: 'Execute Test Plans & Scans', owner: true, admin: true, engineer: true, auditor: false },
  { feature: 'Triage Findings & Apply Waivers', owner: true, admin: true, engineer: true, auditor: false },
  { feature: 'Register Targets & Scope', owner: true, admin: true, engineer: true, auditor: false },
  { feature: 'Configure Policies & Release Gates', owner: true, admin: true, engineer: false, auditor: false },
  { feature: 'Manage Team Members & Roles', owner: true, admin: true, engineer: false, auditor: false },
  { feature: 'Configure SAML/OIDC SSO & SCIM', owner: true, admin: true, engineer: false, auditor: false },
  { feature: 'Manage Billing & Stripe Quotas', owner: true, admin: true, engineer: false, auditor: false },
  { feature: 'Delete Workspace / Purge Data', owner: true, admin: false, engineer: false, auditor: false },
];

export const TeamManagementTab: React.FC = () => {
  const { currentWorkspaceId, showToast } = useAppStore();
  const queryClient = useQueryClient();

  const [isInviteModalOpen, setIsInviteModalOpen] = useState(false);
  const [inviteEmail, setInviteEmail] = useState('');
  const [inviteName, setInviteName] = useState('');
  const [inviteRole, setInviteRole] = useState<'OWNER' | 'ADMIN' | 'ENGINEER' | 'AUDITOR'>('ENGINEER');

  const { data: members = [], isLoading } = useQuery<WorkspaceMember[]>({
    queryKey: ['workspace-members', currentWorkspaceId],
    queryFn: () => governanceApi.getMembers(currentWorkspaceId),
    enabled: !!currentWorkspaceId,
  });

  const addMemberMutation = useMutation({
    mutationFn: (data: { email: string; name?: string; role: 'OWNER' | 'ADMIN' | 'ENGINEER' | 'AUDITOR' }) =>
      governanceApi.addMember(currentWorkspaceId, data),
    onSuccess: (newMember) => {
      showToast(`Added member ${newMember.email} as ${newMember.role}`);
      setIsInviteModalOpen(false);
      setInviteEmail('');
      setInviteName('');
      setInviteRole('ENGINEER');
      queryClient.invalidateQueries({ queryKey: ['workspace-members', currentWorkspaceId] });
    },
    onError: (err: Error) => {
      showToast(err.message, 'error');
    },
  });

  const removeMemberMutation = useMutation({
    mutationFn: (userId: string) => governanceApi.removeMember(currentWorkspaceId, userId),
    onSuccess: () => {
      showToast('Member removed successfully');
      queryClient.invalidateQueries({ queryKey: ['workspace-members', currentWorkspaceId] });
    },
    onError: (err: Error) => {
      showToast(err.message, 'error');
    },
  });

  const handleInviteSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!inviteEmail.trim()) {
      showToast('Email address is required', 'error');
      return;
    }
    addMemberMutation.mutate({
      email: inviteEmail.trim(),
      name: inviteName.trim() || undefined,
      role: inviteRole,
    });
  };

  return (
    <div className="space-y-6 animate-fade-in">
      {/* Top Action Bar */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 p-4 rounded-xl bg-card border border-border/70 glass-card">
        <div>
          <h2 className="text-sm font-semibold text-foreground flex items-center space-x-2">
            <Users className="w-4 h-4 text-blue-400" />
            <span>Workspace Team Members</span>
          </h2>
          <p className="text-xs text-muted-foreground mt-0.5">
            Manage authorized identities and role bindings for workspace: <code className="text-blue-300 font-mono">{currentWorkspaceId}</code>
          </p>
        </div>

        <button
          type="button"
          onClick={() => setIsInviteModalOpen(true)}
          className="flex items-center space-x-2 px-3.5 py-2 rounded-lg bg-primary text-primary-foreground font-medium text-xs hover:bg-blue-600 transition-colors shadow-sm self-start sm:self-auto"
        >
          <UserPlus className="w-3.5 h-3.5" />
          <span>Add Member</span>
        </button>
      </div>

      {/* Members Table */}
      <div className="rounded-xl border border-border/70 bg-card overflow-hidden glass-panel">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-accent/40 border-b border-border text-muted-foreground uppercase text-[10px] font-semibold tracking-wider">
              <tr>
                <th className="px-4 py-3">Member</th>
                <th className="px-4 py-3">Role</th>
                <th className="px-4 py-3">Joined Date</th>
                <th className="px-4 py-3 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border/40">
              {isLoading ? (
                <tr>
                  <td colSpan={4} className="px-4 py-8 text-center text-muted-foreground">
                    Loading workspace members...
                  </td>
                </tr>
              ) : members.length === 0 ? (
                <tr>
                  <td colSpan={4} className="px-4 py-8 text-center text-muted-foreground">
                    <Users className="w-8 h-8 mx-auto mb-2 opacity-40 text-blue-400" />
                    <p className="text-sm font-medium">No members assigned to this workspace</p>
                    <p className="text-xs text-muted-foreground/70 mt-1">
                      Click "Add Member" to assign engineers or auditors.
                    </p>
                  </td>
                </tr>
              ) : (
                members.map((member) => (
                  <tr key={member.userId} className="hover:bg-accent/30 transition-colors">
                    <td className="px-4 py-3">
                      <div className="flex items-center space-x-3">
                        <div className="w-7 h-7 rounded-full bg-gradient-to-br from-blue-500/20 to-cyan-500/20 border border-blue-500/30 flex items-center justify-center font-bold text-blue-300 text-xs shrink-0">
                          {member.name ? member.name[0].toUpperCase() : member.email[0].toUpperCase()}
                        </div>
                        <div>
                          <div className="font-medium text-foreground">{member.name || 'Unnamed Member'}</div>
                          <div className="text-[11px] text-muted-foreground font-mono flex items-center space-x-1">
                            <Mail className="w-3 h-3 opacity-60" />
                            <span>{member.email}</span>
                          </div>
                        </div>
                      </div>
                    </td>
                    <td className="px-4 py-3">
                      <span
                        className={`text-[10px] font-mono px-2 py-0.5 rounded border uppercase font-semibold ${
                          roleColorMap[member.role] || 'bg-accent text-muted-foreground border-border'
                        }`}
                      >
                        {member.role}
                      </span>
                    </td>
                    <td className="px-4 py-3 text-muted-foreground text-[11px] font-mono">
                      <div className="flex items-center space-x-1.5">
                        <Calendar className="w-3 h-3 opacity-60" />
                        <span>{new Date(member.createdAt).toLocaleDateString()}</span>
                      </div>
                    </td>
                    <td className="px-4 py-3 text-right">
                      <button
                        type="button"
                        onClick={() => {
                          if (confirm(`Remove ${member.email} from this workspace?`)) {
                            removeMemberMutation.mutate(member.userId);
                          }
                        }}
                        className="p-1 rounded text-muted-foreground hover:text-red-400 hover:bg-red-500/10 transition-colors"
                        title="Remove Member"
                      >
                        <Trash2 className="w-3.5 h-3.5" />
                      </button>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Role Permission Matrix Card */}
      <div className="p-5 rounded-xl bg-card border border-border/70 glass-card space-y-4">
        <div className="flex items-center space-x-2 text-foreground font-semibold text-sm">
          <Shield className="w-4 h-4 text-blue-400" />
          <span>Role-Based Access Control (RBAC) Permission Matrix</span>
        </div>
        <p className="text-xs text-muted-foreground">
          Platform authorization rules enforced by the controller on all REST routes and engine dispatches.
        </p>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-accent/40 border-b border-border text-muted-foreground uppercase text-[10px] font-semibold">
              <tr>
                <th className="px-3 py-2.5">Feature / Capability</th>
                <th className="px-3 py-2.5 text-center text-purple-300">Owner</th>
                <th className="px-3 py-2.5 text-center text-blue-300">Admin</th>
                <th className="px-3 py-2.5 text-center text-emerald-300">Engineer</th>
                <th className="px-3 py-2.5 text-center text-amber-300">Auditor</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border/40">
              {permissionsMatrix.map((row) => (
                <tr key={row.feature} className="hover:bg-accent/20">
                  <td className="px-3 py-2 font-medium text-foreground">{row.feature}</td>
                  <td className="px-3 py-2 text-center">{row.owner ? <Check className="w-4 h-4 text-emerald-400 mx-auto" /> : <X className="w-4 h-4 text-muted-foreground/30 mx-auto" />}</td>
                  <td className="px-3 py-2 text-center">{row.admin ? <Check className="w-4 h-4 text-emerald-400 mx-auto" /> : <X className="w-4 h-4 text-muted-foreground/30 mx-auto" />}</td>
                  <td className="px-3 py-2 text-center">{row.engineer ? <Check className="w-4 h-4 text-emerald-400 mx-auto" /> : <X className="w-4 h-4 text-muted-foreground/30 mx-auto" />}</td>
                  <td className="px-3 py-2 text-center">{row.auditor ? <Check className="w-4 h-4 text-emerald-400 mx-auto" /> : <X className="w-4 h-4 text-muted-foreground/30 mx-auto" />}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Add Member Modal */}
      {isInviteModalOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 animate-fade-in">
          <div className="fixed inset-0 bg-black/75 backdrop-blur-sm" onClick={() => setIsInviteModalOpen(false)} />
          <div className="relative w-full max-w-md bg-card border border-border/80 rounded-2xl p-6 glass-panel glow-blue z-10 space-y-4">
            <div className="flex items-center justify-between pb-3 border-b border-border">
              <div className="flex items-center space-x-2">
                <UserPlus className="w-4 h-4 text-blue-400" />
                <h3 className="font-semibold text-sm text-foreground">Add Workspace Member</h3>
              </div>
              <button
                type="button"
                onClick={() => setIsInviteModalOpen(false)}
                className="text-muted-foreground hover:text-foreground p-1"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <form onSubmit={handleInviteSubmit} className="space-y-4">
              <div>
                <label className="block text-xs font-medium text-foreground mb-1">Email Address *</label>
                <input
                  type="email"
                  required
                  value={inviteEmail}
                  onChange={(e) => setInviteEmail(e.target.value)}
                  placeholder="engineer@enterprise.internal"
                  className="w-full px-3 py-2 rounded-lg bg-accent/50 border border-border text-xs text-foreground placeholder-muted-foreground focus:outline-none focus:ring-1 focus:ring-blue-500"
                />
              </div>

              <div>
                <label className="block text-xs font-medium text-foreground mb-1">Full Name (Optional)</label>
                <input
                  type="text"
                  value={inviteName}
                  onChange={(e) => setInviteName(e.target.value)}
                  placeholder="Alice Vance"
                  className="w-full px-3 py-2 rounded-lg bg-accent/50 border border-border text-xs text-foreground placeholder-muted-foreground focus:outline-none focus:ring-1 focus:ring-blue-500"
                />
              </div>

              <div>
                <label className="block text-xs font-medium text-foreground mb-1">Role Assignment</label>
                <select
                  value={inviteRole}
                  onChange={(e) => setInviteRole(e.target.value as any)}
                  className="w-full px-3 py-2 rounded-lg bg-accent/50 border border-border text-xs text-foreground focus:outline-none focus:ring-1 focus:ring-blue-500"
                >
                  <option value="ENGINEER">Engineer (Can execute tests and triage findings)</option>
                  <option value="ADMIN">Admin (Can configure policies, targets, and members)</option>
                  <option value="AUDITOR">Auditor (Read-only compliance and audit access)</option>
                  <option value="OWNER">Owner (Full tenant and billing control)</option>
                </select>
              </div>

              <div className="pt-2 flex items-center justify-end space-x-2">
                <button
                  type="button"
                  onClick={() => setIsInviteModalOpen(false)}
                  className="px-3 py-1.5 rounded-lg text-xs font-medium text-muted-foreground hover:text-foreground transition-colors"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={addMemberMutation.isPending}
                  className="px-4 py-1.5 rounded-lg bg-primary text-primary-foreground text-xs font-medium hover:bg-blue-600 transition-colors shadow-sm disabled:opacity-50"
                >
                  {addMemberMutation.isPending ? 'Adding...' : 'Add Member'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};
