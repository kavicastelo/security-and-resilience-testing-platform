import React, { useState, useRef, useEffect } from 'react';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import {
  Building2,
  ChevronDown,
  Check,
  Plus,
  Layers,
} from 'lucide-react';
import { useAppStore } from '../store/useAppStore.js';
import { authFetch } from '../api/client.js';

interface Workspace {
  id: string;
  name: string;
  slug: string;
  tenantId?: string;
  role?: string;
}

interface Tenant {
  id: string;
  name: string;
  slug: string;
  plan?: string;
}

export const WorkspaceSwitcher: React.FC = () => {
  const [isOpen, setIsOpen] = useState(false);
  const dropdownRef = useRef<HTMLDivElement>(null);
  const queryClient = useQueryClient();

  const {
    currentWorkspaceId,
    setCurrentWorkspaceId,
    currentTenantId,
    setCurrentTenantId,
    setActiveTab,
    showToast,
  } = useAppStore();

  // Fetch workspaces
  const { data: workspaces = [] } = useQuery<Workspace[]>({
    queryKey: ['workspaces-list'],
    queryFn: async () => {
      try {
        const res = await authFetch('/api/v1/workspaces');
        if (!res.ok) return [];
        const json = await res.json();
        return Array.isArray(json.data) ? json.data : [];
      } catch {
        return [];
      }
    },
    staleTime: 30000,
  });

  // Fetch tenants
  const { data: tenants = [] } = useQuery<Tenant[]>({
    queryKey: ['tenants-list'],
    queryFn: async () => {
      try {
        const res = await authFetch('/api/v1/tenants');
        if (!res.ok) return [];
        const json = await res.json();
        return Array.isArray(json.data) ? json.data : [];
      } catch {
        return [];
      }
    },
    staleTime: 30000,
  });

  // Close dropdown on outside click
  useEffect(() => {
    const handleOutsideClick = (e: MouseEvent) => {
      if (dropdownRef.current && !dropdownRef.current.contains(e.target as Node)) {
        setIsOpen(false);
      }
    };
    if (isOpen) {
      document.addEventListener('mousedown', handleOutsideClick);
    }
    return () => {
      document.removeEventListener('mousedown', handleOutsideClick);
    };
  }, [isOpen]);

  // Current active workspace display
  const activeWorkspace = workspaces.find((w) => w.id === currentWorkspaceId) || {
    id: currentWorkspaceId || 'default',
    name: currentWorkspaceId === 'default' ? 'Default Workspace' : `Workspace (${currentWorkspaceId.slice(0, 8)})`,
    slug: 'default',
    role: 'ADMIN',
  };

  const activeTenant = tenants.find((t) => t.id === currentTenantId) || {
    id: currentTenantId || 'default',
    name: 'Primary Enterprise Tenant',
    slug: 'primary',
    plan: 'Enterprise',
  };

  const handleSelectWorkspace = (workspace: Workspace) => {
    setCurrentWorkspaceId(workspace.id);
    if (workspace.tenantId) {
      setCurrentTenantId(workspace.tenantId);
    }
    setIsOpen(false);
    showToast(`Switched to workspace: ${workspace.name}`, 'info');
    queryClient.invalidateQueries();
  };

  return (
    <div className="relative" ref={dropdownRef}>
      <button
        type="button"
        onClick={() => setIsOpen(!isOpen)}
        className="flex items-center space-x-2 px-2.5 py-1.5 rounded-lg bg-accent/40 border border-border/80 hover:bg-accent hover:border-border transition-all duration-150 text-left focus:outline-none focus:ring-1 focus:ring-blue-500/50"
        aria-label="Select Workspace"
      >
        <div className="p-1 rounded bg-blue-500/15 text-blue-400">
          <Building2 className="w-3.5 h-3.5" />
        </div>
        <div className="hidden sm:block">
          <div className="flex items-center space-x-1.5">
            <span className="text-xs font-semibold text-foreground truncate max-w-[130px]">
              {activeWorkspace.name}
            </span>
            <span className="text-[9px] font-mono px-1 py-0.2 rounded bg-primary/20 text-blue-400 border border-primary/30">
              {activeWorkspace.role || 'MEMBER'}
            </span>
          </div>
          <p className="text-[10px] text-muted-foreground truncate max-w-[130px]">
            {activeTenant.name}
          </p>
        </div>
        <ChevronDown
          className={`w-3.5 h-3.5 text-muted-foreground transition-transform duration-150 ${
            isOpen ? 'rotate-180 text-foreground' : ''
          }`}
        />
      </button>

      {isOpen && (
        <div className="absolute left-0 mt-2 w-72 bg-card border border-border/80 rounded-xl shadow-2xl glass-panel p-2 z-50 animate-fade-in divide-y divide-border/40">
          {/* Tenant Info Header */}
          <div className="px-3 py-2">
            <div className="flex items-center justify-between">
              <span className="text-[10px] uppercase tracking-wider font-semibold text-muted-foreground">
                Active Tenant
              </span>
              <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                {activeTenant.plan || 'Standard'}
              </span>
            </div>
            <p className="text-xs font-medium text-foreground mt-0.5 truncate">
              {activeTenant.name}
            </p>
          </div>

          {/* Workspaces List */}
          <div className="py-1.5 max-h-48 overflow-y-auto space-y-0.5">
            <div className="px-3 py-1 text-[10px] uppercase tracking-wider font-semibold text-muted-foreground">
              Workspaces ({workspaces.length > 0 ? workspaces.length : 1})
            </div>

            {workspaces.length === 0 ? (
              <div
                onClick={() =>
                  handleSelectWorkspace({
                    id: 'default',
                    name: 'Default Workspace',
                    slug: 'default',
                    role: 'ADMIN',
                  })
                }
                className="flex items-center justify-between px-3 py-2 rounded-lg text-xs cursor-pointer hover:bg-accent/60 transition-colors"
              >
                <div className="flex items-center space-x-2">
                  <Layers className="w-3.5 h-3.5 text-blue-400" />
                  <span className="text-foreground font-medium">Default Workspace</span>
                </div>
                <Check className="w-3.5 h-3.5 text-blue-400" />
              </div>
            ) : (
              workspaces.map((workspace) => {
                const isSelected = workspace.id === activeWorkspace.id;
                return (
                  <div
                    key={workspace.id}
                    onClick={() => handleSelectWorkspace(workspace)}
                    className={`flex items-center justify-between px-3 py-2 rounded-lg text-xs cursor-pointer transition-colors ${
                      isSelected
                        ? 'bg-primary/20 text-foreground font-medium border border-primary/30'
                        : 'text-muted-foreground hover:bg-accent/60 hover:text-foreground'
                    }`}
                  >
                    <div className="flex items-center space-x-2 truncate">
                      <Layers
                        className={`w-3.5 h-3.5 shrink-0 ${
                          isSelected ? 'text-blue-400' : 'text-muted-foreground'
                        }`}
                      />
                      <span className="truncate">{workspace.name}</span>
                    </div>
                    {isSelected && <Check className="w-3.5 h-3.5 text-blue-400 shrink-0 ml-2" />}
                  </div>
                );
              })
            )}
          </div>

          {/* Actions Footer */}
          <div className="pt-1.5">
            <button
              type="button"
              onClick={() => {
                setIsOpen(false);
                setActiveTab('management');
              }}
              className="w-full flex items-center justify-center space-x-1.5 px-3 py-2 rounded-lg text-xs font-medium text-blue-400 hover:bg-blue-500/10 hover:text-blue-300 transition-colors"
            >
              <Plus className="w-3.5 h-3.5" />
              <span>Manage Workspaces & RBAC</span>
            </button>
          </div>
        </div>
      )}
    </div>
  );
};
