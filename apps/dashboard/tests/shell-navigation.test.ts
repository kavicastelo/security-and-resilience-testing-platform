import { describe, it, expect, beforeEach } from 'vitest';
import { useAppStore } from '../src/store/useAppStore.js';

describe('Phase UI-01: Global Shell, Design System & Command Navigation', () => {
  beforeEach(() => {
    const { setActiveTab, setIsCommandPaletteOpen, setCurrentTenantId, setCurrentWorkspaceId } =
      useAppStore.getState();
    setActiveTab('overview');
    setIsCommandPaletteOpen(false);
    setCurrentTenantId('default');
    setCurrentWorkspaceId('default');
  });

  it('updates activeTab and closes mobile drawer on navigation', () => {
    const store = useAppStore.getState();
    expect(store.activeTab).toBe('overview');

    store.setActiveTab('targets');
    expect(useAppStore.getState().activeTab).toBe('targets');
    expect(useAppStore.getState().isMobileMenuOpen).toBe(false);

    store.setActiveTab('api-security');
    expect(useAppStore.getState().activeTab).toBe('api-security');
  });

  it('manages command palette modal open and close states', () => {
    const store = useAppStore.getState();
    expect(store.isCommandPaletteOpen).toBe(false);

    store.setIsCommandPaletteOpen(true);
    expect(useAppStore.getState().isCommandPaletteOpen).toBe(true);

    store.setIsCommandPaletteOpen(false);
    expect(useAppStore.getState().isCommandPaletteOpen).toBe(false);
  });

  it('tracks active tenant and workspace contexts', () => {
    const store = useAppStore.getState();
    expect(store.currentTenantId).toBe('default');
    expect(store.currentWorkspaceId).toBe('default');

    store.setCurrentTenantId('tenant-finance-corp');
    store.setCurrentWorkspaceId('ws-prod-security');

    expect(useAppStore.getState().currentTenantId).toBe('tenant-finance-corp');
    expect(useAppStore.getState().currentWorkspaceId).toBe('ws-prod-security');
  });

  it('supports all defined NavTabs across operational and lab domains', () => {
    const { setActiveTab } = useAppStore.getState();
    const testTabs = [
      'overview',
      'targets',
      'runs',
      'findings',
      'policies',
      'management',
      'api-security',
      'auth-vault',
      'authz-matrix',
      'resilience',
      'performance',
      'infra-supply-chain',
      'agent-fleet',
      'compliance',
      'governance',
      'integrations',
    ] as const;

    for (const tab of testTabs) {
      setActiveTab(tab);
      expect(useAppStore.getState().activeTab).toBe(tab);
    }
  });
});
