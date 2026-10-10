import { create } from 'zustand';
import {
  getStoredApiKey,
  setStoredApiKey,
  clearStoredApiKey,
  getStoredAdminKey,
  setStoredAdminKey,
  clearStoredAdminKey,
} from '../api/client.js';

export interface ToastMessage {
  id: string;
  message: string;
  type: 'success' | 'error' | 'info';
}

export interface AppState {
  activeTab: 'overview' | 'targets' | 'runs' | 'findings' | 'policies' | 'management';
  setActiveTab: (tab: AppState['activeTab']) => void;
  controllerStatus: 'checking' | 'connected' | 'disconnected';
  setControllerStatus: (status: AppState['controllerStatus']) => void;
  isMobileMenuOpen: boolean;
  setIsMobileMenuOpen: (open: boolean) => void;
  isAuthModalOpen: boolean;
  setIsAuthModalOpen: (open: boolean) => void;
  apiKey: string;
  setApiKey: (key: string, persist?: boolean) => void;
  clearApiKey: () => void;
  adminKey: string;
  setAdminKey: (key: string, persist?: boolean) => void;
  clearAdminKey: () => void;
  setCredentials: (apiKey: string, adminKey?: string, persist?: boolean) => void;
  toast: ToastMessage | null;
  showToast: (message: string, type?: ToastMessage['type']) => void;
  hideToast: () => void;
}

export const useAppStore = create<AppState>((set) => ({
  activeTab: 'overview',
  setActiveTab: (activeTab) => set({ activeTab, isMobileMenuOpen: false }),
  controllerStatus: 'checking',
  setControllerStatus: (controllerStatus) => set({ controllerStatus }),
  isMobileMenuOpen: false,
  setIsMobileMenuOpen: (isMobileMenuOpen) => set({ isMobileMenuOpen }),
  isAuthModalOpen: false,
  setIsAuthModalOpen: (isAuthModalOpen) => set({ isAuthModalOpen }),
  apiKey: getStoredApiKey(),
  setApiKey: (key: string, persist = true) => {
    setStoredApiKey(key, persist);
    set({ apiKey: key.trim(), isAuthModalOpen: false });
    if (typeof window !== 'undefined') {
      window.dispatchEvent(new CustomEvent('security-lab:auth-changed', { detail: { apiKey: key.trim() } }));
    }
  },
  clearApiKey: () => {
    clearStoredApiKey();
    set({ apiKey: '', adminKey: '' });
    if (typeof window !== 'undefined') {
      window.dispatchEvent(new CustomEvent('security-lab:auth-changed', { detail: { apiKey: '', adminKey: '' } }));
    }
  },
  adminKey: getStoredAdminKey(),
  setAdminKey: (key: string, persist = true) => {
    setStoredAdminKey(key, persist);
    set({ adminKey: key.trim() });
    if (typeof window !== 'undefined') {
      window.dispatchEvent(new CustomEvent('security-lab:auth-changed', { detail: { adminKey: key.trim() } }));
    }
  },
  clearAdminKey: () => {
    clearStoredAdminKey();
    set({ adminKey: '' });
    if (typeof window !== 'undefined') {
      window.dispatchEvent(new CustomEvent('security-lab:auth-changed', { detail: { adminKey: '' } }));
    }
  },
  setCredentials: (apiKey: string, adminKey?: string, persist = true) => {
    setStoredApiKey(apiKey, persist);
    if (adminKey !== undefined && adminKey.trim().length > 0) {
      setStoredAdminKey(adminKey, persist);
    } else {
      clearStoredAdminKey();
    }
    const resolvedAdmin = adminKey ? adminKey.trim() : apiKey.trim();
    set({ apiKey: apiKey.trim(), adminKey: resolvedAdmin, isAuthModalOpen: false });
    if (typeof window !== 'undefined') {
      window.dispatchEvent(
        new CustomEvent('security-lab:auth-changed', {
          detail: { apiKey: apiKey.trim(), adminKey: resolvedAdmin },
        }),
      );
    }
  },

  toast: null,
  showToast: (message, type = 'success') => {
    const id = String(Date.now());
    set({ toast: { id, message, type } });
    setTimeout(() => {
      set((state) => (state.toast?.id === id ? { toast: null } : state));
    }, 4000);
  },
  hideToast: () => set({ toast: null }),
}));
