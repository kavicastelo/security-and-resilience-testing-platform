import { create } from 'zustand';

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
