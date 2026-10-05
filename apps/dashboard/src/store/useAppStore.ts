import { create } from 'zustand';

export interface AppState {
  activeTab: 'overview' | 'targets' | 'runs' | 'findings' | 'policies';
  setActiveTab: (tab: AppState['activeTab']) => void;
  controllerStatus: 'checking' | 'connected' | 'disconnected';
  setControllerStatus: (status: AppState['controllerStatus']) => void;
}

export const useAppStore = create<AppState>((set) => ({
  activeTab: 'overview',
  setActiveTab: (activeTab) => set({ activeTab }),
  controllerStatus: 'checking',
  setControllerStatus: (controllerStatus) => set({ controllerStatus }),
}));
