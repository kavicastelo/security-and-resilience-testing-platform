import React, { useEffect } from 'react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { Header } from './components/Header.js';
import { Sidebar } from './components/Sidebar.js';
import { Overview } from './components/Overview.js';
import { TargetsView } from './components/TargetsView.js';
import { RunsView } from './components/RunsView.js';
import { FindingsView } from './components/FindingsView.js';
import { useAppStore } from './store/useAppStore.js';

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      refetchOnWindowFocus: false,
      staleTime: 5000,
    },
  },
});

export const AppContent: React.FC = () => {
  const { activeTab, setActiveTab } = useAppStore();

  useEffect(() => {
    const handleNavigate = (e: Event) => {
      const customEvent = e as CustomEvent;
      if (customEvent.detail) {
        setActiveTab(customEvent.detail);
      }
    };

    window.addEventListener('navigate-tab', handleNavigate);
    return () => window.removeEventListener('navigate-tab', handleNavigate);
  }, [setActiveTab]);

  return (
    <div className="min-h-screen flex flex-col bg-background text-foreground">
      <Header />
      <div className="flex flex-1">
        <Sidebar />
        <main className="flex-1 p-8 overflow-y-auto">
          {activeTab === 'overview' && <Overview />}
          {activeTab === 'targets' && <TargetsView />}
          {activeTab === 'runs' && <RunsView />}
          {activeTab === 'findings' && <FindingsView />}
          {activeTab === 'policies' && (
            <div className="p-8 border border-dashed border-border rounded-xl text-center space-y-3">
              <h3 className="text-base font-semibold capitalize text-foreground">
                Release Gate Policies
              </h3>
              <p className="text-sm text-muted-foreground max-w-md mx-auto">
                Security boundary and release gate evaluation policies will be enabled in Phase 3.
              </p>
              <div className="inline-block text-xs font-mono bg-accent px-3 py-1 rounded text-blue-400">
                Status: PLANNED (Phase 3)
              </div>
            </div>
          )}
        </main>
      </div>
    </div>
  );
};

export const App: React.FC = () => {
  return (
    <QueryClientProvider client={queryClient}>
      <AppContent />
    </QueryClientProvider>
  );
};

export default App;
