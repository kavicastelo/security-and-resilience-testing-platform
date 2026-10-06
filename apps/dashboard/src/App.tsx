import React, { useEffect } from 'react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { Header } from './components/Header.js';
import { Sidebar } from './components/Sidebar.js';
import { Overview } from './components/Overview.js';
import { TargetsView } from './components/TargetsView.js';
import { RunsView } from './components/RunsView.js';
import { FindingsView } from './components/FindingsView.js';
import { PoliciesView } from './components/PoliciesView.js';
import { ToastNotification } from './components/ToastNotification.js';
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
    <div className="min-h-screen flex flex-col bg-background text-foreground antialiased selection:bg-blue-600/30 selection:text-blue-200">
      <Header />
      <div className="flex flex-1 relative">
        <Sidebar />
        <main className="flex-1 p-4 sm:p-6 lg:p-8 overflow-y-auto max-w-7xl mx-auto w-full">
          {activeTab === 'overview' && <Overview />}
          {activeTab === 'targets' && <TargetsView />}
          {activeTab === 'runs' && <RunsView />}
          {activeTab === 'findings' && <FindingsView />}
          {activeTab === 'policies' && <PoliciesView />}
        </main>
      </div>
      <ToastNotification />
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
