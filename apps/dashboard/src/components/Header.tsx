import React from 'react';
import { Shield, Terminal, Menu, X, Key } from 'lucide-react';
import { HealthBadge } from './HealthBadge.js';
import { useAppStore } from '../store/useAppStore.js';

export const Header: React.FC = () => {
  const { isMobileMenuOpen, setIsMobileMenuOpen, setIsAuthModalOpen, apiKey } = useAppStore();

  return (
    <header className="h-16 border-b border-border bg-card/60 backdrop-blur-md px-4 sm:px-6 flex items-center justify-between sticky top-0 z-50">
      <div className="flex items-center space-x-3">
        <button
          type="button"
          onClick={() => setIsMobileMenuOpen(!isMobileMenuOpen)}
          className="md:hidden p-2 rounded-lg bg-accent/60 text-muted-foreground hover:text-foreground hover:bg-accent focus:outline-none transition-colors"
          aria-label="Toggle Navigation Menu"
        >
          {isMobileMenuOpen ? <X className="w-5 h-5 text-blue-400" /> : <Menu className="w-5 h-5" />}
        </button>

        <div className="p-2 rounded-lg bg-primary/10 border border-primary/20">
          <Shield className="w-5 h-5 text-blue-500" />
        </div>
        <div>
          <div className="flex items-center space-x-2">
            <h1 className="font-semibold text-sm tracking-tight text-foreground">
              Security Lab
            </h1>
            <span className="text-[10px] font-mono uppercase bg-primary/20 text-blue-400 px-1.5 py-0.5 rounded border border-primary/30">
              Lab Edition
            </span>
          </div>
          <p className="text-xs text-muted-foreground hidden sm:block">Security QA for Enterprise Applications</p>
        </div>
      </div>

      <div className="flex items-center space-x-3 sm:space-x-4">
        <div className="hidden lg:flex items-center space-x-2 text-xs text-muted-foreground bg-accent/60 px-3 py-1.5 rounded-md border border-border">
          <Terminal className="w-3.5 h-3.5 text-blue-400" />
          <span className="font-mono">security-lab --help</span>
        </div>
        <button
          type="button"
          onClick={() => setIsAuthModalOpen(true)}
          className={`flex items-center space-x-1.5 text-xs px-2.5 py-1.5 rounded-md border transition-colors ${
            apiKey
              ? 'bg-blue-500/10 text-blue-400 border-blue-500/20 hover:bg-blue-500/20'
              : 'bg-amber-500/10 text-amber-400 border-amber-500/20 hover:bg-amber-500/20'
          }`}
          title={apiKey ? 'API Key Configured' : 'API Key Missing - Click to configure'}
        >
          <Key className="w-3.5 h-3.5" />
          <span className="hidden sm:inline">{apiKey ? 'Auth: Active' : 'Set API Key'}</span>
        </button>
        <HealthBadge />
      </div>
    </header>
  );
};
