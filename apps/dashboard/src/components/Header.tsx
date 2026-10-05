import React from 'react';
import { Shield, Terminal } from 'lucide-react';
import { HealthBadge } from './HealthBadge.js';

export const Header: React.FC = () => {
  return (
    <header className="h-16 border-b border-border bg-card/60 backdrop-blur-md px-6 flex items-center justify-between sticky top-0 z-50">
      <div className="flex items-center space-x-3">
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
          <p className="text-xs text-muted-foreground">Security QA for Enterprise Applications</p>
        </div>
      </div>

      <div className="flex items-center space-x-4">
        <div className="hidden md:flex items-center space-x-2 text-xs text-muted-foreground bg-accent px-3 py-1.5 rounded-md border border-border">
          <Terminal className="w-3.5 h-3.5 text-blue-400" />
          <span className="font-mono">security-lab --help</span>
        </div>
        <HealthBadge />
      </div>
    </header>
  );
};
