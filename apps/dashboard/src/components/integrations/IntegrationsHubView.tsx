import React, { useState } from 'react';
import { WebhookManagerTab } from './WebhookManagerTab.js';
import { IssueSyncConfigTab } from './IssueSyncConfigTab.js';
import { GitHubActionGeneratorCard } from './GitHubActionGeneratorCard.js';
import {
  GitBranch,
  Radio,
  GitPullRequest,
  FileCode,
  ShieldCheck,
  Send,
  Clock,
} from 'lucide-react';

export type IntegrationTab = 'webhooks' | 'issue-sync' | 'github-actions';

export const IntegrationsHubView: React.FC = () => {
  const [activeTab, setActiveTab] = useState<IntegrationTab>('webhooks');

  return (
    <div className="space-y-6 animate-in fade-in duration-200">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-4 border-b border-border">
        <div className="space-y-1">
          <div className="flex items-center gap-2.5">
            <div className="p-2 rounded-xl bg-primary/10 border border-primary/20 text-primary">
              <GitBranch className="w-5 h-5" />
            </div>
            <h1 className="text-xl font-bold tracking-tight text-foreground">
              CI/CD Integrations, Webhook Manager & Issue Sync
            </h1>
            <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-cyan-500/15 text-cyan-400 border border-cyan-500/30 font-mono">
              HMAC-SHA256 &bull; CI/CD &bull; GitHub &bull; Jira
            </span>
          </div>
          <p className="text-xs text-muted-foreground max-w-3xl">
            Manage HMAC-SHA256 signed outbound webhooks with exponential backoff queues, configure two-way GitHub & Jira issue synchronization, and generate GitHub Actions workflow YAML.
          </p>
        </div>
      </div>

      {/* Top Stat KPI Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {/* Active Webhooks */}
        <div className="p-4 rounded-xl bg-card border border-border shadow-sm flex flex-col justify-between">
          <div className="flex items-center justify-between text-muted-foreground text-xs">
            <span className="font-semibold">Registered Webhooks</span>
            <Radio className="w-4 h-4 text-primary" />
          </div>
          <div className="mt-3">
            <div className="flex items-baseline gap-2">
              <span className="text-2xl font-bold font-mono text-foreground">3</span>
              <span className="text-xs text-emerald-400 font-medium">2 Active &bull; 1 Standby</span>
            </div>
            <p className="text-[11px] text-muted-foreground mt-1">
              HMAC-SHA256 envelope signed
            </p>
          </div>
        </div>

        {/* Successful Deliveries */}
        <div className="p-4 rounded-xl bg-card border border-border shadow-sm flex flex-col justify-between">
          <div className="flex items-center justify-between text-muted-foreground text-xs">
            <span className="font-semibold">Delivery Success Rate</span>
            <Send className="w-4 h-4 text-emerald-400" />
          </div>
          <div className="mt-3">
            <div className="flex items-baseline gap-2">
              <span className="text-2xl font-bold font-mono text-emerald-400">98.4%</span>
              <span className="text-xs text-muted-foreground">HTTP 200/202</span>
            </div>
            <p className="text-[11px] text-muted-foreground mt-1">
              Avg latency: 42ms
            </p>
          </div>
        </div>

        {/* Retry & Dead Letter Queue */}
        <div className="p-4 rounded-xl bg-card border border-border shadow-sm flex flex-col justify-between">
          <div className="flex items-center justify-between text-muted-foreground text-xs">
            <span className="font-semibold">Retry Queue</span>
            <Clock className="w-4 h-4 text-amber-400" />
          </div>
          <div className="mt-3">
            <div className="flex items-baseline gap-2">
              <span className="text-2xl font-bold font-mono text-amber-400">1</span>
              <span className="text-xs text-muted-foreground">in backoff queue</span>
            </div>
            <p className="text-[11px] text-muted-foreground mt-1">
              0 Dead Letters (Max 5 attempts)
            </p>
          </div>
        </div>

        {/* Issue Sync State */}
        <div className="p-4 rounded-xl bg-card border border-border shadow-sm flex flex-col justify-between">
          <div className="flex items-center justify-between text-muted-foreground text-xs">
            <span className="font-semibold">Issue Tracker Sync</span>
            <GitPullRequest className="w-4 h-4 text-cyan-400" />
          </div>
          <div className="mt-3">
            <div className="flex items-baseline gap-2">
              <span className="text-2xl font-bold font-mono text-foreground">GitHub</span>
              <span className="text-xs text-emerald-400 font-medium">Connected</span>
            </div>
            <p className="text-[11px] text-muted-foreground mt-1">
              Auto-close on verified retest
            </p>
          </div>
        </div>
      </div>

      {/* Navigation Sub-Tabs */}
      <div className="flex items-center gap-2 border-b border-border overflow-x-auto pb-1">
        <button
          type="button"
          onClick={() => setActiveTab('webhooks')}
          className={`flex items-center gap-2 px-4 py-2.5 text-xs font-semibold rounded-t-xl transition-all whitespace-nowrap border-b-2 ${
            activeTab === 'webhooks'
              ? 'border-primary text-foreground bg-card'
              : 'border-transparent text-muted-foreground hover:text-foreground hover:bg-muted/40'
          }`}
        >
          <Radio className="w-4 h-4 text-primary" />
          <span>Webhooks & Dispatcher</span>
        </button>

        <button
          type="button"
          onClick={() => setActiveTab('issue-sync')}
          className={`flex items-center gap-2 px-4 py-2.5 text-xs font-semibold rounded-t-xl transition-all whitespace-nowrap border-b-2 ${
            activeTab === 'issue-sync'
              ? 'border-primary text-foreground bg-card'
              : 'border-transparent text-muted-foreground hover:text-foreground hover:bg-muted/40'
          }`}
        >
          <GitPullRequest className="w-4 h-4 text-cyan-400" />
          <span>Issue Trackers (GitHub & Jira)</span>
        </button>

        <button
          type="button"
          onClick={() => setActiveTab('github-actions')}
          className={`flex items-center gap-2 px-4 py-2.5 text-xs font-semibold rounded-t-xl transition-all whitespace-nowrap border-b-2 ${
            activeTab === 'github-actions'
              ? 'border-primary text-foreground bg-card'
              : 'border-transparent text-muted-foreground hover:text-foreground hover:bg-muted/40'
          }`}
        >
          <FileCode className="w-4 h-4 text-purple-400" />
          <span>GitHub Actions Generator</span>
        </button>
      </div>

      {/* Active Tab Panel */}
      <div className="pt-2">
        {activeTab === 'webhooks' && <WebhookManagerTab />}
        {activeTab === 'issue-sync' && <IssueSyncConfigTab />}
        {activeTab === 'github-actions' && <GitHubActionGeneratorCard />}
      </div>

      {/* Mandatory Boundary Directive Footer */}
      <div className="text-[11px] text-muted-foreground border-t border-border pt-4 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-2">
        <span className="flex items-center gap-1.5">
          <ShieldCheck className="w-3.5 h-3.5 text-emerald-400" />
          <strong>Cryptographic Invariant:</strong> Webhook signing secrets and integration tokens are masked in the UI and envelope-encrypted at rest using AES-256-GCM.
        </span>
        <span className="font-mono text-slate-500">Security Lab Dispatcher v1.0</span>
      </div>
    </div>
  );
};
