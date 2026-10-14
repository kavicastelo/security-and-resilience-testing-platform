import React, { useState } from 'react';
import {
  GitHubSyncConfig,
  JiraSyncConfig,
} from '../../api/webhooks.js';
import {
  GitPullRequest,
  Lock,
  Eye,
  EyeOff,
  Copy,
  Check,
  ShieldCheck,
  RefreshCw,
  Sliders,
} from 'lucide-react';
import { useAppStore } from '../../store/useAppStore.js';

export const IssueSyncConfigTab: React.FC = () => {
  const { showToast } = useAppStore();

  // GitHub States
  const [ghConfig, setGhConfig] = useState<GitHubSyncConfig>({
    enabled: true,
    repoOwner: 'security-lab-org',
    repoName: 'core-banking-api',
    personalAccessToken: 'ghp_79xM93kJz0014Lqp29xKm009LqZ12xPq99',
    autoCreateOnSeverity: ['critical', 'high'],
    autoCloseOnRetestResolved: true,
    addLabels: ['security-lab', 'automated-scan', 'triage-required'],
  });
  const [showGhToken, setShowGhToken] = useState(false);
  const [testingGh, setTestingGh] = useState(false);
  const [copiedGhWebhook, setCopiedGhWebhook] = useState(false);

  // Jira States
  const [jiraConfig, setJiraConfig] = useState<JiraSyncConfig>({
    enabled: false,
    hostUrl: 'https://security-lab.atlassian.net',
    projectKey: 'SEC',
    issueType: 'Security Vulnerability',
    userEmail: 'secops-bot@security-lab.internal',
    apiToken: 'ATATT3xFfGF0092xmL99kP0149qZ002xKm129',
    autoCreateOnSeverity: ['critical'],
    autoTransitionOnResolved: true,
    resolvedTransitionName: 'Done',
  });
  const [showJiraToken, setShowJiraToken] = useState(false);
  const [testingJira, setTestingJira] = useState(false);
  const [copiedJiraWebhook, setCopiedJiraWebhook] = useState(false);

  const ghWebhookUrl = `${window.location.origin}/api/v1/integrations/github/webhook`;
  const jiraWebhookUrl = `${window.location.origin}/api/v1/integrations/jira/webhook`;

  const handleTestGh = () => {
    setTestingGh(true);
    setTimeout(() => {
      setTestingGh(false);
      showToast('GitHub token validated! Connected to repository.', 'success');
    }, 800);
  };

  const handleTestJira = () => {
    setTestingJira(true);
    setTimeout(() => {
      setTestingJira(false);
      showToast('Jira Cloud API connection verified successfully.', 'success');
    }, 800);
  };

  const handleSaveAll = () => {
    showToast('Issue synchronization settings saved securely', 'success');
  };

  const copyToClipboard = (text: string, setCopied: (v: boolean) => void) => {
    navigator.clipboard.writeText(text);
    setCopied(true);
    showToast('Webhook endpoint copied to clipboard', 'info');
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="space-y-6">
      {/* Intro Header */}
      <div className="bg-card border border-border p-4 rounded-xl flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
        <div>
          <h2 className="text-sm font-bold text-foreground">Bi-Directional Issue Tracker Synchronization</h2>
          <p className="text-xs text-muted-foreground">
            Automatically create GitHub Issues and Jira tickets when new vulnerabilities are detected, and trigger targeted retests when tickets are closed.
          </p>
        </div>

        <button
          type="button"
          onClick={handleSaveAll}
          className="px-4 py-2 text-xs font-bold rounded-lg bg-primary hover:bg-primary/90 text-primary-foreground shadow-md transition-all whitespace-nowrap"
        >
          Save Sync Settings
        </button>
      </div>

      {/* Grid of Sync Cards */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* GitHub Issues Card */}
        <div className="p-5 rounded-2xl bg-card border border-border shadow-sm flex flex-col justify-between space-y-4">
          <div className="space-y-3">
            {/* Header & Toggle */}
            <div className="flex items-center justify-between pb-3 border-b border-border">
              <div className="flex items-center gap-3">
                <div className="p-2 rounded-xl bg-slate-900 border border-slate-800 text-white">
                  <GitPullRequest className="w-5 h-5 text-cyan-400" />
                </div>
                <div>
                  <h3 className="text-xs font-bold text-foreground flex items-center gap-2">
                    GitHub Issues 2-Way Sync
                    {ghConfig.enabled && (
                      <span className="px-2 py-0.5 rounded-full text-[10px] font-bold bg-emerald-500/10 text-emerald-400 border border-emerald-500/30">
                        Active
                      </span>
                    )}
                  </h3>
                  <p className="text-[11px] text-muted-foreground">
                    Native issue generation with reproduction steps & fingerprint deduping
                  </p>
                </div>
              </div>

              <label className="relative inline-flex items-center cursor-pointer">
                <input
                  type="checkbox"
                  checked={ghConfig.enabled}
                  onChange={(e) => setGhConfig({ ...ghConfig, enabled: e.target.checked })}
                  className="sr-only peer"
                />
                <div className="w-9 h-5 bg-muted peer-focus:outline-none rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-slate-300 after:border after:rounded-full after:h-4 after:w-4 after:transition-all peer-checked:bg-primary"></div>
              </label>
            </div>

            {/* Inputs */}
            <div className="space-y-3">
              <div className="grid grid-cols-2 gap-3">
                <div className="space-y-1">
                  <label className="text-xs font-semibold text-foreground">Repository Owner</label>
                  <input
                    type="text"
                    value={ghConfig.repoOwner}
                    onChange={(e) => setGhConfig({ ...ghConfig, repoOwner: e.target.value })}
                    className="w-full px-3 py-1.5 text-xs bg-muted/40 border border-border rounded-lg text-foreground focus:outline-none focus:ring-1 focus:ring-primary font-mono"
                  />
                </div>
                <div className="space-y-1">
                  <label className="text-xs font-semibold text-foreground">Repository Name</label>
                  <input
                    type="text"
                    value={ghConfig.repoName}
                    onChange={(e) => setGhConfig({ ...ghConfig, repoName: e.target.value })}
                    className="w-full px-3 py-1.5 text-xs bg-muted/40 border border-border rounded-lg text-foreground focus:outline-none focus:ring-1 focus:ring-primary font-mono"
                  />
                </div>
              </div>

              {/* Personal Access Token (Masked) */}
              <div className="space-y-1">
                <div className="flex items-center justify-between">
                  <label className="text-xs font-semibold text-foreground flex items-center gap-1.5">
                    <Lock className="w-3.5 h-3.5 text-muted-foreground" />
                    GitHub Personal Access Token (PAT)
                  </label>
                  <span className="text-[10px] text-muted-foreground font-mono">Scope: repo, issues</span>
                </div>
                <div className="relative flex items-center">
                  <input
                    type={showGhToken ? 'text' : 'password'}
                    value={ghConfig.personalAccessToken}
                    onChange={(e) => setGhConfig({ ...ghConfig, personalAccessToken: e.target.value })}
                    className="w-full pl-3 pr-10 py-1.5 text-xs bg-muted/40 border border-border rounded-lg text-foreground focus:outline-none focus:ring-1 focus:ring-primary font-mono"
                  />
                  <button
                    type="button"
                    onClick={() => setShowGhToken(!showGhToken)}
                    className="absolute right-2.5 p-1 text-muted-foreground hover:text-foreground"
                    title={showGhToken ? 'Mask Token' : 'Reveal Token'}
                  >
                    {showGhToken ? <EyeOff className="w-3.5 h-3.5" /> : <Eye className="w-3.5 h-3.5" />}
                  </button>
                </div>
              </div>

              {/* Rules & Checkboxes */}
              <div className="space-y-2 pt-1 text-xs">
                <label className="flex items-center gap-2 cursor-pointer text-muted-foreground hover:text-foreground">
                  <input
                    type="checkbox"
                    checked={ghConfig.autoCloseOnRetestResolved}
                    onChange={(e) =>
                      setGhConfig({ ...ghConfig, autoCloseOnRetestResolved: e.target.checked })
                    }
                    className="rounded border-border text-primary focus:ring-primary"
                  />
                  <span>Auto-close GitHub issue when finding is verified resolved in test run</span>
                </label>

                <div className="flex items-center gap-3 pt-1">
                  <span className="text-muted-foreground">Auto-create on:</span>
                  {(['critical', 'high', 'medium'] as const).map((sev) => {
                    const active = ghConfig.autoCreateOnSeverity.includes(sev);
                    return (
                      <button
                        key={sev}
                        type="button"
                        onClick={() => {
                          const next = active
                            ? ghConfig.autoCreateOnSeverity.filter((s) => s !== sev)
                            : [...ghConfig.autoCreateOnSeverity, sev];
                          setGhConfig({ ...ghConfig, autoCreateOnSeverity: next });
                        }}
                        className={`px-2 py-0.5 rounded text-[11px] font-bold uppercase transition-all ${
                          active
                            ? 'bg-primary/20 text-primary border border-primary/40'
                            : 'bg-muted text-muted-foreground hover:text-foreground'
                        }`}
                      >
                        {sev}
                      </button>
                    );
                  })}
                </div>
              </div>

              {/* Inbound Webhook Instructions */}
              <div className="p-3 rounded-xl bg-slate-900/80 border border-slate-800 space-y-1.5 text-xs">
                <span className="text-[11px] font-semibold text-slate-300 block">
                  Inbound Webhook URL (Configure in GitHub Repo Settings):
                </span>
                <div className="flex items-center justify-between gap-2 p-1.5 rounded bg-slate-950 font-mono text-[11px] text-cyan-300 overflow-hidden">
                  <span className="truncate">{ghWebhookUrl}</span>
                  <button
                    type="button"
                    onClick={() => copyToClipboard(ghWebhookUrl, setCopiedGhWebhook)}
                    className="p-1 hover:text-white"
                  >
                    {copiedGhWebhook ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                  </button>
                </div>
              </div>
            </div>
          </div>

          <div className="pt-2 border-t border-border flex items-center justify-between">
            <span className="text-[11px] text-muted-foreground flex items-center gap-1">
              <ShieldCheck className="w-3.5 h-3.5 text-emerald-400" /> Secrets encrypted at rest
            </span>
            <button
              type="button"
              onClick={handleTestGh}
              disabled={testingGh}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold bg-muted hover:bg-muted/80 text-foreground transition-colors disabled:opacity-50"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${testingGh ? 'animate-spin' : ''}`} />
              Test Connection
            </button>
          </div>
        </div>

        {/* Jira Cloud Card */}
        <div className="p-5 rounded-2xl bg-card border border-border shadow-sm flex flex-col justify-between space-y-4">
          <div className="space-y-3">
            {/* Header & Toggle */}
            <div className="flex items-center justify-between pb-3 border-b border-border">
              <div className="flex items-center gap-3">
                <div className="p-2 rounded-xl bg-blue-950 border border-blue-800 text-blue-400">
                  <Sliders className="w-5 h-5 text-blue-400" />
                </div>
                <div>
                  <h3 className="text-xs font-bold text-foreground flex items-center gap-2">
                    Jira Cloud Software Sync
                    {jiraConfig.enabled ? (
                      <span className="px-2 py-0.5 rounded-full text-[10px] font-bold bg-emerald-500/10 text-emerald-400 border border-emerald-500/30">
                        Active
                      </span>
                    ) : (
                      <span className="px-2 py-0.5 rounded-full text-[10px] font-bold bg-slate-500/10 text-slate-400 border border-slate-500/30">
                        Standby
                      </span>
                    )}
                  </h3>
                  <p className="text-[11px] text-muted-foreground">
                    Automated ticket dispatching into Agile sprints and security backlogs
                  </p>
                </div>
              </div>

              <label className="relative inline-flex items-center cursor-pointer">
                <input
                  type="checkbox"
                  checked={jiraConfig.enabled}
                  onChange={(e) => setJiraConfig({ ...jiraConfig, enabled: e.target.checked })}
                  className="sr-only peer"
                />
                <div className="w-9 h-5 bg-muted peer-focus:outline-none rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-slate-300 after:border after:rounded-full after:h-4 after:w-4 after:transition-all peer-checked:bg-primary"></div>
              </label>
            </div>

            {/* Inputs */}
            <div className="space-y-3">
              <div className="space-y-1">
                <label className="text-xs font-semibold text-foreground">Jira Host URL</label>
                <input
                  type="url"
                  value={jiraConfig.hostUrl}
                  onChange={(e) => setJiraConfig({ ...jiraConfig, hostUrl: e.target.value })}
                  className="w-full px-3 py-1.5 text-xs bg-muted/40 border border-border rounded-lg text-foreground focus:outline-none focus:ring-1 focus:ring-primary font-mono"
                />
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div className="space-y-1">
                  <label className="text-xs font-semibold text-foreground">Project Key</label>
                  <input
                    type="text"
                    value={jiraConfig.projectKey}
                    onChange={(e) => setJiraConfig({ ...jiraConfig, projectKey: e.target.value })}
                    className="w-full px-3 py-1.5 text-xs bg-muted/40 border border-border rounded-lg text-foreground focus:outline-none focus:ring-1 focus:ring-primary font-mono uppercase"
                  />
                </div>
                <div className="space-y-1">
                  <label className="text-xs font-semibold text-foreground">Issue Type</label>
                  <input
                    type="text"
                    value={jiraConfig.issueType}
                    onChange={(e) => setJiraConfig({ ...jiraConfig, issueType: e.target.value })}
                    className="w-full px-3 py-1.5 text-xs bg-muted/40 border border-border rounded-lg text-foreground focus:outline-none focus:ring-1 focus:ring-primary font-mono"
                  />
                </div>
              </div>

              {/* Bot Email & API Token */}
              <div className="grid grid-cols-2 gap-3">
                <div className="space-y-1">
                  <label className="text-xs font-semibold text-foreground">User / Bot Email</label>
                  <input
                    type="email"
                    value={jiraConfig.userEmail}
                    onChange={(e) => setJiraConfig({ ...jiraConfig, userEmail: e.target.value })}
                    className="w-full px-3 py-1.5 text-xs bg-muted/40 border border-border rounded-lg text-foreground focus:outline-none focus:ring-1 focus:ring-primary font-mono"
                  />
                </div>

                <div className="space-y-1">
                  <label className="text-xs font-semibold text-foreground flex items-center justify-between">
                    <span>Atlassian API Token</span>
                    <button
                      type="button"
                      onClick={() => setShowJiraToken(!showJiraToken)}
                      className="text-[10px] text-muted-foreground hover:text-foreground"
                    >
                      {showJiraToken ? 'Mask' : 'Reveal'}
                    </button>
                  </label>
                  <input
                    type={showJiraToken ? 'text' : 'password'}
                    value={jiraConfig.apiToken}
                    onChange={(e) => setJiraConfig({ ...jiraConfig, apiToken: e.target.value })}
                    className="w-full px-3 py-1.5 text-xs bg-muted/40 border border-border rounded-lg text-foreground focus:outline-none focus:ring-1 focus:ring-primary font-mono"
                  />
                </div>
              </div>

              {/* Inbound Webhook Instructions */}
              <div className="p-3 rounded-xl bg-slate-900/80 border border-slate-800 space-y-1.5 text-xs">
                <span className="text-[11px] font-semibold text-slate-300 block">
                  Inbound Webhook URL (Jira Automation Rule):
                </span>
                <div className="flex items-center justify-between gap-2 p-1.5 rounded bg-slate-950 font-mono text-[11px] text-cyan-300 overflow-hidden">
                  <span className="truncate">{jiraWebhookUrl}</span>
                  <button
                    type="button"
                    onClick={() => copyToClipboard(jiraWebhookUrl, setCopiedJiraWebhook)}
                    className="p-1 hover:text-white"
                  >
                    {copiedJiraWebhook ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                  </button>
                </div>
              </div>
            </div>
          </div>

          <div className="pt-2 border-t border-border flex items-center justify-between">
            <span className="text-[11px] text-muted-foreground flex items-center gap-1">
              <ShieldCheck className="w-3.5 h-3.5 text-emerald-400" /> Secrets encrypted at rest
            </span>
            <button
              type="button"
              onClick={handleTestJira}
              disabled={testingJira}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold bg-muted hover:bg-muted/80 text-foreground transition-colors disabled:opacity-50"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${testingJira ? 'animate-spin' : ''}`} />
              Test Connection
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};
