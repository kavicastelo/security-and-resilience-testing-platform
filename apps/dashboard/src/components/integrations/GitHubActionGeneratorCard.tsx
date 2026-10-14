import React, { useState, useMemo } from 'react';
import {
  WorkflowGeneratorOptions,
  generateGitHubActionYaml,
} from '../../api/webhooks.js';
import {
  FileCode,
  Copy,
  Check,
  Download,
  Sliders,
  CheckCircle2,
  Info,
} from 'lucide-react';
import { useAppStore } from '../../store/useAppStore.js';

export const GitHubActionGeneratorCard: React.FC = () => {
  const { showToast } = useAppStore();
  const [copied, setCopied] = useState(false);

  // Configuration Form State
  const [targetUrl, setTargetUrl] = useState('https://api.target.internal');
  const [policyId, setPolicyId] = useState('strict-zero-tolerance');
  const [failOnBreach, setFailOnBreach] = useState(true);
  const [uploadSarif, setUploadSarif] = useState(true);
  const [postPrComment, setPostPrComment] = useState(true);
  const [timeoutMinutes, setTimeoutMinutes] = useState(15);
  const [triggers, setTriggers] = useState<WorkflowGeneratorOptions['triggerEvents']>([
    'push',
    'pull_request',
    'workflow_dispatch',
  ]);

  const toggleTrigger = (trigger: 'push' | 'pull_request' | 'workflow_dispatch' | 'schedule') => {
    if (triggers.includes(trigger)) {
      if (triggers.length > 1) {
        setTriggers(triggers.filter((t) => t !== trigger));
      } else {
        showToast('At least one trigger event is required', 'info');
      }
    } else {
      setTriggers([...triggers, trigger]);
    }
  };

  const workflowYaml = useMemo(() => {
    return generateGitHubActionYaml({
      triggerEvents: triggers,
      targetUrl,
      failOnPolicyBreach: failOnBreach,
      policyId,
      uploadSarif,
      postPrComment,
      runnerMode: 'controller-api',
      scanTimeoutMinutes: timeoutMinutes,
    });
  }, [triggers, targetUrl, failOnBreach, policyId, uploadSarif, postPrComment, timeoutMinutes]);

  const handleCopy = () => {
    navigator.clipboard.writeText(workflowYaml);
    setCopied(true);
    showToast('GitHub Actions workflow copied to clipboard', 'success');
    setTimeout(() => setCopied(false), 2000);
  };

  const handleDownload = () => {
    const blob = new Blob([workflowYaml], { type: 'text/yaml;charset=utf-8' });
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'security-lab.yml';
    document.body.appendChild(a);
    a.click();
    setTimeout(() => {
      window.URL.revokeObjectURL(url);
      document.body.removeChild(a);
    }, 1000);
    showToast('Downloaded .github/workflows/security-lab.yml', 'info');
  };

  return (
    <div className="space-y-6">
      {/* Intro Header */}
      <div className="bg-card border border-border p-4 rounded-xl flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
        <div>
          <h2 className="text-sm font-bold text-foreground">GitHub Actions Pipeline Workflow Generator</h2>
          <p className="text-xs text-muted-foreground">
            Configure automated release gates, SARIF scanning artifact uploads, and PR summaries with a single copyable workflow.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <button
            type="button"
            onClick={handleCopy}
            className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-semibold bg-muted hover:bg-muted/80 text-foreground rounded-lg transition-colors"
          >
            {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
            {copied ? 'Copied' : 'Copy YAML'}
          </button>
          <button
            type="button"
            onClick={handleDownload}
            className="inline-flex items-center gap-1.5 px-3.5 py-1.5 text-xs font-bold bg-primary hover:bg-primary/90 text-primary-foreground rounded-lg shadow-md transition-all"
          >
            <Download className="w-3.5 h-3.5" />
            Download File
          </button>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Left Side: Interactive Builder Controls */}
        <div className="lg:col-span-5 space-y-4 bg-card border border-border p-5 rounded-2xl shadow-sm">
          <div className="flex items-center gap-2 pb-3 border-b border-border text-xs font-bold text-foreground">
            <Sliders className="w-4 h-4 text-primary" />
            Pipeline Parameters
          </div>

          {/* Target URL */}
          <div className="space-y-1">
            <label className="text-xs font-semibold text-foreground">Target Endpoint URL</label>
            <input
              type="url"
              value={targetUrl}
              onChange={(e) => setTargetUrl(e.target.value)}
              className="w-full px-3 py-1.5 text-xs bg-muted/40 border border-border rounded-lg text-foreground focus:outline-none focus:ring-1 focus:ring-primary font-mono"
              placeholder="https://api.target.internal"
            />
          </div>

          {/* Policy Gate Selection */}
          <div className="space-y-1">
            <label className="text-xs font-semibold text-foreground">Release Gate Policy</label>
            <select
              value={policyId}
              onChange={(e) => setPolicyId(e.target.value)}
              className="w-full px-3 py-1.5 text-xs bg-muted/40 border border-border rounded-lg text-foreground focus:outline-none focus:ring-1 focus:ring-primary"
            >
              <option value="strict-zero-tolerance">Strict Zero Tolerance (Block on Critical/High)</option>
              <option value="pci-dss-baseline">PCI-DSS 4.0 Software Baseline</option>
              <option value="standard-quality-gate">Standard Quality Gate (Non-blocking Warnings)</option>
            </select>
          </div>

          {/* Trigger Events */}
          <div className="space-y-1.5 pt-1">
            <label className="text-xs font-semibold text-foreground block">Workflow Triggers</label>
            <div className="grid grid-cols-2 gap-2">
              {[
                { id: 'push', label: 'Git Push (main/dev)' },
                { id: 'pull_request', label: 'Pull Request' },
                { id: 'workflow_dispatch', label: 'Manual Trigger' },
                { id: 'schedule', label: 'Nightly Cron (02:00)' },
              ].map((t) => {
                const isSelected = triggers.includes(t.id as any);
                return (
                  <button
                    key={t.id}
                    type="button"
                    onClick={() => toggleTrigger(t.id as any)}
                    className={`p-2 rounded-lg text-left text-xs font-medium border transition-colors flex items-center justify-between ${
                      isSelected
                        ? 'bg-primary/10 border-primary/40 text-foreground'
                        : 'bg-muted/30 border-border text-muted-foreground hover:text-foreground'
                    }`}
                  >
                    <span>{t.label}</span>
                    {isSelected && <CheckCircle2 className="w-3.5 h-3.5 text-primary" />}
                  </button>
                );
              })}
            </div>
          </div>

          {/* Pipeline Options Checkboxes */}
          <div className="space-y-2 pt-2 border-t border-border text-xs">
            <label className="flex items-center gap-2 cursor-pointer text-muted-foreground hover:text-foreground">
              <input
                type="checkbox"
                checked={failOnBreach}
                onChange={(e) => setFailOnBreach(e.target.checked)}
                className="rounded border-border text-primary focus:ring-primary"
              />
              <span className="font-semibold text-foreground">Fail CI/CD build on policy breach</span>
            </label>

            <label className="flex items-center gap-2 cursor-pointer text-muted-foreground hover:text-foreground">
              <input
                type="checkbox"
                checked={uploadSarif}
                onChange={(e) => setUploadSarif(e.target.checked)}
                className="rounded border-border text-primary focus:ring-primary"
              />
              <span>Upload SARIF report to GitHub Security tab</span>
            </label>

            <label className="flex items-center gap-2 cursor-pointer text-muted-foreground hover:text-foreground">
              <input
                type="checkbox"
                checked={postPrComment}
                onChange={(e) => setPostPrComment(e.target.checked)}
                className="rounded border-border text-primary focus:ring-primary"
              />
              <span>Post automated release gate comment on Pull Requests</span>
            </label>
          </div>

          {/* Scan Timeout */}
          <div className="space-y-1 pt-2">
            <div className="flex items-center justify-between text-xs">
              <span className="font-semibold text-foreground">Scan Timeout</span>
              <span className="text-muted-foreground font-mono">{timeoutMinutes} minutes</span>
            </div>
            <input
              type="range"
              min="5"
              max="60"
              step="5"
              value={timeoutMinutes}
              onChange={(e) => setTimeoutMinutes(Number(e.target.value))}
              className="w-full h-1.5 bg-muted rounded-lg appearance-none cursor-pointer accent-primary"
            />
          </div>

          {/* Secrets Setup Callout */}
          <div className="p-3 rounded-xl bg-slate-900 border border-slate-800 text-slate-300 text-xs space-y-1.5">
            <div className="flex items-center gap-1.5 font-bold text-cyan-400">
              <Info className="w-3.5 h-3.5" />
              Required GitHub Repository Secrets
            </div>
            <p className="text-[11px] text-muted-foreground">
              Configure in <strong>Settings &gt; Secrets and variables &gt; Actions</strong>:
            </p>
            <div className="font-mono text-[11px] text-slate-300 space-y-0.5">
              <div><code>SECURITY_LAB_API_KEY</code> &bull; Operator API Key</div>
              <div><code>SECURITY_LAB_CONTROLLER_URL</code> &bull; Central Controller URL</div>
            </div>
          </div>
        </div>

        {/* Right Side: Syntax-Highlighted Code Editor Display */}
        <div className="lg:col-span-7 flex flex-col bg-slate-950 border border-border rounded-2xl shadow-xl overflow-hidden">
          <div className="flex items-center justify-between px-4 py-2.5 bg-slate-900/90 border-b border-slate-800 text-xs">
            <div className="flex items-center gap-2">
              <FileCode className="w-4 h-4 text-cyan-400" />
              <span className="font-mono font-bold text-slate-300">
                .github/workflows/security-lab.yml
              </span>
            </div>

            <div className="flex items-center gap-2">
              <button
                type="button"
                onClick={handleCopy}
                className="flex items-center gap-1 text-[11px] text-slate-400 hover:text-white"
              >
                {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                {copied ? 'Copied!' : 'Copy'}
              </button>
            </div>
          </div>

          <div className="p-4 flex-1 overflow-auto max-h-[500px]">
            <pre className="text-[11px] font-mono leading-relaxed text-slate-200 select-text">
              {workflowYaml}
            </pre>
          </div>
        </div>
      </div>
    </div>
  );
};
