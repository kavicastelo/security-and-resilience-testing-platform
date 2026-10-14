import React, { useState } from 'react';
import {
  X,
  Copy,
  Check,
  Key,
  Terminal,
  Server,
  FileCode,
  Shield,
  Eye,
  EyeOff,
  Sparkles,
} from 'lucide-react';
import { generateEnrollmentToken, AgentEnrollmentCommand } from '../../api/agents.js';

export interface AgentEnrollmentModalProps {
  isOpen: boolean;
  onClose: () => void;
  className?: string;
}

export const AgentEnrollmentModal: React.FC<AgentEnrollmentModalProps> = ({
  isOpen,
  onClose,
  className = '',
}) => {
  const [name, setName] = useState('runner-prod-worker');
  const [expiresInDays, setExpiresInDays] = useState(30);
  const [tags, setTags] = useState('vpc-production,high-concurrency');
  const [commandData, setCommandData] = useState<AgentEnrollmentCommand | null>(null);
  const [activeSnippetTab, setActiveSnippetTab] = useState<'docker' | 'k8s' | 'node' | 'systemd'>('docker');
  const [isGenerating, setIsGenerating] = useState(false);
  const [showToken, setShowToken] = useState(false);
  const [copiedSnippet, setCopiedSnippet] = useState(false);
  const [copiedToken, setCopiedToken] = useState(false);

  if (!isOpen) return null;

  const handleGenerate = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsGenerating(true);
    const parsedTags = tags.split(',').map((t) => t.trim()).filter(Boolean);
    const res = await generateEnrollmentToken({
      name,
      expiresInDays,
      tags: parsedTags,
    });
    setCommandData(res);
    setIsGenerating(false);
  };

  const copyToClipboard = (text: string, isTokenOnly = false) => {
    navigator.clipboard.writeText(text);
    if (isTokenOnly) {
      setCopiedToken(true);
      setTimeout(() => setCopiedToken(false), 2500);
    } else {
      setCopiedSnippet(true);
      setTimeout(() => setCopiedSnippet(false), 2500);
    }
  };

  const getSnippetContent = () => {
    if (!commandData) return '';
    switch (activeSnippetTab) {
      case 'docker':
        return commandData.dockerCommand;
      case 'k8s':
        return commandData.k8sSnippet;
      case 'node':
        return commandData.nodeCliCommand;
      case 'systemd':
        return commandData.systemdSnippet;
    }
  };

  return (
    <div className={`fixed inset-0 z-50 flex items-center justify-center p-4 bg-background/80 backdrop-blur-md animate-in fade-in duration-200 ${className}`}>
      <div className="relative w-full max-w-2xl rounded-2xl bg-card border border-border/80 shadow-2xl overflow-hidden flex flex-col max-h-[90vh]">
        {/* Modal Header */}
        <div className="p-5 border-b border-border/40 flex items-center justify-between">
          <div className="flex items-center gap-2.5">
            <div className="p-2 rounded-xl bg-purple-500/10 text-purple-400 border border-purple-500/20">
              <Key className="w-5 h-5" />
            </div>
            <div>
              <h2 className="text-base font-bold text-foreground">Enroll Distributed Agent Node</h2>
              <p className="text-xs text-muted-foreground">
                Generate cryptographic enrollment keys and copy ready-to-run daemon deployment commands.
              </p>
            </div>
          </div>

          <button
            type="button"
            onClick={onClose}
            className="p-1.5 rounded-lg text-muted-foreground hover:text-foreground hover:bg-muted/50 transition-colors"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Modal Body */}
        <div className="p-5 overflow-y-auto space-y-5 text-xs">
          {/* Token Configuration Form */}
          <form onSubmit={handleGenerate} className="grid grid-cols-1 sm:grid-cols-3 gap-3">
            <div>
              <label className="text-[11px] font-medium text-foreground block mb-1">
                Runner Name Prefix
              </label>
              <input
                type="text"
                value={name}
                onChange={(e) => setName(e.target.value)}
                required
                className="w-full text-xs font-mono bg-background/80 border border-border/60 rounded-xl px-3 py-2 text-foreground focus:outline-none focus:ring-1 focus:ring-purple-500"
              />
            </div>

            <div>
              <label className="text-[11px] font-medium text-foreground block mb-1">
                Capability Tags (CSV)
              </label>
              <input
                type="text"
                value={tags}
                onChange={(e) => setTags(e.target.value)}
                placeholder="vpc-prod,high-concurrency"
                className="w-full text-xs font-mono bg-background/80 border border-border/60 rounded-xl px-3 py-2 text-foreground focus:outline-none focus:ring-1 focus:ring-purple-500"
              />
            </div>

            <div>
              <label className="text-[11px] font-medium text-foreground block mb-1">
                Key Validity Window
              </label>
              <select
                value={expiresInDays}
                onChange={(e) => setExpiresInDays(Number(e.target.value))}
                className="w-full text-xs font-mono bg-background/80 border border-border/60 rounded-xl px-3 py-2 text-foreground focus:outline-none focus:ring-1 focus:ring-purple-500 cursor-pointer"
              >
                <option value={7}>7 Days</option>
                <option value={30}>30 Days</option>
                <option value={90}>90 Days</option>
                <option value={365}>1 Year</option>
              </select>
            </div>

            <div className="sm:col-span-3 flex justify-end">
              <button
                type="submit"
                disabled={isGenerating}
                className="flex items-center gap-1.5 px-4 py-2 rounded-xl text-xs font-semibold bg-gradient-to-r from-purple-600 to-indigo-600 hover:from-purple-500 hover:to-indigo-500 text-white shadow-lg shadow-purple-500/20 transition-all"
              >
                <Sparkles className="w-3.5 h-3.5" />
                <span>{commandData ? 'Regenerate Enrollment Token' : 'Generate Token & Commands'}</span>
              </button>
            </div>
          </form>

          {/* Generated Deployment Commands & Snippets */}
          {commandData && (
            <div className="space-y-4 pt-3 border-t border-border/40 animate-in fade-in">
              {/* Token Reveal & Copy Bar */}
              <div className="p-3 rounded-xl bg-background/90 border border-border/60 space-y-1.5">
                <div className="flex items-center justify-between text-[11px] text-muted-foreground font-mono">
                  <span className="flex items-center gap-1 text-foreground font-semibold">
                    <Shield className="w-3.5 h-3.5 text-purple-400" />
                    Tenant Enrollment Key (TEK):
                  </span>
                  <span>Expires: {new Date(commandData.expiresAt).toLocaleDateString()}</span>
                </div>

                <div className="flex items-center gap-2">
                  <div className="flex-1 font-mono text-[11px] text-purple-300 bg-black/60 px-3 py-1.5 rounded-lg border border-border/40 truncate select-all">
                    {showToken
                      ? commandData.token
                      : `${commandData.keyPrefix}${'•'.repeat(24)}`}
                  </div>

                  <button
                    type="button"
                    onClick={() => setShowToken(!showToken)}
                    className="p-1.5 rounded-lg border border-border/50 text-muted-foreground hover:text-foreground"
                    title={showToken ? 'Mask Token' : 'Reveal Token'}
                  >
                    {showToken ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                  </button>

                  <button
                    type="button"
                    onClick={() => copyToClipboard(commandData.token, true)}
                    className="flex items-center gap-1 px-3 py-1.5 rounded-lg bg-purple-500/15 hover:bg-purple-500/25 text-purple-300 border border-purple-500/30 transition-colors font-mono"
                  >
                    {copiedToken ? (
                      <>
                        <Check className="w-3.5 h-3.5 text-emerald-400" />
                        <span className="text-emerald-400">Copied!</span>
                      </>
                    ) : (
                      <>
                        <Copy className="w-3.5 h-3.5" />
                        <span>Copy Key</span>
                      </>
                    )}
                  </button>
                </div>
              </div>

              {/* Multi-Format Execution Snippets */}
              <div className="space-y-2">
                <div className="flex items-center justify-between">
                  {/* Tab Selector */}
                  <div className="flex items-center gap-1 bg-background/80 p-1 rounded-xl border border-border/50 font-mono text-[11px]">
                    <button
                      type="button"
                      onClick={() => setActiveSnippetTab('docker')}
                      className={`flex items-center gap-1 px-2.5 py-1 rounded-lg transition-colors ${
                        activeSnippetTab === 'docker'
                          ? 'bg-purple-500/20 text-purple-300'
                          : 'text-muted-foreground'
                      }`}
                    >
                      <Server className="w-3 h-3" />
                      <span>Docker</span>
                    </button>

                    <button
                      type="button"
                      onClick={() => setActiveSnippetTab('k8s')}
                      className={`flex items-center gap-1 px-2.5 py-1 rounded-lg transition-colors ${
                        activeSnippetTab === 'k8s'
                          ? 'bg-purple-500/20 text-purple-300'
                          : 'text-muted-foreground'
                      }`}
                    >
                      <FileCode className="w-3 h-3" />
                      <span>Kubernetes</span>
                    </button>

                    <button
                      type="button"
                      onClick={() => setActiveSnippetTab('node')}
                      className={`flex items-center gap-1 px-2.5 py-1 rounded-lg transition-colors ${
                        activeSnippetTab === 'node'
                          ? 'bg-purple-500/20 text-purple-300'
                          : 'text-muted-foreground'
                      }`}
                    >
                      <Terminal className="w-3 h-3" />
                      <span>Node CLI</span>
                    </button>

                    <button
                      type="button"
                      onClick={() => setActiveSnippetTab('systemd')}
                      className={`flex items-center gap-1 px-2.5 py-1 rounded-lg transition-colors ${
                        activeSnippetTab === 'systemd'
                          ? 'bg-purple-500/20 text-purple-300'
                          : 'text-muted-foreground'
                      }`}
                    >
                      <span>systemd</span>
                    </button>
                  </div>

                  {/* Copy Snippet Button */}
                  <button
                    type="button"
                    onClick={() => copyToClipboard(getSnippetContent())}
                    className="flex items-center gap-1 px-3 py-1.5 rounded-lg text-xs font-mono bg-background hover:bg-muted text-foreground border border-border/60 transition-colors"
                  >
                    {copiedSnippet ? (
                      <>
                        <Check className="w-3.5 h-3.5 text-emerald-400" />
                        <span className="text-emerald-400">Copied!</span>
                      </>
                    ) : (
                      <>
                        <Copy className="w-3.5 h-3.5 text-muted-foreground" />
                        <span>Copy Snippet</span>
                      </>
                    )}
                  </button>
                </div>

                {/* Code Block */}
                <div className="p-3.5 rounded-xl bg-black/80 border border-border/60 font-mono text-[11px] text-emerald-400 overflow-x-auto max-h-[220px] whitespace-pre select-text">
                  {getSnippetContent()}
                </div>
              </div>
            </div>
          )}
        </div>

        {/* Modal Footer */}
        <div className="p-4 border-t border-border/40 bg-background/50 flex justify-end">
          <button
            type="button"
            onClick={onClose}
            className="px-4 py-2 rounded-xl text-xs font-medium text-foreground bg-muted hover:bg-muted/80 transition-colors"
          >
            Done
          </button>
        </div>
      </div>
    </div>
  );
};
