import React, { useState, useEffect } from 'react';
import {
  X,
  Copy,
  Terminal,
  Clock,
  ArrowUpRight,
  ArrowDownLeft,
  ShieldAlert,
  FileCode,
  Hash,
  Check,
  Code2,
  Sparkles,
  ShieldCheck,
  CheckCircle2,
  AlertCircle,
  Loader2,
} from 'lucide-react';
import { useAppStore } from '../store/useAppStore.js';
import { generateCurlSnippet } from '../lib/curl.js';

export interface EvidenceData {
  id: string;
  testRunId: string;
  executionId: string;
  request?: {
    method: string;
    url: string;
    headers: Record<string, string>;
    body?: string;
  };
  response?: {
    statusCode: number;
    headers: Record<string, string>;
    body?: string;
    responseTimeMs?: number;
  };
  expected?: unknown;
  actual?: unknown;
  immutableHash: string;
  timestamp: string;
}

export interface AiRemediationProposal {
  id: string;
  findingId: string;
  explanation: string;
  gitDiff: string;
  confidenceScore: number;
  verifiedStatus: 'UNVERIFIED' | 'PASSED' | 'FAILED';
  model?: string;
  verificationOutput?: string;
  createdAt: string;
}

export interface EvidenceModalProps {
  isOpen: boolean;
  onClose: () => void;
  findingId?: string;
  findingTitle: string;
  findingSeverity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  category: string;
  evidence: EvidenceData | null;
  isLoading?: boolean;
}

export const EvidenceModal: React.FC<EvidenceModalProps> = ({
  isOpen,
  onClose,
  findingId,
  findingTitle,
  findingSeverity,
  category,
  evidence,
  isLoading = false,
}) => {
  const { showToast } = useAppStore();
  const apiUrl = import.meta.env.VITE_API_URL || 'http://localhost:4000';
  const [activeTab, setActiveTab] = useState<'request' | 'response' | 'diff' | 'curl' | 'raw' | 'ai'>('request');
  const [copiedKey, setCopiedKey] = useState<string | null>(null);

  // AI Remediation state
  const [remediations, setRemediations] = useState<AiRemediationProposal[]>([]);
  const [isGeneratingAi, setIsGeneratingAi] = useState(false);
  const [isVerifyingAi, setIsVerifyingAi] = useState(false);

  useEffect(() => {
    if (isOpen && findingId) {
      fetch(`${apiUrl}/api/v1/findings/${findingId}/remediation`)
        .then((res) => (res.ok ? res.json() : null))
        .then((data) => {
          if (data?.data && Array.isArray(data.data)) {
            setRemediations(data.data);
          }
        })
        .catch(() => {});
    }
  }, [isOpen, findingId, apiUrl]);

  const handleGenerateRemediation = async () => {
    if (!findingId) return;
    setIsGeneratingAi(true);
    try {
      const res = await fetch(`${apiUrl}/api/v1/findings/${findingId}/remediate`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ provider: 'mock' }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error?.message || 'Failed to synthesize AI remediation');
      setRemediations((prev) => [data.data, ...prev]);
      showToast('AI Remediation synthesized successfully', 'success');
    } catch (err) {
      showToast(err instanceof Error ? err.message : String(err), 'error');
    } finally {
      setIsGeneratingAi(false);
    }
  };

  const handleVerifyRemediation = async (remediationId: string) => {
    setIsVerifyingAi(true);
    try {
      const res = await fetch(`${apiUrl}/api/v1/remediations/${remediationId}/verify`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error?.message || 'Verification execution failed');
      setRemediations((prev) =>
        prev.map((r) =>
          r.id === remediationId
            ? {
                ...r,
                verifiedStatus: data.data.verifiedStatus,
                verificationOutput: data.data.verificationDetails,
              }
            : r,
        ),
      );
      if (data.data.verifiedStatus === 'PASSED') {
        showToast('Patch verified: targeted engine confirmed vulnerability mitigated!', 'success');
      } else {
        showToast('Verification failed: flaw still detected on target', 'error');
      }
    } catch (err) {
      showToast(err instanceof Error ? err.message : String(err), 'error');
    } finally {
      setIsVerifyingAi(false);
    }
  };

  if (!isOpen) return null;

  const copyToClipboard = (text: string, label: string) => {
    navigator.clipboard.writeText(text);
    setCopiedKey(label);
    showToast(`Copied ${label} to clipboard`, 'info');
    setTimeout(() => setCopiedKey(null), 2000);
  };

  const getStatusColor = (code?: number) => {
    if (!code) return 'bg-slate-800 text-slate-400 border-slate-700';
    if (code >= 200 && code < 300) return 'bg-emerald-950/60 text-emerald-400 border-emerald-800';
    if (code >= 300 && code < 400) return 'bg-blue-950/60 text-blue-400 border-blue-800';
    if (code >= 400 && code < 500) return 'bg-amber-950/60 text-amber-400 border-amber-800';
    return 'bg-rose-950/60 text-rose-400 border-rose-800';
  };

  const curlCommand = evidence?.request
    ? generateCurlSnippet(evidence.request)
    : '# No HTTP request payload attached to this evidence artifact';

  const severityBadge = (sev: string) => {
    switch (sev) {
      case 'critical':
        return 'bg-purple-950/60 text-purple-400 border-purple-800';
      case 'high':
        return 'bg-rose-950/60 text-rose-400 border-rose-800';
      case 'medium':
        return 'bg-amber-950/60 text-amber-400 border-amber-800';
      case 'low':
        return 'bg-blue-950/60 text-blue-400 border-blue-800';
      default:
        return 'bg-slate-800 text-slate-300 border-slate-700';
    }
  };

  return (
    <div
      role="dialog"
      aria-modal="true"
      aria-labelledby="evidence-modal-title"
      className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm animate-fade-in"
      onClick={(e) => {
        if (e.target === e.currentTarget) onClose();
      }}
    >
      <div className="bg-slate-900 border border-slate-700/80 rounded-xl shadow-2xl w-full max-w-5xl max-h-[92vh] flex flex-col overflow-hidden text-slate-200">
        {/* Header */}
        <div className="p-4 sm:p-5 border-b border-slate-800 bg-slate-900/90 flex items-start justify-between gap-4">
          <div className="flex-1 min-w-0">
            <div className="flex flex-wrap items-center gap-2 mb-2">
              <span
                className={`text-xs px-2.5 py-0.5 rounded-full font-bold uppercase tracking-wider border ${severityBadge(
                  findingSeverity
                )}`}
              >
                {findingSeverity}
              </span>
              <span className="text-xs px-2.5 py-0.5 rounded-full bg-slate-800 text-slate-300 border border-slate-700 font-mono">
                {category}
              </span>
              {evidence?.immutableHash && (
                <div
                  className="flex items-center gap-1.5 px-2 py-0.5 rounded bg-blue-950/40 text-blue-300 text-xs border border-blue-900/60 font-mono cursor-pointer hover:bg-blue-900/50 transition-colors"
                  onClick={() => copyToClipboard(evidence.immutableHash, 'Evidence SHA256')}
                  title="Click to copy SHA256 integrity hash"
                >
                  <Hash className="w-3 h-3" />
                  <span>{evidence.immutableHash.slice(0, 12)}…</span>
                </div>
              )}
            </div>
            <h2 id="evidence-modal-title" className="text-lg sm:text-xl font-bold text-white truncate">
              {findingTitle}
            </h2>
            {evidence?.timestamp && (
              <p className="text-xs text-slate-400 mt-1 flex items-center gap-1.5">
                <Clock className="w-3.5 h-3.5 text-slate-500" />
                Recorded at {new Date(evidence.timestamp).toUTCString()}
              </p>
            )}
          </div>

          <button
            onClick={onClose}
            className="p-1.5 text-slate-400 hover:text-white hover:bg-slate-800 rounded-lg transition-colors"
            title="Close dialog"
            aria-label="Close"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Tab Navigation */}
        <div className="flex items-center gap-1 px-4 sm:px-6 border-b border-slate-800 bg-slate-950/40 text-sm overflow-x-auto">
          <button
            onClick={() => setActiveTab('request')}
            className={`py-3 px-3.5 border-b-2 font-medium flex items-center gap-2 whitespace-nowrap transition-colors ${
              activeTab === 'request'
                ? 'border-blue-500 text-blue-400'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            <ArrowUpRight className="w-4 h-4" />
            HTTP Request
          </button>
          <button
            onClick={() => setActiveTab('response')}
            className={`py-3 px-3.5 border-b-2 font-medium flex items-center gap-2 whitespace-nowrap transition-colors ${
              activeTab === 'response'
                ? 'border-blue-500 text-blue-400'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            <ArrowDownLeft className="w-4 h-4" />
            HTTP Response
            {evidence?.response?.statusCode && (
              <span
                className={`ml-1 text-xs px-1.5 py-0.5 rounded font-mono border ${getStatusColor(
                  evidence.response.statusCode
                )}`}
              >
                {evidence.response.statusCode}
              </span>
            )}
          </button>
          <button
            onClick={() => setActiveTab('curl')}
            className={`py-3 px-3.5 border-b-2 font-medium flex items-center gap-2 whitespace-nowrap transition-colors ${
              activeTab === 'curl'
                ? 'border-blue-500 text-blue-400'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            <Terminal className="w-4 h-4" />
            cURL Snippet
          </button>
          <button
            onClick={() => setActiveTab('diff')}
            className={`py-3 px-3.5 border-b-2 font-medium flex items-center gap-2 whitespace-nowrap transition-colors ${
              activeTab === 'diff'
                ? 'border-blue-500 text-blue-400'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            <Code2 className="w-4 h-4" />
            Expected vs Actual
          </button>
          <button
            onClick={() => setActiveTab('raw')}
            className={`py-3 px-3.5 border-b-2 font-medium flex items-center gap-2 whitespace-nowrap transition-colors ${
              activeTab === 'raw'
                ? 'border-blue-500 text-blue-400'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            <FileCode className="w-4 h-4" />
            Raw JSON Artifact
          </button>
          <button
            onClick={() => setActiveTab('ai')}
            className={`py-3 px-3.5 border-b-2 font-medium flex items-center gap-2 whitespace-nowrap transition-colors ${
              activeTab === 'ai'
                ? 'border-purple-500 text-purple-400'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            <Sparkles className="w-4 h-4 text-purple-400" />
            AI Remediation Diff
            {remediations.length > 0 && (
              <span
                className={`ml-1 text-[10px] px-1.5 py-0.5 rounded font-bold uppercase border ${
                  remediations[0]?.verifiedStatus === 'PASSED'
                    ? 'bg-emerald-950/60 text-emerald-400 border-emerald-800'
                    : remediations[0]?.verifiedStatus === 'FAILED'
                    ? 'bg-rose-950/60 text-rose-400 border-rose-800'
                    : 'bg-amber-950/60 text-amber-400 border-amber-800'
                }`}
              >
                {remediations[0]?.verifiedStatus}
              </span>
            )}
          </button>
        </div>

        {/* Tab Body */}
        <div className="flex-1 overflow-y-auto p-4 sm:p-6 bg-slate-950/70">
          {isLoading ? (
            <div className="flex flex-col items-center justify-center py-20 text-slate-400">
              <div className="w-8 h-8 border-2 border-blue-500 border-t-transparent rounded-full animate-spin mb-3"></div>
              <p className="text-sm">Loading verified forensic evidence snapshot...</p>
            </div>
          ) : !evidence ? (
            <div className="flex flex-col items-center justify-center py-16 text-center text-slate-400">
              <ShieldAlert className="w-12 h-12 text-slate-600 mb-3" />
              <h3 className="text-base font-semibold text-slate-300">No Raw Evidence Artifact Attached</h3>
              <p className="text-xs text-slate-500 max-w-md mt-1">
                This finding was identified through static analysis or metadata inspection without a captured HTTP session.
              </p>
            </div>
          ) : (
            <div>
              {/* 1. Request Tab */}
              {activeTab === 'request' && (
                <div className="space-y-4">
                  {evidence.request ? (
                    <>
                      <div className="flex items-center justify-between bg-slate-900/90 border border-slate-800 rounded-lg p-3">
                        <div className="flex items-center gap-3 overflow-x-auto text-sm">
                          <span className="px-2.5 py-1 rounded bg-blue-600/20 text-blue-400 font-mono font-bold uppercase text-xs border border-blue-600/30">
                            {evidence.request.method}
                          </span>
                          <span className="font-mono text-slate-200 truncate">{evidence.request.url}</span>
                        </div>
                        <button
                          onClick={() => copyToClipboard(evidence.request!.url, 'URL')}
                          className="text-slate-400 hover:text-white p-1 rounded transition-colors"
                          title="Copy Request URL"
                        >
                          {copiedKey === 'URL' ? <Check className="w-4 h-4 text-emerald-400" /> : <Copy className="w-4 h-4" />}
                        </button>
                      </div>

                      {/* Request Headers */}
                      <div>
                        <div className="flex items-center justify-between mb-2">
                          <h4 className="text-xs font-semibold uppercase tracking-wider text-slate-400">Request Headers</h4>
                          <button
                            onClick={() =>
                              copyToClipboard(JSON.stringify(evidence.request?.headers, null, 2), 'Request Headers')
                            }
                            className="text-xs text-blue-400 hover:text-blue-300 flex items-center gap-1"
                          >
                            <Copy className="w-3 h-3" /> Copy
                          </button>
                        </div>
                        <div className="bg-slate-900 border border-slate-800 rounded-lg overflow-x-auto text-xs font-mono">
                          <table className="w-full text-left border-collapse">
                            <tbody>
                              {Object.entries(evidence.request.headers || {}).map(([key, val]) => (
                                <tr key={key} className="border-b border-slate-800/60 last:border-none">
                                  <td className="py-1.5 px-3 font-semibold text-slate-400 whitespace-nowrap bg-slate-950/40 w-1/3">
                                    {key}
                                  </td>
                                  <td className="py-1.5 px-3 text-slate-200 break-all">{String(val)}</td>
                                </tr>
                              ))}
                            </tbody>
                          </table>
                        </div>
                      </div>

                      {/* Request Body */}
                      {evidence.request.body && (
                        <div>
                          <div className="flex items-center justify-between mb-2">
                            <h4 className="text-xs font-semibold uppercase tracking-wider text-slate-400">Request Body</h4>
                            <button
                              onClick={() => copyToClipboard(evidence.request!.body!, 'Request Body')}
                              className="text-xs text-blue-400 hover:text-blue-300 flex items-center gap-1"
                            >
                              <Copy className="w-3 h-3" /> Copy
                            </button>
                          </div>
                          <pre className="p-4 bg-slate-900 border border-slate-800 rounded-lg text-xs font-mono text-emerald-300 overflow-x-auto whitespace-pre-wrap">
                            {evidence.request.body}
                          </pre>
                        </div>
                      )}
                    </>
                  ) : (
                    <p className="text-sm text-slate-500 italic">No request payload recorded.</p>
                  )}
                </div>
              )}

              {/* 2. Response Tab */}
              {activeTab === 'response' && (
                <div className="space-y-4">
                  {evidence.response ? (
                    <>
                      <div className="flex items-center justify-between bg-slate-900/90 border border-slate-800 rounded-lg p-3">
                        <div className="flex items-center gap-3 text-sm">
                          <span
                            className={`px-2.5 py-1 rounded font-mono font-bold text-xs border ${getStatusColor(
                              evidence.response.statusCode
                            )}`}
                          >
                            HTTP {evidence.response.statusCode}
                          </span>
                          {evidence.response.responseTimeMs !== undefined && (
                            <span className="text-xs text-slate-400 flex items-center gap-1">
                              <Clock className="w-3.5 h-3.5 text-slate-500" />
                              {evidence.response.responseTimeMs} ms
                            </span>
                          )}
                        </div>
                      </div>

                      {/* Response Headers */}
                      <div>
                        <div className="flex items-center justify-between mb-2">
                          <h4 className="text-xs font-semibold uppercase tracking-wider text-slate-400">
                            Response Headers
                          </h4>
                          <button
                            onClick={() =>
                              copyToClipboard(JSON.stringify(evidence.response?.headers, null, 2), 'Response Headers')
                            }
                            className="text-xs text-blue-400 hover:text-blue-300 flex items-center gap-1"
                          >
                            <Copy className="w-3 h-3" /> Copy
                          </button>
                        </div>
                        <div className="bg-slate-900 border border-slate-800 rounded-lg overflow-x-auto text-xs font-mono">
                          <table className="w-full text-left border-collapse">
                            <tbody>
                              {Object.entries(evidence.response.headers || {}).map(([key, val]) => (
                                <tr key={key} className="border-b border-slate-800/60 last:border-none">
                                  <td className="py-1.5 px-3 font-semibold text-slate-400 whitespace-nowrap bg-slate-950/40 w-1/3">
                                    {key}
                                  </td>
                                  <td className="py-1.5 px-3 text-slate-200 break-all">{String(val)}</td>
                                </tr>
                              ))}
                            </tbody>
                          </table>
                        </div>
                      </div>

                      {/* Response Body */}
                      {evidence.response.body && (
                        <div>
                          <div className="flex items-center justify-between mb-2">
                            <h4 className="text-xs font-semibold uppercase tracking-wider text-slate-400">Response Body</h4>
                            <button
                              onClick={() => copyToClipboard(evidence.response!.body!, 'Response Body')}
                              className="text-xs text-blue-400 hover:text-blue-300 flex items-center gap-1"
                            >
                              <Copy className="w-3 h-3" /> Copy
                            </button>
                          </div>
                          <pre className="p-4 bg-slate-900 border border-slate-800 rounded-lg text-xs font-mono text-cyan-300 overflow-x-auto whitespace-pre-wrap max-h-96">
                            {evidence.response.body}
                          </pre>
                        </div>
                      )}
                    </>
                  ) : (
                    <p className="text-sm text-slate-500 italic">No response payload recorded.</p>
                  )}
                </div>
              )}

              {/* 3. cURL Tab */}
              {activeTab === 'curl' && (
                <div className="space-y-3">
                  <div className="flex items-center justify-between">
                    <p className="text-xs text-slate-400">
                      Replay this reproduction request locally using cURL:
                    </p>
                    <button
                      onClick={() => copyToClipboard(curlCommand, 'cURL command')}
                      className="px-3 py-1 bg-blue-600 hover:bg-blue-500 text-white rounded text-xs flex items-center gap-1.5 transition-colors"
                    >
                      {copiedKey === 'cURL command' ? (
                        <>
                          <Check className="w-3.5 h-3.5" /> Copied!
                        </>
                      ) : (
                        <>
                          <Copy className="w-3.5 h-3.5" /> Copy cURL
                        </>
                      )}
                    </button>
                  </div>
                  <pre className="p-4 bg-slate-900 border border-slate-800 rounded-lg text-xs font-mono text-amber-300 overflow-x-auto whitespace-pre-wrap">
                    {curlCommand}
                  </pre>
                </div>
              )}

              {/* 4. Diff / Expected vs Actual */}
              {activeTab === 'diff' && (
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <div className="bg-slate-900 border border-slate-800 rounded-lg p-4">
                    <h4 className="text-xs font-bold uppercase tracking-wider text-emerald-400 mb-2 flex items-center gap-1.5">
                      <span className="w-2 h-2 rounded-full bg-emerald-500 inline-block"></span>
                      Expected Condition
                    </h4>
                    <pre className="p-3 bg-slate-950 rounded border border-slate-800/80 text-xs font-mono text-emerald-300 overflow-x-auto whitespace-pre-wrap">
                      {evidence.expected !== undefined
                        ? JSON.stringify(evidence.expected, null, 2)
                        : 'No formal contract assertion specified'}
                    </pre>
                  </div>
                  <div className="bg-slate-900 border border-slate-800 rounded-lg p-4">
                    <h4 className="text-xs font-bold uppercase tracking-wider text-rose-400 mb-2 flex items-center gap-1.5">
                      <span className="w-2 h-2 rounded-full bg-rose-500 inline-block"></span>
                      Actual Observed Behavior
                    </h4>
                    <pre className="p-3 bg-slate-950 rounded border border-slate-800/80 text-xs font-mono text-rose-300 overflow-x-auto whitespace-pre-wrap">
                      {evidence.actual !== undefined
                        ? JSON.stringify(evidence.actual, null, 2)
                        : 'Observed violation during execution run'}
                    </pre>
                  </div>
                </div>
              )}

              {/* 5. Raw Artifact */}
              {activeTab === 'raw' && (
                <div className="space-y-3">
                  <div className="flex items-center justify-between">
                    <p className="text-xs text-slate-400">Cryptographically verifiable immutable JSON payload:</p>
                    <button
                      onClick={() => copyToClipboard(JSON.stringify(evidence, null, 2), 'Raw Evidence JSON')}
                      className="text-xs text-blue-400 hover:text-blue-300 flex items-center gap-1"
                    >
                      <Copy className="w-3.5 h-3.5" /> Copy JSON
                    </button>
                  </div>
                  <pre className="p-4 bg-slate-900 border border-slate-800 rounded-lg text-xs font-mono text-slate-300 overflow-x-auto max-h-[500px]">
                    {JSON.stringify(evidence, null, 2)}
                  </pre>
                </div>
              )}

              {/* 6. AI Remediation & Verified Patch */}
              {activeTab === 'ai' && (
                <div className="space-y-4">
                  {remediations.length === 0 ? (
                    <div className="bg-slate-900/60 border border-purple-900/30 rounded-xl p-8 text-center max-w-xl mx-auto my-6">
                      <div className="w-12 h-12 rounded-full bg-purple-500/10 border border-purple-500/30 flex items-center justify-center mx-auto mb-4 text-purple-400">
                        <Sparkles className="w-6 h-6" />
                      </div>
                      <h3 className="text-base font-bold text-white mb-2">Synthesize Context-Aware Security Patch</h3>
                      <p className="text-xs text-slate-400 mb-6 leading-relaxed">
                        The AI engine analyzes raw HTTP evidence, vulnerability rules, and target context to synthesize a production-grade code remediation diff and automated verification steps.
                      </p>
                      <button
                        onClick={handleGenerateRemediation}
                        disabled={isGeneratingAi}
                        className="px-5 py-2.5 bg-gradient-to-r from-purple-600 to-indigo-600 hover:from-purple-500 hover:to-indigo-500 disabled:opacity-50 text-white font-medium rounded-lg text-xs shadow-lg shadow-purple-950/50 inline-flex items-center gap-2 transition-all"
                      >
                        {isGeneratingAi ? (
                          <>
                            <Loader2 className="w-4 h-4 animate-spin" />
                            Synthesizing Code Patch...
                          </>
                        ) : (
                          <>
                            <Sparkles className="w-4 h-4" />
                            Synthesize AI Remediation Patch
                          </>
                        )}
                      </button>
                    </div>
                  ) : (
                    <div className="space-y-4">
                      {/* Top Action Bar */}
                      <div className="flex flex-wrap items-center justify-between gap-3 p-4 bg-slate-900/90 border border-slate-800 rounded-xl">
                        <div className="flex items-center gap-3">
                          <span
                            className={`px-2.5 py-1 rounded-full text-xs font-bold uppercase tracking-wider border flex items-center gap-1.5 ${
                              remediations[0]?.verifiedStatus === 'PASSED'
                                ? 'bg-emerald-950/60 text-emerald-400 border-emerald-800'
                                : remediations[0]?.verifiedStatus === 'FAILED'
                                ? 'bg-rose-950/60 text-rose-400 border-rose-800'
                                : 'bg-amber-950/60 text-amber-400 border-amber-800'
                            }`}
                          >
                            {remediations[0]?.verifiedStatus === 'PASSED' ? (
                              <CheckCircle2 className="w-3.5 h-3.5" />
                            ) : remediations[0]?.verifiedStatus === 'FAILED' ? (
                              <AlertCircle className="w-3.5 h-3.5" />
                            ) : (
                              <Clock className="w-3.5 h-3.5" />
                            )}
                            {remediations[0]?.verifiedStatus}
                          </span>
                          <span className="text-xs text-slate-400 font-mono">
                            Confidence: <span className="text-slate-200">{Math.round(remediations[0]!.confidenceScore * 100)}%</span>
                          </span>
                          {remediations[0]?.model && (
                            <span className="text-xs text-slate-500 font-mono hidden sm:inline">
                              Model: {remediations[0]?.model}
                            </span>
                          )}
                        </div>

                        <div className="flex items-center gap-2">
                          <button
                            onClick={() => handleVerifyRemediation(remediations[0]!.id)}
                            disabled={isVerifyingAi}
                            className="px-3.5 py-1.5 bg-emerald-600 hover:bg-emerald-500 disabled:opacity-50 text-white rounded-lg text-xs font-medium flex items-center gap-1.5 shadow-sm transition-colors"
                          >
                            {isVerifyingAi ? (
                              <>
                                <Loader2 className="w-3.5 h-3.5 animate-spin" />
                                Retesting Target...
                              </>
                            ) : (
                              <>
                                <ShieldCheck className="w-3.5 h-3.5" />
                                Verify Patch via Retest
                              </>
                            )}
                          </button>
                          <button
                            onClick={handleGenerateRemediation}
                            disabled={isGeneratingAi}
                            className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded-lg text-xs font-medium transition-colors"
                          >
                            Regenerate
                          </button>
                        </div>
                      </div>

                      {/* Verification Output Banner */}
                      {remediations[0]?.verificationOutput && (
                        <div
                          className={`p-3.5 rounded-lg border text-xs flex items-start gap-2.5 ${
                            remediations[0]?.verifiedStatus === 'PASSED'
                              ? 'bg-emerald-950/40 border-emerald-800/80 text-emerald-300'
                              : 'bg-rose-950/40 border-rose-800/80 text-rose-300'
                          }`}
                        >
                          {remediations[0]?.verifiedStatus === 'PASSED' ? (
                            <CheckCircle2 className="w-4 h-4 text-emerald-400 flex-shrink-0 mt-0.5" />
                          ) : (
                            <AlertCircle className="w-4 h-4 text-rose-400 flex-shrink-0 mt-0.5" />
                          )}
                          <div>
                            <div className="font-semibold mb-0.5">Automated Verification Outcome</div>
                            <div className="font-mono text-[11px] opacity-90">{remediations[0]?.verificationOutput}</div>
                          </div>
                        </div>
                      )}

                      {/* Root Cause & Exploit Explanation */}
                      <div className="bg-slate-900 border border-slate-800 rounded-xl p-5">
                        <h4 className="text-xs font-bold uppercase tracking-wider text-purple-400 mb-3 flex items-center gap-2">
                          <Sparkles className="w-3.5 h-3.5" />
                          Root Cause Analysis & Exploit Mechanism
                        </h4>
                        <div className="text-xs text-slate-300 leading-relaxed whitespace-pre-wrap font-sans">
                          {remediations[0]?.explanation}
                        </div>
                      </div>

                      {/* Unified Git Diff */}
                      <div className="space-y-2">
                        <div className="flex items-center justify-between">
                          <h4 className="text-xs font-bold uppercase tracking-wider text-indigo-400 flex items-center gap-1.5">
                            <FileCode className="w-3.5 h-3.5" />
                            Unified Git Diff Patch
                          </h4>
                          <button
                            onClick={() => copyToClipboard(remediations[0]!.gitDiff, 'Git Diff Patch')}
                            className="px-2.5 py-1 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded text-xs flex items-center gap-1.5 transition-colors"
                          >
                            {copiedKey === 'Git Diff Patch' ? (
                              <>
                                <Check className="w-3.5 h-3.5" /> Copied!
                              </>
                            ) : (
                              <>
                                <Copy className="w-3.5 h-3.5" /> Copy Diff
                              </>
                            )}
                          </button>
                        </div>
                        <pre className="p-4 bg-slate-950 border border-slate-800 rounded-xl text-xs font-mono overflow-x-auto leading-relaxed">
                          {remediations[0]?.gitDiff.split('\n').map((line, idx) => {
                            let color = 'text-slate-300';
                            let bg = '';
                            if (line.startsWith('+') && !line.startsWith('+++')) {
                              color = 'text-emerald-400';
                              bg = 'bg-emerald-950/20';
                            } else if (line.startsWith('-') && !line.startsWith('---')) {
                              color = 'text-rose-400';
                              bg = 'bg-rose-950/20';
                            } else if (line.startsWith('@@')) {
                              color = 'text-cyan-400';
                            } else if (line.startsWith('diff --git')) {
                              color = 'text-amber-400 font-bold';
                            }
                            return (
                              <div key={idx} className={`${color} ${bg} px-1 rounded`}>
                                {line || ' '}
                              </div>
                            );
                          })}
                        </pre>
                      </div>
                    </div>
                  )}
                </div>
              )}
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="p-4 border-t border-slate-800 bg-slate-900/90 flex items-center justify-between">
          <div className="text-xs text-slate-400">
            {evidence?.id && (
              <span className="font-mono">
                Artifact ID: <span className="text-slate-300">{evidence.id}</span>
              </span>
            )}
          </div>
          <button
            onClick={onClose}
            className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-white rounded-lg text-sm font-medium transition-colors"
          >
            Close
          </button>
        </div>
      </div>
    </div>
  );
};
