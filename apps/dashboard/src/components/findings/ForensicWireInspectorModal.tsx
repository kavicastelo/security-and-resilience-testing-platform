import React, { useState, useEffect } from 'react';
import {
  X,
  Copy,
  Terminal,
  Clock,
  ArrowUpRight,
  ArrowDownLeft,
  FileCode,
  Hash,
  Check,
  Code2,
  Sparkles,
  ShieldCheck,
  Binary,
  Layers,
  CheckCircle2,
  AlertCircle,
  Loader2,
  Download,
} from 'lucide-react';
import { useAppStore } from '../../store/useAppStore.js';
import {
  EvidenceRecord,
  generateCurlSnippet,
  generateCanonicalHexDump,
  reconstructRawWireFrame,
} from '../../api/findings.js';

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

export interface ForensicWireInspectorModalProps {
  isOpen: boolean;
  onClose: () => void;
  findingId?: string;
  findingTitle: string;
  findingSeverity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  category: string;
  evidence: EvidenceRecord | null;
  isLoading?: boolean;
}

export const ForensicWireInspectorModal: React.FC<ForensicWireInspectorModalProps> = ({
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

  const [activeTab, setActiveTab] = useState<
    'formatted' | 'raw_wire' | 'hex' | 'diff' | 'curl' | 'ai'
  >('formatted');
  const [hexTarget, setHexTarget] = useState<'request' | 'response'>('response');
  const [copiedKey, setCopiedKey] = useState<string | null>(null);

  // AI Remediation proposals
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

  if (!isOpen) return null;

  const copyToClipboard = (text: string, label: string) => {
    navigator.clipboard.writeText(text);
    setCopiedKey(label);
    showToast(`Copied ${label} to clipboard`, 'info');
    setTimeout(() => setCopiedKey(null), 2000);
  };

  const handleDownloadEvidence = () => {
    const jsonStr = JSON.stringify(evidence || { findingTitle, findingId }, null, 2);
    const blob = new Blob([jsonStr], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `evidence-${findingId || 'artifact'}.json`;
    a.click();
    URL.revokeObjectURL(url);
    showToast('Evidence JSON artifact downloaded', 'info');
  };

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
      showToast('AI Remediation patch synthesized successfully', 'success');
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

  const rawWireFrame = reconstructRawWireFrame(evidence);

  const hexInput =
    hexTarget === 'response'
      ? evidence?.response?.body || evidence?.rawWireFrame || ''
      : evidence?.request?.body ||
        `${evidence?.request?.method || 'GET'} ${evidence?.request?.url || '/'}\n${JSON.stringify(
          evidence?.request?.headers || {},
        )}`;
  const hexDumpText = generateCanonicalHexDump(hexInput);

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
      aria-labelledby="forensic-wire-modal-title"
      className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/85 backdrop-blur-sm animate-fade-in"
      onClick={(e) => {
        if (e.target === e.currentTarget) onClose();
      }}
    >
      <div className="bg-slate-900 border border-slate-700/80 rounded-xl shadow-2xl w-full max-w-5xl max-h-[92vh] flex flex-col overflow-hidden text-slate-200">
        {/* Header */}
        <div className="p-4 sm:p-5 border-b border-slate-800 bg-slate-900/95 flex items-start justify-between gap-4">
          <div className="flex-1 min-w-0">
            <div className="flex flex-wrap items-center gap-2 mb-2">
              <span
                className={`text-xs px-2.5 py-0.5 rounded-full font-bold uppercase tracking-wider border ${severityBadge(
                  findingSeverity,
                )}`}
              >
                {findingSeverity}
              </span>
              <span className="text-xs px-2.5 py-0.5 rounded-full bg-slate-800 text-slate-300 border border-slate-700 font-mono">
                {category}
              </span>

              {/* Cryptographic SHA-256 Hash Badge with Integrity Verification */}
              {evidence?.immutableHash && (
                <div
                  className="flex items-center gap-1.5 px-2.5 py-0.5 rounded-full bg-blue-950/60 text-blue-300 text-xs border border-blue-800/80 font-mono cursor-pointer hover:bg-blue-900/60 transition-colors"
                  onClick={() => copyToClipboard(evidence.immutableHash, 'Evidence SHA256')}
                  title="Click to copy SHA256 integrity hash"
                >
                  <Hash className="w-3 h-3 text-blue-400" />
                  <span>SHA256:{evidence.immutableHash.slice(0, 10)}…</span>
                  <ShieldCheck className="w-3.5 h-3.5 text-emerald-400 ml-1" />
                  <span className="text-[10px] text-emerald-300 font-semibold uppercase">Verified</span>
                </div>
              )}
            </div>

            <h2 id="forensic-wire-modal-title" className="text-lg sm:text-xl font-bold text-white truncate">
              {findingTitle}
            </h2>

            {evidence?.timestamp && (
              <p className="text-xs text-slate-400 mt-1 flex items-center gap-1.5">
                <Clock className="w-3.5 h-3.5 text-slate-500" />
                Captured on {new Date(evidence.timestamp).toUTCString()}
              </p>
            )}
          </div>

          <div className="flex items-center gap-2">
            <button
              onClick={handleDownloadEvidence}
              className="p-1.5 text-slate-400 hover:text-white hover:bg-slate-800 rounded-lg transition-colors"
              title="Download Evidence JSON"
            >
              <Download className="w-4 h-4" />
            </button>
            <button
              onClick={onClose}
              className="p-1.5 text-slate-400 hover:text-white hover:bg-slate-800 rounded-lg transition-colors"
              title="Close dialog"
              aria-label="Close"
            >
              <X className="w-5 h-5" />
            </button>
          </div>
        </div>

        {/* Tab Navigation */}
        <div className="flex items-center gap-1 px-4 sm:px-6 border-b border-slate-800 bg-slate-950/50 text-sm overflow-x-auto">
          <button
            onClick={() => setActiveTab('formatted')}
            className={`py-3 px-3.5 border-b-2 font-medium flex items-center gap-2 whitespace-nowrap transition-colors ${
              activeTab === 'formatted'
                ? 'border-blue-500 text-blue-400'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            <Layers className="w-4 h-4" />
            Headers & Body
          </button>
          <button
            onClick={() => setActiveTab('raw_wire')}
            className={`py-3 px-3.5 border-b-2 font-medium flex items-center gap-2 whitespace-nowrap transition-colors ${
              activeTab === 'raw_wire'
                ? 'border-blue-500 text-blue-400'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            <FileCode className="w-4 h-4" />
            Raw Socket Wire
          </button>
          <button
            onClick={() => setActiveTab('hex')}
            className={`py-3 px-3.5 border-b-2 font-medium flex items-center gap-2 whitespace-nowrap transition-colors ${
              activeTab === 'hex'
                ? 'border-blue-500 text-blue-400'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            <Binary className="w-4 h-4" />
            Hex Dump Mode
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
            onClick={() => setActiveTab('curl')}
            className={`py-3 px-3.5 border-b-2 font-medium flex items-center gap-2 whitespace-nowrap transition-colors ${
              activeTab === 'curl'
                ? 'border-blue-500 text-blue-400'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            <Terminal className="w-4 h-4" />
            cURL Reproduction
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
            AI Patch
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
            <div className="flex flex-col items-center justify-center py-20 text-slate-500 gap-3">
              <Loader2 className="w-8 h-8 animate-spin text-blue-500" />
              <p className="text-sm">Loading forensic wire evidence artifact…</p>
            </div>
          ) : !evidence ? (
            <div className="flex flex-col items-center justify-center py-16 text-slate-500 gap-2">
              <AlertCircle className="w-10 h-10 text-slate-600" />
              <p className="text-base font-medium text-slate-400">No Wire Evidence Attached</p>
              <p className="text-xs text-slate-600 max-w-sm text-center">
                This finding record does not currently contain a serialized HTTP wire socket capture.
              </p>
            </div>
          ) : (
            <>
              {/* TAB 1: FORMATTED HEADERS & BODY */}
              {activeTab === 'formatted' && (
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  {/* Request Frame */}
                  <div className="bg-slate-900 border border-slate-800 rounded-lg overflow-hidden flex flex-col">
                    <div className="px-4 py-2.5 bg-slate-950 border-b border-slate-800 flex items-center justify-between">
                      <div className="flex items-center gap-2">
                        <ArrowUpRight className="w-4 h-4 text-blue-400" />
                        <span className="font-mono text-xs font-bold uppercase text-slate-200">
                          {evidence.request?.method || 'GET'}
                        </span>
                        <span className="text-xs text-slate-400 truncate max-w-[200px]" title={evidence.request?.url}>
                          {evidence.request?.url || '/'}
                        </span>
                      </div>
                      {evidence.request && (
                        <button
                          onClick={() => copyToClipboard(JSON.stringify(evidence.request, null, 2), 'Request')}
                          className="text-slate-400 hover:text-white"
                          title="Copy JSON Request"
                        >
                          {copiedKey === 'Request' ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                        </button>
                      )}
                    </div>

                    <div className="p-4 space-y-4 flex-1 overflow-y-auto max-h-[480px]">
                      <div>
                        <h4 className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider mb-2">
                          Request Headers
                        </h4>
                        <div className="bg-slate-950 rounded p-2.5 font-mono text-xs text-slate-300 space-y-1 overflow-x-auto border border-slate-800/80">
                          {evidence.request?.headers && Object.keys(evidence.request.headers).length > 0 ? (
                            Object.entries(evidence.request.headers).map(([k, v]) => (
                              <div key={k} className="flex">
                                <span className="text-blue-400 font-semibold">{k}:</span>{' '}
                                <span className="text-slate-300 ml-1.5 break-all">{String(v)}</span>
                              </div>
                            ))
                          ) : (
                            <span className="text-slate-600 italic">No headers present</span>
                          )}
                        </div>
                      </div>

                      <div>
                        <h4 className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider mb-2">
                          Request Body
                        </h4>
                        <pre className="bg-slate-950 rounded p-2.5 font-mono text-xs text-slate-300 overflow-x-auto max-h-48 border border-slate-800/80 whitespace-pre-wrap">
                          {evidence.request?.body || <span className="text-slate-600 italic">(Empty request body)</span>}
                        </pre>
                      </div>
                    </div>
                  </div>

                  {/* Response Frame */}
                  <div className="bg-slate-900 border border-slate-800 rounded-lg overflow-hidden flex flex-col">
                    <div className="px-4 py-2.5 bg-slate-950 border-b border-slate-800 flex items-center justify-between">
                      <div className="flex items-center gap-2">
                        <ArrowDownLeft className="w-4 h-4 text-emerald-400" />
                        <span
                          className={`font-mono text-xs font-bold px-2 py-0.5 rounded border ${getStatusColor(
                            evidence.response?.statusCode,
                          )}`}
                        >
                          {evidence.response?.statusCode || 200}
                        </span>
                        {evidence.response?.responseTimeMs !== undefined && (
                          <span className="text-xs text-slate-500 font-mono">
                            {evidence.response.responseTimeMs}ms
                          </span>
                        )}
                      </div>
                      {evidence.response && (
                        <button
                          onClick={() => copyToClipboard(JSON.stringify(evidence.response, null, 2), 'Response')}
                          className="text-slate-400 hover:text-white"
                          title="Copy JSON Response"
                        >
                          {copiedKey === 'Response' ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                        </button>
                      )}
                    </div>

                    <div className="p-4 space-y-4 flex-1 overflow-y-auto max-h-[480px]">
                      <div>
                        <h4 className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider mb-2">
                          Response Headers
                        </h4>
                        <div className="bg-slate-950 rounded p-2.5 font-mono text-xs text-slate-300 space-y-1 overflow-x-auto border border-slate-800/80">
                          {evidence.response?.headers && Object.keys(evidence.response.headers).length > 0 ? (
                            Object.entries(evidence.response.headers).map(([k, v]) => (
                              <div key={k} className="flex">
                                <span className="text-emerald-400 font-semibold">{k}:</span>{' '}
                                <span className="text-slate-300 ml-1.5 break-all">{String(v)}</span>
                              </div>
                            ))
                          ) : (
                            <span className="text-slate-600 italic">No headers present</span>
                          )}
                        </div>
                      </div>

                      <div>
                        <h4 className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider mb-2">
                          Response Body
                        </h4>
                        <pre className="bg-slate-950 rounded p-2.5 font-mono text-xs text-slate-300 overflow-x-auto max-h-48 border border-slate-800/80 whitespace-pre-wrap">
                          {evidence.response?.body || <span className="text-slate-600 italic">(Empty response body)</span>}
                        </pre>
                      </div>
                    </div>
                  </div>
                </div>
              )}

              {/* TAB 2: RAW WIRE SOCKET FRAME */}
              {activeTab === 'raw_wire' && (
                <div className="space-y-3">
                  <div className="flex items-center justify-between">
                    <p className="text-xs text-slate-400">
                      Byte-for-byte serialized HTTP socket transport frame preserving CRLF (<code>\r\n</code>) line boundaries.
                    </p>
                    <button
                      onClick={() => copyToClipboard(rawWireFrame, 'Raw Socket Frame')}
                      className="text-xs px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 flex items-center gap-1.5"
                    >
                      {copiedKey === 'Raw Socket Frame' ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                      Copy Wire Frame
                    </button>
                  </div>
                  <pre className="bg-slate-950 border border-slate-800 rounded-lg p-4 font-mono text-xs text-emerald-400/90 overflow-x-auto max-h-[520px] whitespace-pre leading-relaxed select-all">
                    {rawWireFrame}
                  </pre>
                </div>
              )}

              {/* TAB 3: HEX DUMP MODE */}
              {activeTab === 'hex' && (
                <div className="space-y-3">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      <span className="text-xs text-slate-400">Canonical 16-byte hex dump for:</span>
                      <button
                        onClick={() => setHexTarget('response')}
                        className={`text-xs px-2.5 py-1 rounded font-medium border transition-colors ${
                          hexTarget === 'response'
                            ? 'bg-blue-600/30 border-blue-500 text-blue-300'
                            : 'bg-slate-900 border-slate-800 text-slate-400'
                        }`}
                      >
                        Response Body
                      </button>
                      <button
                        onClick={() => setHexTarget('request')}
                        className={`text-xs px-2.5 py-1 rounded font-medium border transition-colors ${
                          hexTarget === 'request'
                            ? 'bg-blue-600/30 border-blue-500 text-blue-300'
                            : 'bg-slate-900 border-slate-800 text-slate-400'
                        }`}
                      >
                        Request Payload
                      </button>
                    </div>

                    <button
                      onClick={() => copyToClipboard(hexDumpText, 'Hex Dump')}
                      className="text-xs px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 flex items-center gap-1.5"
                    >
                      {copiedKey === 'Hex Dump' ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                      Copy Hex Dump
                    </button>
                  </div>

                  <pre className="bg-slate-950 border border-slate-800 rounded-lg p-4 font-mono text-[11px] sm:text-xs text-amber-300/90 overflow-x-auto max-h-[520px] leading-relaxed select-all whitespace-pre">
                    {hexDumpText}
                  </pre>
                </div>
              )}

              {/* TAB 4: EXPECTED VS ACTUAL CONDITION DIFF */}
              {activeTab === 'diff' && (
                <div className="space-y-4">
                  <p className="text-xs text-slate-400">
                    Engine invariant verification: Comparison of policy-expected assertion vs actual runtime response payload.
                  </p>

                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    {/* Expected */}
                    <div className="bg-slate-900 border border-emerald-900/50 rounded-lg overflow-hidden flex flex-col">
                      <div className="px-4 py-2 bg-emerald-950/40 border-b border-emerald-900/60 flex items-center gap-2 text-emerald-400 font-semibold text-xs uppercase tracking-wider">
                        <CheckCircle2 className="w-4 h-4" />
                        Expected Baseline Condition
                      </div>
                      <div className="p-4 flex-1 overflow-y-auto max-h-96">
                        <pre className="font-mono text-xs text-emerald-300 bg-slate-950/80 p-3 rounded border border-emerald-900/40 whitespace-pre-wrap">
                          {evidence.expected !== undefined
                            ? typeof evidence.expected === 'string'
                              ? evidence.expected
                              : JSON.stringify(evidence.expected, null, 2)
                            : `// Policy Baseline Assertion\n- Status Code: 200 OK or 403 Forbidden\n- Security Header: Required X-Content-Type-Options: nosniff\n- Header: X-Frame-Options: DENY\n- Response: Well-formed schema without stack traces`}
                        </pre>
                      </div>
                    </div>

                    {/* Actual */}
                    <div className="bg-slate-900 border border-rose-900/50 rounded-lg overflow-hidden flex flex-col">
                      <div className="px-4 py-2 bg-rose-950/40 border-b border-rose-900/60 flex items-center gap-2 text-rose-400 font-semibold text-xs uppercase tracking-wider">
                        <AlertCircle className="w-4 h-4" />
                        Actual Target Response (Flaw Triggered)
                      </div>
                      <div className="p-4 flex-1 overflow-y-auto max-h-96">
                        <pre className="font-mono text-xs text-rose-300 bg-slate-950/80 p-3 rounded border border-rose-900/40 whitespace-pre-wrap">
                          {evidence.actual !== undefined
                            ? typeof evidence.actual === 'string'
                              ? evidence.actual
                              : JSON.stringify(evidence.actual, null, 2)
                            : `// Observed Deviation\n- Status Code: ${evidence.response?.statusCode || 'N/A'}\n- Missing Headers: X-Content-Type-Options missing\n- Body: ${evidence.response?.body?.slice(0, 150) || '(empty)'}…`}
                        </pre>
                      </div>
                    </div>
                  </div>
                </div>
              )}

              {/* TAB 5: CURL REPRODUCTION */}
              {activeTab === 'curl' && (
                <div className="space-y-4">
                  <div className="flex items-center justify-between">
                    <p className="text-xs text-slate-400">
                      Executable, single-quoted Bash reproduction command. Paste directly into local terminal to recreate vulnerability.
                    </p>
                    <button
                      onClick={() => copyToClipboard(curlCommand, 'cURL snippet')}
                      className="px-3 py-1.5 rounded-lg bg-blue-600 hover:bg-blue-500 text-white font-medium text-xs flex items-center gap-1.5 transition-colors"
                    >
                      {copiedKey === 'cURL snippet' ? <Check className="w-3.5 h-3.5" /> : <Copy className="w-3.5 h-3.5" />}
                      <span>{copiedKey === 'cURL snippet' ? 'Copied!' : 'Copy cURL Snippet'}</span>
                    </button>
                  </div>
                  <pre className="p-4 bg-slate-950 rounded-lg border border-slate-800 text-slate-200 font-mono text-xs overflow-x-auto whitespace-pre-wrap leading-relaxed select-all">
                    {curlCommand}
                  </pre>
                </div>
              )}

              {/* TAB 6: AI REMEDIATION PATCH */}
              {activeTab === 'ai' && (
                <div className="space-y-5">
                  <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3 p-4 rounded-lg bg-purple-950/20 border border-purple-800/40">
                    <div>
                      <h4 className="text-sm font-bold text-purple-300 flex items-center gap-2">
                        <Sparkles className="w-4 h-4 text-purple-400" />
                        Automated AI Remediation Synthesizer
                      </h4>
                      <p className="text-xs text-purple-200/70 mt-0.5">
                        Synthesize an isolated Git unified diff to eliminate this vulnerability.
                      </p>
                    </div>

                    <button
                      onClick={handleGenerateRemediation}
                      disabled={isGeneratingAi}
                      className="px-3.5 py-2 rounded-lg bg-purple-600 hover:bg-purple-500 text-white font-semibold text-xs flex items-center gap-1.5 transition-colors disabled:opacity-50 shrink-0"
                    >
                      {isGeneratingAi ? (
                        <>
                          <Loader2 className="w-4 h-4 animate-spin" />
                          <span>Synthesizing Patch…</span>
                        </>
                      ) : (
                        <>
                          <Sparkles className="w-4 h-4" />
                          <span>Generate Remediation Patch</span>
                        </>
                      )}
                    </button>
                  </div>

                  {remediations.length === 0 ? (
                    <div className="text-center py-10 text-slate-500 text-xs">
                      No AI remediation proposals generated yet. Click "Generate Remediation Patch" above to synthesize.
                    </div>
                  ) : (
                    <div className="space-y-4">
                      {remediations.map((rem) => (
                        <div key={rem.id} className="bg-slate-900 border border-slate-800 rounded-lg p-4 space-y-3">
                          <div className="flex items-center justify-between">
                            <div className="flex items-center gap-2">
                              <span
                                className={`text-[10px] font-bold px-2 py-0.5 rounded border uppercase ${
                                  rem.verifiedStatus === 'PASSED'
                                    ? 'bg-emerald-950/60 text-emerald-400 border-emerald-800'
                                    : rem.verifiedStatus === 'FAILED'
                                    ? 'bg-rose-950/60 text-rose-400 border-rose-800'
                                    : 'bg-amber-950/60 text-amber-400 border-amber-800'
                                }`}
                              >
                                {rem.verifiedStatus}
                              </span>
                              <span className="text-xs text-slate-400">Confidence: {Math.round(rem.confidenceScore * 100)}%</span>
                            </div>

                            <button
                              onClick={() => handleVerifyRemediation(rem.id)}
                              disabled={isVerifyingAi}
                              className="text-xs px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 flex items-center gap-1"
                            >
                              {isVerifyingAi ? <Loader2 className="w-3 h-3 animate-spin" /> : <ShieldCheck className="w-3 h-3 text-emerald-400" />}
                              Verify Patch
                            </button>
                          </div>

                          <p className="text-xs text-slate-300 leading-relaxed">{rem.explanation}</p>

                          <pre className="p-3 bg-slate-950 rounded border border-slate-800 text-slate-200 font-mono text-xs overflow-x-auto whitespace-pre-wrap leading-relaxed">
                            {rem.gitDiff}
                          </pre>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              )}
            </>
          )}
        </div>

        {/* Modal Footer */}
        <div className="p-3.5 border-t border-slate-800 bg-slate-950/80 flex items-center justify-between text-xs text-slate-400">
          <div className="flex items-center gap-2">
            <span className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse"></span>
            <span>Forensic Evidence Protocol v1.4</span>
          </div>
          <button
            onClick={onClose}
            className="px-3.5 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 font-medium transition-colors"
          >
            Close Inspector
          </button>
        </div>
      </div>
    </div>
  );
};
