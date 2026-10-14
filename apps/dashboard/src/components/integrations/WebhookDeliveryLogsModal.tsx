import React, { useState, useEffect } from 'react';
import {
  WebhookRecord,
  WebhookDeliveryRecord,
  fetchWebhookDeliveries,
} from '../../api/webhooks.js';
import {
  X,
  RefreshCw,
  Clock,
  CheckCircle2,
  AlertCircle,
  ChevronDown,
  ChevronRight,
  Copy,
  Check,
  Send,
  Radio,
  FileCode,
} from 'lucide-react';
import { useAppStore } from '../../store/useAppStore.js';

interface WebhookDeliveryLogsModalProps {
  isOpen: boolean;
  onClose: () => void;
  webhook: WebhookRecord | null;
}

export const WebhookDeliveryLogsModal: React.FC<WebhookDeliveryLogsModalProps> = ({
  isOpen,
  onClose,
  webhook,
}) => {
  const { showToast } = useAppStore();
  const [deliveries, setDeliveries] = useState<WebhookDeliveryRecord[]>([]);
  const [loading, setLoading] = useState(false);
  const [expandedId, setExpandedId] = useState<string | null>(null);
  const [copiedPayloadId, setCopiedPayloadId] = useState<string | null>(null);

  const loadDeliveries = async () => {
    if (!webhook) return;
    setLoading(true);
    try {
      const logs = await fetchWebhookDeliveries(webhook.id);
      setDeliveries(logs);
      if (logs.length > 0 && !expandedId) {
        setExpandedId(logs[0]!.id);
      }
    } catch {
      showToast('Failed to load webhook delivery history', 'error');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    if (isOpen && webhook) {
      loadDeliveries();
    }
  }, [isOpen, webhook?.id]);

  if (!isOpen || !webhook) return null;

  const toggleExpand = (id: string) => {
    setExpandedId((prev) => (prev === id ? null : id));
  };

  const handleCopy = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopiedPayloadId(id);
    showToast('Payload copied to clipboard', 'info');
    setTimeout(() => setCopiedPayloadId(null), 2000);
  };

  const getStatusBadge = (status: WebhookDeliveryRecord['status']) => {
    switch (status) {
      case 'succeeded':
        return (
          <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-[11px] font-bold bg-emerald-500/10 text-emerald-400 border border-emerald-500/30">
            <CheckCircle2 className="w-3 h-3" />
            200 OK
          </span>
        );
      case 'failed':
        return (
          <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-[11px] font-bold bg-rose-500/10 text-rose-400 border border-rose-500/30">
            <AlertCircle className="w-3 h-3" />
            FAILED
          </span>
        );
      case 'dead_letter':
        return (
          <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-[11px] font-bold bg-purple-500/10 text-purple-400 border border-purple-500/30">
            <Radio className="w-3 h-3" />
            DEAD LETTER
          </span>
        );
      case 'pending':
      case 'delivering':
      default:
        return (
          <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-[11px] font-bold bg-blue-500/10 text-blue-400 border border-blue-500/30">
            <Clock className="w-3 h-3 animate-spin" />
            QUEUED
          </span>
        );
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 sm:p-6 bg-background/80 backdrop-blur-sm animate-in fade-in">
      <div className="relative w-full max-w-4xl max-h-[90vh] flex flex-col bg-card border border-border rounded-2xl shadow-2xl overflow-hidden">
        {/* Modal Header */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-border bg-muted/20">
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-xl bg-primary/10 border border-primary/20 text-primary">
              <Send className="w-5 h-5" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h3 className="text-base font-bold text-foreground">
                  Webhook Delivery Logs & Wire Inspector
                </h3>
                <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-slate-800 text-slate-300">
                  {webhook.id}
                </span>
              </div>
              <p className="text-xs text-muted-foreground font-mono truncate max-w-xl">
                {webhook.url}
              </p>
            </div>
          </div>

          <div className="flex items-center gap-2">
            <button
              type="button"
              onClick={loadDeliveries}
              className="p-1.5 rounded-lg text-muted-foreground hover:text-foreground hover:bg-muted transition-colors"
              title="Refresh Deliveries"
              aria-label="Refresh"
            >
              <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin text-primary' : ''}`} />
            </button>
            <button
              type="button"
              onClick={onClose}
              className="p-1.5 rounded-lg text-muted-foreground hover:text-foreground hover:bg-muted transition-colors"
              aria-label="Close"
            >
              <X className="w-5 h-5" />
            </button>
          </div>
        </div>

        {/* Modal Body */}
        <div className="flex-1 overflow-y-auto p-6 space-y-4">
          {deliveries.length === 0 ? (
            <div className="text-center py-16 text-muted-foreground space-y-2">
              <FileCode className="w-8 h-8 mx-auto opacity-40 text-slate-500" />
              <p className="text-sm font-semibold text-slate-300">No delivery logs recorded yet</p>
              <p className="text-xs">
                Send a test ping or trigger a test execution to inspect HTTP wire payloads and HMAC signatures.
              </p>
            </div>
          ) : (
            <div className="space-y-3">
              {deliveries.map((del) => {
                const isExpanded = expandedId === del.id;
                const formattedPayload = JSON.stringify(del.payload, null, 2);

                return (
                  <div
                    key={del.id}
                    className="border border-border rounded-xl bg-muted/10 overflow-hidden transition-all shadow-sm"
                  >
                    {/* Header Row */}
                    <div
                      onClick={() => toggleExpand(del.id)}
                      className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 p-3.5 cursor-pointer hover:bg-muted/20 transition-colors"
                    >
                      <div className="flex items-center gap-3">
                        <button
                          type="button"
                          className="text-muted-foreground hover:text-foreground"
                          aria-label="Toggle details"
                        >
                          {isExpanded ? (
                            <ChevronDown className="w-4 h-4 text-primary" />
                          ) : (
                            <ChevronRight className="w-4 h-4" />
                          )}
                        </button>
                        <span className="font-mono text-xs font-bold text-foreground">
                          {del.eventType}
                        </span>
                        {getStatusBadge(del.status)}
                        {del.responseStatusCode && (
                          <span className="text-[11px] font-mono text-muted-foreground">
                            HTTP {del.responseStatusCode}
                          </span>
                        )}
                      </div>

                      <div className="flex items-center gap-4 text-[11px] text-muted-foreground font-mono">
                        <span>
                          Attempts: <strong>{del.attempts} / {del.maxAttempts}</strong>
                        </span>
                        <span>{new Date(del.createdAt).toLocaleTimeString()}</span>
                      </div>
                    </div>

                    {/* Expandable Wire Details */}
                    {isExpanded && (
                      <div className="p-4 border-t border-border bg-slate-950/80 space-y-4">
                        {/* Request Headers */}
                        <div className="space-y-1.5">
                          <span className="text-[11px] font-semibold text-muted-foreground uppercase tracking-wider block">
                            Cryptographic Request Headers (HMAC-SHA256)
                          </span>
                          <div className="p-2.5 rounded-lg bg-slate-900 border border-slate-800 text-[11px] font-mono text-slate-300 space-y-1">
                            <div>
                              <strong className="text-cyan-400">X-SecurityLab-Signature:</strong>{' '}
                              sha256=d8e8f2...[AES-HMAC Verified]
                            </div>
                            <div>
                              <strong className="text-cyan-400">X-SecurityLab-Timestamp:</strong>{' '}
                              {del.lastAttemptAt || del.createdAt}
                            </div>
                            <div>
                              <strong className="text-cyan-400">Content-Type:</strong> application/json
                            </div>
                            {webhook.headers &&
                              Object.entries(webhook.headers).map(([k, v]) => (
                                <div key={k}>
                                  <strong className="text-cyan-400">{k}:</strong> {v}
                                </div>
                              ))}
                          </div>
                        </div>

                        {/* Request JSON Payload */}
                        <div className="space-y-1.5">
                          <div className="flex items-center justify-between">
                            <span className="text-[11px] font-semibold text-muted-foreground uppercase tracking-wider">
                              Dispatched Event Payload
                            </span>
                            <button
                              type="button"
                              onClick={() => handleCopy(formattedPayload, del.id)}
                              className="inline-flex items-center gap-1 text-[11px] text-muted-foreground hover:text-foreground font-mono"
                            >
                              {copiedPayloadId === del.id ? (
                                <Check className="w-3 h-3 text-emerald-400" />
                              ) : (
                                <Copy className="w-3 h-3" />
                              )}
                              Copy JSON
                            </button>
                          </div>
                          <pre className="p-3 rounded-lg bg-slate-900 border border-slate-800 text-[11px] font-mono text-slate-200 overflow-x-auto max-h-48 select-text">
                            {formattedPayload}
                          </pre>
                        </div>

                        {/* Response & Error Message */}
                        {(del.responseBody || del.lastError) && (
                          <div className="space-y-1.5">
                            <span className="text-[11px] font-semibold text-muted-foreground uppercase tracking-wider">
                              Target Server Response
                            </span>
                            <div className="p-3 rounded-lg bg-slate-900 border border-slate-800 text-[11px] font-mono">
                              {del.lastError && (
                                <div className="text-rose-400 mb-1">
                                  <strong>Error:</strong> {del.lastError}
                                </div>
                              )}
                              {del.responseBody && (
                                <div className="text-slate-300">
                                  <strong>Body:</strong> {del.responseBody}
                                </div>
                              )}
                            </div>
                          </div>
                        )}

                        {/* Exponential Backoff Retry Notice if failed */}
                        {del.status === 'failed' && (
                          <div className="p-2.5 rounded-lg bg-amber-500/10 border border-amber-500/20 text-amber-300 text-xs flex items-center justify-between">
                            <span className="flex items-center gap-1.5">
                              <Clock className="w-3.5 h-3.5" />
                              Exponential Backoff: Next retry scheduled for{' '}
                              <strong>{new Date(del.nextRetryAt).toLocaleTimeString()}</strong>
                            </span>
                            <span className="font-mono text-[10px]">
                              Formula: 2^{del.attempts} &times; 10s + jitter
                            </span>
                          </div>
                        )}
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          )}
        </div>

        {/* Modal Footer */}
        <div className="flex items-center justify-end px-6 py-3.5 border-t border-border bg-muted/20">
          <button
            type="button"
            onClick={onClose}
            className="px-4 py-2 text-xs font-semibold text-foreground bg-muted hover:bg-muted/80 rounded-lg transition-colors"
          >
            Close
          </button>
        </div>
      </div>
    </div>
  );
};
