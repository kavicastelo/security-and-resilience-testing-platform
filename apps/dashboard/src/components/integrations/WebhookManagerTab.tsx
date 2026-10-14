import React, { useState, useEffect } from 'react';
import {
  WebhookRecord,
  CreateWebhookPayload,
  fetchWebhooks,
  createWebhook,
  deleteWebhook,
  testWebhookPing,
  generateHmacSecret,
} from '../../api/webhooks.js';
import { WebhookDeliveryLogsModal } from './WebhookDeliveryLogsModal.js';
import {
  Plus,
  Send,
  Trash2,
  ListFilter,
  CheckCircle2,
  Lock,
  Eye,
  EyeOff,
  Copy,
  Check,
  RefreshCw,
  Sparkles,
  Radio,
} from 'lucide-react';
import { useAppStore } from '../../store/useAppStore.js';

export const WebhookManagerTab: React.FC = () => {
  const { showToast } = useAppStore();
  const [webhooks, setWebhooks] = useState<WebhookRecord[]>([]);
  const [loading, setLoading] = useState(true);
  const [isCreateModalOpen, setIsCreateModalOpen] = useState(false);
  const [testingWebhookId, setTestingWebhookId] = useState<string | null>(null);
  const [selectedLogsWebhook, setSelectedLogsWebhook] = useState<WebhookRecord | null>(null);

  // Form states for creation
  const [newUrl, setNewUrl] = useState('');
  const [newDescription, setNewDescription] = useState('');
  const [newSecret, setNewSecret] = useState(generateHmacSecret());
  const [showSecret, setShowSecret] = useState(false);
  const [copiedSecret, setCopiedSecret] = useState(false);
  const [allEventsChecked, setAllEventsChecked] = useState(false);
  const [selectedEvents, setSelectedEvents] = useState<string[]>([
    'run.completed',
    'finding.critical',
    'policy.failed',
  ]);
  const [customHeaderKey, setCustomHeaderKey] = useState('');
  const [customHeaderVal, setCustomHeaderVal] = useState('');
  const [headersMap, setHeadersMap] = useState<Record<string, string>>({});

  const availableEvents: Array<{ id: string; label: string; desc: string }> = [
    { id: 'run.completed', label: 'run.completed', desc: 'Scan execution finishes' },
    { id: 'run.failed', label: 'run.failed', desc: 'Execution aborts with engine error' },
    { id: 'finding.critical', label: 'finding.critical', desc: 'Critical severity vulnerability detected' },
    { id: 'finding.triaged', label: 'finding.triaged', desc: 'Finding status transitioned or waived' },
    { id: 'policy.failed', label: 'policy.failed', desc: 'Release gate evaluates to REJECTED' },
    { id: 'release.evaluated', label: 'release.evaluated', desc: 'Release posture score calculated' },
  ];

  const loadData = async () => {
    setLoading(true);
    try {
      const data = await fetchWebhooks();
      setWebhooks(data);
    } catch {
      showToast('Failed to load webhook configurations', 'error');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData();
  }, []);

  const handleToggleEvent = (eventId: string) => {
    if (selectedEvents.includes(eventId)) {
      setSelectedEvents(selectedEvents.filter((e) => e !== eventId));
    } else {
      setSelectedEvents([...selectedEvents, eventId]);
    }
  };

  const handleAddHeader = () => {
    if (customHeaderKey.trim() && customHeaderVal.trim()) {
      setHeadersMap({ ...headersMap, [customHeaderKey.trim()]: customHeaderVal.trim() });
      setCustomHeaderKey('');
      setCustomHeaderVal('');
    }
  };

  const handleRemoveHeader = (key: string) => {
    const next = { ...headersMap };
    delete next[key];
    setHeadersMap(next);
  };

  const handleCreateWebhook = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newUrl.trim()) {
      showToast('Webhook endpoint URL is required', 'error');
      return;
    }

    try {
      const payload: CreateWebhookPayload = {
        url: newUrl.trim(),
        description: newDescription.trim() || undefined,
        secret: newSecret.trim() || undefined,
        events: allEventsChecked ? ['*'] : selectedEvents,
        headers: Object.keys(headersMap).length > 0 ? headersMap : undefined,
      };

      const created = await createWebhook(payload);
      setWebhooks([created, ...webhooks]);
      setIsCreateModalOpen(false);
      showToast('Webhook endpoint registered successfully', 'success');

      // Reset form
      setNewUrl('');
      setNewDescription('');
      setNewSecret(generateHmacSecret());
      setHeadersMap({});
    } catch {
      showToast('Failed to create webhook endpoint', 'error');
    }
  };

  const handleDelete = async (id: string) => {
    if (!window.confirm('Are you sure you want to delete this webhook endpoint?')) return;
    try {
      const ok = await deleteWebhook(id);
      if (ok) {
        setWebhooks(webhooks.filter((w) => w.id !== id));
        showToast('Webhook endpoint deleted', 'info');
      }
    } catch {
      showToast('Failed to delete webhook', 'error');
    }
  };

  const handleTestPing = async (id: string) => {
    setTestingWebhookId(id);
    try {
      const result = await testWebhookPing(id);
      if (result.success) {
        showToast(result.message, 'success');
      } else {
        showToast('Test ping failed', 'error');
      }
    } catch {
      showToast('Test ping request failed', 'error');
    } finally {
      setTestingWebhookId(null);
    }
  };

  const handleCopySecret = () => {
    navigator.clipboard.writeText(newSecret);
    setCopiedSecret(true);
    showToast('HMAC secret copied to clipboard', 'info');
    setTimeout(() => setCopiedSecret(false), 2000);
  };

  return (
    <div className="space-y-4">
      {/* Action Toolbar */}
      <div className="flex flex-col sm:flex-row items-stretch sm:items-center justify-between gap-3 bg-card border border-border p-4 rounded-xl">
        <div>
          <h2 className="text-sm font-bold text-foreground">Configured Webhook Dispatchers</h2>
          <p className="text-xs text-muted-foreground">
            Outbound HTTP webhooks signed with HMAC-SHA256 and protected with exponential backoff retry queues.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <button
            type="button"
            onClick={loadData}
            className="p-2 rounded-lg bg-muted text-muted-foreground hover:text-foreground transition-colors"
            title="Refresh Webhooks"
            aria-label="Refresh"
          >
            <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin text-primary' : ''}`} />
          </button>

          <button
            type="button"
            onClick={() => setIsCreateModalOpen(true)}
            className="inline-flex items-center gap-1.5 px-3.5 py-2 rounded-lg bg-primary hover:bg-primary/90 text-primary-foreground text-xs font-bold shadow-md transition-all"
          >
            <Plus className="w-4 h-4" />
            Register Webhook
          </button>
        </div>
      </div>

      {/* Webhook Endpoints List */}
      <div className="space-y-3">
        {webhooks.length === 0 ? (
          <div className="p-12 text-center rounded-xl bg-card border border-border text-muted-foreground space-y-2">
            <Radio className="w-8 h-8 mx-auto opacity-40 text-slate-500" />
            <p className="text-sm font-semibold text-slate-200">No webhooks registered</p>
            <p className="text-xs">
              Click &ldquo;Register Webhook&rdquo; to send real-time security events to your Slack, PagerDuty, or SIEM pipelines.
            </p>
          </div>
        ) : (
          webhooks.map((wh) => (
            <div
              key={wh.id}
              className="p-4 rounded-xl bg-card border border-border shadow-sm flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 hover:border-slate-700 transition-colors"
            >
              <div className="space-y-1.5 flex-1 min-w-0">
                <div className="flex items-center gap-2.5">
                  <span
                    className={`w-2.5 h-2.5 rounded-full ${
                      wh.isActive ? 'bg-emerald-400' : 'bg-slate-600'
                    }`}
                    title={wh.isActive ? 'Active' : 'Disabled'}
                  />
                  <h3 className="text-xs font-bold text-foreground truncate">{wh.description || wh.id}</h3>
                  <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-primary/10 text-primary border border-primary/20">
                    HMAC-SHA256
                  </span>
                </div>

                <div className="font-mono text-xs text-muted-foreground truncate">
                  {wh.url}
                </div>

                {/* Subscribed Events Pills */}
                <div className="flex flex-wrap items-center gap-1.5 pt-1">
                  {wh.events.map((ev) => (
                    <span
                      key={ev}
                      className="px-2 py-0.5 rounded text-[10px] font-mono font-medium bg-muted text-slate-300 border border-border"
                    >
                      {ev}
                    </span>
                  ))}
                  {wh.headers && Object.keys(wh.headers).length > 0 && (
                    <span className="text-[10px] text-muted-foreground font-mono">
                      +{Object.keys(wh.headers).length} custom header(s)
                    </span>
                  )}
                </div>
              </div>

              {/* Action Buttons */}
              <div className="flex items-center gap-2 self-end sm:self-center">
                <button
                  type="button"
                  onClick={() => handleTestPing(wh.id)}
                  disabled={testingWebhookId === wh.id}
                  className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium bg-primary/10 text-primary hover:bg-primary/20 border border-primary/30 transition-colors disabled:opacity-50"
                >
                  <Send className={`w-3.5 h-3.5 ${testingWebhookId === wh.id ? 'animate-pulse' : ''}`} />
                  {testingWebhookId === wh.id ? 'Pinging...' : 'Send Test Ping'}
                </button>

                <button
                  type="button"
                  onClick={() => setSelectedLogsWebhook(wh)}
                  className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium bg-muted text-foreground hover:bg-muted/80 transition-colors"
                >
                  <ListFilter className="w-3.5 h-3.5" />
                  Delivery Logs
                </button>

                <button
                  type="button"
                  onClick={() => handleDelete(wh.id)}
                  className="p-1.5 rounded-lg text-rose-400 hover:text-rose-300 hover:bg-rose-500/10 transition-colors"
                  title="Delete Webhook"
                  aria-label="Delete"
                >
                  <Trash2 className="w-4 h-4" />
                </button>
              </div>
            </div>
          ))
        )}
      </div>

      {/* Register Webhook Modal */}
      {isCreateModalOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-background/80 backdrop-blur-sm animate-in fade-in">
          <div className="w-full max-w-2xl bg-card border border-border rounded-2xl shadow-2xl overflow-hidden flex flex-col max-h-[90vh]">
            <div className="flex items-center justify-between px-6 py-4 border-b border-border bg-muted/20">
              <div className="flex items-center gap-2.5">
                <Radio className="w-5 h-5 text-primary" />
                <h3 className="text-base font-bold text-foreground">Register Outbound Webhook</h3>
              </div>
              <button
                type="button"
                onClick={() => setIsCreateModalOpen(false)}
                className="text-muted-foreground hover:text-foreground"
              >
                &times;
              </button>
            </div>

            <form onSubmit={handleCreateWebhook} className="p-6 space-y-4 overflow-y-auto">
              {/* Endpoint URL */}
              <div className="space-y-1">
                <label className="text-xs font-semibold text-foreground">
                  Payload URL <span className="text-rose-500">*</span>
                </label>
                <input
                  type="url"
                  required
                  value={newUrl}
                  onChange={(e) => setNewUrl(e.target.value)}
                  placeholder="https://hooks.slack.com/services/... or https://api.yoursiem.com/events"
                  className="w-full px-3 py-2 text-xs bg-muted/40 border border-border rounded-lg text-foreground focus:outline-none focus:ring-1 focus:ring-primary font-mono"
                />
              </div>

              {/* Description */}
              <div className="space-y-1">
                <label className="text-xs font-semibold text-foreground">Description / Integration Name</label>
                <input
                  type="text"
                  value={newDescription}
                  onChange={(e) => setNewDescription(e.target.value)}
                  placeholder="e.g. Primary Incident Response Slack Channel"
                  className="w-full px-3 py-2 text-xs bg-muted/40 border border-border rounded-lg text-foreground focus:outline-none focus:ring-1 focus:ring-primary"
                />
              </div>

              {/* Secret Key Input with Masking & Auto-generation */}
              <div className="space-y-1">
                <div className="flex items-center justify-between">
                  <label className="text-xs font-semibold text-foreground flex items-center gap-1.5">
                    <Lock className="w-3.5 h-3.5 text-muted-foreground" />
                    HMAC-SHA256 Signing Secret Key
                  </label>
                  <button
                    type="button"
                    onClick={() => setNewSecret(generateHmacSecret())}
                    className="text-[11px] text-cyan-400 hover:text-cyan-300 font-mono flex items-center gap-1"
                  >
                    <Sparkles className="w-3 h-3" /> Auto-Generate Key
                  </button>
                </div>

                <div className="relative flex items-center">
                  <input
                    type={showSecret ? 'text' : 'password'}
                    value={newSecret}
                    onChange={(e) => setNewSecret(e.target.value)}
                    className="w-full pl-3 pr-20 py-2 text-xs bg-muted/40 border border-border rounded-lg text-foreground focus:outline-none focus:ring-1 focus:ring-primary font-mono"
                  />
                  <div className="absolute right-2 flex items-center gap-1">
                    <button
                      type="button"
                      onClick={() => setShowSecret(!showSecret)}
                      className="p-1 text-muted-foreground hover:text-foreground"
                      title={showSecret ? 'Mask Secret' : 'Reveal Secret'}
                    >
                      {showSecret ? <EyeOff className="w-3.5 h-3.5" /> : <Eye className="w-3.5 h-3.5" />}
                    </button>
                    <button
                      type="button"
                      onClick={handleCopySecret}
                      className="p-1 text-muted-foreground hover:text-foreground"
                      title="Copy Secret Key"
                    >
                      {copiedSecret ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                    </button>
                  </div>
                </div>

                <p className="text-[11px] text-muted-foreground">
                  Signing secrets are envelope-encrypted at rest using AES-256-GCM. Used by receiving endpoints to compute <code className="text-slate-300 font-mono">X-SecurityLab-Signature</code>.
                </p>
              </div>

              {/* Subscribed Events */}
              <div className="space-y-2 pt-2">
                <div className="flex items-center justify-between">
                  <label className="text-xs font-semibold text-foreground">Trigger Events</label>
                  <label className="flex items-center gap-1.5 text-xs text-muted-foreground cursor-pointer">
                    <input
                      type="checkbox"
                      checked={allEventsChecked}
                      onChange={(e) => setAllEventsChecked(e.target.checked)}
                      className="rounded border-border text-primary focus:ring-primary"
                    />
                    <span>Subscribe to all events (*)</span>
                  </label>
                </div>

                {!allEventsChecked && (
                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                    {availableEvents.map((ev) => {
                      const isChecked = selectedEvents.includes(ev.id);
                      return (
                        <div
                          key={ev.id}
                          onClick={() => handleToggleEvent(ev.id)}
                          className={`p-2.5 rounded-lg border cursor-pointer transition-colors ${
                            isChecked
                              ? 'bg-primary/10 border-primary/40'
                              : 'bg-muted/20 border-border hover:border-slate-700'
                          }`}
                        >
                          <div className="flex items-center justify-between">
                            <span className="font-mono text-xs font-bold text-foreground">{ev.label}</span>
                            {isChecked && <CheckCircle2 className="w-3.5 h-3.5 text-primary" />}
                          </div>
                          <p className="text-[10px] text-muted-foreground mt-0.5">{ev.desc}</p>
                        </div>
                      );
                    })}
                  </div>
                )}
              </div>

              {/* Custom HTTP Headers */}
              <div className="space-y-2 pt-2">
                <label className="text-xs font-semibold text-foreground">Custom HTTP Headers (Optional)</label>
                <div className="flex items-center gap-2">
                  <input
                    type="text"
                    placeholder="Header Key (e.g. Authorization)"
                    value={customHeaderKey}
                    onChange={(e) => setCustomHeaderKey(e.target.value)}
                    className="flex-1 px-3 py-1.5 text-xs bg-muted/40 border border-border rounded-lg text-foreground focus:outline-none focus:ring-1 focus:ring-primary font-mono"
                  />
                  <input
                    type="text"
                    placeholder="Header Value"
                    value={customHeaderVal}
                    onChange={(e) => setCustomHeaderVal(e.target.value)}
                    className="flex-1 px-3 py-1.5 text-xs bg-muted/40 border border-border rounded-lg text-foreground focus:outline-none focus:ring-1 focus:ring-primary font-mono"
                  />
                  <button
                    type="button"
                    onClick={handleAddHeader}
                    className="px-3 py-1.5 text-xs bg-muted hover:bg-muted/80 text-foreground font-semibold rounded-lg"
                  >
                    Add
                  </button>
                </div>

                {Object.keys(headersMap).length > 0 && (
                  <div className="flex flex-wrap gap-1.5 pt-1">
                    {Object.entries(headersMap).map(([k, v]) => (
                      <span
                        key={k}
                        className="inline-flex items-center gap-1 px-2.5 py-1 rounded-md text-[11px] font-mono bg-muted border border-border text-foreground"
                      >
                        <strong>{k}:</strong> {v.length > 20 ? `${v.slice(0, 20)}...` : v}
                        <button
                          type="button"
                          onClick={() => handleRemoveHeader(k)}
                          className="text-muted-foreground hover:text-rose-400 ml-1"
                        >
                          &times;
                        </button>
                      </span>
                    ))}
                  </div>
                )}
              </div>

              {/* Footer Actions */}
              <div className="flex items-center justify-end gap-2 pt-4 border-t border-border">
                <button
                  type="button"
                  onClick={() => setIsCreateModalOpen(false)}
                  className="px-4 py-2 text-xs font-semibold text-muted-foreground hover:text-foreground rounded-lg"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="px-5 py-2 text-xs font-bold rounded-lg bg-primary hover:bg-primary/90 text-primary-foreground shadow-md transition-all"
                >
                  Save Webhook
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Delivery Logs Modal */}
      <WebhookDeliveryLogsModal
        isOpen={Boolean(selectedLogsWebhook)}
        onClose={() => setSelectedLogsWebhook(null)}
        webhook={selectedLogsWebhook}
      />
    </div>
  );
};
