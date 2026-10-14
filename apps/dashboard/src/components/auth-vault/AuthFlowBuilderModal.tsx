import React, { useState } from 'react';
import {
  X,
  KeyRound,
  ShieldCheck,
  ShieldAlert,
  Play,
  Save,
  Plus,
  Trash2,
  ArrowUp,
  ArrowDown,
  Lock,
  Eye,
  EyeOff,
  Layers,
  Loader2,
  Zap,
} from 'lucide-react';
import {
  AuthFlow,
  AuthType,
  AuthStep,
  AUTH_FLOW_TEMPLATES,
  executeAuthFlowTest,
  updateTargetAuthFlow,
  AuthTestResult,
} from '../../api/authVault.js';
import { useAppStore } from '../../store/useAppStore.js';

interface AuthFlowBuilderModalProps {
  isOpen: boolean;
  onClose: () => void;
  targetId: string;
  targetName: string;
  targetUrl: string;
  initialFlow?: AuthFlow | null;
  onSaved?: () => void;
}

export const AuthFlowBuilderModal: React.FC<AuthFlowBuilderModalProps> = ({
  isOpen,
  onClose,
  targetId,
  targetName,
  targetUrl,
  initialFlow,
  onSaved,
}) => {
  const { showToast } = useAppStore();

  const [flow, setFlow] = useState<AuthFlow>(() => {
    if (initialFlow) return JSON.parse(JSON.stringify(initialFlow));
    return JSON.parse(JSON.stringify(AUTH_FLOW_TEMPLATES.formCsrf.flow));
  });

  const [showSecrets, setShowSecrets] = useState<boolean>(false);
  const [isTesting, setIsTesting] = useState<boolean>(false);
  const [isSaving, setIsSaving] = useState<boolean>(false);
  const [testResult, setTestResult] = useState<AuthTestResult | null>(null);

  if (!isOpen) return null;

  // Load a pre-defined template
  const handleApplyTemplate = (key: string) => {
    const tmpl = AUTH_FLOW_TEMPLATES[key];
    if (tmpl) {
      setFlow(JSON.parse(JSON.stringify(tmpl.flow)));
      setTestResult(null);
      showToast(`Applied "${tmpl.label}" flow template`, 'info');
    }
  };

  // Step Sequencer Handlers
  const handleAddStep = () => {
    const newStep: AuthStep = {
      name: `Step #${(flow.steps?.length || 0) + 1}`,
      url: '/auth/step',
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: {},
      extract: [{ from: 'BODY_JSON', key: 'token', saveAs: 'token' }],
    };
    setFlow((prev) => ({
      ...prev,
      steps: [...(prev.steps || []), newStep],
    }));
  };

  const handleRemoveStep = (index: number) => {
    setFlow((prev) => ({
      ...prev,
      steps: prev.steps?.filter((_, i) => i !== index),
    }));
  };

  const handleMoveStep = (index: number, direction: 'UP' | 'DOWN') => {
    if (!flow.steps) return;
    const targetIdx = direction === 'UP' ? index - 1 : index + 1;
    if (targetIdx < 0 || targetIdx >= flow.steps.length) return;

    const newSteps = [...flow.steps];
    const [moved] = newSteps.splice(index, 1);
    newSteps.splice(targetIdx, 0, moved);

    setFlow((prev) => ({ ...prev, steps: newSteps }));
  };

  const handleUpdateStep = (index: number, updates: Partial<AuthStep>) => {
    setFlow((prev) => ({
      ...prev,
      steps: prev.steps?.map((step, i) => (i === index ? { ...step, ...updates } : step)),
    }));
  };

  // Execute Live Flow Test
  const handleTestFlow = async () => {
    setIsTesting(true);
    setTestResult(null);
    try {
      const result = await executeAuthFlowTest(targetUrl, flow);
      setTestResult(result);
      if (result.success) {
        showToast('Authentication handshake succeeded!', 'success');
      } else {
        showToast(result.error || 'Authentication flow failed', 'error');
      }
    } catch (err: any) {
      showToast(err.message || 'Error executing test flow', 'error');
    } finally {
      setIsTesting(false);
    }
  };

  // Save to target (controller envelope-encrypts via AES-256-GCM)
  const handleSave = async () => {
    setIsSaving(true);
    try {
      await updateTargetAuthFlow(targetId, flow);
      showToast('Credentials and auth flow encrypted & saved to Vault', 'success');
      if (onSaved) onSaved();
      onClose();
    } catch (err: any) {
      showToast(err.message || 'Failed to persist credentials', 'error');
    } finally {
      setIsSaving(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-background/80 backdrop-blur-sm animate-fade-in">
      <div className="relative w-full max-w-4xl max-h-[90vh] overflow-hidden rounded-2xl bg-card border border-border shadow-2xl flex flex-col">
        {/* Header Bar */}
        <div className="p-4 sm:p-5 border-b border-border flex items-center justify-between bg-accent/20">
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-xl bg-cyan-500/15 border border-cyan-500/30 text-cyan-400">
              <KeyRound className="w-5 h-5" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h2 className="text-base font-bold text-foreground">
                  Stateful Authentication Flow Builder
                </h2>
                <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-cyan-500/15 text-cyan-300 border border-cyan-500/30">
                  AES-256-GCM
                </span>
              </div>
              <p className="text-xs text-muted-foreground">
                Target: <span className="font-semibold text-foreground">{targetName}</span> ({targetUrl})
              </p>
            </div>
          </div>

          <button
            type="button"
            onClick={onClose}
            className="p-1.5 rounded-lg text-muted-foreground hover:text-foreground hover:bg-accent transition-colors"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Scrollable Content Canvas */}
        <div className="p-5 overflow-y-auto space-y-6 flex-1">
          {/* Preset Templates Quick-Bar */}
          <div className="p-3 rounded-xl bg-accent/30 border border-border flex flex-wrap items-center justify-between gap-2.5">
            <span className="text-xs font-bold uppercase tracking-wider text-muted-foreground flex items-center gap-1.5">
              <Zap className="w-3.5 h-3.5 text-cyan-400" />
              Templates:
            </span>
            <div className="flex flex-wrap items-center gap-2">
              {Object.entries(AUTH_FLOW_TEMPLATES).map(([key, tmpl]) => (
                <button
                  key={key}
                  type="button"
                  onClick={() => handleApplyTemplate(key)}
                  className="px-2.5 py-1 rounded-lg text-xs bg-background hover:bg-cyan-500/10 text-foreground hover:text-cyan-300 border border-border transition-colors font-medium"
                >
                  {tmpl.label}
                </button>
              ))}
            </div>
          </div>

          {/* Authentication Type Selector */}
          <div className="space-y-1.5">
            <label className="text-[11px] font-bold uppercase tracking-wider text-muted-foreground block">
              Authentication Mechanism
            </label>
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-2.5">
              {(['FORM', 'OAUTH2', 'BEARER', 'API_KEY'] as AuthType[]).map((type) => (
                <button
                  key={type}
                  type="button"
                  onClick={() => setFlow((prev) => ({ ...prev, type }))}
                  className={`p-3 rounded-xl border text-center transition-all ${
                    flow.type === type
                      ? 'bg-cyan-500/15 border-cyan-500/40 text-cyan-300 shadow-sm'
                      : 'bg-background hover:bg-accent/40 border-border text-muted-foreground hover:text-foreground'
                  }`}
                >
                  <span className="block font-mono font-bold text-xs">{type}</span>
                  <span className="text-[10px] text-muted-foreground block mt-0.5">
                    {type === 'FORM' && 'Multi-Step Login'}
                    {type === 'OAUTH2' && 'Token Exchange'}
                    {type === 'BEARER' && 'JWT Header'}
                    {type === 'API_KEY' && 'Custom Header'}
                  </span>
                </button>
              ))}
            </div>
          </div>

          {/* Secrets Mask Toggle */}
          <div className="flex items-center justify-between text-xs">
            <span className="text-muted-foreground flex items-center gap-1.5">
              <Lock className="w-3.5 h-3.5 text-cyan-400" />
              Envelope-Encrypted Secrets Vault Input
            </span>
            <button
              type="button"
              onClick={() => setShowSecrets(!showSecrets)}
              className="text-muted-foreground hover:text-foreground flex items-center gap-1 text-[11px]"
            >
              {showSecrets ? <EyeOff className="w-3.5 h-3.5" /> : <Eye className="w-3.5 h-3.5" />}
              <span>{showSecrets ? 'Mask Sensitive Fields' : 'Reveal Sensitive Fields'}</span>
            </button>
          </div>

          {/* Credentials Inputs (FORM / API_KEY / BEARER) */}
          {flow.type !== 'OAUTH2' && (
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 p-4 rounded-xl bg-background/60 border border-border">
              {flow.type === 'FORM' && (
                <>
                  <div className="space-y-1">
                    <label className="text-[11px] font-bold uppercase tracking-wider text-muted-foreground">
                      Username / Email
                    </label>
                    <input
                      type="text"
                      value={flow.credentials?.username || ''}
                      onChange={(e) =>
                        setFlow((prev) => ({
                          ...prev,
                          credentials: { ...(prev.credentials || {}), username: e.target.value },
                        }))
                      }
                      placeholder="user@example.com"
                      className="w-full px-3 py-1.5 rounded-lg bg-background border border-border text-xs text-foreground focus:outline-none focus:ring-1 focus:ring-cyan-500 font-mono"
                    />
                  </div>

                  <div className="space-y-1">
                    <label className="text-[11px] font-bold uppercase tracking-wider text-muted-foreground">
                      Password
                    </label>
                    <input
                      type={showSecrets ? 'text' : 'password'}
                      value={flow.credentials?.password || ''}
                      onChange={(e) =>
                        setFlow((prev) => ({
                          ...prev,
                          credentials: { ...(prev.credentials || {}), password: e.target.value },
                        }))
                      }
                      placeholder="••••••••••••"
                      className="w-full px-3 py-1.5 rounded-lg bg-background border border-border text-xs text-foreground focus:outline-none focus:ring-1 focus:ring-cyan-500 font-mono"
                    />
                  </div>

                  <div className="space-y-1">
                    <label className="text-[11px] font-bold uppercase tracking-wider text-muted-foreground">
                      TOTP Base32 Seed (Optional)
                    </label>
                    <input
                      type={showSecrets ? 'text' : 'password'}
                      value={flow.totpSecret || ''}
                      onChange={(e) => setFlow((prev) => ({ ...prev, totpSecret: e.target.value }))}
                      placeholder="JBSWY3DPEHPK3PXP"
                      className="w-full px-3 py-1.5 rounded-lg bg-background border border-border text-xs text-foreground focus:outline-none focus:ring-1 focus:ring-cyan-500 font-mono uppercase"
                    />
                  </div>
                </>
              )}

              {(flow.type === 'BEARER' || flow.type === 'API_KEY') && (
                <div className="sm:col-span-3 space-y-1">
                  <label className="text-[11px] font-bold uppercase tracking-wider text-muted-foreground">
                    Static Token / Key Value
                  </label>
                  <input
                    type={showSecrets ? 'text' : 'password'}
                    value={flow.credentials?.token || flow.credentials?.apiKey || ''}
                    onChange={(e) =>
                      setFlow((prev) => ({
                        ...prev,
                        credentials: {
                          token: e.target.value,
                          apiKey: e.target.value,
                        },
                      }))
                    }
                    placeholder="Enter secret token or key..."
                    className="w-full px-3 py-1.5 rounded-lg bg-background border border-border text-xs text-foreground focus:outline-none focus:ring-1 focus:ring-cyan-500 font-mono"
                  />
                </div>
              )}
            </div>
          )}

          {/* OAuth2 Config Box */}
          {flow.type === 'OAUTH2' && (
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 p-4 rounded-xl bg-background/60 border border-border">
              <div className="space-y-1">
                <label className="text-[11px] font-bold uppercase tracking-wider text-muted-foreground">
                  Token URL
                </label>
                <input
                  type="text"
                  value={flow.oauth2Config?.tokenUrl || ''}
                  onChange={(e) =>
                    setFlow((prev) => ({
                      ...prev,
                      oauth2Config: {
                        grantType: 'client_credentials',
                        clientId: '',
                        clientSecret: '',
                        ...(prev.oauth2Config || {}),
                        tokenUrl: e.target.value,
                      },
                    }))
                  }
                  placeholder="/oauth/v2/token"
                  className="w-full px-3 py-1.5 rounded-lg bg-background border border-border text-xs text-foreground font-mono focus:outline-none focus:ring-1 focus:ring-cyan-500"
                />
              </div>

              <div className="space-y-1">
                <label className="text-[11px] font-bold uppercase tracking-wider text-muted-foreground">
                  Grant Type
                </label>
                <select
                  value={flow.oauth2Config?.grantType || 'client_credentials'}
                  onChange={(e) =>
                    setFlow((prev) => ({
                      ...prev,
                      oauth2Config: {
                        tokenUrl: '',
                        clientId: '',
                        clientSecret: '',
                        ...(prev.oauth2Config || {}),
                        grantType: e.target.value as any,
                      },
                    }))
                  }
                  className="w-full px-3 py-1.5 rounded-lg bg-background border border-border text-xs text-foreground font-mono focus:outline-none focus:ring-1 focus:ring-cyan-500"
                >
                  <option value="client_credentials">Client Credentials</option>
                  <option value="password">Password (Resource Owner)</option>
                  <option value="authorization_code">Authorization Code</option>
                  <option value="refresh_token">Refresh Token</option>
                </select>
              </div>

              <div className="space-y-1">
                <label className="text-[11px] font-bold uppercase tracking-wider text-muted-foreground">
                  Client ID
                </label>
                <input
                  type="text"
                  value={flow.oauth2Config?.clientId || ''}
                  onChange={(e) =>
                    setFlow((prev) => ({
                      ...prev,
                      oauth2Config: {
                        grantType: 'client_credentials',
                        tokenUrl: '',
                        clientSecret: '',
                        ...(prev.oauth2Config || {}),
                        clientId: e.target.value,
                      },
                    }))
                  }
                  placeholder="client_id_001"
                  className="w-full px-3 py-1.5 rounded-lg bg-background border border-border text-xs text-foreground font-mono focus:outline-none focus:ring-1 focus:ring-cyan-500"
                />
              </div>

              <div className="space-y-1">
                <label className="text-[11px] font-bold uppercase tracking-wider text-muted-foreground">
                  Client Secret
                </label>
                <input
                  type={showSecrets ? 'text' : 'password'}
                  value={flow.oauth2Config?.clientSecret || ''}
                  onChange={(e) =>
                    setFlow((prev) => ({
                      ...prev,
                      oauth2Config: {
                        grantType: 'client_credentials',
                        tokenUrl: '',
                        clientId: '',
                        ...(prev.oauth2Config || {}),
                        clientSecret: e.target.value,
                      },
                    }))
                  }
                  placeholder="••••••••••••"
                  className="w-full px-3 py-1.5 rounded-lg bg-background border border-border text-xs text-foreground font-mono focus:outline-none focus:ring-1 focus:ring-cyan-500"
                />
              </div>
            </div>
          )}

          {/* Step Sequence Timeline (for FORM type) */}
          {flow.type === 'FORM' && (
            <div className="space-y-3">
              <div className="flex items-center justify-between">
                <span className="text-xs font-bold uppercase tracking-wider text-muted-foreground flex items-center gap-1.5">
                  <Layers className="w-3.5 h-3.5 text-cyan-400" />
                  Authentication Sequence Steps ({flow.steps?.length || 0})
                </span>

                <button
                  type="button"
                  onClick={handleAddStep}
                  className="flex items-center gap-1 px-2.5 py-1 rounded-lg bg-cyan-600/15 hover:bg-cyan-600/25 text-cyan-300 border border-cyan-500/40 text-xs font-medium transition-colors"
                >
                  <Plus className="w-3 h-3" />
                  <span>Add Step</span>
                </button>
              </div>

              <div className="space-y-3">
                {flow.steps?.map((step, idx) => (
                  <div
                    key={idx}
                    className="p-4 rounded-xl bg-background border border-border space-y-3 relative group"
                  >
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-2">
                        <span className="w-6 h-6 rounded-full bg-cyan-500/15 text-cyan-300 font-mono font-bold text-xs flex items-center justify-center border border-cyan-500/30">
                          {idx + 1}
                        </span>
                        <input
                          type="text"
                          value={step.name || ''}
                          onChange={(e) => handleUpdateStep(idx, { name: e.target.value })}
                          placeholder="Step Name (e.g. Fetch CSRF Token)"
                          className="px-2 py-1 rounded bg-accent/40 border border-border text-xs font-medium text-foreground focus:outline-none focus:ring-1 focus:ring-cyan-500"
                        />
                      </div>

                      {/* Step Actions */}
                      <div className="flex items-center gap-1">
                        <button
                          type="button"
                          disabled={idx === 0}
                          onClick={() => handleMoveStep(idx, 'UP')}
                          className="p-1 rounded text-muted-foreground hover:text-foreground disabled:opacity-30"
                          title="Move Up"
                        >
                          <ArrowUp className="w-3.5 h-3.5" />
                        </button>
                        <button
                          type="button"
                          disabled={idx === (flow.steps?.length || 0) - 1}
                          onClick={() => handleMoveStep(idx, 'DOWN')}
                          className="p-1 rounded text-muted-foreground hover:text-foreground disabled:opacity-30"
                          title="Move Down"
                        >
                          <ArrowDown className="w-3.5 h-3.5" />
                        </button>
                        <button
                          type="button"
                          onClick={() => handleRemoveStep(idx)}
                          className="p-1 rounded text-muted-foreground hover:text-rose-400"
                          title="Remove Step"
                        >
                          <Trash2 className="w-3.5 h-3.5" />
                        </button>
                      </div>
                    </div>

                    {/* Method & URL */}
                    <div className="grid grid-cols-12 gap-2">
                      <div className="col-span-3">
                        <select
                          value={step.method}
                          onChange={(e) => handleUpdateStep(idx, { method: e.target.value as any })}
                          className="w-full px-2 py-1.5 rounded-lg bg-accent/30 border border-border text-xs font-mono font-bold text-foreground focus:outline-none focus:ring-1 focus:ring-cyan-500"
                        >
                          <option value="GET">GET</option>
                          <option value="POST">POST</option>
                          <option value="PUT">PUT</option>
                          <option value="PATCH">PATCH</option>
                          <option value="DELETE">DELETE</option>
                        </select>
                      </div>

                      <div className="col-span-9">
                        <input
                          type="text"
                          value={step.url}
                          onChange={(e) => handleUpdateStep(idx, { url: e.target.value })}
                          placeholder="/auth/login"
                          className="w-full px-3 py-1.5 rounded-lg bg-background border border-border text-xs font-mono text-foreground focus:outline-none focus:ring-1 focus:ring-cyan-500"
                        />
                      </div>
                    </div>

                    {/* Variable Extraction Settings */}
                    <div className="p-3 rounded-lg bg-accent/20 border border-border/70 text-xs space-y-1.5">
                      <span className="font-semibold text-muted-foreground block text-[11px] uppercase tracking-wider">
                        Dynamic Variable Extraction:
                      </span>
                      {step.extract && step.extract.length > 0 ? (
                        step.extract.map((ext, extIdx) => (
                          <div key={extIdx} className="flex items-center gap-2 font-mono text-[11px]">
                            <span className="px-2 py-0.5 rounded bg-cyan-500/10 text-cyan-300 border border-cyan-500/30">
                              {ext.from}
                            </span>
                            <span className="text-muted-foreground">Key:</span>
                            <span className="text-foreground">{ext.key}</span>
                            <span className="text-muted-foreground">&rarr; Save As:</span>
                            <span className="text-emerald-400 font-bold">{`{{${ext.saveAs}}}`}</span>
                          </div>
                        ))
                      ) : (
                        <p className="text-muted-foreground italic text-[11px]">
                          No variables extracted in this step.
                        </p>
                      )}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Test Handshake Result Output */}
          {testResult && (
            <div
              className={`p-4 rounded-xl border space-y-3 ${
                testResult.success
                  ? 'bg-emerald-950/20 border-emerald-500/30'
                  : 'bg-rose-950/20 border-rose-500/30'
              }`}
            >
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  {testResult.success ? (
                    <ShieldCheck className="w-5 h-5 text-emerald-400" />
                  ) : (
                    <ShieldAlert className="w-5 h-5 text-rose-400" />
                  )}
                  <span className="text-sm font-bold text-foreground">
                    {testResult.success ? 'Authentication Handshake Verified' : 'Handshake Failed'}
                  </span>
                </div>
                <span className="text-xs font-mono text-muted-foreground">
                  {testResult.totalDurationMs}ms total
                </span>
              </div>

              {testResult.finalToken && (
                <div className="p-2.5 rounded-lg bg-zinc-950/80 border border-border text-xs font-mono flex items-center justify-between">
                  <span className="text-muted-foreground">Extracted Session Token:</span>
                  <span className="text-emerald-400 font-bold select-all">
                    {testResult.finalToken.slice(0, 32)}...
                  </span>
                </div>
              )}

              {testResult.stepsExecuted.length > 0 && (
                <div className="space-y-1">
                  <span className="text-[11px] font-bold uppercase tracking-wider text-muted-foreground block">
                    Execution Step Trace:
                  </span>
                  <div className="space-y-1 text-xs font-mono">
                    {testResult.stepsExecuted.map((s) => (
                      <div
                        key={s.stepIndex}
                        className="flex items-center justify-between p-2 rounded bg-card/60 border border-border/60"
                      >
                        <div className="flex items-center gap-2">
                          <span className="px-1.5 py-0.5 rounded text-[10px] bg-cyan-500/15 text-cyan-300">
                            {s.method}
                          </span>
                          <span className="text-foreground">{s.name}</span>
                        </div>
                        <div className="flex items-center gap-3">
                          <span
                            className={
                              s.statusCode < 400 ? 'text-emerald-400' : 'text-rose-400'
                            }
                          >
                            HTTP {s.statusCode}
                          </span>
                          <span className="text-muted-foreground">{s.durationMs}ms</span>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}
        </div>

        {/* Modal Footer Controls */}
        <div className="p-4 border-t border-border flex flex-wrap items-center justify-between gap-3 bg-accent/20">
          <button
            type="button"
            onClick={handleTestFlow}
            disabled={isTesting}
            className="flex items-center gap-1.5 px-4 py-2 rounded-xl bg-accent hover:bg-accent/80 text-foreground font-semibold text-xs border border-border transition-colors shadow-sm disabled:opacity-50"
          >
            {isTesting ? (
              <>
                <Loader2 className="w-3.5 h-3.5 animate-spin text-cyan-400" />
                <span>Executing Handshake...</span>
              </>
            ) : (
              <>
                <Play className="w-3.5 h-3.5 text-cyan-400" />
                <span>Test Flow Handshake</span>
              </>
            )}
          </button>

          <div className="flex items-center gap-2">
            <button
              type="button"
              onClick={onClose}
              className="px-4 py-2 rounded-xl bg-background hover:bg-accent text-muted-foreground hover:text-foreground text-xs font-medium border border-border transition-colors"
            >
              Cancel
            </button>
            <button
              type="button"
              onClick={handleSave}
              disabled={isSaving}
              className="flex items-center gap-1.5 px-4 py-2 rounded-xl bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-white font-semibold text-xs transition-all shadow-md disabled:opacity-50"
            >
              {isSaving ? (
                <>
                  <Loader2 className="w-3.5 h-3.5 animate-spin" />
                  <span>Encrypting...</span>
                </>
              ) : (
                <>
                  <Save className="w-3.5 h-3.5" />
                  <span>Save to Encrypted Vault</span>
                </>
              )}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};
