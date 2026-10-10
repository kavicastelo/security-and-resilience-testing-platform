import React, { useState, useEffect } from 'react';
import {
  Key,
  Eye,
  EyeOff,
  ShieldCheck,
  ShieldAlert,
  X,
  AlertCircle,
  Sparkles,
  Copy,
  Check,
} from 'lucide-react';
import { useAppStore } from '../store/useAppStore.js';

/**
 * Generates a cryptographically secure random hexadecimal token.
 * Defaults to 16 bytes = 32 hexadecimal characters.
 */
function generateSecureToken(byteLength = 16): string {
  const bytes = new Uint8Array(byteLength);
  if (typeof window !== 'undefined' && window.crypto) {
    window.crypto.getRandomValues(bytes);
  } else {
    for (let i = 0; i < byteLength; i++) {
      bytes[i] = Math.floor(Math.random() * 256);
    }
  }
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

export const ApiKeyModal: React.FC = () => {
  const {
    isAuthModalOpen,
    setIsAuthModalOpen,
    apiKey,
    adminKey,
    setCredentials,
    clearApiKey,
    showToast,
  } = useAppStore();

  const [inputKey, setInputKey] = useState('');
  const [showKey, setShowKey] = useState(false);
  const [copiedKey, setCopiedKey] = useState(false);

  const [useSeparateAdminKey, setUseSeparateAdminKey] = useState(false);
  const [inputAdminKey, setInputAdminKey] = useState('');
  const [showAdminKey, setShowAdminKey] = useState(false);
  const [copiedAdminKey, setCopiedAdminKey] = useState(false);

  const [rememberLocal, setRememberLocal] = useState(true);

  useEffect(() => {
    if (isAuthModalOpen) {
      const currentApi = apiKey || '';
      const currentAdmin = adminKey || '';
      setInputKey(currentApi);
      setInputAdminKey(currentAdmin);
      setUseSeparateAdminKey(Boolean(currentAdmin && currentAdmin !== currentApi));
      setShowKey(false);
      setShowAdminKey(false);
      setCopiedKey(false);
      setCopiedAdminKey(false);
    }
  }, [isAuthModalOpen, apiKey, adminKey]);

  if (!isAuthModalOpen) return null;

  const handleGenerateApiKey = () => {
    const token = generateSecureToken(16); // 32 hex chars
    setInputKey(token);
    setShowKey(true);
    showToast('Generated 32-character secure API token', 'info');
  };

  const handleGenerateAdminKey = () => {
    const token = generateSecureToken(16); // 32 hex chars
    setInputAdminKey(token);
    setShowAdminKey(true);
    showToast('Generated 32-character secure Admin token', 'info');
  };

  const copyToClipboard = async (text: string, type: 'operator' | 'admin') => {
    if (!text) return;
    try {
      if (typeof navigator !== 'undefined' && navigator.clipboard) {
        await navigator.clipboard.writeText(text);
      } else {
        const textArea = document.createElement('textarea');
        textArea.value = text;
        document.body.appendChild(textArea);
        textArea.select();
        document.execCommand('copy');
        document.body.removeChild(textArea);
      }

      if (type === 'operator') {
        setCopiedKey(true);
        setTimeout(() => setCopiedKey(false), 2000);
      } else {
        setCopiedAdminKey(true);
        setTimeout(() => setCopiedAdminKey(false), 2000);
      }
      showToast(`${type === 'operator' ? 'API' : 'Admin'} key copied to clipboard`, 'success');
    } catch {
      showToast('Failed to copy to clipboard', 'error');
    }
  };

  const handleFillDevDefaults = () => {
    setInputKey('this-is-sixteen-character-long-api-key');
    setInputAdminKey('this-is-sixteen-character-admin-key');
    setShowKey(true);
    setShowAdminKey(true);
    setUseSeparateAdminKey(true);
    showToast('Loaded local developer environment keys', 'info');
  };

  const handleSave = (e: React.FormEvent) => {
    e.preventDefault();
    const trimmedKey = inputKey.trim();
    if (!trimmedKey) {
      showToast('API key cannot be empty', 'error');
      return;
    }

    if (trimmedKey.length < 16) {
      showToast('API key must be at least 16 characters long', 'error');
      return;
    }

    const trimmedAdmin = inputAdminKey.trim();
    if (useSeparateAdminKey && trimmedAdmin && trimmedAdmin.length < 16) {
      showToast('Admin key must be at least 16 characters long', 'error');
      return;
    }

    const finalAdmin = useSeparateAdminKey && trimmedAdmin ? trimmedAdmin : trimmedKey;
    setCredentials(trimmedKey, finalAdmin, rememberLocal);
    showToast('Credentials configured successfully', 'success');
  };

  const handleClear = () => {
    clearApiKey();
    setInputKey('');
    setInputAdminKey('');
    setUseSeparateAdminKey(false);
    showToast('API and Admin credentials cleared', 'info');
  };

  const isOperatorConfigured = Boolean(apiKey);
  const isAdminConfigured = Boolean(adminKey);

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-background/80 backdrop-blur-sm animate-in fade-in duration-200">
      <div className="relative w-full max-w-lg p-6 bg-card border border-border rounded-xl shadow-2xl space-y-5">
        <button
          type="button"
          onClick={() => setIsAuthModalOpen(false)}
          className="absolute top-4 right-4 p-1.5 rounded-lg text-muted-foreground hover:text-foreground hover:bg-accent transition-colors"
          aria-label="Close"
        >
          <X className="w-4 h-4" />
        </button>

        <div className="flex items-center space-x-3">
          <div className="p-2.5 rounded-lg bg-blue-500/10 border border-blue-500/20 text-blue-400">
            <Key className="w-5 h-5" />
          </div>
          <div>
            <h2 className="text-base font-semibold text-foreground">Controller API Key & Credentials</h2>
            <p className="text-xs text-muted-foreground">Configure operator and administrative keys for protected operations</p>
          </div>
        </div>

        <div className="p-3 rounded-lg bg-accent/40 border border-border/60 text-xs text-muted-foreground flex items-start space-x-2.5">
          <AlertCircle className="w-4 h-4 text-blue-400 shrink-0 mt-0.5" />
          <div className="space-y-1">
            <p>
              The controller strictly enforces authentication for all targets, test runs, policies, and management endpoints.
            </p>
            <p className="text-[11px] text-muted-foreground/90">
              Keys must be at least 16 characters. Use the <strong className="text-blue-300">Generate Token</strong> button to create high-entropy credentials.
            </p>
          </div>
        </div>

        <form onSubmit={handleSave} className="space-y-4">
          {/* Operator API Key */}
          <div className="space-y-1.5">
            <div className="flex items-center justify-between">
              <label htmlFor="apiKeyInput" className="text-xs font-medium text-foreground block">
                Controller API Key / Operator Token
              </label>
              <div className="flex items-center space-x-1.5">
                <button
                  type="button"
                  id="generate-api-token-btn"
                  onClick={handleGenerateApiKey}
                  className="flex items-center space-x-1 text-[11px] text-blue-400 hover:text-blue-300 bg-blue-500/10 hover:bg-blue-500/20 px-2 py-0.5 rounded border border-blue-500/20 transition-colors"
                  title="Generate a cryptographically secure 32-character random token"
                >
                  <Sparkles className="w-3 h-3" />
                  <span>Generate Token</span>
                </button>
                <button
                  type="button"
                  id="copy-api-token-btn"
                  onClick={() => copyToClipboard(inputKey, 'operator')}
                  className="flex items-center space-x-1 text-[11px] text-muted-foreground hover:text-foreground bg-accent hover:bg-accent/80 px-2 py-0.5 rounded border border-border transition-colors disabled:opacity-50"
                  disabled={!inputKey}
                  title="Copy API key to clipboard"
                >
                  {copiedKey ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                  <span>{copiedKey ? 'Copied!' : 'Copy'}</span>
                </button>
              </div>
            </div>

            <div className="relative">
              <input
                id="apiKeyInput"
                type={showKey ? 'text' : 'password'}
                value={inputKey}
                onChange={(e) => setInputKey(e.target.value)}
                placeholder="security-lab-api-key..."
                className="w-full px-3 py-2 pr-10 text-xs font-mono bg-background border border-border rounded-lg text-foreground focus:outline-none focus:ring-1 focus:ring-blue-500 placeholder:text-muted-foreground"
                autoFocus
              />
              <button
                type="button"
                onClick={() => setShowKey(!showKey)}
                className="absolute right-2.5 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground p-1"
                aria-label={showKey ? 'Hide key' : 'Show key'}
              >
                {showKey ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
              </button>
            </div>

            <div className="flex items-center justify-between text-[11px] text-muted-foreground">
              <span>{inputKey ? `${inputKey.length} chars (min 16)` : 'Min 16 chars required'}</span>
              <button
                type="button"
                onClick={handleFillDevDefaults}
                className="text-muted-foreground hover:text-blue-400 underline decoration-dotted transition-colors"
              >
                Fill Preconfigured Dev Keys
              </button>
            </div>
          </div>

          {/* Dedicated Admin Key Section */}
          <div className="pt-3 border-t border-border/60 space-y-2.5">
            <div className="flex items-center justify-between">
              <label className="flex items-center space-x-2 cursor-pointer text-xs font-medium text-foreground">
                <input
                  type="checkbox"
                  id="separate-admin-key-toggle"
                  checked={useSeparateAdminKey}
                  onChange={(e) => setUseSeparateAdminKey(e.target.checked)}
                  className="rounded border-border text-blue-600 focus:ring-blue-500 bg-background"
                />
                <span>Configure separate Administrative Key</span>
              </label>
              <span className="text-[11px] text-muted-foreground">
                {useSeparateAdminKey ? 'Dedicated Key' : 'Inherits API Key'}
              </span>
            </div>

            {useSeparateAdminKey && (
              <div className="space-y-1.5 pl-5 border-l-2 border-purple-500/30 animate-in fade-in duration-150">
                <div className="flex items-center justify-between">
                  <label htmlFor="adminKeyInput" className="text-xs text-muted-foreground block">
                    Admin Key (<code className="text-purple-300 font-mono">X-Admin-Key</code>)
                  </label>
                  <div className="flex items-center space-x-1.5">
                    <button
                      type="button"
                      id="generate-admin-token-btn"
                      onClick={handleGenerateAdminKey}
                      className="flex items-center space-x-1 text-[11px] text-purple-400 hover:text-purple-300 bg-purple-500/10 hover:bg-purple-500/20 px-2 py-0.5 rounded border border-purple-500/20 transition-colors"
                      title="Generate a cryptographically secure random token for admin operations"
                    >
                      <Sparkles className="w-3 h-3" />
                      <span>Generate Token</span>
                    </button>
                    <button
                      type="button"
                      id="copy-admin-token-btn"
                      onClick={() => copyToClipboard(inputAdminKey, 'admin')}
                      className="flex items-center space-x-1 text-[11px] text-muted-foreground hover:text-foreground bg-accent hover:bg-accent/80 px-2 py-0.5 rounded border border-border transition-colors disabled:opacity-50"
                      disabled={!inputAdminKey}
                      title="Copy admin key to clipboard"
                    >
                      {copiedAdminKey ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                      <span>{copiedAdminKey ? 'Copied!' : 'Copy'}</span>
                    </button>
                  </div>
                </div>

                <div className="relative">
                  <input
                    id="adminKeyInput"
                    type={showAdminKey ? 'text' : 'password'}
                    value={inputAdminKey}
                    onChange={(e) => setInputAdminKey(e.target.value)}
                    placeholder="security-lab-admin-key..."
                    className="w-full px-3 py-2 pr-10 text-xs font-mono bg-background border border-border rounded-lg text-foreground focus:outline-none focus:ring-1 focus:ring-purple-500 placeholder:text-muted-foreground"
                  />
                  <button
                    type="button"
                    onClick={() => setShowAdminKey(!showAdminKey)}
                    className="absolute right-2.5 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground p-1"
                    aria-label={showAdminKey ? 'Hide admin key' : 'Show admin key'}
                  >
                    {showAdminKey ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                  </button>
                </div>
                <p className="text-[11px] text-muted-foreground">
                  Elevates privileges for purge, demo seeding, disaster recovery restore, and job watchdog.
                </p>
              </div>
            )}
          </div>

          <div className="flex items-center justify-between text-xs pt-1">
            <label className="flex items-center space-x-2 cursor-pointer text-muted-foreground">
              <input
                type="checkbox"
                checked={rememberLocal}
                onChange={(e) => setRememberLocal(e.target.checked)}
                className="rounded border-border text-blue-600 focus:ring-blue-500 bg-background"
              />
              <span>Remember in localStorage</span>
            </label>

            <div className="flex items-center space-x-2">
              {isOperatorConfigured && (
                <span className="flex items-center space-x-1 text-emerald-400 text-[11px]">
                  <ShieldCheck className="w-3.5 h-3.5" />
                  <span>Operator Active</span>
                </span>
              )}
              {isAdminConfigured && (
                <span className="flex items-center space-x-1 text-purple-400 text-[11px]">
                  <ShieldAlert className="w-3.5 h-3.5" />
                  <span>Admin Active</span>
                </span>
              )}
            </div>
          </div>

          <div className="flex items-center justify-between pt-2 space-x-3">
            {apiKey || adminKey ? (
              <button
                type="button"
                onClick={handleClear}
                className="px-3 py-2 text-xs font-medium text-destructive hover:bg-destructive/10 rounded-lg transition-colors"
              >
                Clear All Keys
              </button>
            ) : <div />}

            <div className="flex items-center space-x-2">
              <button
                type="button"
                onClick={() => setIsAuthModalOpen(false)}
                className="px-3 py-2 text-xs font-medium text-muted-foreground hover:bg-accent rounded-lg transition-colors"
              >
                Cancel
              </button>
              <button
                type="submit"
                id="save-credentials-btn"
                className="px-4 py-2 text-xs font-medium bg-blue-600 hover:bg-blue-500 text-white rounded-lg transition-colors shadow-sm"
              >
                Save Credentials
              </button>
            </div>
          </div>
        </form>
      </div>
    </div>
  );
};
