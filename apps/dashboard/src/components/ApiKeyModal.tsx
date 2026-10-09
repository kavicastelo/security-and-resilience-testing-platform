import React, { useState, useEffect } from 'react';
import { Key, Eye, EyeOff, ShieldCheck, X, AlertCircle } from 'lucide-react';
import { useAppStore } from '../store/useAppStore.js';

export const ApiKeyModal: React.FC = () => {
  const { isAuthModalOpen, setIsAuthModalOpen, apiKey, setApiKey, clearApiKey, showToast } = useAppStore();
  const [inputKey, setInputKey] = useState('');
  const [showKey, setShowKey] = useState(false);
  const [rememberLocal, setRememberLocal] = useState(true);

  useEffect(() => {
    if (isAuthModalOpen) {
      setInputKey(apiKey || '');
    }
  }, [isAuthModalOpen, apiKey]);

  if (!isAuthModalOpen) return null;

  const handleSave = (e: React.FormEvent) => {
    e.preventDefault();
    if (!inputKey.trim()) {
      showToast('API key cannot be empty', 'error');
      return;
    }

    setApiKey(inputKey.trim(), rememberLocal);
    showToast('API key configured successfully', 'success');
    setIsAuthModalOpen(false);
  };

  const handleClear = () => {
    clearApiKey();
    setInputKey('');
    showToast('API key cleared', 'info');
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-background/80 backdrop-blur-sm animate-in fade-in duration-200">
      <div className="relative w-full max-w-md p-6 bg-card border border-border rounded-xl shadow-2xl space-y-5">
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
            <h2 className="text-base font-semibold text-foreground">Controller API Key</h2>
            <p className="text-xs text-muted-foreground">Configure authentication for protected API operations</p>
          </div>
        </div>

        <div className="p-3 rounded-lg bg-accent/40 border border-border/60 text-xs text-muted-foreground flex items-start space-x-2.5">
          <AlertCircle className="w-4 h-4 text-blue-400 shrink-0 mt-0.5" />
          <p>
            The controller enforces authentication for all target, test run, policy, and management endpoints.
            Provide your <code className="text-blue-300 font-mono">SECURITY_LAB_API_KEY</code>.
          </p>
        </div>

        <form onSubmit={handleSave} className="space-y-4">
          <div className="space-y-1.5">
            <label htmlFor="apiKeyInput" className="text-xs font-medium text-foreground block">
              API Key or Bearer Token
            </label>
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
          </div>

          <div className="flex items-center justify-between text-xs">
            <label className="flex items-center space-x-2 cursor-pointer text-muted-foreground">
              <input
                type="checkbox"
                checked={rememberLocal}
                onChange={(e) => setRememberLocal(e.target.checked)}
                className="rounded border-border text-blue-600 focus:ring-blue-500 bg-background"
              />
              <span>Remember in localStorage</span>
            </label>

            {apiKey && (
              <span className="flex items-center space-x-1 text-emerald-400 text-[11px]">
                <ShieldCheck className="w-3.5 h-3.5" />
                <span>Configured</span>
              </span>
            )}
          </div>

          <div className="flex items-center justify-between pt-2 space-x-3">
            {apiKey ? (
              <button
                type="button"
                onClick={handleClear}
                className="px-3 py-2 text-xs font-medium text-destructive hover:bg-destructive/10 rounded-lg transition-colors"
              >
                Clear Key
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
