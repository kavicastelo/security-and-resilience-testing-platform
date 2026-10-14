import React, { useState, useEffect } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import {
  ShieldCheck,
  Download,
  Copy,
  Check,
  Eye,
  EyeOff,
  Save,
} from 'lucide-react';
import { governanceApi, WorkspaceSsoConfig } from '../../api/governance.js';
import { useAppStore } from '../../store/useAppStore.js';

export const SsoConfigTab: React.FC = () => {
  const { currentWorkspaceId, showToast } = useAppStore();
  const queryClient = useQueryClient();

  const [copiedField, setCopiedField] = useState<string | null>(null);
  const [showClientSecret, setShowClientSecret] = useState(false);

  // Form state
  const [enabled, setEnabled] = useState(false);
  const [provider, setProvider] = useState<'saml' | 'oidc'>('saml');
  const [defaultRole, setDefaultRole] = useState<'ADMIN' | 'ENGINEER' | 'AUDITOR'>('ENGINEER');

  // SAML fields
  const [samlEntryPoint, setSamlEntryPoint] = useState('');
  const [samlIssuer, setSamlIssuer] = useState('');
  const [samlCert, setSamlCert] = useState('');

  // OIDC fields
  const [oidcIssuer, setOidcIssuer] = useState('');
  const [oidcClientId, setOidcClientId] = useState('');
  const [oidcClientSecret, setOidcClientSecret] = useState('');
  const [oidcScopes, setOidcScopes] = useState('openid profile email');

  const { data: ssoConfig, isLoading } = useQuery<WorkspaceSsoConfig>({
    queryKey: ['workspace-sso', currentWorkspaceId],
    queryFn: () => governanceApi.getSsoConfig(currentWorkspaceId),
    enabled: !!currentWorkspaceId,
  });

  useEffect(() => {
    if (ssoConfig) {
      setEnabled(ssoConfig.enabled);
      setProvider(ssoConfig.provider || 'saml');
      setDefaultRole(ssoConfig.defaultRole || 'ENGINEER');
      if (ssoConfig.saml) {
        setSamlEntryPoint(ssoConfig.saml.entryPoint || '');
        setSamlIssuer(ssoConfig.saml.issuer || '');
        setSamlCert(ssoConfig.saml.cert || '');
      }
      if (ssoConfig.oidc) {
        setOidcIssuer(ssoConfig.oidc.issuer || '');
        setOidcClientId(ssoConfig.oidc.clientId || '');
        setOidcClientSecret(ssoConfig.oidc.clientSecret || '');
        setOidcScopes(ssoConfig.oidc.scopes?.join(' ') || 'openid profile email');
      }
    }
  }, [ssoConfig]);

  const updateMutation = useMutation({
    mutationFn: (config: WorkspaceSsoConfig) => governanceApi.updateSsoConfig(currentWorkspaceId, config),
    onSuccess: () => {
      showToast('SSO configuration saved successfully');
      queryClient.invalidateQueries({ queryKey: ['workspace-sso', currentWorkspaceId] });
    },
    onError: (err: Error) => {
      showToast(err.message, 'error');
    },
  });

  const handleCopy = (text: string, field: string) => {
    navigator.clipboard.writeText(text);
    setCopiedField(field);
    setTimeout(() => setCopiedField(null), 2000);
  };

  const handleSave = (e: React.FormEvent) => {
    e.preventDefault();
    const payload: WorkspaceSsoConfig = {
      enabled,
      provider,
      defaultRole,
      saml:
        provider === 'saml'
          ? {
              entryPoint: samlEntryPoint.trim(),
              issuer: samlIssuer.trim(),
              cert: samlCert.trim(),
            }
          : undefined,
      oidc:
        provider === 'oidc'
          ? {
              issuer: oidcIssuer.trim(),
              clientId: oidcClientId.trim(),
              clientSecret: oidcClientSecret.trim() || undefined,
              scopes: oidcScopes.trim().split(/\s+/),
            }
          : undefined,
    };
    updateMutation.mutate(payload);
  };

  const hostUrl = typeof window !== 'undefined' ? window.location.origin : 'https://security-lab.local';
  const samlAcsUrl = `${hostUrl}/api/v1/auth/sso/saml/${encodeURIComponent(currentWorkspaceId)}/acs`;
  const samlMetadataUrl = `${hostUrl}/api/v1/auth/sso/saml/${encodeURIComponent(currentWorkspaceId)}/metadata`;

  return (
    <div className="space-y-6 animate-fade-in max-w-4xl">
      {/* Header Info */}
      <div className="p-4 rounded-xl bg-card border border-border/70 glass-card flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h2 className="text-sm font-semibold text-foreground flex items-center space-x-2">
            <ShieldCheck className="w-4 h-4 text-blue-400" />
            <span>Enterprise Single Sign-On (SSO)</span>
          </h2>
          <p className="text-xs text-muted-foreground mt-0.5">
            Configure SAML 2.0 (Okta, Azure AD, Ping) or OpenID Connect (Google, Auth0) for workspace authentication.
          </p>
        </div>

        <div className="flex items-center space-x-2">
          <label className="relative inline-flex items-center cursor-pointer">
            <input
              type="checkbox"
              checked={enabled}
              onChange={(e) => setEnabled(e.target.checked)}
              className="sr-only peer"
            />
            <div className="w-9 h-5 bg-accent peer-focus:outline-none rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-4 after:w-4 after:transition-all peer-checked:bg-blue-600"></div>
          </label>
          <span className="text-xs font-medium text-foreground">
            {enabled ? 'SSO Enforced' : 'SSO Inactive'}
          </span>
        </div>
      </div>

      <form onSubmit={handleSave} className="space-y-6">
        {/* Protocol Selector */}
        <div className="grid grid-cols-2 gap-3 p-1 rounded-xl bg-accent/30 border border-border/70 max-w-sm">
          <button
            type="button"
            onClick={() => setProvider('saml')}
            className={`py-2 px-3 rounded-lg text-xs font-medium transition-all ${
              provider === 'saml'
                ? 'bg-primary text-primary-foreground shadow-sm'
                : 'text-muted-foreground hover:text-foreground'
            }`}
          >
            SAML 2.0 Identity Provider
          </button>
          <button
            type="button"
            onClick={() => setProvider('oidc')}
            className={`py-2 px-3 rounded-lg text-xs font-medium transition-all ${
              provider === 'oidc'
                ? 'bg-primary text-primary-foreground shadow-sm'
                : 'text-muted-foreground hover:text-foreground'
            }`}
          >
            OpenID Connect (OIDC)
          </button>
        </div>

        {/* SAML Configuration Form */}
        {provider === 'saml' && (
          <div className="p-5 rounded-xl bg-card border border-border/70 glass-card space-y-4">
            <h3 className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">
              SAML 2.0 IdP Parameters
            </h3>

            <div>
              <label className="block text-xs font-medium text-foreground mb-1">
                Identity Provider Single Sign-On URL (SSO URL) *
              </label>
              <input
                type="url"
                required={enabled}
                value={samlEntryPoint}
                onChange={(e) => setSamlEntryPoint(e.target.value)}
                placeholder="https://company.okta.com/app/security-lab/sso/saml"
                className="w-full px-3 py-2 rounded-lg bg-accent/40 border border-border text-xs text-foreground placeholder-muted-foreground focus:outline-none focus:ring-1 focus:ring-blue-500 font-mono"
              />
            </div>

            <div>
              <label className="block text-xs font-medium text-foreground mb-1">
                Identity Provider Issuer / Entity ID *
              </label>
              <input
                type="text"
                required={enabled}
                value={samlIssuer}
                onChange={(e) => setSamlIssuer(e.target.value)}
                placeholder="http://www.okta.com/exk1234567890abcdef"
                className="w-full px-3 py-2 rounded-lg bg-accent/40 border border-border text-xs text-foreground placeholder-muted-foreground focus:outline-none focus:ring-1 focus:ring-blue-500 font-mono"
              />
            </div>

            <div>
              <label className="block text-xs font-medium text-foreground mb-1">
                X.509 Public Signing Certificate (PEM) *
              </label>
              <textarea
                rows={4}
                required={enabled}
                value={samlCert}
                onChange={(e) => setSamlCert(e.target.value)}
                placeholder="-----BEGIN CERTIFICATE-----&#10;MIIDpDCCAoygAwIBAgIGAV...&#10;-----END CERTIFICATE-----"
                className="w-full px-3 py-2 rounded-lg bg-accent/40 border border-border text-xs text-foreground placeholder-muted-foreground focus:outline-none focus:ring-1 focus:ring-blue-500 font-mono text-[11px]"
              />
            </div>

            {/* Service Provider Info */}
            <div className="pt-3 border-t border-border/70 space-y-3">
              <h4 className="text-xs font-semibold text-foreground">Service Provider (Security Lab) Endpoints</h4>
              
              <div className="space-y-2">
                <div>
                  <div className="text-[11px] text-muted-foreground mb-1">Assertion Consumer Service (ACS) URL:</div>
                  <div className="flex items-center space-x-2">
                    <input
                      type="text"
                      readOnly
                      value={samlAcsUrl}
                      className="w-full px-3 py-1.5 rounded-lg bg-accent/60 border border-border text-xs font-mono text-blue-300 select-all"
                    />
                    <button
                      type="button"
                      onClick={() => handleCopy(samlAcsUrl, 'acs')}
                      className="p-1.5 rounded-lg bg-accent hover:bg-accent/80 text-muted-foreground hover:text-foreground transition-colors shrink-0"
                      title="Copy ACS URL"
                    >
                      {copiedField === 'acs' ? <Check className="w-4 h-4 text-emerald-400" /> : <Copy className="w-4 h-4" />}
                    </button>
                  </div>
                </div>

                <div>
                  <div className="text-[11px] text-muted-foreground mb-1">SP Metadata XML Endpoint:</div>
                  <div className="flex items-center space-x-2">
                    <input
                      type="text"
                      readOnly
                      value={samlMetadataUrl}
                      className="w-full px-3 py-1.5 rounded-lg bg-accent/60 border border-border text-xs font-mono text-blue-300 select-all"
                    />
                    <a
                      href={samlMetadataUrl}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="p-1.5 rounded-lg bg-accent hover:bg-accent/80 text-muted-foreground hover:text-foreground transition-colors shrink-0"
                      title="Download XML"
                    >
                      <Download className="w-4 h-4" />
                    </a>
                  </div>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* OIDC Configuration Form */}
        {provider === 'oidc' && (
          <div className="p-5 rounded-xl bg-card border border-border/70 glass-card space-y-4">
            <h3 className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">
              OpenID Connect Parameters
            </h3>

            <div>
              <label className="block text-xs font-medium text-foreground mb-1">
                OIDC Discovery Issuer URL *
              </label>
              <input
                type="url"
                required={enabled}
                value={oidcIssuer}
                onChange={(e) => setOidcIssuer(e.target.value)}
                placeholder="https://accounts.google.com"
                className="w-full px-3 py-2 rounded-lg bg-accent/40 border border-border text-xs text-foreground placeholder-muted-foreground focus:outline-none focus:ring-1 focus:ring-blue-500 font-mono"
              />
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
              <div>
                <label className="block text-xs font-medium text-foreground mb-1">Client ID *</label>
                <input
                  type="text"
                  required={enabled}
                  value={oidcClientId}
                  onChange={(e) => setOidcClientId(e.target.value)}
                  placeholder="security-lab-client-id"
                  className="w-full px-3 py-2 rounded-lg bg-accent/40 border border-border text-xs text-foreground placeholder-muted-foreground focus:outline-none focus:ring-1 focus:ring-blue-500 font-mono"
                />
              </div>

              <div>
                <label className="block text-xs font-medium text-foreground mb-1">Client Secret</label>
                <div className="relative">
                  <input
                    type={showClientSecret ? 'text' : 'password'}
                    value={oidcClientSecret}
                    onChange={(e) => setOidcClientSecret(e.target.value)}
                    placeholder="••••••••••••••••"
                    className="w-full px-3 py-2 rounded-lg bg-accent/40 border border-border text-xs text-foreground placeholder-muted-foreground focus:outline-none focus:ring-1 focus:ring-blue-500 font-mono pr-9"
                  />
                  <button
                    type="button"
                    onClick={() => setShowClientSecret(!showClientSecret)}
                    className="absolute right-2 top-2 text-muted-foreground hover:text-foreground"
                  >
                    {showClientSecret ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                  </button>
                </div>
              </div>
            </div>

            <div>
              <label className="block text-xs font-medium text-foreground mb-1">OAuth Scopes</label>
              <input
                type="text"
                value={oidcScopes}
                onChange={(e) => setOidcScopes(e.target.value)}
                placeholder="openid profile email"
                className="w-full px-3 py-2 rounded-lg bg-accent/40 border border-border text-xs text-foreground placeholder-muted-foreground focus:outline-none focus:ring-1 focus:ring-blue-500 font-mono"
              />
            </div>
          </div>
        )}

        {/* Default Role Assignment */}
        <div className="p-4 rounded-xl bg-card border border-border/70 glass-card flex items-center justify-between">
          <div>
            <div className="text-xs font-medium text-foreground">Default Just-In-Time (JIT) Provisioning Role</div>
            <div className="text-[11px] text-muted-foreground">Assigned to first-time SSO users matching domain constraints</div>
          </div>
          <select
            value={defaultRole}
            onChange={(e) => setDefaultRole(e.target.value as any)}
            className="px-3 py-1.5 rounded-lg bg-accent border border-border text-xs text-foreground focus:outline-none focus:ring-1 focus:ring-blue-500 font-mono"
          >
            <option value="ENGINEER">ENGINEER (Standard QA)</option>
            <option value="AUDITOR">AUDITOR (Read-Only)</option>
            <option value="ADMIN">ADMIN (Workspace Admin)</option>
          </select>
        </div>

        {/* Save Bar */}
        <div className="flex items-center justify-end space-x-3 pt-2">
          <button
            type="submit"
            disabled={updateMutation.isPending || isLoading}
            className="flex items-center space-x-2 px-4 py-2 rounded-xl bg-primary text-primary-foreground font-medium text-xs hover:bg-blue-600 transition-colors shadow-md disabled:opacity-50"
          >
            <Save className="w-4 h-4" />
            <span>{updateMutation.isPending ? 'Saving Settings...' : 'Save SSO Settings'}</span>
          </button>
        </div>
      </form>
    </div>
  );
};
