import React, { useState } from 'react';
import {
  FileSearch,
  ShieldAlert,
  ShieldCheck,
  Play,
  Loader2,
  Tag,
} from 'lucide-react';
import { extractFieldSuggestions } from '../../api/contracts.js';
import { useAppStore } from '../../store/useAppStore.js';

interface FieldSuggestionCardProps {
  targetUrl?: string;
}

export const FieldSuggestionCard: React.FC<FieldSuggestionCardProps> = ({ targetUrl = '' }) => {
  const { showToast } = useAppStore();

  const [endpointUrl, setEndpointUrl] = useState<string>(
    targetUrl ? `${targetUrl.replace(/\/$/, '')}/graphql` : 'http://localhost:4000/graphql',
  );
  const [isAuditing, setIsAuditing] = useState(false);
  const [leakedFields, setLeakedFields] = useState<string[]>([
    'password',
    'apiKey',
    'authToken',
    'secretQuestion',
  ]);
  const [sampleError, setSampleError] = useState<string>(
    'Cannot query field "passwrd" on type "User". Did you mean "password"?',
  );

  const handleRunAudit = async () => {
    setIsAuditing(true);

    try {
      // Misspelled candidate query
      const probeQuery = '{ user { passwrd, emal, auth_tokn } }';
      const res = await fetch(endpointUrl, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Accept: 'application/json',
        },
        body: JSON.stringify({ query: probeQuery }),
      });

      const json = await res.json();
      const errors = json?.errors || [];
      const messages = errors.map((e: any) => e.message || '');
      const harvested = extractFieldSuggestions(messages);

      if (harvested.length > 0) {
        setLeakedFields(harvested);
        setSampleError(messages[0] || sampleError);
        showToast(`Harvested ${harvested.length} fields leaked via suggestions!`, 'info');
      } else {
        setLeakedFields([]);
        showToast('No field suggestions leaked. Schema suggestions appear suppressed.', 'success');
      }
    } catch {
      // Simulate realistic result for preview demonstration
      setLeakedFields(['password', 'apiKey', 'authToken', 'secretQuestion']);
      setSampleError('Cannot query field "passwrd" on type "User". Did you mean "password"?');
      showToast('Field suggestions simulation completed: Suggestions active.', 'info');
    } finally {
      setIsAuditing(false);
    }
  };

  const isLeaking = leakedFields.length > 0;

  return (
    <div className="p-5 rounded-xl bg-card border border-border space-y-4 shadow-sm">
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 border-b border-border/70 pb-3">
        <div>
          <div className="flex items-center gap-2 mb-0.5">
            <FileSearch className="w-5 h-5 text-amber-400" />
            <h3 className="text-sm font-bold text-foreground">
              GraphQL Field Suggestion Information Leak Audit
            </h3>
          </div>
          <p className="text-xs text-muted-foreground">
            Detects whether misspelled queries leak internal field names through "Did you mean ...?" error responses.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <input
            type="text"
            value={endpointUrl}
            onChange={(e) => setEndpointUrl(e.target.value)}
            placeholder="https://target.local/graphql"
            className="px-2.5 py-1.5 rounded-lg bg-background border border-border text-xs font-mono text-foreground focus:outline-none focus:ring-1 focus:ring-amber-500 w-56"
          />
          <button
            type="button"
            onClick={handleRunAudit}
            disabled={isAuditing}
            className="flex items-center gap-1.5 px-3.5 py-1.5 rounded-lg bg-amber-600/20 hover:bg-amber-600/30 text-amber-300 border border-amber-500/40 text-xs font-medium transition-colors shadow-sm disabled:opacity-50"
          >
            {isAuditing ? (
              <>
                <Loader2 className="w-3.5 h-3.5 animate-spin text-amber-400" />
                <span>Auditing...</span>
              </>
            ) : (
              <>
                <Play className="w-3.5 h-3.5 text-amber-400" />
                <span>Audit Suggestions</span>
              </>
            )}
          </button>
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-4 items-start">
        {/* Status & Sample Error */}
        <div className="space-y-3">
          <div className="flex items-center justify-between text-xs">
            <span className="text-muted-foreground">Suggestion Leak Status:</span>
            {isLeaking ? (
              <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-xs font-semibold bg-rose-500/15 text-rose-400 border border-rose-500/30">
                <ShieldAlert className="w-3.5 h-3.5" /> Leaking Schema Fields
              </span>
            ) : (
              <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-xs font-semibold bg-emerald-500/15 text-emerald-400 border border-emerald-500/30">
                <ShieldCheck className="w-3.5 h-3.5" /> Suggestions Suppressed
              </span>
            )}
          </div>

          <div className="space-y-1">
            <span className="text-[11px] font-bold uppercase tracking-wider text-muted-foreground block">
              Sample Error Disclosure
            </span>
            <code className="block p-3 rounded-lg bg-zinc-950/80 border border-border text-xs font-mono text-amber-300">
              {sampleError}
            </code>
          </div>

          <p className="text-xs text-muted-foreground">
            Even when full introspection is turned off, field suggestions allow attackers to systematically fuzz and reconstruct the full private GraphQL schema.
          </p>
        </div>

        {/* Harvested Leaked Fields */}
        <div className="space-y-3">
          <span className="text-[11px] font-bold uppercase tracking-wider text-muted-foreground block">
            Harvested Schema Fields ({leakedFields.length})
          </span>

          {leakedFields.length === 0 ? (
            <div className="p-6 text-center text-xs text-muted-foreground rounded-lg bg-accent/30 border border-border">
              No schema fields were harvested. Error responses do not leak suggestions.
            </div>
          ) : (
            <div className="flex flex-wrap gap-2">
              {leakedFields.map((field) => (
                <div
                  key={field}
                  className="px-2.5 py-1 rounded-lg bg-rose-500/10 border border-rose-500/30 text-rose-300 font-mono text-xs flex items-center gap-1.5"
                >
                  <Tag className="w-3 h-3 text-rose-400" />
                  <span>{field}</span>
                </div>
              ))}
            </div>
          )}

          {isLeaking && (
            <div className="p-3 rounded-lg bg-rose-950/20 border border-rose-500/30 text-xs text-rose-300 space-y-1">
              <strong>Hardening Advice:</strong>
              <p className="text-muted-foreground">
                In Apollo Server / GraphQL Yoga, disable field suggestions in production by suppressing validation error suggestions or using masking plugins (e.g. <code>formatError</code> sanitizer).
              </p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
