import React, { useState, useMemo } from 'react';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import {
  Search,
  Zap,
  ShieldAlert,
  ShieldCheck,
  Copy,
  Check,
  Layers,
  Code2,
  Database,
  ArrowRight,
  Loader2,
} from 'lucide-react';
import {
  GraphQLParsedSchema,
  parseGraphQLSchema,
  formatGraphQLType,
  GraphQLField,
  fetchTargetSpecs,
  saveTargetSpec,
  executeGraphQLIntrospection,
  ContractSpecRecord,
} from '../../api/contracts.js';
import { useAppStore } from '../../store/useAppStore.js';

// Realistic sample introspection schema for immediate offline/preview inspection
const SAMPLE_GRAPHQL_SCHEMA: object = {
  data: {
    __schema: {
      queryType: { name: 'Query' },
      mutationType: { name: 'Mutation' },
      subscriptionType: { name: 'Subscription' },
      types: [
        {
          kind: 'OBJECT',
          name: 'Query',
          description: 'Root Query Object exposing data entities and access filters',
          fields: [
            {
              name: 'me',
              description: 'Retrieve current authenticated customer profile',
              type: { kind: 'OBJECT', name: 'User' },
              args: [],
            },
            {
              name: 'user',
              description: 'Fetch user details by ID or email (BOLA vulnerability candidate)',
              type: { kind: 'OBJECT', name: 'User' },
              args: [
                {
                  name: 'id',
                  description: 'Target user ID',
                  type: { kind: 'NON_NULL', ofType: { kind: 'SCALAR', name: 'ID' } },
                },
              ],
            },
            {
              name: 'orders',
              description: 'List orders associated with user',
              type: {
                kind: 'LIST',
                ofType: { kind: 'NON_NULL', ofType: { kind: 'OBJECT', name: 'Order' } },
              },
              args: [
                {
                  name: 'status',
                  description: 'Filter by order status',
                  type: { kind: 'SCALAR', name: 'String' },
                },
                {
                  name: 'limit',
                  defaultValue: '20',
                  type: { kind: 'SCALAR', name: 'Int' },
                },
              ],
            },
            {
              name: 'auditLogs',
              description: 'Internal security audit trails (privilege escalation leak)',
              type: {
                kind: 'LIST',
                ofType: { kind: 'OBJECT', name: 'AuditRecord' },
              },
              args: [],
            },
          ],
        },
        {
          kind: 'OBJECT',
          name: 'Mutation',
          description: 'Mutating operations for state changes, auth, and payments',
          fields: [
            {
              name: 'login',
              description: 'Authenticate and generate bearer session token',
              type: { kind: 'OBJECT', name: 'AuthPayload' },
              args: [
                { name: 'username', type: { kind: 'NON_NULL', ofType: { kind: 'SCALAR', name: 'String' } } },
                { name: 'password', type: { kind: 'NON_NULL', ofType: { kind: 'SCALAR', name: 'String' } } },
              ],
            },
            {
              name: 'updateRole',
              description: 'Promote user to administrator (Privilege Escalation probe)',
              type: { kind: 'OBJECT', name: 'User' },
              args: [
                { name: 'userId', type: { kind: 'NON_NULL', ofType: { kind: 'SCALAR', name: 'ID' } } },
                { name: 'role', type: { kind: 'NON_NULL', ofType: { kind: 'SCALAR', name: 'String' } } },
              ],
            },
            {
              name: 'transferFunds',
              description: 'Execute instant peer-to-peer balance transfer',
              type: { kind: 'OBJECT', name: 'Transaction' },
              args: [
                { name: 'recipientId', type: { kind: 'NON_NULL', ofType: { kind: 'SCALAR', name: 'ID' } } },
                { name: 'amount', type: { kind: 'NON_NULL', ofType: { kind: 'SCALAR', name: 'Float' } } },
              ],
            },
          ],
        },
        {
          kind: 'OBJECT',
          name: 'User',
          description: 'User account model with sensitive attributes and relationships',
          fields: [
            { name: 'id', type: { kind: 'NON_NULL', ofType: { kind: 'SCALAR', name: 'ID' } } },
            { name: 'email', type: { kind: 'NON_NULL', ofType: { kind: 'SCALAR', name: 'String' } } },
            { name: 'role', type: { kind: 'SCALAR', name: 'String' } },
            { name: 'apiKey', description: 'Internal tenant API token (Confidential)', type: { kind: 'SCALAR', name: 'String' } },
            {
              name: 'friends',
              description: 'Recursive peer relationship (Circular query depth test point)',
              type: { kind: 'LIST', ofType: { kind: 'OBJECT', name: 'User' } },
            },
            {
              name: 'posts',
              description: 'Posts authored by user',
              type: { kind: 'LIST', ofType: { kind: 'OBJECT', name: 'Post' } },
            },
          ],
        },
        {
          kind: 'OBJECT',
          name: 'Post',
          description: 'User authored post',
          fields: [
            { name: 'id', type: { kind: 'NON_NULL', ofType: { kind: 'SCALAR', name: 'ID' } } },
            { name: 'title', type: { kind: 'SCALAR', name: 'String' } },
            { name: 'author', type: { kind: 'OBJECT', name: 'User' } },
          ],
        },
        {
          kind: 'OBJECT',
          name: 'Order',
          description: 'Customer order entity',
          fields: [
            { name: 'id', type: { kind: 'NON_NULL', ofType: { kind: 'SCALAR', name: 'ID' } } },
            { name: 'amount', type: { kind: 'SCALAR', name: 'Float' } },
            { name: 'status', type: { kind: 'SCALAR', name: 'String' } },
            { name: 'customer', type: { kind: 'OBJECT', name: 'User' } },
          ],
        },
      ],
    },
  },
};

interface GraphQLIntrospectionViewerProps {
  targetId?: string;
  targetUrl?: string;
  targetName?: string;
  onSelectQueryForDepth?: (rootField: string, nestedField: string) => void;
}

export const GraphQLIntrospectionViewer: React.FC<GraphQLIntrospectionViewerProps> = ({
  targetId,
  targetUrl = '',
  onSelectQueryForDepth,
}) => {
  const { showToast } = useAppStore();
  const queryClient = useQueryClient();

  const { data: targetSpecs = [], isLoading: isLoadingSpecs } = useQuery<ContractSpecRecord[]>({
    queryKey: ['target-specs', targetId],
    queryFn: () => (targetId ? fetchTargetSpecs(targetId) : Promise.resolve([])),
    enabled: Boolean(targetId),
  });

  const graphQLSpecs = useMemo(() => targetSpecs.filter((s) => s.type === 'graphql'), [targetSpecs]);

  const [endpointInput, setEndpointInput] = useState<string>(
    targetUrl ? `${targetUrl.replace(/\/$/, '')}/graphql` : 'http://localhost:4000/graphql',
  );

  const [selectedSpecId, setSelectedSpecId] = useState<string | null>(null);
  const [ephemeralSchema, setEphemeralSchema] = useState<GraphQLParsedSchema | null>(null);
  const [activeTab, setActiveTab] = useState<'queries' | 'mutations' | 'types' | 'raw'>('queries');
  const [searchTerm, setSearchTerm] = useState<string>('');
  const [isIntrospecting, setIsIntrospecting] = useState<boolean>(false);
  const [isSaving, setIsSaving] = useState<boolean>(false);
  const [introspectionExposed, setIntrospectionExposed] = useState<boolean>(true);
  const [generatedQuery, setGeneratedQuery] = useState<string | null>(null);
  const [copiedQuery, setCopiedQuery] = useState<boolean>(false);

  const schemaData = useMemo<GraphQLParsedSchema | null>(() => {
    if (selectedSpecId) {
      const found = graphQLSpecs.find((s) => s.id === selectedSpecId);
      if (found) {
        try {
          const parsedJson = JSON.parse(found.content);
          return parseGraphQLSchema(parsedJson);
        } catch {
          // ignore error and fallback
        }
      }
    }
    if (graphQLSpecs.length > 0) {
      try {
        const parsedJson = JSON.parse(graphQLSpecs[0].content);
        return parseGraphQLSchema(parsedJson);
      } catch {
        // ignore error and fallback
      }
    }
    return ephemeralSchema;
  }, [selectedSpecId, graphQLSpecs, ephemeralSchema]);

  // Trigger server-side introspection against endpoint with SSRF checks
  const handleIntrospect = async () => {
    if (!endpointInput.trim()) {
      showToast('Please specify a GraphQL endpoint URL', 'error');
      return;
    }

    setIsIntrospecting(true);
    try {
      const result = await executeGraphQLIntrospection({
        targetId: targetId || '',
        endpointUrl: endpointInput.trim(),
      });

      const parsed = parseGraphQLSchema(result.schema);
      setEphemeralSchema(parsed);
      setIntrospectionExposed(true);
      if (result.specRecord?.id) {
        setSelectedSpecId(result.specRecord.id);
      }
      if (targetId) {
        await queryClient.invalidateQueries({ queryKey: ['target-specs', targetId] });
      }
      showToast(
        `Introspection successful! Mapped ${parsed.typesCount} types and ${parsed.queries.length} queries. Persisted to database.`,
        'success',
      );
    } catch (err: any) {
      setIntrospectionExposed(false);
      showToast(
        err.message || `Unable to reach ${endpointInput}. Introspection might be disabled or blocked by SSRF checks.`,
        'error',
      );
    } finally {
      setIsIntrospecting(false);
    }
  };

  // Load and persist sample GraphQL schema template
  const handleLoadSample = async () => {
    try {
      const parsed = parseGraphQLSchema(SAMPLE_GRAPHQL_SCHEMA);
      setEphemeralSchema(parsed);
      setIntrospectionExposed(true);

      if (targetId) {
        setIsSaving(true);
        try {
          const saved = await saveTargetSpec({
            targetId,
            name: 'Sample GraphQL Schema',
            type: 'graphql',
            content: JSON.stringify(SAMPLE_GRAPHQL_SCHEMA, null, 2),
          });
          setSelectedSpecId(saved.id);
          await queryClient.invalidateQueries({ queryKey: ['target-specs', targetId] });
          showToast('Imported and persisted sample GraphQL schema', 'success');
        } finally {
          setIsSaving(false);
        }
      } else {
        showToast('Loaded sample GraphQL schema', 'info');
      }
    } catch (err: any) {
      showToast(err.message || 'Failed to load sample schema', 'error');
    }
  };

  // Generate sample query for a field
  const handleGenerateQuery = (field: GraphQLField) => {
    let queryBody = `query Explore_${field.name} {\n  ${field.name}`;
    if (field.args && field.args.length > 0) {
      const argsList = field.args.map((a) => `${a.name}: "sample"`).join(', ');
      queryBody += `(${argsList})`;
    }
    queryBody += ` {\n    __typename\n    id\n  }\n}`;
    setGeneratedQuery(queryBody);
    showToast(`Generated GraphQL query for ${field.name}`, 'info');
  };

  const copyGeneratedQuery = () => {
    if (generatedQuery) {
      navigator.clipboard.writeText(generatedQuery);
      setCopiedQuery(true);
      showToast('Query copied to clipboard', 'info');
      setTimeout(() => setCopiedQuery(false), 2000);
    }
  };

  // Filter queries / mutations / types
  const filteredQueries = useMemo(() => {
    if (!schemaData) return [];
    return schemaData.queries.filter(
      (q) =>
        q.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
        (q.description && q.description.toLowerCase().includes(searchTerm.toLowerCase())),
    );
  }, [schemaData, searchTerm]);

  const filteredMutations = useMemo(() => {
    if (!schemaData) return [];
    return schemaData.mutations.filter(
      (m) =>
        m.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
        (m.description && m.description.toLowerCase().includes(searchTerm.toLowerCase())),
    );
  }, [schemaData, searchTerm]);

  const filteredTypes = useMemo(() => {
    if (!schemaData) return [];
    return schemaData.types.filter(
      (t) =>
        t.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
        (t.description && t.description.toLowerCase().includes(searchTerm.toLowerCase())),
    );
  }, [schemaData, searchTerm]);

  return (
    <div className="space-y-6">
      {/* Endpoint Explorer Header Bar */}
      <div className="p-4 rounded-xl bg-card border border-border shadow-sm flex flex-col md:flex-row items-center justify-between gap-4">
        <div className="flex-1 w-full">
          <label className="text-[11px] font-bold uppercase tracking-wider text-muted-foreground block mb-1">
            GraphQL Target Endpoint
          </label>
          <div className="flex items-center gap-2">
            <input
              type="text"
              value={endpointInput}
              onChange={(e) => setEndpointInput(e.target.value)}
              placeholder="https://target.local/graphql"
              className="flex-1 px-3 py-1.5 rounded-lg bg-background border border-border text-xs font-mono text-foreground focus:outline-none focus:ring-1 focus:ring-cyan-500"
            />
            <button
              type="button"
              onClick={handleIntrospect}
              disabled={isIntrospecting}
              className="flex items-center gap-1.5 px-3.5 py-1.5 rounded-lg bg-cyan-600/20 hover:bg-cyan-600/30 text-cyan-300 border border-cyan-500/40 text-xs font-medium transition-colors shadow-sm disabled:opacity-50"
            >
              {isIntrospecting ? (
                <>
                  <Loader2 className="w-3.5 h-3.5 animate-spin text-cyan-400" />
                  <span>Introspecting...</span>
                </>
              ) : (
                <>
                  <Zap className="w-3.5 h-3.5 text-cyan-400" />
                  <span>Run Introspection</span>
                </>
              )}
            </button>
          </div>
        </div>

        {/* Spec Switcher & Import Template */}
        <div className="flex flex-wrap items-center gap-2">
          {graphQLSpecs.length > 0 && (
            <div className="flex items-center gap-1.5 text-xs text-muted-foreground">
              <span>Spec:</span>
              <select
                value={selectedSpecId || (graphQLSpecs[0]?.id ?? '')}
                onChange={(e) => setSelectedSpecId(e.target.value)}
                className="px-2.5 py-1 rounded bg-background border border-border text-xs text-foreground focus:outline-none focus:ring-1 focus:ring-cyan-500"
              >
                {graphQLSpecs.map((s) => (
                  <option key={s.id} value={s.id}>
                    {s.name} ({new Date(s.createdAt).toLocaleDateString()})
                  </option>
                ))}
              </select>
            </div>
          )}

          <button
            type="button"
            onClick={handleLoadSample}
            disabled={isSaving}
            className="px-2.5 py-1.5 rounded-lg bg-accent/60 hover:bg-accent text-foreground hover:text-cyan-400 border border-border text-xs transition-colors disabled:opacity-50"
          >
            Import Template
          </button>
        </div>

        {/* Introspection Security Exposure Status Badge */}
        <div className="flex flex-col items-end">
          <span className="text-[11px] text-muted-foreground mb-1">Introspection Status</span>
          {introspectionExposed ? (
            <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-medium bg-rose-500/15 text-rose-400 border border-rose-500/30 animate-pulse">
              <ShieldAlert className="w-3.5 h-3.5" /> Schema Introspection Exposed
            </span>
          ) : (
            <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-medium bg-emerald-500/15 text-emerald-400 border border-emerald-500/30">
              <ShieldCheck className="w-3.5 h-3.5" /> Introspection Hardened / Disabled
            </span>
          )}
        </div>
      </div>

      {!schemaData && !isLoadingSpecs && (
        <div className="p-12 rounded-xl bg-card border border-border text-center space-y-4 shadow-sm">
          <div className="w-14 h-14 rounded-full bg-cyan-500/10 text-cyan-400 mx-auto flex items-center justify-center border border-cyan-500/20">
            <Database className="w-7 h-7" />
          </div>
          <div>
            <h3 className="text-base font-semibold text-foreground">No GraphQL schema introspected for this target</h3>
            <p className="text-xs text-muted-foreground mt-1 max-w-md mx-auto">
              Execute server-side introspection against your target GraphQL endpoint above to map queries, mutations, and types, or import a pre-packaged sample schema template.
            </p>
          </div>
          <div className="flex flex-wrap items-center justify-center gap-3 pt-2">
            <button
              type="button"
              onClick={handleLoadSample}
              disabled={isSaving}
              className="flex items-center gap-2 px-4 py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-medium transition-colors shadow-sm disabled:opacity-50"
            >
              <Code2 className="w-4 h-4" />
              <span>Import Sample Schema Template</span>
            </button>
          </div>
        </div>
      )}

      {!schemaData && isLoadingSpecs && (
        <div className="p-12 rounded-xl bg-card border border-border text-center space-y-3">
          <Loader2 className="w-6 h-6 animate-spin text-cyan-400 mx-auto" />
          <p className="text-xs text-muted-foreground">Loading GraphQL schema records for target...</p>
        </div>
      )}

      {schemaData && (
        <>
          {/* Metrics Row */}
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
            <div className="p-3 rounded-xl bg-card border border-border flex items-center gap-3">
              <div className="p-2 rounded-lg bg-cyan-500/15 text-cyan-400">
                <Code2 className="w-4 h-4" />
              </div>
              <div>
                <span className="text-[11px] text-muted-foreground block">Queries</span>
                <span className="text-lg font-bold font-mono text-foreground">{schemaData.queries.length}</span>
              </div>
            </div>

            <div className="p-3 rounded-xl bg-card border border-border flex items-center gap-3">
              <div className="p-2 rounded-lg bg-amber-500/15 text-amber-400">
                <Zap className="w-4 h-4" />
              </div>
              <div>
                <span className="text-[11px] text-muted-foreground block">Mutations</span>
                <span className="text-lg font-bold font-mono text-foreground">{schemaData.mutations.length}</span>
              </div>
            </div>

            <div className="p-3 rounded-xl bg-card border border-border flex items-center gap-3">
              <div className="p-2 rounded-lg bg-purple-500/15 text-purple-400">
                <Database className="w-4 h-4" />
              </div>
              <div>
                <span className="text-[11px] text-muted-foreground block">Object Types</span>
                <span className="text-lg font-bold font-mono text-foreground">{schemaData.typesCount}</span>
              </div>
            </div>

            <div className="p-3 rounded-xl bg-card border border-border flex items-center gap-3">
              <div className="p-2 rounded-lg bg-emerald-500/15 text-emerald-400">
                <Layers className="w-4 h-4" />
              </div>
              <div>
                <span className="text-[11px] text-muted-foreground block">Total Fields</span>
                <span className="text-lg font-bold font-mono text-foreground">{schemaData.totalFieldsCount}</span>
              </div>
            </div>
          </div>

      {/* Filter and Tab Navigation */}
      <div className="flex flex-col sm:flex-row items-center justify-between gap-3 border-b border-border/70 pb-3">
        <div className="flex items-center gap-2">
          <button
            type="button"
            onClick={() => setActiveTab('queries')}
            className={`px-3 py-1.5 rounded-lg text-xs font-medium transition-colors ${
              activeTab === 'queries'
                ? 'bg-cyan-500/15 text-cyan-300 border border-cyan-500/30'
                : 'text-muted-foreground hover:text-foreground hover:bg-accent'
            }`}
          >
            Queries ({schemaData.queries.length})
          </button>
          <button
            type="button"
            onClick={() => setActiveTab('mutations')}
            className={`px-3 py-1.5 rounded-lg text-xs font-medium transition-colors ${
              activeTab === 'mutations'
                ? 'bg-amber-500/15 text-amber-300 border border-amber-500/30'
                : 'text-muted-foreground hover:text-foreground hover:bg-accent'
            }`}
          >
            Mutations ({schemaData.mutations.length})
          </button>
          <button
            type="button"
            onClick={() => setActiveTab('types')}
            className={`px-3 py-1.5 rounded-lg text-xs font-medium transition-colors ${
              activeTab === 'types'
                ? 'bg-purple-500/15 text-purple-300 border border-purple-500/30'
                : 'text-muted-foreground hover:text-foreground hover:bg-accent'
            }`}
          >
            Types & Schemas ({schemaData.typesCount})
          </button>
        </div>

        <div className="relative w-full sm:w-64">
          <Search className="w-3.5 h-3.5 absolute left-3 top-1/2 -translate-y-1/2 text-muted-foreground" />
          <input
            type="text"
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            placeholder="Search queries, types..."
            className="w-full pl-8 pr-3 py-1.5 rounded-lg bg-background border border-border text-xs text-foreground placeholder:text-muted-foreground focus:outline-none focus:ring-1 focus:ring-cyan-500"
          />
        </div>
      </div>

      {/* Main Content Area */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
        {/* Left Side: Field List Cards */}
        <div className="lg:col-span-7 space-y-3">
          {activeTab === 'queries' && (
            <div className="space-y-3">
              {filteredQueries.length === 0 ? (
                <div className="p-8 text-center text-xs text-muted-foreground rounded-xl bg-card border border-border">
                  No queries match your search term.
                </div>
              ) : (
                filteredQueries.map((q) => (
                  <div
                    key={q.name}
                    className="p-4 rounded-xl bg-card border border-border hover:border-cyan-500/40 transition-all space-y-2.5 shadow-sm"
                  >
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-2">
                        <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-cyan-500/15 text-cyan-400 border border-cyan-500/30">
                          QUERY
                        </span>
                        <span className="text-xs font-mono font-bold text-foreground">{q.name}</span>
                        <span className="text-xs font-mono text-muted-foreground">
                          : {formatGraphQLType(q.type)}
                        </span>
                      </div>

                      <div className="flex items-center gap-2">
                        {onSelectQueryForDepth && (
                          <button
                            type="button"
                            onClick={() => onSelectQueryForDepth(q.name, 'friends')}
                            title="Test this query in Depth Attack Simulator"
                            className="px-2 py-1 rounded text-[11px] bg-accent hover:bg-rose-500/20 text-rose-300 hover:text-rose-200 border border-border transition-colors font-mono flex items-center gap-1"
                          >
                            <span>Depth Test</span>
                            <ArrowRight className="w-3 h-3" />
                          </button>
                        )}
                        <button
                          type="button"
                          onClick={() => handleGenerateQuery(q)}
                          className="px-2 py-1 rounded text-[11px] bg-cyan-500/15 hover:bg-cyan-500/25 text-cyan-300 border border-cyan-500/30 transition-colors font-mono"
                        >
                          Generate Probe
                        </button>
                      </div>
                    </div>

                    {q.description && <p className="text-xs text-muted-foreground">{q.description}</p>}

                    {/* Arguments */}
                    {q.args && q.args.length > 0 && (
                      <div className="pt-2 border-t border-border/50 text-[11px]">
                        <span className="text-muted-foreground block mb-1 font-mono">Arguments:</span>
                        <div className="flex flex-wrap gap-2">
                          {q.args.map((a) => (
                            <span key={a.name} className="px-2 py-0.5 rounded bg-background border border-border font-mono text-foreground">
                              {a.name}: <span className="text-cyan-400">{formatGraphQLType(a.type)}</span>
                            </span>
                          ))}
                        </div>
                      </div>
                    )}
                  </div>
                ))
              )}
            </div>
          )}

          {activeTab === 'mutations' && (
            <div className="space-y-3">
              {filteredMutations.length === 0 ? (
                <div className="p-8 text-center text-xs text-muted-foreground rounded-xl bg-card border border-border">
                  No mutations match your search term.
                </div>
              ) : (
                filteredMutations.map((m) => (
                  <div
                    key={m.name}
                    className="p-4 rounded-xl bg-card border border-border hover:border-amber-500/40 transition-all space-y-2.5 shadow-sm"
                  >
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-2">
                        <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-amber-500/15 text-amber-400 border border-amber-500/30">
                          MUTATION
                        </span>
                        <span className="text-xs font-mono font-bold text-foreground">{m.name}</span>
                        <span className="text-xs font-mono text-muted-foreground">
                          : {formatGraphQLType(m.type)}
                        </span>
                      </div>

                      <button
                        type="button"
                        onClick={() => handleGenerateQuery(m)}
                        className="px-2 py-1 rounded text-[11px] bg-amber-500/15 hover:bg-amber-500/25 text-amber-300 border border-amber-500/30 transition-colors font-mono"
                      >
                        Generate Probe
                      </button>
                    </div>

                    {m.description && <p className="text-xs text-muted-foreground">{m.description}</p>}

                    {m.args && m.args.length > 0 && (
                      <div className="pt-2 border-t border-border/50 text-[11px]">
                        <span className="text-muted-foreground block mb-1 font-mono">Arguments:</span>
                        <div className="flex flex-wrap gap-2">
                          {m.args.map((a) => (
                            <span key={a.name} className="px-2 py-0.5 rounded bg-background border border-border font-mono text-foreground">
                              {a.name}: <span className="text-amber-400">{formatGraphQLType(a.type)}</span>
                            </span>
                          ))}
                        </div>
                      </div>
                    )}
                  </div>
                ))
              )}
            </div>
          )}

          {activeTab === 'types' && (
            <div className="space-y-3">
              {filteredTypes.map((t) => (
                <div key={t.name} className="p-4 rounded-xl bg-card border border-border space-y-2.5 shadow-sm">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-purple-500/15 text-purple-400 border border-purple-500/30">
                        {t.kind}
                      </span>
                      <span className="text-xs font-mono font-bold text-foreground">{t.name}</span>
                    </div>
                    {t.fields && (
                      <span className="text-[11px] text-muted-foreground font-mono">
                        {t.fields.length} fields
                      </span>
                    )}
                  </div>

                  {t.description && <p className="text-xs text-muted-foreground">{t.description}</p>}

                  {t.fields && t.fields.length > 0 && (
                    <div className="pt-2 border-t border-border/50 space-y-1">
                      {t.fields.slice(0, 6).map((f) => (
                        <div key={f.name} className="flex items-center justify-between text-[11px] font-mono py-0.5">
                          <span className="text-foreground">{f.name}</span>
                          <span className="text-purple-400">{formatGraphQLType(f.type)}</span>
                        </div>
                      ))}
                      {t.fields.length > 6 && (
                        <span className="text-[10px] text-muted-foreground block pt-1 italic">
                          +{t.fields.length - 6} additional fields
                        </span>
                      )}
                    </div>
                  )}
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Right Side: Generated Query Playground */}
        <div className="lg:col-span-5 rounded-xl bg-card border border-border p-5 space-y-4 shadow-sm">
          <div className="flex items-center justify-between border-b border-border/70 pb-3">
            <h4 className="text-xs font-bold uppercase tracking-wider text-muted-foreground flex items-center gap-1.5">
              <Code2 className="w-3.5 h-3.5 text-cyan-400" />
              GraphQL Query Workbench
            </h4>
            {generatedQuery && (
              <button
                type="button"
                onClick={copyGeneratedQuery}
                className="flex items-center gap-1 text-[11px] text-cyan-400 hover:text-cyan-300 font-mono"
              >
                {copiedQuery ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                <span>Copy Query</span>
              </button>
            )}
          </div>

          {generatedQuery ? (
            <div className="space-y-3">
              <pre className="p-3 rounded-lg bg-zinc-950/80 border border-border/80 text-xs font-mono text-cyan-300 overflow-x-auto min-h-[160px]">
                {generatedQuery}
              </pre>

              <div className="p-3 rounded-lg bg-accent/40 border border-border text-xs text-muted-foreground space-y-1">
                <span className="font-semibold text-foreground block">Ready for Probe Dispatch</span>
                <p>
                  Copy this payload into your terminal or send directly using the CLI:
                </p>
                <code className="block p-1.5 rounded bg-background text-[11px] font-mono text-cyan-400 mt-1 select-all">
                  curl -X POST {endpointInput} -H "Content-Type: application/json" -d '{'{"query":"{me{id}}"}'}'
                </code>
              </div>
            </div>
          ) : (
            <div className="py-16 text-center text-xs text-muted-foreground">
              Select any query or mutation from the list and click "Generate Probe" to build a structured GraphQL query here.
            </div>
          )}
        </div>
      </div>
        </>
      )}
    </div>
  );
};
