import React, { useState, useMemo } from 'react';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import {
  FileCode2,
  Upload,
  Search,
  ShieldAlert,
  ShieldCheck,
  Lock,
  Copy,
  Check,
  Play,
  Loader2,
  Code,
  Tag,
  Server,
  Layers,
} from 'lucide-react';
import {
  ParsedOpenApiSpec,
  parseOpenApiDocument,
  verifyContractViaApi,
  ContractVerificationResult,
  fetchTargetSpecs,
  saveTargetSpec,
  ContractSpecRecord,
} from '../../api/contracts.js';
import { useAppStore } from '../../store/useAppStore.js';

// Pre-packaged realistic sample specs for instant testing & importing
const SAMPLE_SPECS: Record<string, { label: string; desc: string; data: object }> = {
  ecommerce: {
    label: 'E-Commerce & Orders API',
    desc: 'Authentication, cart management, payments, and order tracking (OpenAPI 3.0)',
    data: {
      openapi: '3.0.3',
      info: {
        title: 'CyberOps E-Commerce & Logistics API',
        version: '2.4.0',
        description: 'Production API specification for customer orders, inventory, and payment processing.',
      },
      servers: [{ url: 'https://api.cyberops.store/v2', description: 'Production Gateway' }],
      components: {
        securitySchemes: {
          bearerAuth: { type: 'http', scheme: 'bearer', bearerFormat: 'JWT' },
          apiKey: { type: 'apiKey', in: 'header', name: 'X-API-KEY' },
        },
      },
      paths: {
        '/auth/login': {
          post: {
            tags: ['Authentication'],
            summary: 'Authenticate user and exchange credentials for JWT token',
            operationId: 'authLogin',
            requestBody: {
              required: true,
              content: {
                'application/json': {
                  schema: {
                    type: 'object',
                    required: ['email', 'password'],
                    properties: {
                      email: { type: 'string', format: 'email' },
                      password: { type: 'string', format: 'password' },
                      mfaCode: { type: 'string' },
                    },
                  },
                },
              },
            },
            responses: {
              '200': { description: 'Authenticated successfully' },
              '401': { description: 'Invalid credentials or expired MFA' },
            },
          },
        },
        '/users/me': {
          get: {
            tags: ['Users'],
            summary: 'Fetch currently authenticated user profile',
            operationId: 'getMe',
            security: [{ bearerAuth: [] }],
            responses: {
              '200': { description: 'User profile retrieved' },
              '401': { description: 'Unauthorized' },
            },
          },
          put: {
            tags: ['Users'],
            summary: 'Update current user profile and notification preferences',
            operationId: 'updateMe',
            security: [{ bearerAuth: [] }],
            requestBody: {
              required: true,
              content: {
                'application/json': {
                  schema: {
                    type: 'object',
                    properties: {
                      name: { type: 'string' },
                      phone: { type: 'string' },
                      marketingOptIn: { type: 'boolean' },
                    },
                  },
                },
              },
            },
            responses: {
              '200': { description: 'Profile updated' },
            },
          },
        },
        '/orders': {
          get: {
            tags: ['Orders'],
            summary: 'List recent orders with pagination and date filter',
            operationId: 'listOrders',
            security: [{ bearerAuth: [] }],
            parameters: [
              { name: 'limit', in: 'query', required: false, schema: { type: 'integer', minimum: 1, maximum: 100 } },
              { name: 'cursor', in: 'query', required: false, schema: { type: 'string' } },
              { name: 'status', in: 'query', required: false, schema: { type: 'string', enum: ['PENDING', 'PROCESSING', 'DELIVERED', 'CANCELLED'] } },
            ],
            responses: {
              '200': { description: 'Paginated orders' },
            },
          },
          post: {
            tags: ['Orders'],
            summary: 'Place a new purchase order',
            operationId: 'createOrder',
            security: [{ bearerAuth: [] }],
            requestBody: {
              required: true,
              content: {
                'application/json': {
                  schema: {
                    type: 'object',
                    required: ['items', 'shippingAddressId'],
                    properties: {
                      items: {
                        type: 'array',
                        items: {
                          type: 'object',
                          required: ['productId', 'quantity'],
                          properties: {
                            productId: { type: 'string', format: 'uuid' },
                            quantity: { type: 'integer', minimum: 1 },
                            unitPrice: { type: 'number' },
                          },
                        },
                      },
                      shippingAddressId: { type: 'string', format: 'uuid' },
                      couponCode: { type: 'string' },
                    },
                  },
                },
              },
            },
            responses: {
              '201': { description: 'Order created' },
              '400': { description: 'Invalid order request' },
            },
          },
        },
        '/orders/{id}': {
          get: {
            tags: ['Orders'],
            summary: 'Retrieve detailed order receipt by identifier',
            operationId: 'getOrderById',
            security: [{ bearerAuth: [] }],
            parameters: [
              { name: 'id', in: 'path', required: true, schema: { type: 'string', format: 'uuid' } },
            ],
            responses: {
              '200': { description: 'Order details' },
              '404': { description: 'Order not found' },
            },
          },
          delete: {
            tags: ['Orders'],
            summary: 'Cancel pending order and trigger refund',
            operationId: 'cancelOrder',
            security: [{ bearerAuth: [] }],
            parameters: [
              { name: 'id', in: 'path', required: true, schema: { type: 'string', format: 'uuid' } },
            ],
            responses: {
              '204': { description: 'Order cancelled' },
            },
          },
        },
        '/payments/charge': {
          post: {
            tags: ['Payments'],
            summary: 'Process credit card charge via payment gateway token',
            operationId: 'chargePayment',
            security: [{ apiKey: [] }],
            requestBody: {
              required: true,
              content: {
                'application/json': {
                  schema: {
                    type: 'object',
                    required: ['amount', 'currency', 'paymentToken'],
                    properties: {
                      amount: { type: 'number', minimum: 0.5 },
                      currency: { type: 'string', enum: ['USD', 'EUR', 'GBP'] },
                      paymentToken: { type: 'string' },
                      idempotencyKey: { type: 'string' },
                    },
                  },
                },
              },
            },
            responses: {
              '200': { description: 'Charge succeeded' },
              '402': { description: 'Payment required / card declined' },
            },
          },
        },
      },
    },
  },
  fhir: {
    label: 'Healthcare FHIR Clinical API',
    desc: 'Patient records, clinical encounters, and diagnostic telemetry (HIPAA compliant)',
    data: {
      openapi: '3.0.0',
      info: {
        title: 'FHIR Health Informatics Interface',
        version: '1.2.0',
        description: 'Clinical health record exchange specification.',
      },
      servers: [{ url: 'https://fhir.healthguard.org/r4' }],
      components: {
        securitySchemes: {
          oauth2: { type: 'oauth2', description: 'SMART on FHIR OAuth2' },
        },
      },
      paths: {
        '/Patient': {
          get: {
            tags: ['Patients'],
            summary: 'Search patient directory',
            operationId: 'searchPatients',
            parameters: [
              { name: 'identifier', in: 'query', required: false, schema: { type: 'string' } },
              { name: 'family', in: 'query', required: false, schema: { type: 'string' } },
              { name: 'birthdate', in: 'query', required: false, schema: { type: 'string', format: 'date' } },
            ],
            responses: { '200': { description: 'Bundle of patient records' } },
          },
          post: {
            tags: ['Patients'],
            summary: 'Register new patient record',
            operationId: 'createPatient',
            requestBody: {
              required: true,
              content: {
                'application/json': {
                  schema: {
                    type: 'object',
                    required: ['name', 'gender', 'birthDate'],
                    properties: {
                      name: { type: 'string' },
                      gender: { type: 'string', enum: ['male', 'female', 'other', 'unknown'] },
                      birthDate: { type: 'string', format: 'date' },
                    },
                  },
                },
              },
            },
            responses: { '201': { description: 'Patient registered' } },
          },
        },
        '/Observation': {
          get: {
            tags: ['Diagnostics'],
            summary: 'Query diagnostic lab observations',
            operationId: 'getObservations',
            parameters: [
              { name: 'patient', in: 'query', required: true, schema: { type: 'string' } },
              { name: 'code', in: 'query', required: false, schema: { type: 'string' } },
            ],
            responses: { '200': { description: 'Clinical observations' } },
          },
        },
      },
    },
  },
  petstore: {
    label: 'Swagger Petstore API',
    desc: 'Classic Petstore sample spec with pet and store inventory endpoints (OpenAPI 3.0)',
    data: {
      openapi: '3.0.0',
      info: {
        title: 'Swagger Petstore',
        version: '1.0.0',
        description: 'A sample API that uses a petstore as an example to demonstrate features in OpenAPI 3.0.',
      },
      servers: [{ url: 'https://petstore3.swagger.io/api/v3' }],
      components: {
        securitySchemes: {
          api_key: { type: 'apiKey', name: 'api_key', in: 'header' },
          petstore_auth: {
            type: 'oauth2',
            flows: {
              implicit: {
                authorizationUrl: 'https://petstore.swagger.io/oauth/authorize',
                scopes: { 'write:pets': 'modify pets in your account', 'read:pets': 'read your pets' },
              },
            },
          },
        },
      },
      paths: {
        '/pet': {
          post: {
            tags: ['Pets'],
            summary: 'Add a new pet to the store',
            operationId: 'addPet',
            security: [{ petstore_auth: ['write:pets', 'read:pets'] }],
            requestBody: {
              required: true,
              content: {
                'application/json': {
                  schema: {
                    type: 'object',
                    required: ['name', 'photoUrls'],
                    properties: {
                      id: { type: 'integer', format: 'int64' },
                      name: { type: 'string', example: 'doggie' },
                      photoUrls: { type: 'array', items: { type: 'string' } },
                      status: { type: 'string', enum: ['available', 'pending', 'sold'] },
                    },
                  },
                },
              },
            },
            responses: { '200': { description: 'Successful operation' } },
          },
        },
        '/pet/findByStatus': {
          get: {
            tags: ['Pets'],
            summary: 'Finds Pets by status',
            operationId: 'findPetsByStatus',
            security: [{ petstore_auth: ['read:pets'] }],
            parameters: [
              {
                name: 'status',
                in: 'query',
                required: false,
                schema: { type: 'string', enum: ['available', 'pending', 'sold'], default: 'available' },
              },
            ],
            responses: { '200': { description: 'successful operation' } },
          },
        },
      },
    },
  },
};

interface OpenApiCatalogProps {
  targetId?: string;
  targetUrl?: string;
  targetName?: string;
}

export const OpenApiCatalog: React.FC<OpenApiCatalogProps> = ({ targetId, targetUrl }) => {
  const { showToast } = useAppStore();
  const queryClient = useQueryClient();

  const { data: targetSpecs = [], isLoading: isLoadingSpecs } = useQuery<ContractSpecRecord[]>({
    queryKey: ['target-specs', targetId],
    queryFn: () => (targetId ? fetchTargetSpecs(targetId) : Promise.resolve([])),
    enabled: Boolean(targetId),
  });

  const openApiSpecs = useMemo(() => targetSpecs.filter((s) => s.type === 'openapi'), [targetSpecs]);

  const [selectedSpecId, setSelectedSpecId] = useState<string | null>(null);
  const [ephemeralSpec, setEphemeralSpec] = useState<ParsedOpenApiSpec | null>(null);

  const activeSpec = useMemo<ParsedOpenApiSpec | null>(() => {
    if (selectedSpecId) {
      const found = openApiSpecs.find((s) => s.id === selectedSpecId);
      if (found) {
        try {
          return parseOpenApiDocument(found.content);
        } catch {
          // ignore parse errors and fallback
        }
      }
    }
    if (openApiSpecs.length > 0) {
      try {
        return parseOpenApiDocument(openApiSpecs[0].content);
      } catch {
        // ignore parse errors and fallback
      }
    }
    return ephemeralSpec;
  }, [selectedSpecId, openApiSpecs, ephemeralSpec]);

  const [selectedTag, setSelectedTag] = useState<string>('all');
  const [selectedMethod, setSelectedMethod] = useState<string>('all');
  const [searchFilter, setSearchFilter] = useState<string>('');
  const [selectedEndpointIndex, setSelectedEndpointIndex] = useState<number>(0);
  const [copiedPayload, setCopiedPayload] = useState(false);
  const [isVerifying, setIsVerifying] = useState(false);
  const [isSaving, setIsSaving] = useState(false);
  const [verificationResult, setVerificationResult] = useState<ContractVerificationResult | null>(null);

  // Method styling chips
  const methodColors: Record<string, string> = {
    GET: 'bg-blue-500/15 text-blue-400 border-blue-500/30',
    POST: 'bg-emerald-500/15 text-emerald-400 border-emerald-500/30',
    PUT: 'bg-amber-500/15 text-amber-400 border-amber-500/30',
    DELETE: 'bg-rose-500/15 text-rose-400 border-rose-500/30',
    PATCH: 'bg-purple-500/15 text-purple-400 border-purple-500/30',
    OPTIONS: 'bg-zinc-500/15 text-zinc-400 border-zinc-500/30',
    HEAD: 'bg-zinc-500/15 text-zinc-400 border-zinc-500/30',
  };

  // Filter endpoints
  const filteredEndpoints = useMemo(() => {
    if (!activeSpec) return [];
    return activeSpec.endpoints.filter((ep) => {
      const matchTag = selectedTag === 'all' || ep.tags.includes(selectedTag);
      const matchMethod = selectedMethod === 'all' || ep.method === selectedMethod;
      const matchSearch =
        !searchFilter ||
        ep.path.toLowerCase().includes(searchFilter.toLowerCase()) ||
        (ep.summary && ep.summary.toLowerCase().includes(searchFilter.toLowerCase()));
      return matchTag && matchMethod && matchSearch;
    });
  }, [activeSpec, selectedTag, selectedMethod, searchFilter]);

  const selectedEndpoint = filteredEndpoints[selectedEndpointIndex] || filteredEndpoints[0];

  // Handle file drop / upload with database persistence
  const handleFileUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    const reader = new FileReader();
    reader.onload = async (event) => {
      try {
        const content = event.target?.result as string;
        const parsed = parseOpenApiDocument(content);
        setEphemeralSpec(parsed);
        setSelectedEndpointIndex(0);
        setVerificationResult(null);

        if (targetId) {
          setIsSaving(true);
          try {
            const specName = file.name.replace(/\.(json|ya?ml)$/i, '') || parsed.title;
            const saved = await saveTargetSpec({
              targetId,
              name: specName,
              type: 'openapi',
              content,
            });
            setSelectedSpecId(saved.id);
            await queryClient.invalidateQueries({ queryKey: ['target-specs', targetId] });
            showToast(`Uploaded & saved OpenAPI spec: ${parsed.title} (${parsed.totalEndpoints} endpoints)`, 'success');
          } finally {
            setIsSaving(false);
          }
        } else {
          showToast(`Loaded OpenAPI spec: ${parsed.title} (${parsed.totalEndpoints} endpoints)`, 'success');
        }
      } catch (err: any) {
        showToast(err.message || 'Failed to parse uploaded OpenAPI file', 'error');
      }
    };
    reader.readAsText(file);
  };

  // Load and persist sample spec template
  const handleLoadSample = async (key: string) => {
    try {
      const sample = SAMPLE_SPECS[key];
      if (!sample) return;
      const parsed = parseOpenApiDocument(sample.data);
      setEphemeralSpec(parsed);
      setSelectedEndpointIndex(0);
      setVerificationResult(null);

      if (targetId) {
        setIsSaving(true);
        try {
          const saved = await saveTargetSpec({
            targetId,
            name: sample.label,
            type: 'openapi',
            content: JSON.stringify(sample.data, null, 2),
          });
          setSelectedSpecId(saved.id);
          await queryClient.invalidateQueries({ queryKey: ['target-specs', targetId] });
          showToast(`Imported & persisted template spec: ${parsed.title}`, 'success');
        } finally {
          setIsSaving(false);
        }
      } else {
        showToast(`Loaded template spec: ${parsed.title}`, 'info');
      }
    } catch (err: any) {
      showToast(err.message || 'Error loading sample', 'error');
    }
  };

  // Trigger contract verification via backend
  const handleVerifyContract = async () => {
    if (!activeSpec) return;
    if (!targetUrl) {
      showToast('Please select or configure an authorized target URL first.', 'error');
      return;
    }

    setIsVerifying(true);
    setVerificationResult(null);
    try {
      const result = await verifyContractViaApi({
        spec: activeSpec.title,
        targetUrl,
        options: {
          spec: JSON.parse(JSON.stringify(activeSpec)),
        },
      });
      setVerificationResult(result);
      if (result.success) {
        showToast('Contract verification audit completed', 'success');
      } else {
        showToast(result.error?.message || 'Contract verification failed', 'error');
      }
    } catch (err: any) {
      showToast(err.message || 'Failed to dispatch contract audit', 'error');
    } finally {
      setIsVerifying(false);
    }
  };

  const copyPayload = (payload: unknown) => {
    navigator.clipboard.writeText(JSON.stringify(payload, null, 2));
    setCopiedPayload(true);
    showToast('Mock request payload copied to clipboard', 'info');
    setTimeout(() => setCopiedPayload(false), 2000);
  };

  if (!activeSpec) {
    if (isLoadingSpecs) {
      return (
        <div className="p-12 rounded-xl bg-card border border-border text-center space-y-3">
          <Loader2 className="w-6 h-6 animate-spin text-cyan-400 mx-auto" />
          <p className="text-xs text-muted-foreground">Loading contract specifications for target...</p>
        </div>
      );
    }
    return (
      <div className="p-12 rounded-xl bg-card border border-border text-center space-y-4 shadow-sm">
        <div className="w-14 h-14 rounded-full bg-cyan-500/10 text-cyan-400 mx-auto flex items-center justify-center border border-cyan-500/20">
          <FileCode2 className="w-7 h-7" />
        </div>
        <div>
          <h3 className="text-base font-semibold text-foreground">No API specifications saved for this target</h3>
          <p className="text-xs text-muted-foreground mt-1 max-w-md mx-auto">
            Upload an OpenAPI 3.0 / Swagger (JSON or YAML) specification to explore endpoints, analyze authorization schemes, and run contract verification audits.
          </p>
        </div>
        <div className="flex flex-wrap items-center justify-center gap-3 pt-3">
          <label className="flex items-center gap-2 px-4 py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-medium cursor-pointer transition-colors shadow-sm">
            <Upload className="w-4 h-4" />
            <span>Upload OpenAPI (YAML/JSON)</span>
            <input type="file" accept=".json,.yaml,.yml" onChange={handleFileUpload} className="hidden" />
          </label>
          <div className="flex items-center gap-2">
            <span className="text-xs text-muted-foreground">or import template:</span>
            {Object.entries(SAMPLE_SPECS).map(([k, s]) => (
              <button
                key={k}
                type="button"
                onClick={() => handleLoadSample(k)}
                disabled={isSaving}
                className="px-3 py-1.5 rounded-lg bg-accent/80 hover:bg-accent text-xs text-foreground border border-border transition-colors hover:text-cyan-400 disabled:opacity-50"
              >
                {s.label.split(' ')[0]}
              </button>
            ))}
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Spec Control & Uploader Bar */}
      <div className="p-4 rounded-xl bg-card border border-border shadow-sm flex flex-col lg:flex-row items-start lg:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <FileCode2 className="w-5 h-5 text-cyan-400" />
            <h2 className="text-base font-bold text-foreground">{activeSpec.title}</h2>
            <span className="px-2 py-0.5 rounded text-xs font-mono bg-accent text-cyan-300 border border-border">
              v{activeSpec.version}
            </span>
          </div>
          <p className="text-xs text-muted-foreground mt-0.5">
            {activeSpec.description || 'OpenAPI 3.0 contract and endpoint inventory'}
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-2.5">
          {/* Spec Switcher when multiple specs are persisted */}
          {openApiSpecs.length > 0 && (
            <div className="flex items-center gap-1.5 text-xs text-muted-foreground">
              <span>Spec:</span>
              <select
                value={selectedSpecId || (openApiSpecs[0]?.id ?? '')}
                onChange={(e) => setSelectedSpecId(e.target.value)}
                className="px-2.5 py-1 rounded bg-background border border-border text-xs text-foreground focus:outline-none focus:ring-1 focus:ring-cyan-500"
              >
                {openApiSpecs.map((s) => (
                  <option key={s.id} value={s.id}>
                    {s.name} ({new Date(s.createdAt).toLocaleDateString()})
                  </option>
                ))}
              </select>
            </div>
          )}

          {/* Import Template Dropdown / Quick Buttons */}
          <div className="flex items-center gap-1.5 text-xs text-muted-foreground">
            <span>Import:</span>
            {Object.entries(SAMPLE_SPECS).map(([k, s]) => (
              <button
                key={k}
                type="button"
                onClick={() => handleLoadSample(k)}
                disabled={isSaving}
                className="px-2 py-1 rounded bg-accent/60 hover:bg-accent text-foreground hover:text-cyan-400 border border-border text-xs transition-colors disabled:opacity-50"
              >
                {s.label.split(' ')[0]}
              </button>
            ))}
          </div>

          {/* Upload Spec Button */}
          <label className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-cyan-600/15 hover:bg-cyan-600/25 text-cyan-300 border border-cyan-500/40 text-xs font-medium cursor-pointer transition-colors shadow-sm">
            <Upload className="w-3.5 h-3.5 text-cyan-400" />
            <span>Upload OpenAPI (JSON/YAML)</span>
            <input type="file" accept=".json,.yaml,.yml" onChange={handleFileUpload} className="hidden" />
          </label>

          {/* Trigger Contract Audit Button */}
          <button
            type="button"
            onClick={handleVerifyContract}
            disabled={isVerifying}
            className="flex items-center gap-1.5 px-3.5 py-1.5 rounded-lg bg-emerald-600/20 hover:bg-emerald-600/30 text-emerald-300 border border-emerald-500/40 text-xs font-medium transition-colors shadow-sm disabled:opacity-50"
          >
            {isVerifying ? (
              <>
                <Loader2 className="w-3.5 h-3.5 animate-spin text-emerald-400" />
                <span>Auditing Schema...</span>
              </>
            ) : (
              <>
                <Play className="w-3.5 h-3.5 text-emerald-400" />
                <span>Verify Contract Conformance</span>
              </>
            )}
          </button>
        </div>
      </div>

      {/* Metrics & Servers Header */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        <div className="p-3 rounded-xl bg-card border border-border flex items-center gap-3">
          <div className="p-2 rounded-lg bg-blue-500/15 text-blue-400">
            <Layers className="w-4 h-4" />
          </div>
          <div>
            <span className="text-[11px] text-muted-foreground block">Declared Endpoints</span>
            <span className="text-lg font-bold font-mono text-foreground">{activeSpec.totalEndpoints}</span>
          </div>
        </div>

        <div className="p-3 rounded-xl bg-card border border-border flex items-center gap-3">
          <div className="p-2 rounded-lg bg-purple-500/15 text-purple-400">
            <Tag className="w-4 h-4" />
          </div>
          <div>
            <span className="text-[11px] text-muted-foreground block">Tag Groups</span>
            <span className="text-lg font-bold font-mono text-foreground">{activeSpec.tags.length}</span>
          </div>
        </div>

        <div className="p-3 rounded-xl bg-card border border-border flex items-center gap-3">
          <div className="p-2 rounded-lg bg-amber-500/15 text-amber-400">
            <Lock className="w-4 h-4" />
          </div>
          <div>
            <span className="text-[11px] text-muted-foreground block">Auth Schemes</span>
            <span className="text-lg font-bold font-mono text-foreground">
              {Object.keys(activeSpec.securitySchemes).length}
            </span>
          </div>
        </div>

        <div className="p-3 rounded-xl bg-card border border-border flex items-center gap-3">
          <div className="p-2 rounded-lg bg-emerald-500/15 text-emerald-400">
            <Server className="w-4 h-4" />
          </div>
          <div>
            <span className="text-[11px] text-muted-foreground block">Gateway Base</span>
            <span className="text-xs font-mono text-foreground truncate block max-w-[140px]">
              {activeSpec.servers[0]?.url || 'Target Default'}
            </span>
          </div>
        </div>
      </div>

      {/* Contract Verification Result Alert (if run) */}
      {verificationResult && (
        <div
          className={`p-4 rounded-xl border ${
            verificationResult.success
              ? 'bg-emerald-950/20 border-emerald-500/30'
              : 'bg-rose-950/20 border-rose-500/30'
          }`}
        >
          <div className="flex items-center justify-between mb-2">
            <div className="flex items-center gap-2">
              {verificationResult.success ? (
                <ShieldCheck className="w-5 h-5 text-emerald-400" />
              ) : (
                <ShieldAlert className="w-5 h-5 text-rose-400" />
              )}
              <span className="text-sm font-bold text-foreground">
                Contract Audit Conformance:{' '}
                {verificationResult.success ? 'Validated Clean' : 'Violations Detected'}
              </span>
            </div>
            {verificationResult.data?.durationMs && (
              <span className="text-xs font-mono text-muted-foreground">
                {verificationResult.data.durationMs}ms
              </span>
            )}
          </div>

          {verificationResult.data?.findings && verificationResult.data.findings.length > 0 ? (
            <div className="space-y-2 mt-3">
              {verificationResult.data.findings.map((f, i) => (
                <div key={i} className="p-3 rounded-lg bg-card/60 border border-border text-xs space-y-1">
                  <div className="flex items-center justify-between">
                    <span className="font-semibold text-rose-400">{f.title}</span>
                    <span className="px-2 py-0.5 rounded text-[10px] uppercase font-bold bg-rose-500/15 text-rose-400 border border-rose-500/30">
                      {f.severity}
                    </span>
                  </div>
                  <p className="text-muted-foreground">{f.description}</p>
                </div>
              ))}
            </div>
          ) : (
            <p className="text-xs text-muted-foreground">
              All declared endpoints comply with baseline security contracts. No unauthenticated mutating routes or HTTP Basic cleartext flaws detected.
            </p>
          )}
        </div>
      )}

      {/* Search & Tag Filter Bar */}
      <div className="flex flex-col sm:flex-row items-center justify-between gap-3">
        <div className="relative w-full sm:w-80">
          <Search className="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2 text-muted-foreground" />
          <input
            type="text"
            value={searchFilter}
            onChange={(e) => setSearchFilter(e.target.value)}
            placeholder="Search path, operation, or summary..."
            className="w-full pl-9 pr-3 py-1.5 rounded-lg bg-background border border-border text-xs text-foreground placeholder:text-muted-foreground focus:outline-none focus:ring-1 focus:ring-cyan-500"
          />
        </div>

        <div className="flex flex-wrap items-center gap-2 w-full sm:w-auto">
          {/* Method Filter */}
          <select
            value={selectedMethod}
            onChange={(e) => {
              setSelectedMethod(e.target.value);
              setSelectedEndpointIndex(0);
            }}
            className="px-2.5 py-1.5 rounded-lg bg-background border border-border text-xs text-foreground focus:outline-none focus:ring-1 focus:ring-cyan-500"
          >
            <option value="all">All Methods</option>
            <option value="GET">GET</option>
            <option value="POST">POST</option>
            <option value="PUT">PUT</option>
            <option value="DELETE">DELETE</option>
            <option value="PATCH">PATCH</option>
          </select>

          {/* Tag Filter */}
          <select
            value={selectedTag}
            onChange={(e) => {
              setSelectedTag(e.target.value);
              setSelectedEndpointIndex(0);
            }}
            className="px-2.5 py-1.5 rounded-lg bg-background border border-border text-xs text-foreground focus:outline-none focus:ring-1 focus:ring-cyan-500"
          >
            <option value="all">All Tags ({activeSpec.tags.length})</option>
            {activeSpec.tags.map((t) => (
              <option key={t} value={t}>
                {t}
              </option>
            ))}
          </select>
        </div>
      </div>

      {/* Main 2-Column Catalog Explorer */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
        {/* Left Column: Endpoints List */}
        <div className="lg:col-span-5 rounded-xl bg-card border border-border overflow-hidden shadow-sm">
          <div className="p-3 border-b border-border bg-accent/30 flex items-center justify-between text-xs">
            <span className="font-semibold text-foreground">
              Endpoints ({filteredEndpoints.length})
            </span>
            <span className="text-muted-foreground text-[11px]">Click to inspect schema</span>
          </div>

          <div className="divide-y divide-border/60 max-h-[600px] overflow-y-auto">
            {filteredEndpoints.length === 0 ? (
              <div className="p-8 text-center text-xs text-muted-foreground">
                No endpoints match the active filter criteria.
              </div>
            ) : (
              filteredEndpoints.map((ep, idx) => {
                const isSelected = selectedEndpoint?.path === ep.path && selectedEndpoint?.method === ep.method;
                const badgeColor = methodColors[ep.method] || 'bg-zinc-500/15 text-zinc-400 border-zinc-500/30';

                return (
                  <button
                    key={`${ep.method}-${ep.path}-${idx}`}
                    type="button"
                    onClick={() => setSelectedEndpointIndex(idx)}
                    className={`w-full p-3 text-left transition-colors flex items-center justify-between gap-3 ${
                      isSelected
                        ? 'bg-cyan-500/10 border-l-2 border-l-cyan-400'
                        : 'hover:bg-accent/40'
                    }`}
                  >
                    <div className="min-w-0 flex-1">
                      <div className="flex items-center gap-2 mb-1">
                        <span className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold border ${badgeColor}`}>
                          {ep.method}
                        </span>
                        <span className="text-xs font-mono font-medium text-foreground truncate">
                          {ep.path}
                        </span>
                      </div>
                      <p className="text-[11px] text-muted-foreground truncate">{ep.summary}</p>
                    </div>

                    {ep.security && ep.security.length > 0 && (
                      <span title="Protected by Authentication Scheme">
                        <Lock className="w-3.5 h-3.5 text-amber-400 flex-shrink-0" />
                      </span>
                    )}
                  </button>
                );
              })
            )}
          </div>
        </div>

        {/* Right Column: Endpoint Inspector */}
        <div className="lg:col-span-7 rounded-xl bg-card border border-border overflow-hidden shadow-sm p-5 space-y-5">
          {selectedEndpoint ? (
            <>
              {/* Endpoint Header Bar */}
              <div className="border-b border-border/70 pb-4 space-y-2">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <div className="flex items-center gap-2.5">
                    <span
                      className={`px-2.5 py-1 rounded text-xs font-mono font-bold border ${
                        methodColors[selectedEndpoint.method] || 'bg-zinc-500/15 text-zinc-400'
                      }`}
                    >
                      {selectedEndpoint.method}
                    </span>
                    <span className="text-sm font-mono font-bold text-foreground">
                      {selectedEndpoint.path}
                    </span>
                  </div>

                  <button
                    type="button"
                    onClick={() => {
                      navigator.clipboard.writeText(selectedEndpoint.path);
                      showToast('Endpoint path copied', 'info');
                    }}
                    className="p-1 rounded text-muted-foreground hover:text-cyan-400 hover:bg-accent transition-colors"
                    title="Copy Path"
                  >
                    <Copy className="w-4 h-4" />
                  </button>
                </div>

                <div className="flex flex-wrap items-center gap-2 pt-1 text-xs text-muted-foreground">
                  <span>Tags:</span>
                  {selectedEndpoint.tags.map((t) => (
                    <span key={t} className="px-2 py-0.5 rounded bg-accent text-foreground text-[10px]">
                      {t}
                    </span>
                  ))}
                  {selectedEndpoint.operationId && (
                    <span className="text-[11px] font-mono text-cyan-300">
                      ID: {selectedEndpoint.operationId}
                    </span>
                  )}
                </div>

                {selectedEndpoint.description && (
                  <p className="text-xs text-muted-foreground pt-1">{selectedEndpoint.description}</p>
                )}
              </div>

              {/* Parameters Table */}
              <div className="space-y-2">
                <h4 className="text-xs font-bold uppercase tracking-wider text-muted-foreground flex items-center gap-1.5">
                  <Code className="w-3.5 h-3.5 text-cyan-400" />
                  Parameters ({selectedEndpoint.parameters.length})
                </h4>

                {selectedEndpoint.parameters.length === 0 ? (
                  <p className="text-xs text-muted-foreground italic">No parameters declared.</p>
                ) : (
                  <div className="border border-border/70 rounded-lg overflow-hidden">
                    <table className="w-full text-left text-xs">
                      <thead className="bg-accent/40 text-muted-foreground border-b border-border/70 font-mono text-[11px]">
                        <tr>
                          <th className="p-2">Name</th>
                          <th className="p-2">In</th>
                          <th className="p-2">Type</th>
                          <th className="p-2">Required</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-border/60">
                        {selectedEndpoint.parameters.map((p, idx) => (
                          <tr key={idx} className="hover:bg-accent/20">
                            <td className="p-2 font-mono font-medium text-foreground">{p.name}</td>
                            <td className="p-2 font-mono text-muted-foreground">{p.in}</td>
                            <td className="p-2 font-mono text-cyan-400">{p.type || 'string'}</td>
                            <td className="p-2">
                              {p.required ? (
                                <span className="px-1.5 py-0.5 rounded text-[10px] bg-rose-500/15 text-rose-400 font-bold">
                                  REQUIRED
                                </span>
                              ) : (
                                <span className="text-muted-foreground text-[11px]">Optional</span>
                              )}
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}
              </div>

              {/* Request Body & Mock Payload */}
              {selectedEndpoint.requestBody && (
                <div className="space-y-2">
                  <div className="flex items-center justify-between">
                    <h4 className="text-xs font-bold uppercase tracking-wider text-muted-foreground flex items-center gap-1.5">
                      <FileCode2 className="w-3.5 h-3.5 text-emerald-400" />
                      Request Body Payload Schema
                    </h4>
                    {Boolean(selectedEndpoint.requestBody.samplePayload) && (
                      <button
                        type="button"
                        onClick={() => copyPayload(selectedEndpoint.requestBody?.samplePayload)}
                        className="flex items-center gap-1 text-[11px] text-cyan-400 hover:text-cyan-300 font-mono"
                      >
                        {copiedPayload ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                        <span>Copy Mock JSON</span>
                      </button>
                    )}
                  </div>

                  {Boolean(selectedEndpoint.requestBody.samplePayload) ? (
                    <pre className="p-3 rounded-lg bg-zinc-950/80 border border-border/80 text-xs font-mono text-emerald-400 overflow-x-auto max-h-48">
                      {JSON.stringify(selectedEndpoint.requestBody.samplePayload, null, 2)}
                    </pre>
                  ) : (
                    <p className="text-xs text-muted-foreground italic">
                      Schema defined: {selectedEndpoint.requestBody.contentTypes.join(', ')}
                    </p>
                  )}
                </div>
              )}

              {/* Declared Responses */}
              <div className="space-y-2">
                <h4 className="text-xs font-bold uppercase tracking-wider text-muted-foreground">
                  Declared Responses
                </h4>
                <div className="flex flex-wrap gap-2">
                  {Object.entries(selectedEndpoint.responses).map(([code, resp]) => (
                    <div
                      key={code}
                      className="px-2.5 py-1 rounded bg-accent/60 border border-border text-xs flex items-center gap-2"
                    >
                      <span
                        className={`font-mono font-bold ${
                          code.startsWith('2')
                            ? 'text-emerald-400'
                            : code.startsWith('4')
                            ? 'text-amber-400'
                            : 'text-rose-400'
                        }`}
                      >
                        {code}
                      </span>
                      <span className="text-muted-foreground text-[11px] truncate max-w-xs">
                        {resp.description || 'Status Code'}
                      </span>
                    </div>
                  ))}
                </div>
              </div>
            </>
          ) : (
            <div className="py-12 text-center text-xs text-muted-foreground">
              Select an endpoint to inspect parameters, security requirements, and payload schemas.
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
