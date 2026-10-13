import {
  PersonaConfig,
  ExpectedPermission,
  AuthzMatrixTestCase,
  HttpMethod,
} from '@security-lab/contracts';
import { ApiInventory } from '@security-lab/domain';

export interface ExplicitRouteConfig {
  path: string;
  method?: HttpMethod;
  parameterName?: string;
  isAdminOnly?: boolean;
  isPublic?: boolean;
  expectedStatuses?: number[];
}

export interface AuthzMatrixOptions {
  /** Raw OpenAPI 3.x spec (JSON or YAML string or object) */
  spec?: string | Record<string, unknown>;
  /** File path or URL to OpenAPI spec */
  specPath?: string;
  specUrl?: string;
  /** Explicit API inventory if already parsed */
  inventory?: ApiInventory;
  /** Multi-persona credentials to permute */
  personas?: PersonaConfig[];
  /** Explicit list of endpoints if not parsing OpenAPI */
  routes?: ExplicitRouteConfig[];
  /** Expected permission matrix rules */
  expectedPermissions?: ExpectedPermission[];
  /** Allow testing destructive DELETE methods (default: false) */
  allowDestructive?: boolean;
  /** Max concurrent requests (default: 5) */
  concurrency?: number;
  /** Request timeout in ms (default: 10000) */
  timeoutMs?: number;
}

export interface PermutationGenerationResult {
  testCases: AuthzMatrixTestCase[];
  routesCount: number;
  parameterizedRoutesCount: number;
  privilegedRoutesCount: number;
}

export interface ComparisonResult {
  isViolation: boolean;
  violationType?: 'BOLA_HORIZONTAL_IDOR' | 'BFLA_VERTICAL_ESCALATION' | 'MISSING_AUTHENTICATION';
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  reason: string;
  dataLeakageDetected: boolean;
}
