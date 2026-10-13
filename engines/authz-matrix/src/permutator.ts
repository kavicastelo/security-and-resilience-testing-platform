import {
  PersonaConfig,
  AuthzMatrixTestCase,
  HttpMethod,
} from '@security-lab/contracts';
import { parseOpenApiSpec } from '@security-lab/domain';
import { AuthzMatrixOptions, PermutationGenerationResult } from './types.js';

export const DEFAULT_SYNTHETIC_PERSONAS: PersonaConfig[] = [
  {
    id: 'user_a',
    name: 'Primary Tenant User (User A)',
    role: 'user',
    token: 'token-user-a',
    headers: { Authorization: 'Bearer token-user-a' },
    resourceIds: {
      id: 'res-user-a',
      userId: 'usr-a',
      docId: 'doc-101',
      orderId: 'ord-101',
      accountId: 'acc-101',
      documentId: 'doc-101',
      item: 'item-101',
    },
    isGuest: false,
    metadata: {},
  },
  {
    id: 'user_b',
    name: 'Foreign Tenant User (User B)',
    role: 'user',
    token: 'token-user-b',
    headers: { Authorization: 'Bearer token-user-b' },
    resourceIds: {
      id: 'res-user-b',
      userId: 'usr-b',
      docId: 'doc-102',
      orderId: 'ord-102',
      accountId: 'acc-102',
      documentId: 'doc-102',
      item: 'item-102',
    },
    isGuest: false,
    metadata: {},
  },
  {
    id: 'admin_user',
    name: 'Platform Administrator',
    role: 'admin',
    token: 'token-admin',
    headers: { Authorization: 'Bearer token-admin' },
    resourceIds: {},
    isGuest: false,
    metadata: {},
  },
  {
    id: 'anonymous_guest',
    name: 'Unauthenticated Public Guest',
    role: 'anonymous',
    headers: {},
    resourceIds: {},
    isGuest: true,
    metadata: {},
  },
];

const ADMIN_PATH_PATTERNS = [
  /\/admin(\/|$)/i,
  /\/internal(\/|$)/i,
  /\/manage(\/|$)/i,
  /\/system(\/|$)/i,
  /\/root(\/|$)/i,
  /\/backoffice(\/|$)/i,
];

/**
 * Checks if a path is considered administrative/privileged.
 */
export function isPrivilegedPath(path: string): boolean {
  return ADMIN_PATH_PATTERNS.some((p) => p.test(path));
}

/**
 * Extracts parameter names from path template e.g. /api/users/{id}/documents/{docId}
 */
export function extractPathParameterNames(path: string): string[] {
  const params: string[] = [];
  // Match {paramName}
  const curlyMatches = path.match(/\{([a-zA-Z0-9_-]+)\}/g);
  if (curlyMatches) {
    for (const m of curlyMatches) {
      params.push(m.slice(1, -1));
    }
  }
  // Match :paramName
  const colonMatches = path.match(/:([a-zA-Z0-9_-]+)/g);
  if (colonMatches) {
    for (const m of colonMatches) {
      params.push(m.slice(1));
    }
  }
  return params;
}

/**
 * Generates the complete test matrix of authorization permutations across routes and personas.
 */
export function generateAuthzMatrixPermutations(
  targetBaseUrl: string,
  options: AuthzMatrixOptions,
): PermutationGenerationResult {
  const personas = (options.personas && options.personas.length > 0)
    ? options.personas
    : DEFAULT_SYNTHETIC_PERSONAS;

  // Resolve normalized routes list
  const routes: Array<{
    path: string;
    method: HttpMethod;
    parameterNames: string[];
    isPrivileged: boolean;
    isPublic: boolean;
    expectedStatuses?: number[];
  }> = [];

  if (options.inventory) {
    for (const ep of options.inventory.endpoints) {
      if (ep.method === 'DELETE' && !options.allowDestructive) continue;
      const parameterNames = extractPathParameterNames(ep.path);
      routes.push({
        path: ep.path,
        method: ep.method,
        parameterNames,
        isPrivileged: isPrivilegedPath(ep.path),
        isPublic: ep.isExplicitlyPublic,
      });
    }
  } else if (options.spec) {
    const inv = parseOpenApiSpec(options.spec);
    for (const ep of inv.endpoints) {
      if (ep.method === 'DELETE' && !options.allowDestructive) continue;
      const parameterNames = extractPathParameterNames(ep.path);
      routes.push({
        path: ep.path,
        method: ep.method,
        parameterNames,
        isPrivileged: isPrivilegedPath(ep.path),
        isPublic: ep.isExplicitlyPublic,
      });
    }
  } else if (options.routes && options.routes.length > 0) {
    for (const r of options.routes) {
      const method = r.method || 'GET';
      if (method === 'DELETE' && !options.allowDestructive) continue;
      const paramNames = r.parameterName
        ? [r.parameterName]
        : extractPathParameterNames(r.path);
      routes.push({
        path: r.path,
        method,
        parameterNames: paramNames,
        isPrivileged: r.isAdminOnly ?? isPrivilegedPath(r.path),
        isPublic: r.isPublic ?? false,
        expectedStatuses: r.expectedStatuses,
      });
    }
  }

  const testCases: AuthzMatrixTestCase[] = [];
  let parameterizedRoutesCount = 0;
  let privilegedRoutesCount = 0;

  const userPersonas = personas.filter((p) => p.role === 'user');
  const anonymousPersona = personas.find((p) => p.isGuest || p.role === 'anonymous') || {
    id: 'anonymous',
    name: 'Anonymous Guest',
    role: 'anonymous',
    headers: {},
    resourceIds: {},
    isGuest: true,
    metadata: {},
  };

  const primaryOwner = userPersonas[0] || DEFAULT_SYNTHETIC_PERSONAS[0]!;

  for (const route of routes) {
    const isParameterized = route.parameterNames.length > 0;
    if (isParameterized) parameterizedRoutesCount++;
    if (route.isPrivileged) privilegedRoutesCount++;

    // 1. Horizontal BOLA / IDOR Testing
    if (isParameterized && !route.isPublic) {
      const primaryParam = route.parameterNames[0]!;
      // Find foreign resource ID belonging to primaryOwner
      const targetResourceId =
        primaryOwner.resourceIds[primaryParam] ||
        primaryOwner.resourceIds['id'] ||
        primaryOwner.resourceIds['docId'] ||
        primaryOwner.resourceIds['userId'] ||
        'res-owner-target-101';

      // Replace path parameters with primary owner's resource ID
      let resolvedPath = route.path;
      for (const pName of route.parameterNames) {
        const idVal = primaryOwner.resourceIds[pName] || targetResourceId;
        resolvedPath = resolvedPath
          .replace(`{${pName}}`, idVal)
          .replace(`:${pName}`, idVal);
      }

      const fullUrl = new URL(resolvedPath.startsWith('/') ? resolvedPath.slice(1) : resolvedPath, targetBaseUrl.endsWith('/') ? targetBaseUrl : `${targetBaseUrl}/`).toString();

      // Test every non-owner user persona attempting to access primaryOwner's resource
      for (const attacker of userPersonas) {
        if (attacker.id === primaryOwner.id) continue;

        testCases.push({
          id: `bola_${route.method.toLowerCase()}_${route.path}_${attacker.id}_vs_${primaryOwner.id}`,
          type: 'BOLA_HORIZONTAL_IDOR',
          endpointPath: route.path,
          method: route.method,
          url: fullUrl,
          actorPersona: attacker,
          targetResourceId,
          resourceParamName: primaryParam,
          ownerPersona: primaryOwner,
          expectedStatuses: route.expectedStatuses ?? [401, 403, 404],
          description: `Asserts ${attacker.name} cannot access ${primaryOwner.name}'s resource "${targetResourceId}" via ${route.method} ${route.path}`,
        });
      }

      // Also assert anonymous cannot access the private resource
      testCases.push({
        id: `bola_${route.method.toLowerCase()}_${route.path}_anon_vs_${primaryOwner.id}`,
        type: 'BOLA_HORIZONTAL_IDOR',
        endpointPath: route.path,
        method: route.method,
        url: fullUrl,
        actorPersona: anonymousPersona,
        targetResourceId,
        resourceParamName: primaryParam,
        ownerPersona: primaryOwner,
        expectedStatuses: route.expectedStatuses ?? [401, 403, 404],
        description: `Asserts unauthenticated guest cannot access ${primaryOwner.name}'s resource "${targetResourceId}" via ${route.method} ${route.path}`,
      });
    }

    // 2. Vertical BFLA Privilege Escalation Testing
    if (route.isPrivileged) {
      let resolvedPath = route.path;
      for (const pName of route.parameterNames) {
        resolvedPath = resolvedPath
          .replace(`{${pName}}`, 'admin-test-id')
          .replace(`:${pName}`, 'admin-test-id');
      }
      const fullUrl = new URL(resolvedPath.startsWith('/') ? resolvedPath.slice(1) : resolvedPath, targetBaseUrl.endsWith('/') ? targetBaseUrl : `${targetBaseUrl}/`).toString();

      // Test all unprivileged personas against privileged admin endpoint
      for (const regularUser of userPersonas) {
        testCases.push({
          id: `bfla_${route.method.toLowerCase()}_${route.path}_${regularUser.id}`,
          type: 'BFLA_VERTICAL_ESCALATION',
          endpointPath: route.path,
          method: route.method,
          url: fullUrl,
          actorPersona: regularUser,
          expectedStatuses: route.expectedStatuses ?? [401, 403, 404],
          description: `Asserts unprivileged ${regularUser.name} is rejected when accessing administrative endpoint ${route.method} ${route.path}`,
        });
      }

      // Anonymous against admin endpoint
      testCases.push({
        id: `bfla_${route.method.toLowerCase()}_${route.path}_anon`,
        type: 'BFLA_VERTICAL_ESCALATION',
        endpointPath: route.path,
        method: route.method,
        url: fullUrl,
        actorPersona: anonymousPersona,
        expectedStatuses: [401, 403, 404],
        description: `Asserts unauthenticated guest is rejected when accessing administrative endpoint ${route.method} ${route.path}`,
      });
    }

    // 3. Missing Authentication Boundary Testing
    if (!route.isPublic && !route.isPrivileged && !isParameterized) {
      const fullUrl = new URL(route.path.startsWith('/') ? route.path.slice(1) : route.path, targetBaseUrl.endsWith('/') ? targetBaseUrl : `${targetBaseUrl}/`).toString();
      testCases.push({
        id: `missing_auth_${route.method.toLowerCase()}_${route.path}_anon`,
        type: 'MISSING_AUTHENTICATION',
        endpointPath: route.path,
        method: route.method,
        url: fullUrl,
        actorPersona: anonymousPersona,
        expectedStatuses: [401, 403],
        description: `Asserts protected non-public endpoint ${route.method} ${route.path} rejects unauthenticated requests`,
      });
    }
  }

  return {
    testCases,
    routesCount: routes.length,
    parameterizedRoutesCount,
    privilegedRoutesCount,
  };
}
