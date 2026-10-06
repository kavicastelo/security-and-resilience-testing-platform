import {
  AuthorizationTestSuite,
  IdentityProfile,
  ResourceIdentifier,
  HttpMethod,
} from '@security-lab/domain';

export type PermutationType =
  | 'baseline_owner'
  | 'horizontal_bola'
  | 'vertical_bfla'
  | 'unauthenticated_access';

export interface AuthorizationPermutation {
  readonly id: string;
  readonly ruleId: string;
  readonly permutationType: PermutationType;
  readonly identity: IdentityProfile;
  readonly targetUrl: string;
  readonly resolvedPath: string;
  readonly method: HttpMethod;
  readonly expectedAccess: 'ALLOW' | 'DENY';
  readonly expectedStatusCodes: number[];
  readonly resource?: ResourceIdentifier;
  readonly ownerIdentity?: IdentityProfile;
  readonly body?: unknown;
  readonly description: string;
}

/**
 * Resolves a template path by replacing object ID and user ID parameters.
 */
export function resolveResourcePath(
  pathTemplate: string,
  resource?: ResourceIdentifier,
  identity?: IdentityProfile,
): string {
  let resolved = pathTemplate;

  if (resource) {
    const paramName = resource.pathParam || 'id';
    const encodedVal = encodeURIComponent(resource.value);

    // Replace {paramName}
    resolved = resolved.replace(new RegExp(`\\{${paramName}\\}`, 'g'), encodedVal);
    // Replace :paramName
    resolved = resolved.replace(new RegExp(`:${paramName}(?=[/?#]|$)`, 'g'), encodedVal);

    // Generic fallback for {id} or :id if specific name wasn't matched
    resolved = resolved.replace(/\{id\}/g, encodedVal);
    resolved = resolved.replace(/:id(?=[/?#]|$)/g, encodedVal);
  }

  if (identity && identity.metadata) {
    for (const [key, val] of Object.entries(identity.metadata)) {
      const encodedVal = encodeURIComponent(String(val));
      resolved = resolved.replace(new RegExp(`\\{${key}\\}`, 'g'), encodedVal);
      resolved = resolved.replace(new RegExp(`:${key}(?=[/?#]|$)`, 'g'), encodedVal);
    }
  }

  return resolved;
}

/**
 * Constructs request headers for a given test identity.
 */
export function buildIdentityHeaders(
  identity: IdentityProfile,
  customHeaders?: Record<string, string>,
): Record<string, string> {
  const headers: Record<string, string> = {
    'User-Agent': 'SecurityLab-QA/1.0',
    Accept: 'application/json, text/plain, */*',
    ...customHeaders,
    ...identity.headers,
  };

  if (!identity.isGuest && identity.token) {
    const hasAuth = Object.keys(headers).some((h) => h.toLowerCase() === 'authorization');
    if (!hasAuth) {
      headers['Authorization'] = identity.token.startsWith('Bearer ')
        ? identity.token
        : `Bearer ${identity.token}`;
    }
  }

  return headers;
}

/**
 * Checks whether an HTTP response represents a genuine successful authorization.
 * Accurately filters out APIs returning soft-403 errors wrapped in HTTP 200 OK.
 */
export function isSuccessfulAuthorizedResponse(status: number, bodyText: string): boolean {
  if (status < 200 || status >= 300) {
    return false;
  }

  try {
    const json = JSON.parse(bodyText);
    if (json && typeof json === 'object') {
      const err = json.error || json.err || json.message;
      if (typeof err === 'string') {
        const lower = err.toLowerCase();
        if (
          lower.includes('unauthorized') ||
          lower.includes('forbidden') ||
          lower.includes('denied') ||
          lower.includes('not permitted') ||
          lower.includes('not allowed') ||
          lower.includes('permission denied')
        ) {
          return false;
        }
      }
    }
  } catch {
    const lower = bodyText.toLowerCase();
    if (
      lower.includes('403 forbidden') ||
      lower.includes('401 unauthorized') ||
      lower.includes('access denied')
    ) {
      return false;
    }
  }

  return true;
}

/**
 * Generates test permutations across identities and resources from a declarative suite.
 */
export function generateAuthorizationPermutations(
  suite: AuthorizationTestSuite,
  baseUrl: string,
): AuthorizationPermutation[] {
  const permutations: AuthorizationPermutation[] = [];
  const normalizedBase = baseUrl.replace(/\/+$/, '');

  // Synthetic guest identity for unauthenticated access checks if none defined
  const guestIdentity: IdentityProfile = suite.identities.find((i) => i.isGuest) || {
    id: '__guest_anonymous__',
    name: 'Anonymous Guest',
    role: 'guest',
    isGuest: true,
    headers: {},
    metadata: {},
  };

  for (const rule of suite.rules) {
    const isObjectLevel = rule.path.includes('{') || rule.path.includes(':');

    if (isObjectLevel) {
      // -----------------------------------------------------------------------
      // 1. Object-Level Permutations (BOLA / IDOR)
      // -----------------------------------------------------------------------
      const matchingResources = suite.resources.filter(
        (r) => !rule.resourceType || r.resourceType === rule.resourceType,
      );

      for (const resource of matchingResources) {
        const owner = suite.identities.find((i) => i.id === resource.ownerIdentityId);
        const resolvedPath = resolveResourcePath(rule.path, resource, owner);
        const fullUrl = `${normalizedBase}${resolvedPath.startsWith('/') ? '' : '/'}${resolvedPath}`;

        // A. Baseline Owner Legitimate Access
        if (owner && rule.allowOwner) {
          permutations.push({
            id: `perm_${rule.id}_owner_${owner.id}_${resource.id}`,
            ruleId: rule.id,
            permutationType: 'baseline_owner',
            identity: owner,
            targetUrl: fullUrl,
            resolvedPath,
            method: rule.method,
            expectedAccess: 'ALLOW',
            expectedStatusCodes: rule.expectedAllowedStatus,
            resource,
            ownerIdentity: owner,
            body: rule.body,
            description: `Legitimate Access: Owner "${owner.name}" accessing owned ${resource.resourceType} "${resource.id}"`,
          });
        }

        // B. Horizontal Unauthorized Access (BOLA)
        for (const candidate of suite.identities) {
          if (candidate.isGuest) continue;
          if (candidate.id === resource.ownerIdentityId) continue;

          // Check if candidate's role is globally permitted (e.g. admin)
          const isRoleAllowed = rule.allowedRoles.includes(candidate.role);
          if (!isRoleAllowed) {
            permutations.push({
              id: `perm_${rule.id}_bola_${candidate.id}_${resource.id}`,
              ruleId: rule.id,
              permutationType: 'horizontal_bola',
              identity: candidate,
              targetUrl: fullUrl,
              resolvedPath,
              method: rule.method,
              expectedAccess: 'DENY',
              expectedStatusCodes: rule.expectedDeniedStatus,
              resource,
              ownerIdentity: owner,
              body: rule.body,
              description: `BOLA Probe: Non-owner "${candidate.name}" attempting to access ${resource.resourceType} "${resource.id}" (owned by "${owner?.name || resource.ownerIdentityId}")`,
            });
          }
        }

        // C. Anonymous Access Probe on Resource
        if (!rule.allowGuest) {
          permutations.push({
            id: `perm_${rule.id}_unauth_${resource.id}`,
            ruleId: rule.id,
            permutationType: 'unauthenticated_access',
            identity: guestIdentity,
            targetUrl: fullUrl,
            resolvedPath,
            method: rule.method,
            expectedAccess: 'DENY',
            expectedStatusCodes: rule.expectedDeniedStatus,
            resource,
            ownerIdentity: owner,
            body: rule.body,
            description: `Anonymous Probe: Unauthenticated request attempting to access ${resource.resourceType} "${resource.id}"`,
          });
        }
      }
    } else {
      // -----------------------------------------------------------------------
      // 2. Function-Level Permutations (BFLA & Missing Controls)
      // -----------------------------------------------------------------------
      const fullUrl = `${normalizedBase}${rule.path.startsWith('/') ? '' : '/'}${rule.path}`;

      // A. Anonymous Access Check
      if (!rule.allowGuest) {
        permutations.push({
          id: `perm_${rule.id}_unauth_func`,
          ruleId: rule.id,
          permutationType: 'unauthenticated_access',
          identity: guestIdentity,
          targetUrl: fullUrl,
          resolvedPath: rule.path,
          method: rule.method,
          expectedAccess: 'DENY',
          expectedStatusCodes: rule.expectedDeniedStatus,
          body: rule.body,
          description: `Anonymous Access Probe: Unauthenticated request to protected function "${rule.path}"`,
        });
      }

      // B. Role-Based Permissions (BFLA)
      for (const identity of suite.identities) {
        if (identity.isGuest) continue;

        const isAllowed =
          rule.allowedRoles.length === 0 || rule.allowedRoles.includes(identity.role);

        if (isAllowed) {
          permutations.push({
            id: `perm_${rule.id}_allowed_${identity.id}`,
            ruleId: rule.id,
            permutationType: 'baseline_owner',
            identity,
            targetUrl: fullUrl,
            resolvedPath: rule.path,
            method: rule.method,
            expectedAccess: 'ALLOW',
            expectedStatusCodes: rule.expectedAllowedStatus,
            body: rule.body,
            description: `Authorized Role: Identity "${identity.name}" with permitted role "${identity.role}" accessing "${rule.path}"`,
          });
        } else {
          permutations.push({
            id: `perm_${rule.id}_bfla_${identity.id}`,
            ruleId: rule.id,
            permutationType: 'vertical_bfla',
            identity,
            targetUrl: fullUrl,
            resolvedPath: rule.path,
            method: rule.method,
            expectedAccess: 'DENY',
            expectedStatusCodes: rule.expectedDeniedStatus,
            body: rule.body,
            description: `BFLA Probe: Unprivileged identity "${identity.name}" (role: "${identity.role}") attempting to access restricted function "${rule.path}" (allowed: [${rule.allowedRoles.join(', ')}])`,
          });
        }
      }
    }
  }

  return permutations;
}
