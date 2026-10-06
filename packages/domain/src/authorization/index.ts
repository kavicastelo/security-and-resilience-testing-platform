import { z } from 'zod';
import YAML from 'yaml';

export const IdentityProfileSchema = z.object({
  id: z.string().min(1),
  name: z.string().min(1),
  role: z.string().default('user'),
  token: z.string().optional(),
  headers: z.record(z.string(), z.string()).default({}),
  metadata: z.record(z.string(), z.any()).default({}),
  isGuest: z.boolean().default(false),
});

export type IdentityProfile = z.infer<typeof IdentityProfileSchema>;

export const ResourceIdentifierSchema = z.object({
  id: z.string().min(1),
  ownerIdentityId: z.string().min(1),
  resourceType: z.string().min(1),
  pathParam: z.string().default('id'),
  value: z.string().min(1),
  metadata: z.record(z.string(), z.any()).default({}),
});

export type ResourceIdentifier = z.infer<typeof ResourceIdentifierSchema>;

export const PermissionActionSchema = z.enum(['read', 'write', 'delete', 'admin']);
export type PermissionAction = z.infer<typeof PermissionActionSchema>;

export const HttpMethodSchema = z.enum(['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS']);
export type HttpMethod = z.infer<typeof HttpMethodSchema>;

export const PermissionRuleSchema = z.object({
  id: z.string().min(1),
  name: z.string().min(1),
  path: z.string().min(1),
  method: HttpMethodSchema.default('GET'),
  resourceType: z.string().optional(),
  action: PermissionActionSchema.default('read'),
  allowedRoles: z.array(z.string()).default([]),
  allowOwner: z.boolean().default(true),
  allowGuest: z.boolean().default(false),
  body: z.any().optional(),
  expectedAllowedStatus: z.array(z.number().int()).default([200, 201, 204]),
  expectedDeniedStatus: z.array(z.number().int()).default([401, 403, 404]),
});

export type PermissionRule = z.infer<typeof PermissionRuleSchema>;

export const AuthorizationTestSuiteSchema = z.object({
  id: z.string().min(1),
  name: z.string().min(1),
  version: z.string().regex(/^\d+\.\d+\.\d+$/).default('1.0.0'),
  category: z.literal('authorization').default('authorization'),
  description: z.string().optional(),
  identities: z.array(IdentityProfileSchema).min(1),
  resources: z.array(ResourceIdentifierSchema).default([]),
  rules: z.array(PermissionRuleSchema).min(1),
});

export type AuthorizationTestSuite = z.infer<typeof AuthorizationTestSuiteSchema>;

export class AuthorizationTestSuiteParseError extends Error {
  constructor(message: string, public readonly details?: unknown) {
    super(message);
    this.name = 'AuthorizationTestSuiteParseError';
  }
}

/**
 * Parses and validates a raw YAML string against the AuthorizationTestSuite schema.
 */
export function parseAuthorizationTestSuiteYaml(yamlContent: string): AuthorizationTestSuite {
  let parsedObject: unknown;
  try {
    parsedObject = YAML.parse(yamlContent);
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    throw new AuthorizationTestSuiteParseError(`Malformed YAML in authorization test suite: ${msg}`);
  }

  const result = AuthorizationTestSuiteSchema.safeParse(parsedObject);
  if (!result.success) {
    const issues = result.error.issues
      .map((i) => `  - ${i.path.join('.')}: ${i.message}`)
      .join('\n');
    throw new AuthorizationTestSuiteParseError(
      `Authorization test suite validation failed:\n${issues}`,
      result.error.format(),
    );
  }

  return result.data;
}
