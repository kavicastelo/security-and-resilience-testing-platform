import { z } from 'zod';
import { RoleSchema } from './auth.js';

// --- SSO Schemas ---

export const SsoProviderSchema = z.enum(['saml', 'oidc']);
export type SsoProvider = z.infer<typeof SsoProviderSchema>;

export const SamlConfigSchema = z.object({
  entryPoint: z.string().url(),
  issuer: z.string().min(1),
  cert: z.string().min(1), // X.509 certificate in PEM or base64 format
  callbackUrl: z.string().url().optional(),
});
export type SamlConfig = z.infer<typeof SamlConfigSchema>;

export const OidcConfigSchema = z.object({
  issuer: z.string().min(1),
  clientId: z.string().min(1),
  clientSecret: z.string().min(1),
  authorizationUrl: z.string().url().optional(),
  tokenUrl: z.string().url().optional(),
  userInfoUrl: z.string().url().optional(),
  redirectUri: z.string().url().optional(),
});
export type OidcConfig = z.infer<typeof OidcConfigSchema>;

export const SsoConfigSchema = z.object({
  enabled: z.boolean().default(false),
  provider: SsoProviderSchema,
  domain: z.string().min(1).optional(), // e.g. "enterprise.corp"
  saml: SamlConfigSchema.optional(),
  oidc: OidcConfigSchema.optional(),
  roleMapping: z.record(RoleSchema).optional(), // e.g. { "SecurityAdmins": "ADMIN", "DevOps": "ENGINEER" }
  defaultRole: RoleSchema.default('ENGINEER'),
});
export type SsoConfig = z.infer<typeof SsoConfigSchema>;

// --- Billing & Metering Schemas ---

export const SubscriptionTierSchema = z.enum(['free', 'starter', 'enterprise']);
export type SubscriptionTier = z.infer<typeof SubscriptionTierSchema>;

export const QuotaLimitsSchema = z.object({
  maxExecutionMinutesPerMonth: z.number().int().nonnegative(),
  maxActiveTargets: z.number().int().nonnegative(),
  maxConcurrentRuns: z.number().int().nonnegative(),
});
export type QuotaLimits = z.infer<typeof QuotaLimitsSchema>;

export const DEFAULT_TIER_QUOTAS: Record<SubscriptionTier, QuotaLimits> = {
  free: {
    maxExecutionMinutesPerMonth: 100,
    maxActiveTargets: 2,
    maxConcurrentRuns: 1,
  },
  starter: {
    maxExecutionMinutesPerMonth: 1000,
    maxActiveTargets: 10,
    maxConcurrentRuns: 3,
  },
  enterprise: {
    maxExecutionMinutesPerMonth: 10000,
    maxActiveTargets: 100,
    maxConcurrentRuns: 10,
  },
};

export const WorkspaceBillingSchema = z.object({
  workspaceId: z.string().uuid(),
  subscriptionTier: SubscriptionTierSchema,
  stripeCustomerId: z.string().nullable().optional(),
  quotaLimits: QuotaLimitsSchema,
  usageMinutes: z.number().int().nonnegative(),
  isQuotaExceeded: z.boolean().default(false),
});
export type WorkspaceBilling = z.infer<typeof WorkspaceBillingSchema>;

// --- SCIM 2.0 Schemas ---

export const ScimUserSchema = z.object({
  schemas: z.array(z.string()).default(['urn:ietf:params:scim:schemas:core:2.0:User']),
  id: z.string(),
  userName: z.string(),
  name: z.object({
    formatted: z.string().optional(),
    familyName: z.string().optional(),
    givenName: z.string().optional(),
  }).optional(),
  emails: z.array(z.object({
    value: z.string(),
    type: z.string().optional(),
    primary: z.boolean().optional(),
  })).optional(),
  active: z.boolean().default(true),
  roles: z.array(z.object({
    value: z.string(),
    primary: z.boolean().optional(),
  })).optional(),
  meta: z.object({
    resourceType: z.literal('User').default('User'),
    created: z.string().optional(),
    lastModified: z.string().optional(),
    location: z.string().optional(),
  }).optional(),
});
export type ScimUser = z.infer<typeof ScimUserSchema>;

export const ScimGroupSchema = z.object({
  schemas: z.array(z.string()).default(['urn:ietf:params:scim:schemas:core:2.0:Group']),
  id: z.string(),
  displayName: z.string(),
  members: z.array(z.object({
    value: z.string(),
    display: z.string().optional(),
    $ref: z.string().optional(),
  })).optional(),
  meta: z.object({
    resourceType: z.literal('Group').default('Group'),
    created: z.string().optional(),
    lastModified: z.string().optional(),
    location: z.string().optional(),
  }).optional(),
});
export type ScimGroup = z.infer<typeof ScimGroupSchema>;

export const ScimListResponseSchema = z.object({
  schemas: z.array(z.string()).default(['urn:ietf:params:scim:api:messages:2.0:ListResponse']),
  totalResults: z.number().int().nonnegative(),
  startIndex: z.number().int().positive(),
  itemsPerPage: z.number().int().nonnegative(),
  Resources: z.array(z.any()),
});
export type ScimListResponse<T = any> = z.infer<typeof ScimListResponseSchema> & { Resources: T[] };
