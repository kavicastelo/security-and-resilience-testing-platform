import { z } from 'zod';

export const AuthTypeSchema = z.enum(['FORM', 'OAUTH2', 'API_KEY', 'BEARER']);
export type AuthType = z.infer<typeof AuthTypeSchema>;

export const AuthStepExtractSchema = z.object({
  /** Source to extract from */
  from: z.enum(['BODY_JSON', 'BODY_REGEX', 'HEADER', 'COOKIE']),
  /** Key or path in source */
  key: z.string(),
  /** Variable name to save into session state */
  saveAs: z.string(),
});
export type AuthStepExtract = z.infer<typeof AuthStepExtractSchema>;

export const AuthStepSchema = z.object({
  name: z.string().optional(),
  url: z.string(),
  method: z.enum(['GET', 'POST', 'PUT', 'PATCH', 'DELETE']).default('POST'),
  headers: z.record(z.string()).optional(),
  body: z.record(z.unknown()).optional(),
  extract: z.array(AuthStepExtractSchema).optional(),
});
export type AuthStep = z.infer<typeof AuthStepSchema>;

export const OAuth2GrantTypeSchema = z.enum([
  'client_credentials',
  'password',
  'authorization_code',
  'refresh_token',
]);
export type OAuth2GrantType = z.infer<typeof OAuth2GrantTypeSchema>;

export const OAuth2ConfigSchema = z.object({
  grantType: OAuth2GrantTypeSchema.default('client_credentials'),
  tokenUrl: z.string(),
  clientId: z.string(),
  clientSecret: z.string(),
  username: z.string().optional(),
  password: z.string().optional(),
  scope: z.string().optional(),
  audience: z.string().optional(),
});
export type OAuth2Config = z.infer<typeof OAuth2ConfigSchema>;

export const CsrfConfigSchema = z.object({
  tokenUrl: z.string().optional(),
  paramName: z.string().default('_csrf'),
  headerName: z.string().default('X-CSRF-Token'),
  regexPattern: z.string().optional(),
  jsonPath: z.string().optional(),
});
export type CsrfConfig = z.infer<typeof CsrfConfigSchema>;

export const AuthFlowSchema = z.object({
  type: AuthTypeSchema,
  loginUrl: z.string().optional(),
  steps: z.array(AuthStepSchema).optional(),
  totpSecret: z.string().optional(),
  tokenExtractionPath: z.string().optional(), // default 'access_token' or 'token'
  credentials: z.record(z.string()).optional(), // e.g. { username, password }
  oauth2Config: OAuth2ConfigSchema.optional(),
  csrfConfig: CsrfConfigSchema.optional(),
  headers: z.record(z.string()).optional(), // Header template e.g. { "Authorization": "Bearer {{token}}" }
});
export type AuthFlow = z.infer<typeof AuthFlowSchema>;

export const EncryptedDataSchema = z.object({
  algorithm: z.literal('aes-256-gcm'),
  encryptedData: z.string(),
  iv: z.string(),
  tag: z.string(),
  encryptedDek: z.string(),
  dekIv: z.string(),
  dekTag: z.string(),
  keyId: z.string().optional(),
});
export type EncryptedData = z.infer<typeof EncryptedDataSchema>;

export const TargetAuthProfileSchema = z.object({
  id: z.string().uuid().optional(),
  targetId: z.string().uuid().optional(),
  name: z.string().optional(),
  flow: AuthFlowSchema,
  encryptedAuthData: EncryptedDataSchema.optional(),
  activeToken: z.string().optional(),
  activeCookies: z.record(z.string()).optional(),
  tokenExpiresAt: z.union([z.string().datetime(), z.date()]).optional(),
  lastRefreshedAt: z.union([z.string().datetime(), z.date()]).optional(),
});
export type TargetAuthProfile = z.infer<typeof TargetAuthProfileSchema>;

export const AuthSessionStateSchema = z.object({
  token: z.string().optional(),
  tokenType: z.string().default('Bearer'),
  cookies: z.record(z.string()).default({}),
  headers: z.record(z.string()).default({}),
  expiresAt: z.number().optional(), // Unix timestamp (ms)
  lastRefreshedAt: z.number().default(() => Date.now()),
  variables: z.record(z.unknown()).default({}),
});
export type AuthSessionState = z.infer<typeof AuthSessionStateSchema>;
