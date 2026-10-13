import { z } from 'zod';

export const RoleSchema = z.enum(['ADMIN', 'ENGINEER', 'AUDITOR']);
export type Role = z.infer<typeof RoleSchema>;

export const WorkspaceSchema = z.object({
  id: z.string().uuid(),
  name: z.string().min(1).max(100),
  slug: z.string().min(1).max(100),
  description: z.string().nullable().optional(),
  createdAt: z.union([z.string().datetime(), z.date()]),
  updatedAt: z.union([z.string().datetime(), z.date()]),
});
export type Workspace = z.infer<typeof WorkspaceSchema>;

export const CreateWorkspaceSchema = z.object({
  name: z.string().min(1).max(100),
  slug: z.string().min(1).max(100).optional(),
  description: z.string().max(500).optional(),
});
export type CreateWorkspaceInput = z.infer<typeof CreateWorkspaceSchema>;

export const UpdateWorkspaceSchema = z.object({
  name: z.string().min(1).max(100).optional(),
  description: z.string().max(500).optional(),
});
export type UpdateWorkspaceInput = z.infer<typeof UpdateWorkspaceSchema>;

export const UserSchema = z.object({
  id: z.string().uuid(),
  email: z.string().email(),
  name: z.string().min(1).max(100),
  createdAt: z.union([z.string().datetime(), z.date()]),
  updatedAt: z.union([z.string().datetime(), z.date()]),
});
export type User = z.infer<typeof UserSchema>;

export const CreateUserSchema = z.object({
  email: z.string().email(),
  name: z.string().min(1).max(100),
  password: z.string().min(8).max(128).optional(),
  role: RoleSchema.optional().default('ENGINEER'),
  workspaceId: z.string().uuid().optional(),
});
export type CreateUserInput = z.infer<typeof CreateUserSchema>;

export const WorkspaceMembershipSchema = z.object({
  id: z.string().uuid(),
  workspaceId: z.string().uuid(),
  userId: z.string().uuid(),
  role: RoleSchema,
  createdAt: z.union([z.string().datetime(), z.date()]),
  updatedAt: z.union([z.string().datetime(), z.date()]),
});
export type WorkspaceMembership = z.infer<typeof WorkspaceMembershipSchema>;

export const AddWorkspaceMemberSchema = z.object({
  userId: z.string().uuid().optional(),
  email: z.string().email().optional(),
  role: RoleSchema.default('ENGINEER'),
});
export type AddWorkspaceMemberInput = z.infer<typeof AddWorkspaceMemberSchema>;

export const ApiKeySchema = z.object({
  id: z.string().uuid(),
  workspaceId: z.string().uuid(),
  userId: z.string().uuid().nullable().optional(),
  name: z.string().min(1).max(100),
  keyPrefix: z.string().min(1).max(16),
  role: RoleSchema,
  expiresAt: z.union([z.string().datetime(), z.date()]).nullable().optional(),
  revokedAt: z.union([z.string().datetime(), z.date()]).nullable().optional(),
  lastUsedAt: z.union([z.string().datetime(), z.date()]).nullable().optional(),
  createdAt: z.union([z.string().datetime(), z.date()]),
  updatedAt: z.union([z.string().datetime(), z.date()]),
});
export type ApiKey = z.infer<typeof ApiKeySchema>;

export const CreateApiKeySchema = z.object({
  name: z.string().min(1).max(100),
  role: RoleSchema.default('ENGINEER'),
  workspaceId: z.string().uuid().optional(),
  userId: z.string().uuid().optional(),
  expiresInDays: z.number().int().positive().optional(),
});
export type CreateApiKeyInput = z.infer<typeof CreateApiKeySchema>;

export const ApiKeyCreatedResponseSchema = z.object({
  apiKey: ApiKeySchema,
  secretKey: z.string(),
});
export type ApiKeyCreatedResponse = z.infer<typeof ApiKeyCreatedResponseSchema>;

export const AuthTokenPayloadSchema = z.object({
  sub: z.string().uuid(),
  email: z.string().email(),
  name: z.string().optional(),
  workspaceId: z.string().uuid(),
  role: RoleSchema,
  tenantId: z.string().uuid().optional(),
  iat: z.number().optional(),
  exp: z.number().optional(),
});
export type AuthTokenPayload = z.infer<typeof AuthTokenPayloadSchema>;

export const LoginRequestSchema = z.object({
  email: z.string().email(),
  password: z.string(),
  workspaceId: z.string().uuid().optional(),
});
export type LoginRequest = z.infer<typeof LoginRequestSchema>;

export const LoginResponseSchema = z.object({
  token: z.string(),
  user: UserSchema,
  workspaceId: z.string().uuid(),
  role: RoleSchema,
});
export type LoginResponse = z.infer<typeof LoginResponseSchema>;
