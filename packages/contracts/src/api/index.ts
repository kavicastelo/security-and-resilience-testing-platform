import { z } from 'zod';

export const ServiceHealthStatusSchema = z.enum(['up', 'down', 'degraded']);

export const HealthCheckResponseSchema = z.object({
  status: z.enum(['ok', 'degraded', 'error']),
  version: z.string(),
  timestamp: z.string().datetime(),
  uptime: z.number(),
  services: z.object({
    database: ServiceHealthStatusSchema,
  }),
});

export type HealthCheckResponse = z.infer<typeof HealthCheckResponseSchema>;

export const ApiErrorResponseSchema = z.object({
  success: z.literal(false),
  error: z.object({
    code: z.string(),
    message: z.string(),
    details: z.unknown().optional(),
    correlationId: z.string().optional(),
  }),
});

export type ApiErrorResponse = z.infer<typeof ApiErrorResponseSchema>;

export const ApiSuccessResponseSchema = <T extends z.ZodTypeAny>(dataSchema: T) =>
  z.object({
    success: z.literal(true),
    data: dataSchema,
    meta: z
      .object({
        page: z.number().int().optional(),
        pageSize: z.number().int().optional(),
        total: z.number().int().optional(),
      })
      .optional(),
  });

export type ApiResponse<T> =
  | { success: true; data: T; meta?: { page?: number; pageSize?: number; total?: number } }
  | { success: false; error: { code: string; message: string; details?: unknown; correlationId?: string } };
