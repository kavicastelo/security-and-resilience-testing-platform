import { z } from 'zod';

export const FormFieldSchema = z.object({
  name: z.string(),
  type: z.string().default('text'),
  value: z.string().optional(),
  required: z.boolean().default(false),
  placeholder: z.string().optional(),
});
export type FormField = z.infer<typeof FormFieldSchema>;

export const FormDefinitionSchema = z.object({
  action: z.string(),
  method: z.enum(['GET', 'POST', 'PUT', 'DELETE', 'PATCH']).default('POST'),
  enctype: z.string().default('application/x-www-form-urlencoded'),
  fields: z.array(FormFieldSchema).default([]),
});
export type FormDefinition = z.infer<typeof FormDefinitionSchema>;

export const DiscoveredRouteSchema = z.object({
  url: z.string().url(),
  path: z.string(),
  method: z.enum(['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS']).default('GET'),
  source: z.enum(['link', 'form', 'xhr', 'fetch', 'spa_router', 'button', 'script']).default('link'),
  queryParams: z.array(z.string()).default([]),
  headers: z.record(z.string()).optional(),
  forms: z.array(FormDefinitionSchema).default([]),
  contentType: z.string().optional(),
  statusCode: z.number().int().optional(),
  dynamicElements: z.array(z.string()).default([]),
});
export type DiscoveredRoute = z.infer<typeof DiscoveredRouteSchema>;

export const CrawledTargetInventorySchema = z.object({
  targetUrl: z.string().url(),
  crawledAt: z.string().datetime(),
  durationMs: z.number().nonnegative(),
  pagesCrawled: z.number().int().nonnegative(),
  routes: z.array(DiscoveredRouteSchema).default([]),
  apiEndpoints: z.array(DiscoveredRouteSchema).default([]),
  forms: z.array(FormDefinitionSchema).default([]),
  errors: z.array(z.string()).default([]),
});
export type CrawledTargetInventory = z.infer<typeof CrawledTargetInventorySchema>;

export const CrawlerConfigSchema = z.object({
  maxDepth: z.number().int().positive().default(3),
  maxPages: z.number().int().positive().default(50),
  concurrency: z.number().int().positive().default(4),
  requestsPerSecond: z.number().positive().default(10),
  timeoutMs: z.number().positive().default(30000),
  viewport: z
    .object({
      width: z.number().int().positive().default(1280),
      height: z.number().int().positive().default(720),
    })
    .default({ width: 1280, height: 720 }),
  userAgent: z.string().optional(),
  interceptNetwork: z.boolean().default(true),
  extractSpaRoutes: z.boolean().default(true),
});
export type CrawlerConfig = z.infer<typeof CrawlerConfigSchema>;
