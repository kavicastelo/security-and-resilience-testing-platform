import { z } from 'zod';

export const SbomFormatSchema = z.enum([
  'cyclonedx_json',
  'spdx_json',
  'package_lock',
  'generic_json',
  'unknown',
]);

export type SbomFormat = z.infer<typeof SbomFormatSchema>;

export const SbomComponentSchema = z.object({
  name: z.string().min(1),
  version: z.string().min(1),
  purl: z.string().optional(),
  type: z.string().optional(),
  ecosystem: z.string().optional(),
  licenses: z.array(z.string()).default([]),
  description: z.string().optional(),
  hashes: z.record(z.string(), z.string()).optional(),
  location: z.string().optional(),
});

export type SbomComponent = z.infer<typeof SbomComponentSchema>;

export const SbomAdvisoryMatchSchema = z.object({
  id: z.string(),
  aliases: z.array(z.string()).default([]),
  summary: z.string().optional(),
  details: z.string().optional(),
  severity: z.enum(['critical', 'high', 'medium', 'low', 'info']),
  cvssScore: z.number().min(0).max(10).optional(),
  fixedVersion: z.string().optional(),
  affectedRange: z.string().optional(),
  referenceUrls: z.array(z.string()).default([]),
});

export type SbomAdvisoryMatch = z.infer<typeof SbomAdvisoryMatchSchema>;

export const SbomLicensePolicySchema = z.object({
  allowedLicenses: z.array(z.string()).optional(),
  disallowedLicenses: z.array(z.string()).default([
    'GPL-3.0-only',
    'GPL-3.0-or-later',
    'AGPL-3.0-only',
    'AGPL-3.0-or-later',
    'AGPL-1.0-only',
    'AGPL-1.0-or-later',
    'SSPL-1.0',
    'EUPL-1.2',
  ]),
  warnOnUnknownLicense: z.boolean().default(false),
  disallowedLicenseSeverity: z.enum(['critical', 'high', 'medium', 'low']).default('high'),
});

export type SbomLicensePolicy = z.infer<typeof SbomLicensePolicySchema>;

export const SbomEngineOptionsSchema = z.object({
  sbomContent: z.string().optional(),
  sbomFilePath: z.string().optional(),
  format: SbomFormatSchema.optional(),
  enableOsvLookup: z.boolean().default(true),
  offlineMode: z.boolean().default(false),
  licensePolicy: SbomLicensePolicySchema.optional(),
  failOnSeverity: z.enum(['critical', 'high', 'medium', 'low']).optional(),
});

export type SbomEngineOptions = z.infer<typeof SbomEngineOptionsSchema>;

export const SbomExecutionSummarySchema = z.object({
  totalComponents: z.number().int().nonnegative(),
  vulnerableComponents: z.number().int().nonnegative(),
  totalVulnerabilities: z.number().int().nonnegative(),
  licenseViolations: z.number().int().nonnegative(),
  componentsByEcosystem: z.record(z.string(), z.number().int().nonnegative()),
  vulnerabilitiesBySeverity: z.record(z.string(), z.number().int().nonnegative()),
  durationMs: z.number().nonnegative(),
});

export type SbomExecutionSummary = z.infer<typeof SbomExecutionSummarySchema>;
