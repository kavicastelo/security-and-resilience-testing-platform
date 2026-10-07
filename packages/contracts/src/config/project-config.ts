import { z } from 'zod';
import YAML from 'yaml';
import fs from 'node:fs';
import path from 'node:path';
import { PolicyRuleSchema, PolicyWaiverSchema } from '@security-lab/domain';

export const ProjectTargetConfigSchema = z.object({
  baseUrl: z.string().url(),
  name: z.string().optional(),
  allowedHosts: z.array(z.string()).optional(),
  allowedPorts: z.array(z.number().int()).optional(),
  excludedPaths: z.array(z.string()).optional(),
  headers: z.record(z.string(), z.string()).optional(),
});

export const ProjectPolicyConfigSchema = z.object({
  name: z.string().default('Project Policy'),
  maxAllowedSeverity: z.enum(['critical', 'high', 'medium', 'low', 'info']).default('high'),
  maxCriticalFindings: z.number().int().default(0),
  maxHighFindings: z.number().int().default(0),
  minPostureScore: z.number().min(0).max(100).default(80),
  failOn: z.enum(['failed', 'warning', 'never']).default('failed'),
  requiredEngines: z.array(z.string()).optional(),
  rules: z.array(PolicyRuleSchema).optional(),
  waivers: z.array(PolicyWaiverSchema).optional(),
});

export const ProjectReportersConfigSchema = z.preprocess((val) => {
  if (val && typeof val === 'object') {
    const raw = val as Record<string, unknown>;
    const formats = Array.isArray(raw.formats) ? [...raw.formats] : [];
    let sarifFile = typeof raw.sarifFile === 'string' ? raw.sarifFile : undefined;
    let junitFile = typeof raw.junitFile === 'string' ? raw.junitFile : undefined;
    let htmlFile = typeof raw.htmlFile === 'string' ? raw.htmlFile : undefined;
    let jsonFile = typeof raw.jsonFile === 'string' ? raw.jsonFile : undefined;

    const sarif = raw.sarif as { enabled?: boolean; output?: string } | undefined;
    if (sarif) {
      if (sarif.enabled !== false && !formats.includes('sarif')) formats.push('sarif');
      if (sarif.output) sarifFile = sarif.output;
    }
    const junit = raw.junit as { enabled?: boolean; output?: string } | undefined;
    if (junit) {
      if (junit.enabled !== false && !formats.includes('junit')) formats.push('junit');
      if (junit.output) junitFile = junit.output;
    }
    const html = raw.html as { enabled?: boolean; output?: string } | undefined;
    if (html) {
      if (html.enabled !== false && !formats.includes('html')) formats.push('html');
      if (html.output) htmlFile = html.output;
    }
    const json = raw.json as { enabled?: boolean; output?: string } | undefined;
    if (json) {
      if (json.enabled !== false && !formats.includes('json')) formats.push('json');
      if (json.output) jsonFile = json.output;
    }

    return {
      ...raw,
      formats: formats.length > 0 ? formats : raw.formats || ['terminal'],
      sarifFile,
      junitFile,
      htmlFile,
      jsonFile,
    };
  }
  return val;
}, z.object({
  formats: z.array(z.enum(['terminal', 'sarif', 'junit', 'html', 'json'])).default(['terminal']),
  outputDir: z.string().default('./reports'),
  sarifFile: z.string().optional(),
  junitFile: z.string().optional(),
  htmlFile: z.string().optional(),
  jsonFile: z.string().optional(),
  sarif: z.object({
    enabled: z.boolean().optional(),
    output: z.string().optional(),
  }).optional(),
  junit: z.object({
    enabled: z.boolean().optional(),
    output: z.string().optional(),
  }).optional(),
  html: z.object({
    enabled: z.boolean().optional(),
    output: z.string().optional(),
  }).optional(),
  json: z.object({
    enabled: z.boolean().optional(),
    output: z.string().optional(),
  }).optional(),
}));

export const ProjectDefinitionsConfigSchema = z.preprocess((val) => {
  if (Array.isArray(val)) {
    return {
      engines: ['headers', 'cors', 'tls', 'declarative'],
      items: val,
    };
  }
  return val;
}, z.object({
  engines: z.array(z.string()).default(['headers', 'cors', 'tls']),
  declarativeFiles: z.array(z.string()).optional(),
  contractFiles: z.array(z.string()).optional(),
  items: z.array(z.any()).optional(),
}));

export const ProjectConfigSchema = z.object({
  version: z.string().default('1.0'),
  name: z.string().default('Security Lab Project'),
  target: ProjectTargetConfigSchema,
  definitions: ProjectDefinitionsConfigSchema.default({
    engines: ['headers', 'cors', 'tls'],
  }),
  policy: ProjectPolicyConfigSchema.default({
    name: 'Project Policy',
    maxAllowedSeverity: 'high',
    maxCriticalFindings: 0,
    maxHighFindings: 0,
    minPostureScore: 80,
    failOn: 'failed',
  }),
  reporters: ProjectReportersConfigSchema.default({
    formats: ['terminal'],
    outputDir: './reports',
  }),
});

export type ProjectConfig = z.infer<typeof ProjectConfigSchema>;
export type ProjectTargetConfig = z.infer<typeof ProjectTargetConfigSchema>;
export type ProjectPolicyConfig = z.infer<typeof ProjectPolicyConfigSchema>;
export type ProjectReportersConfig = z.infer<typeof ProjectReportersConfigSchema>;
export type ProjectDefinitionsConfig = z.infer<typeof ProjectDefinitionsConfigSchema>;

/**
 * Parses raw YAML text into a validated ProjectConfig object.
 */
export function parseProjectConfig(yamlString: string): ProjectConfig {
  let parsed: unknown;
  try {
    parsed = YAML.parse(yamlString);
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : String(err);
    throw new Error(`YAML parsing syntax error: ${message}`);
  }

  const result = ProjectConfigSchema.safeParse(parsed);
  if (!result.success) {
    const errorDetails = result.error.errors
      .map((err) => `  - ${err.path.join('.')}: ${err.message}`)
      .join('\n');
    throw new Error(`Invalid .securitylab.yaml configuration:\n${errorDetails}`);
  }

  return result.data;
}

/**
 * Searches for a standard .securitylab.yaml configuration file in the given directory.
 */
export function findProjectConfigFile(startDir: string = process.cwd()): string | null {
  const candidateNames = [
    '.securitylab.yaml',
    '.securitylab.yml',
    'securitylab.yaml',
    'securitylab.yml',
  ];

  for (const name of candidateNames) {
    const fullPath = path.resolve(startDir, name);
    if (fs.existsSync(fullPath)) {
      return fullPath;
    }
  }

  return null;
}

/**
 * Loads and parses a project configuration file from disk.
 * If no specific path is given, automatically discovers `.securitylab.yaml`.
 */
export function loadProjectConfigFile(
  specificFilePath?: string,
  startDir: string = process.cwd(),
): { config: ProjectConfig; filePath: string } | null {
  const targetPath = specificFilePath
    ? path.resolve(startDir, specificFilePath)
    : findProjectConfigFile(startDir);

  if (!targetPath || !fs.existsSync(targetPath)) {
    if (specificFilePath) {
      throw new Error(`Configuration file not found at "${targetPath}"`);
    }
    return null;
  }

  const content = fs.readFileSync(targetPath, 'utf-8');
  const config = parseProjectConfig(content);

  return { config, filePath: targetPath };
}
