import YAML from 'yaml';
import { TestDefinition, TestDefinitionSchema } from './index.js';

export class TestDefinitionParseError extends Error {
  constructor(message: string, public readonly details?: unknown) {
    super(message);
    this.name = 'TestDefinitionParseError';
  }
}

/**
 * Parses and validates a raw YAML string against the platform TestDefinition schema.
 */
export function parseTestDefinitionYaml(yamlContent: string): TestDefinition {
  let parsedObject: unknown;
  try {
    parsedObject = YAML.parse(yamlContent);
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    throw new TestDefinitionParseError(`Malformed YAML in test definition: ${msg}`);
  }

  const result = TestDefinitionSchema.safeParse(parsedObject);
  if (!result.success) {
    const issues = result.error.issues
      .map((i) => `  - ${i.path.join('.')}: ${i.message}`)
      .join('\n');
    throw new TestDefinitionParseError(
      `Test definition schema validation failed:\n${issues}`,
      result.error.format(),
    );
  }

  return result.data;
}
