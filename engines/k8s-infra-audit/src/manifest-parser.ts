import YAML from 'yaml';
import { K8sPodSpec, K8sWorkloadDocument } from './types.js';

export interface ParseManifestResult {
  documents: K8sWorkloadDocument[];
  errors: Array<{ message: string; line?: number; raw?: string }>;
}

/**
 * Extracts the effective K8sPodSpec from any supported Kubernetes workload kind.
 */
export function extractPodSpec(doc: K8sWorkloadDocument): K8sPodSpec | undefined {
  const kind = doc.kind;
  const spec = doc.spec as any;
  if (!spec) return undefined;

  if (kind === 'Pod') {
    return spec as K8sPodSpec;
  }

  if (
    kind === 'Deployment' ||
    kind === 'StatefulSet' ||
    kind === 'DaemonSet' ||
    kind === 'Job' ||
    kind === 'ReplicaSet' ||
    kind === 'ReplicationController'
  ) {
    return spec.template?.spec as K8sPodSpec | undefined;
  }

  if (kind === 'CronJob') {
    return spec.jobTemplate?.spec?.template?.spec as K8sPodSpec | undefined;
  }

  // Fallback for custom resources or helm templates containing template.spec
  if (spec.template?.spec) {
    return spec.template.spec as K8sPodSpec;
  }

  return undefined;
}

/**
 * Finds approximate line number in YAML content for a key/token or snippet.
 */
export function findLineNumber(content: string, searchPattern: string | RegExp, startLine = 1): number {
  const lines = content.split('\n');
  for (let i = startLine - 1; i < lines.length; i++) {
    const line = lines[i];
    if (line === undefined) continue;
    if (typeof searchPattern === 'string') {
      if (line.includes(searchPattern)) return i + 1;
    } else if (searchPattern.test(line)) {
      return i + 1;
    }
  }
  return startLine;
}

/**
 * Parses multi-document YAML content safely into structured K8sWorkloadDocuments.
 */
export function parseKubernetesManifests(
  rawYaml: string,
  filePath?: string,
): ParseManifestResult {
  const documents: K8sWorkloadDocument[] = [];
  const errors: Array<{ message: string; line?: number; raw?: string }> = [];

  if (!rawYaml || !rawYaml.trim()) {
    return { documents, errors };
  }

  try {
    const parsedDocs = YAML.parseAllDocuments(rawYaml, { prettyErrors: true });

    let currentOffsetLine = 1;
    const rawDocChunks = rawYaml.split(/(?:^|\n)---(?:\n|$)/);

    for (let i = 0; i < parsedDocs.length; i++) {
      const doc = parsedDocs[i];
      if (!doc) continue;

      const rawChunk = rawDocChunks[i] ?? '';

      if (doc.errors && doc.errors.length > 0) {
        for (const err of doc.errors) {
          errors.push({
            message: `YAML syntax error in document ${i + 1}: ${err.message}`,
            line: err.linePos?.[0]?.line ?? currentOffsetLine,
            raw: rawChunk.slice(0, 200),
          });
        }
        continue;
      }

      const json = doc.toJSON();
      if (!json || typeof json !== 'object') {
        continue;
      }

      const endOffsetLine = currentOffsetLine + rawChunk.split('\n').length;

      documents.push({
        apiVersion: json.apiVersion,
        kind: json.kind,
        metadata: json.metadata,
        spec: json.spec,
        rawText: rawChunk,
        startLine: currentOffsetLine,
        endLine: endOffsetLine,
        filePath,
      });

      currentOffsetLine = endOffsetLine + 1;
    }
  } catch (err: unknown) {
    errors.push({
      message: `Fatal YAML parsing error: ${err instanceof Error ? err.message : String(err)}`,
      line: 1,
    });
  }

  return { documents, errors };
}
