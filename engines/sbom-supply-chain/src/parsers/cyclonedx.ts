import { ParsedSbom, SbomComponent, SbomParserResult } from '../types.js';

function extractEcosystemFromPurl(purl?: string): string | undefined {
  if (!purl) return undefined;
  const match = purl.match(/^pkg:([a-zA-Z0-9_-]+)\//);
  if (!match || !match[1]) return undefined;

  const rawEco = match[1].toLowerCase();
  switch (rawEco) {
    case 'npm':
      return 'npm';
    case 'maven':
      return 'Maven';
    case 'pypi':
      return 'PyPI';
    case 'golang':
      return 'Go';
    case 'nuget':
      return 'NuGet';
    case 'cargo':
      return 'crates.io';
    case 'composer':
      return 'Packagist';
    case 'gem':
      return 'RubyGems';
    default:
      return match[1];
  }
}

/**
 * Parses CycloneDX 1.3 / 1.4 / 1.5 JSON SBOMs into normalized components.
 */
export function parseCycloneDXJson(rawJson: string, filePath?: string): SbomParserResult {
  const errors: string[] = [];

  let data: any;
  try {
    data = JSON.parse(rawJson);
  } catch (err: unknown) {
    return {
      errors: [`Invalid JSON in CycloneDX document: ${err instanceof Error ? err.message : String(err)}`],
    };
  }

  if (!data || typeof data !== 'object') {
    return { errors: ['CycloneDX content is not an object'] };
  }

  if (data.bomFormat && String(data.bomFormat).toLowerCase() !== 'cyclonedx') {
    return { errors: [`Unsupported bomFormat: "${data.bomFormat}". Expected "CycloneDX"`] };
  }

  const rawComponents = Array.isArray(data.components) ? data.components : [];
  const components: SbomComponent[] = [];

  for (let i = 0; i < rawComponents.length; i++) {
    const c = rawComponents[i];
    if (!c || typeof c !== 'object') continue;

    const name = String(c.name || '').trim();
    const version = String(c.version || '').trim();

    if (!name) {
      errors.push(`CycloneDX component at index ${i} is missing name`);
      continue;
    }

    // Extract licenses
    const licenses: string[] = [];
    if (Array.isArray(c.licenses)) {
      for (const licItem of c.licenses) {
        if (licItem.license?.id) {
          licenses.push(String(licItem.license.id).trim());
        } else if (licItem.license?.name) {
          licenses.push(String(licItem.license.name).trim());
        } else if (licItem.expression) {
          licenses.push(String(licItem.expression).trim());
        }
      }
    }

    // Extract hashes
    const hashes: Record<string, string> = {};
    if (Array.isArray(c.hashes)) {
      for (const h of c.hashes) {
        if (h.alg && h.content) {
          hashes[String(h.alg)] = String(h.content);
        }
      }
    }

    const purl = c.purl ? String(c.purl).trim() : undefined;
    const ecosystem = extractEcosystemFromPurl(purl) || (c.type === 'npm' ? 'npm' : undefined);

    components.push({
      name,
      version: version || 'unknown',
      purl,
      type: c.type ? String(c.type) : 'library',
      ecosystem,
      licenses,
      description: c.description ? String(c.description) : undefined,
      hashes: Object.keys(hashes).length > 0 ? hashes : undefined,
      location: filePath ? `${filePath}:${name}@${version}` : `${name}@${version}`,
    });
  }

  const parsed: ParsedSbom = {
    format: 'cyclonedx_json',
    specVersion: data.specVersion ? String(data.specVersion) : undefined,
    metadata: {
      timestamp: data.metadata?.timestamp ? String(data.metadata.timestamp) : undefined,
      tools: Array.isArray(data.metadata?.tools) ? data.metadata.tools.map((t: any) => t.name || String(t)) : [],
    },
    components,
    rawText: rawJson,
    filePath,
  };

  return { sbom: parsed, errors };
}
