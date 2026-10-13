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
    default:
      return match[1];
  }
}

/**
 * Parses SPDX 2.2 / 2.3 JSON SBOM documents into normalized components.
 */
export function parseSpdxJson(rawJson: string, filePath?: string): SbomParserResult {
  const errors: string[] = [];

  let data: any;
  try {
    data = JSON.parse(rawJson);
  } catch (err: unknown) {
    return {
      errors: [`Invalid JSON in SPDX document: ${err instanceof Error ? err.message : String(err)}`],
    };
  }

  if (!data || typeof data !== 'object') {
    return { errors: ['SPDX content is not an object'] };
  }

  if (data.spdxVersion && !String(data.spdxVersion).toUpperCase().startsWith('SPDX')) {
    return { errors: [`Unsupported spdxVersion: "${data.spdxVersion}". Expected SPDX identifier.`] };
  }

  const rawPackages = Array.isArray(data.packages) ? data.packages : [];
  const components: SbomComponent[] = [];

  for (let i = 0; i < rawPackages.length; i++) {
    const pkg = rawPackages[i];
    if (!pkg || typeof pkg !== 'object') continue;

    const name = String(pkg.name || '').trim();
    const version = String(pkg.versionInfo || '').trim();

    if (!name) {
      errors.push(`SPDX package at index ${i} is missing name`);
      continue;
    }

    // Extract licenses
    const licenses: string[] = [];
    const concluded = String(pkg.licenseConcluded || '').trim();
    const declared = String(pkg.licenseDeclared || '').trim();

    if (concluded && concluded !== 'NOASSERTION' && concluded !== 'NONE') {
      licenses.push(concluded);
    }
    if (declared && declared !== 'NOASSERTION' && declared !== 'NONE' && declared !== concluded) {
      licenses.push(declared);
    }

    // Extract externalRefs (purl)
    let purl: string | undefined;
    if (Array.isArray(pkg.externalRefs)) {
      const purlRef = pkg.externalRefs.find(
        (ref: any) =>
          String(ref.referenceType).toLowerCase() === 'purl' ||
          String(ref.referenceType).toLowerCase() === 'package-url',
      );
      if (purlRef?.referenceLocator) {
        purl = String(purlRef.referenceLocator).trim();
      }
    }

    // Extract checksums
    const hashes: Record<string, string> = {};
    if (Array.isArray(pkg.checksums)) {
      for (const cs of pkg.checksums) {
        if (cs.algorithm && cs.checksumValue) {
          hashes[String(cs.algorithm)] = String(cs.checksumValue);
        }
      }
    }

    const ecosystem = extractEcosystemFromPurl(purl);

    components.push({
      name,
      version: version || 'unknown',
      purl,
      type: 'package',
      ecosystem,
      licenses,
      description: pkg.description ? String(pkg.description) : undefined,
      hashes: Object.keys(hashes).length > 0 ? hashes : undefined,
      location: filePath ? `${filePath}:${name}@${version}` : `${name}@${version}`,
    });
  }

  const parsed: ParsedSbom = {
    format: 'spdx_json',
    specVersion: data.spdxVersion ? String(data.spdxVersion) : undefined,
    metadata: {
      timestamp: data.creationInfo?.created ? String(data.creationInfo.created) : undefined,
      tools: Array.isArray(data.creationInfo?.creators) ? data.creationInfo.creators.map(String) : [],
    },
    components,
    rawText: rawJson,
    filePath,
  };

  return { sbom: parsed, errors };
}
