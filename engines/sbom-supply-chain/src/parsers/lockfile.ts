import { ParsedSbom, SbomComponent, SbomParserResult } from '../types.js';

/**
 * Parses package-lock.json (v1, v2, v3) into normalized components.
 */
export function parsePackageLockJson(rawJson: string, filePath?: string): SbomParserResult {
  const errors: string[] = [];

  let data: any;
  try {
    data = JSON.parse(rawJson);
  } catch (err: unknown) {
    return {
      errors: [`Invalid JSON in package-lock.json: ${err instanceof Error ? err.message : String(err)}`],
    };
  }

  const components: SbomComponent[] = [];

  // npm v2/v3 format
  if (data.packages && typeof data.packages === 'object') {
    for (const [pkgPath, pkgInfo] of Object.entries(data.packages)) {
      if (pkgPath === '' || !pkgInfo || typeof pkgInfo !== 'object') continue;

      const cleanName = pkgPath.replace(/^node_modules\//, '');
      const version = String((pkgInfo as any).version || '').trim();
      if (!cleanName || !version) continue;

      const license = (pkgInfo as any).license ? [String((pkgInfo as any).license)] : [];

      components.push({
        name: cleanName,
        version,
        purl: `pkg:npm/${cleanName}@${version}`,
        type: 'library',
        ecosystem: 'npm',
        licenses: license,
        location: filePath ? `${filePath}:${cleanName}@${version}` : `${cleanName}@${version}`,
      });
    }
  } else if (data.dependencies && typeof data.dependencies === 'object') {
    // npm v1 format
    for (const [pkgName, pkgInfo] of Object.entries(data.dependencies)) {
      if (!pkgInfo || typeof pkgInfo !== 'object') continue;
      const version = String((pkgInfo as any).version || '').trim();
      if (!pkgName || !version) continue;

      components.push({
        name: pkgName,
        version,
        purl: `pkg:npm/${pkgName}@${version}`,
        type: 'library',
        ecosystem: 'npm',
        licenses: [],
        location: filePath ? `${filePath}:${pkgName}@${version}` : `${pkgName}@${version}`,
      });
    }
  }

  const parsed: ParsedSbom = {
    format: 'package_lock',
    specVersion: String(data.lockfileVersion || '2'),
    metadata: {
      tools: ['npm'],
    },
    components,
    rawText: rawJson,
    filePath,
  };

  return { sbom: parsed, errors };
}
