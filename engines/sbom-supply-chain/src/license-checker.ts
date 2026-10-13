import { LicenseCheckResult, SbomComponent, SbomLicensePolicy } from './types.js';

const DEFAULT_DISALLOWED_LICENSES = new Set([
  'GPL-3.0-ONLY',
  'GPL-3.0-OR-LATER',
  'GPL-3.0',
  'AGPL-3.0-ONLY',
  'AGPL-3.0-OR-LATER',
  'AGPL-3.0',
  'AGPL-1.0-ONLY',
  'AGPL-1.0-OR-LATER',
  'SSPL-1.0',
  'EUPL-1.2',
  'CC-BY-NC-4.0',
]);

/**
 * Normalizes common informal license names to standardized uppercase SPDX identifiers.
 */
export function normalizeLicenseName(name: string): string {
  const clean = name.trim().toUpperCase();
  if (clean === 'GPL-3.0' || clean === 'GPLV3') return 'GPL-3.0-ONLY';
  if (clean === 'AGPL-3.0' || clean === 'AGPLV3') return 'AGPL-3.0-ONLY';
  if (clean === 'GPL-2.0' || clean === 'GPLV2') return 'GPL-2.0-ONLY';
  if (clean === 'APACHE 2.0' || clean === 'APACHE-2') return 'APACHE-2.0';
  if (clean === 'BSD 3-CLAUSE' || clean === 'BSD-3') return 'BSD-3-CLAUSE';
  if (clean === 'BSD 2-CLAUSE' || clean === 'BSD-2') return 'BSD-2-CLAUSE';
  return clean;
}

/**
 * Evaluates components against software license compliance policies.
 */
export function evaluateLicenseCompliance(
  components: SbomComponent[],
  policy?: SbomLicensePolicy,
): LicenseCheckResult[] {
  const disallowedList = (policy?.disallowedLicenses || Array.from(DEFAULT_DISALLOWED_LICENSES)).map((l) =>
    normalizeLicenseName(l),
  );
  const disallowedSet = new Set(disallowedList);

  const allowedSet = policy?.allowedLicenses
    ? new Set(policy.allowedLicenses.map((l) => normalizeLicenseName(l)))
    : undefined;

  const results: LicenseCheckResult[] = [];

  for (const comp of components) {
    if (!comp.licenses || comp.licenses.length === 0) {
      if (policy?.warnOnUnknownLicense) {
        results.push({
          component: comp,
          isViolation: true,
          message: `Component "${comp.name}@${comp.version}" has no declared software license.`,
        });
      }
      continue;
    }

    for (const rawLic of comp.licenses) {
      // Check for dual/composite expressions
      if (rawLic.includes(' OR ')) {
        // e.g. "MIT OR AGPL-3.0-only" - consumer can elect MIT
        const branches = rawLic.split(' OR ').map((b) => normalizeLicenseName(b.replace(/[()]/g, '')));
        const allDisallowed = branches.every((b) => disallowedSet.has(b));
        if (allDisallowed) {
          results.push({
            component: comp,
            disallowedLicense: rawLic,
            isViolation: true,
            message: `Component "${comp.name}@${comp.version}" offers only disallowed licenses in expression "${rawLic}".`,
          });
        }
        continue;
      }

      if (rawLic.includes(' AND ')) {
        // e.g. "MIT AND GPL-3.0-only" - both obligations attach
        const branches = rawLic.split(' AND ').map((b) => normalizeLicenseName(b.replace(/[()]/g, '')));
        const foundDisallowed = branches.find((b) => disallowedSet.has(b));
        if (foundDisallowed) {
          results.push({
            component: comp,
            disallowedLicense: foundDisallowed,
            isViolation: true,
            message: `Component "${comp.name}@${comp.version}" requires disallowed license "${foundDisallowed}" in composite expression "${rawLic}".`,
          });
        }
        continue;
      }

      const normalized = normalizeLicenseName(rawLic);

      if (disallowedSet.has(normalized)) {
        results.push({
          component: comp,
          disallowedLicense: rawLic,
          isViolation: true,
          message: `Component "${comp.name}@${comp.version}" declares disallowed copyleft/restrictive license "${rawLic}".`,
        });
        break;
      }

      if (allowedSet && !allowedSet.has(normalized)) {
        results.push({
          component: comp,
          disallowedLicense: rawLic,
          isViolation: true,
          message: `Component "${comp.name}@${comp.version}" license "${rawLic}" is not in the approved whitelist.`,
        });
        break;
      }
    }
  }

  return results;
}
