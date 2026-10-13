import {
  AuthzMatrixReport,
  AuthzMatrixReportCell,
  AuthzMatrixTestCase,
  PersonaConfig,
} from '@security-lab/contracts';
import { ComparisonResult } from './types.js';

export function buildMatrixReport(
  title: string,
  testCases: AuthzMatrixTestCase[],
  results: Map<string, { status: number; comp: ComparisonResult }>,
  personas: PersonaConfig[],
): AuthzMatrixReport {
  const cells: AuthzMatrixReportCell[] = [];
  const endpointsSet = new Set<string>();

  let passedCount = 0;
  let violationCount = 0;

  for (const tc of testCases) {
    endpointsSet.add(`${tc.method} ${tc.endpointPath}`);
    const res = results.get(tc.id);
    const httpStatus = res?.status ?? 0;
    const isViol = res?.comp.isViolation ?? false;

    let cellStatus: AuthzMatrixReportCell['status'] = 'DENIED';
    if (isViol) {
      violationCount++;
      if (res?.comp.violationType === 'BOLA_HORIZONTAL_IDOR') {
        cellStatus = 'VIOLATION_BOLA';
      } else if (res?.comp.violationType === 'BFLA_VERTICAL_ESCALATION') {
        cellStatus = 'VIOLATION_BFLA';
      } else {
        cellStatus = 'VIOLATION_MISSING_AUTH';
      }
    } else {
      passedCount++;
      cellStatus = httpStatus >= 200 && httpStatus < 300 ? 'ALLOWED' : 'DENIED';
    }

    cells.push({
      endpoint: tc.endpointPath,
      method: tc.method,
      personaId: tc.actorPersona.id,
      status: cellStatus,
      httpStatus,
    });
  }

  // Construct Markdown grid
  const personaIds = Array.from(new Set(personas.map((p) => p.id)));
  const distinctEndpoints = Array.from(endpointsSet).sort();

  let md = `### Authorization Permission Matrix: ${title}\n\n`;
  md += `| Route | ${personaIds.join(' | ')} |\n`;
  md += `|:---|${personaIds.map(() => ':---:').join('|')}|\n`;

  for (const epStr of distinctEndpoints) {
    const [method, path] = epStr.split(' ');
    let row = `| \`${method} ${path}\` |`;
    for (const pId of personaIds) {
      const cell = cells.find(
        (c) => c.endpoint === path && c.method === method && c.personaId === pId,
      );
      if (!cell) {
        row += ' - |';
      } else if (cell.status === 'VIOLATION_BOLA') {
        row += ` 🚨 **BOLA** (${cell.httpStatus}) |`;
      } else if (cell.status === 'VIOLATION_BFLA') {
        row += ` 🚨 **BFLA** (${cell.httpStatus}) |`;
      } else if (cell.status === 'VIOLATION_MISSING_AUTH') {
        row += ` ⚠️ **NO_AUTH** (${cell.httpStatus}) |`;
      } else if (cell.status === 'DENIED') {
        row += ` 🛡️ Denied (${cell.httpStatus}) |`;
      } else {
        row += ` ✅ Allowed (${cell.httpStatus}) |`;
      }
    }
    md += `${row}\n`;
  }

  return {
    title,
    endpointsCount: distinctEndpoints.length,
    personasCount: personaIds.length,
    totalTests: testCases.length,
    passedCount,
    violationCount,
    cells,
    markdownTable: md,
  };
}
