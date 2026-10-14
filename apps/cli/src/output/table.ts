import pc from 'picocolors';
import { Finding } from '@security-lab/domain';

// Regex to strip ANSI escape codes for accurate string length computation
// eslint-disable-next-line no-control-regex
const ANSI_REGEX = /[\u001b\u009b][[()#;?]*(?:[0-9]{1,4}(?:;[0-9]{0,4})*)?[0-9A-ORZcf-nqry=><]/g;

export function stripAnsi(text: string): string {
  return text.replace(ANSI_REGEX, '');
}

export function visibleLength(text: string): number {
  return stripAnsi(text).length;
}

export interface TableOptions {
  borderStyle?: 'unicode' | 'ascii' | 'compact';
  align?: ('left' | 'right' | 'center')[];
  maxColWidth?: number;
}

export function renderTable(
  headers: string[],
  rows: (string | number)[][],
  options: TableOptions = {},
): string {
  const borderStyle = options.borderStyle ?? 'unicode';
  const maxColWidth = options.maxColWidth ?? 60;

  // Format cell contents to string and clamp/truncate if necessary
  const formattedRows: string[][] = rows.map((row) =>
    row.map((cell) => {
      const cellStr = cell !== null && cell !== undefined ? String(cell) : '';
      return cellStr;
    }),
  );

  // Compute column widths based on visible length
  const colCount = Math.max(headers.length, ...formattedRows.map((r) => r.length));
  const colWidths: number[] = [];

  for (let c = 0; c < colCount; c++) {
    const headerCell = headers[c];
    let max = headerCell ? visibleLength(headerCell) : 0;
    for (const row of formattedRows) {
      const cell = row[c];
      if (cell) {
        const len = visibleLength(cell);
        if (len > max) {
          max = len;
        }
      }
    }
    colWidths[c] = Math.min(Math.max(max, 3), maxColWidth);
  }

  // Borders definition
  const borders =
    borderStyle === 'unicode'
      ? {
          topLeft: '┌',
          topMid: '┬',
          topRight: '┐',
          midLeft: '├',
          midMid: '┼',
          midRight: '┤',
          botLeft: '└',
          botMid: '┴',
          botRight: '┘',
          horiz: '─',
          vert: '│',
        }
      : borderStyle === 'ascii'
        ? {
            topLeft: '+',
            topMid: '+',
            topRight: '+',
            midLeft: '+',
            midMid: '+',
            midRight: '+',
            botLeft: '+',
            botMid: '+',
            botRight: '+',
            horiz: '-',
            vert: '|',
          }
        : {
            topLeft: '',
            topMid: '',
            topRight: '',
            midLeft: '',
            midMid: '',
            midRight: '',
            botLeft: '',
            botMid: '',
            botRight: '',
            horiz: '-',
            vert: ' ',
          };

  const padCell = (content: string, width: number, align: 'left' | 'right' | 'center' = 'left'): string => {
    const rawLen = visibleLength(content);
    if (rawLen > width) {
      // Truncate cleanly preserving ANSI if possible or simple slice
      const stripped = stripAnsi(content);
      return stripped.slice(0, width - 1) + '…';
    }
    const padTotal = width - rawLen;
    if (align === 'right') {
      return ' '.repeat(padTotal) + content;
    }
    if (align === 'center') {
      const padLeft = Math.floor(padTotal / 2);
      const padRight = padTotal - padLeft;
      return ' '.repeat(padLeft) + content + ' '.repeat(padRight);
    }
    return content + ' '.repeat(padTotal);
  };

  const lines: string[] = [];

  // Top border
  if (borders.topLeft) {
    const topSegments = colWidths.map((w) => borders.horiz.repeat(w + 2));
    lines.push(borders.topLeft + topSegments.join(borders.topMid) + borders.topRight);
  }

  // Header row
  if (headers.length > 0) {
    const headerCells = headers.map((h, i) => {
      const padded = padCell(pc.bold(pc.cyan(h)), colWidths[i] || 0, options.align?.[i] || 'left');
      return ` ${padded} `;
    });
    lines.push(borders.vert + headerCells.join(borders.vert) + borders.vert);

    // Separator below header
    const sepSegments = colWidths.map((w) => borders.horiz.repeat(w + 2));
    lines.push(borders.midLeft + sepSegments.join(borders.midMid) + borders.midRight);
  }

  // Data rows
  for (const row of formattedRows) {
    const cells = colWidths.map((w, i) => {
      const cellContent = row[i] || '';
      const padded = padCell(cellContent, w, options.align?.[i] || 'left');
      return ` ${padded} `;
    });
    lines.push(borders.vert + cells.join(borders.vert) + borders.vert);
  }

  // Bottom border
  if (borders.botLeft) {
    const botSegments = colWidths.map((w) => borders.horiz.repeat(w + 2));
    lines.push(borders.botLeft + botSegments.join(borders.botMid) + borders.botRight);
  }

  return lines.join('\n');
}

export function formatSeverityBadge(severity: string): string {
  const norm = severity.toLowerCase();
  switch (norm) {
    case 'critical':
      return pc.bgRed(pc.bold(pc.white(' CRITICAL ')));
    case 'high':
      return pc.red(pc.bold('HIGH'));
    case 'medium':
      return pc.yellow(pc.bold('MEDIUM'));
    case 'low':
      return pc.blue(pc.bold('LOW'));
    default:
      return pc.gray(severity.toUpperCase());
  }
}

export function renderFindingsTable(findings: Finding[]): string {
  if (findings.length === 0) {
    return pc.green('✔ Zero security vulnerabilities detected.');
  }

  const headers = ['SEVERITY', 'TITLE', 'CATEGORY', 'RECOMMENDATION / REMEDIATION'];
  const rows = findings.map((f) => [
    formatSeverityBadge(f.severity),
    pc.bold(f.title),
    f.category,
    f.recommendation || f.description || 'Review endpoint defensive configurations',
  ]);

  return renderTable(headers, rows, {
    borderStyle: 'unicode',
    align: ['center', 'left', 'left', 'left'],
    maxColWidth: 50,
  });
}

export function renderSummaryBox(
  title: string,
  entries: Array<{ label: string; value: string | number; color?: (v: string) => string }>,
): string {
  const maxLabelLen = Math.max(...entries.map((e) => visibleLength(e.label)), 10);
  const maxValLen = Math.max(...entries.map((e) => visibleLength(String(e.value))), 10);
  const contentWidth = Math.max(maxLabelLen + maxValLen + 5, visibleLength(title) + 4, 45);

  const topBorder = `┌─ ${pc.bold(pc.cyan(title))} ${'─'.repeat(Math.max(0, contentWidth - visibleLength(title) - 4))}┐`;
  const botBorder = `└${'─'.repeat(contentWidth)}┘`;

  const lines = [topBorder];
  for (const entry of entries) {
    const valStr = String(entry.value);
    const coloredVal = entry.color ? entry.color(valStr) : pc.bold(valStr);
    const spaces = ' '.repeat(Math.max(1, contentWidth - visibleLength(entry.label) - visibleLength(valStr) - 4));
    lines.push(`│  ${pc.dim(entry.label)}:${spaces}${coloredVal}  │`);
  }
  lines.push(botBorder);

  return lines.join('\n');
}
