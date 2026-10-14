import pc from 'picocolors';

export interface DiffFormatOptions {
  showLineNumbers?: boolean;
}

/**
 * Colors standard unified diff text for rich terminal display.
 */
export function formatTerminalDiff(diffText: string, options: DiffFormatOptions = {}): string {
  const lines = diffText.split(/\r?\n/);
  const formatted: string[] = [];

  let oldLine = 0;
  let newLine = 0;

  for (const line of lines) {
    if (line.startsWith('--- ')) {
      formatted.push(pc.red(pc.bold(line)));
    } else if (line.startsWith('+++ ')) {
      formatted.push(pc.green(pc.bold(line)));
    } else if (line.startsWith('@@')) {
      formatted.push(pc.cyan(pc.bold(line)));
      // Parse chunk header e.g. @@ -10,5 +10,6 @@
      const match = line.match(/@@ -(\d+)(?:,\d+)? \+(\d+)(?:,\d+)? @@/);
      if (match && match[1] && match[2]) {
        oldLine = parseInt(match[1], 10);
        newLine = parseInt(match[2], 10);
      }
    } else if (line.startsWith('+')) {
      const lineNum = options.showLineNumbers ? pc.dim(`${String(newLine++).padStart(4)} │ `) : '';
      formatted.push(`${lineNum}${pc.green(line)}`);
    } else if (line.startsWith('-')) {
      const lineNum = options.showLineNumbers ? pc.dim(`${String(oldLine++).padStart(4)} │ `) : '';
      formatted.push(`${lineNum}${pc.red(line)}`);
    } else {
      const lineNum = options.showLineNumbers
        ? pc.dim(`${String(newLine++).padStart(4)} │ `)
        : '';
      oldLine++;
      formatted.push(`${lineNum}${pc.gray(line)}`);
    }
  }

  return formatted.join('\n');
}

/**
 * Simple line-based unified diff generator for remediation patches.
 */
export function createUnifiedDiff(
  filePath: string,
  original: string,
  updated: string,
): string {
  const origLines = original.split(/\r?\n/);
  const updatedLines = updated.split(/\r?\n/);

  const diffLines: string[] = [
    `--- a/${filePath}`,
    `+++ b/${filePath}`,
    `@@ -1,${origLines.length} +1,${updatedLines.length} @@`,
  ];

  const maxLen = Math.max(origLines.length, updatedLines.length);
  for (let i = 0; i < maxLen; i++) {
    const orig = origLines[i];
    const up = updatedLines[i];

    if (orig === undefined && up !== undefined) {
      diffLines.push(`+${up}`);
    } else if (orig !== undefined && up === undefined) {
      diffLines.push(`-${orig}`);
    } else if (orig !== up) {
      diffLines.push(`-${orig}`);
      diffLines.push(`+${up}`);
    } else {
      diffLines.push(` ${orig}`);
    }
  }

  return diffLines.join('\n');
}
