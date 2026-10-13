import { DockerfileInstruction, ParsedDockerfile } from './types.js';

/**
 * Parses raw Dockerfile content into structured instructions with line numbers.
 */
export function parseDockerfile(rawContent: string, filePath?: string): ParsedDockerfile {
  const instructions: DockerfileInstruction[] = [];
  const lines = rawContent.split(/\r?\n/);

  let currentInstruction = '';
  let currentArgs = '';
  let currentRaw = '';
  let instructionStartLine = 1;
  let inContinuation = false;

  for (let i = 0; i < lines.length; i++) {
    const rawLine = lines[i] ?? '';
    const trimmed = rawLine.trim();
    const lineNum = i + 1;

    // Ignore comment lines unless continuing
    if (!inContinuation && (trimmed.startsWith('#') || trimmed.length === 0)) {
      continue;
    }

    if (!inContinuation) {
      // Find instruction keyword (e.g. FROM, RUN, USER, ENV, ARG, EXPOSE)
      const match = trimmed.match(/^([A-Za-z]+)(?:\s+(.*))?$/s);
      if (!match || !match[1]) continue;

      currentInstruction = match[1].toUpperCase();
      currentArgs = match[2] ?? '';
      currentRaw = rawLine;
      instructionStartLine = lineNum;

      if (currentArgs.endsWith('\\')) {
        inContinuation = true;
        currentArgs = currentArgs.slice(0, -1).trim();
      } else {
        instructions.push({
          instruction: currentInstruction,
          args: currentArgs.trim(),
          raw: currentRaw,
          lineNumber: instructionStartLine,
        });
      }
    } else {
      // Continuing previous instruction
      currentRaw += '\n' + rawLine;
      let lineContent = trimmed;
      if (lineContent.endsWith('\\')) {
        lineContent = lineContent.slice(0, -1).trim();
        currentArgs += ' ' + lineContent;
      } else {
        currentArgs += ' ' + lineContent;
        inContinuation = false;
        instructions.push({
          instruction: currentInstruction,
          args: currentArgs.trim(),
          raw: currentRaw,
          lineNumber: instructionStartLine,
        });
      }
    }
  }

  // Handle unclosed continuation at EOF
  if (inContinuation && currentInstruction) {
    instructions.push({
      instruction: currentInstruction,
      args: currentArgs.trim(),
      raw: currentRaw,
      lineNumber: instructionStartLine,
    });
  }

  return {
    filePath,
    rawContent,
    instructions,
  };
}
