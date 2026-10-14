import React, { useState, useMemo } from 'react';
import {
  Copy,
  Check,
  Download,
  Code2,
  Columns,
  ListFilter,
  FileCode,
  FileCheck,
} from 'lucide-react';
import { useAppStore } from '../../store/useAppStore.js';
import { parseGitDiffString, ParsedDiff } from '../../api/remediation.js';

interface CodeDiffViewerProps {
  gitDiff: string;
  filePath?: string;
  modelAttribution?: string;
}

export const CodeDiffViewer: React.FC<CodeDiffViewerProps> = ({
  gitDiff,
  filePath: propFilePath,
  modelAttribution,
}) => {
  const { showToast } = useAppStore();
  const [viewMode, setViewMode] = useState<'unified' | 'split'>('unified');
  const [copied, setCopied] = useState(false);

  const parsedDiff: ParsedDiff = useMemo(() => {
    return parseGitDiffString(gitDiff);
  }, [gitDiff]);

  const effectivePath = propFilePath || parsedDiff.filePath;

  const handleCopy = () => {
    navigator.clipboard.writeText(gitDiff);
    setCopied(true);
    showToast('Copied raw git patch diff to clipboard', 'info');
    setTimeout(() => setCopied(false), 2000);
  };

  const handleDownload = () => {
    const blob = new Blob([gitDiff], { type: 'text/plain;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `${effectivePath.replace(/[/\\?%*:|"<>]/g, '_')}.patch`;
    a.click();
    URL.revokeObjectURL(url);
    showToast(`Downloaded ${a.download}`, 'info');
  };

  return (
    <div className="rounded-xl border border-purple-500/50 bg-slate-950/90 shadow-xl shadow-purple-950/20 overflow-hidden font-mono text-xs">
      {/* Diff Toolbar Header */}
      <div className="px-4 py-3 bg-purple-950/30 border-b border-purple-500/30 flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-center gap-2.5 min-w-0">
          <div className="p-1.5 rounded-lg bg-purple-500/20 border border-purple-500/40 text-purple-300">
            <FileCode className="w-4 h-4" />
          </div>
          <div className="truncate">
            <div className="text-white font-semibold text-xs truncate flex items-center gap-2">
              <span>{effectivePath}</span>
              {modelAttribution && (
                <span className="text-[10px] px-2 py-0.5 rounded-full bg-purple-500/20 text-purple-300 border border-purple-500/30 font-sans">
                  Suggested by {modelAttribution}
                </span>
              )}
            </div>
            <div className="flex items-center gap-2 text-[11px] text-slate-400 font-sans mt-0.5">
              <span className="text-emerald-400 font-semibold font-mono">
                +{parsedDiff.additions} lines
              </span>
              <span className="text-slate-600">•</span>
              <span className="text-rose-400 font-semibold font-mono">
                -{parsedDiff.deletions} lines
              </span>
            </div>
          </div>
        </div>

        {/* View Mode Controls & Actions */}
        <div className="flex items-center gap-2 shrink-0 font-sans">
          {/* Mode Switcher */}
          <div className="flex items-center bg-slate-900 border border-slate-800 rounded-lg p-0.5 text-xs">
            <button
              type="button"
              onClick={() => setViewMode('unified')}
              className={`flex items-center gap-1.5 px-2.5 py-1 rounded-md text-xs font-medium transition-all ${
                viewMode === 'unified'
                  ? 'bg-purple-600 text-white shadow-sm'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              <ListFilter className="w-3.5 h-3.5" />
              <span>Unified</span>
            </button>
            <button
              type="button"
              onClick={() => setViewMode('split')}
              className={`flex items-center gap-1.5 px-2.5 py-1 rounded-md text-xs font-medium transition-all ${
                viewMode === 'split'
                  ? 'bg-purple-600 text-white shadow-sm'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              <Columns className="w-3.5 h-3.5" />
              <span>Split Diff</span>
            </button>
          </div>

          {/* Copy Patch */}
          <button
            type="button"
            onClick={handleCopy}
            className="flex items-center gap-1.5 px-2.5 py-1 rounded-lg bg-slate-900 hover:bg-slate-850 text-slate-300 border border-slate-800 text-xs font-medium transition-colors"
            title="Copy raw patch diff"
          >
            {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
            <span>{copied ? 'Copied' : 'Copy Patch'}</span>
          </button>

          {/* Download Patch */}
          <button
            type="button"
            onClick={handleDownload}
            className="flex items-center gap-1.5 px-2.5 py-1 rounded-lg bg-slate-900 hover:bg-slate-850 text-slate-300 border border-slate-800 text-xs font-medium transition-colors"
            title="Download .patch file"
          >
            <Download className="w-3.5 h-3.5" />
            <span>.patch</span>
          </button>
        </div>
      </div>

      {/* Diff Body */}
      <div className="overflow-x-auto max-h-[520px] divide-y divide-slate-800/80 bg-slate-950/70 select-text">
        {parsedDiff.hunks.length === 0 ? (
          <div className="p-8 text-center text-slate-500 font-sans">
            <Code2 className="w-8 h-8 text-slate-600 mx-auto mb-2" />
            <p className="text-sm text-slate-400">Empty or unparseable patch diff</p>
            <pre className="mt-2 text-xs text-slate-600 font-mono text-left max-w-md mx-auto overflow-x-auto">
              {gitDiff || '(No diff content)'}
            </pre>
          </div>
        ) : viewMode === 'unified' ? (
          /* UNIFIED DIFF VIEW */
          parsedDiff.hunks.map((hunk, hIdx) => (
            <div key={`hunk-${hIdx}`} className="divide-y divide-slate-900/60">
              {/* Hunk Header */}
              <div className="px-4 py-1.5 bg-blue-950/30 text-blue-400 text-[11px] font-mono border-y border-blue-900/40 select-none flex items-center justify-between">
                <span>{hunk.header}</span>
                <span className="text-[10px] text-blue-500/70 uppercase font-sans">Hunk #{hIdx + 1}</span>
              </div>

              {/* Lines */}
              {hunk.lines.map((line, lIdx) => (
                <div
                  key={`line-${lIdx}`}
                  className={`flex items-start text-xs font-mono leading-relaxed transition-colors ${
                    line.type === 'add'
                      ? 'bg-emerald-950/30 text-emerald-300 hover:bg-emerald-950/40'
                      : line.type === 'delete'
                      ? 'bg-rose-950/30 text-rose-300 hover:bg-rose-950/40'
                      : 'text-slate-300 hover:bg-slate-900/40'
                  }`}
                >
                  {/* Old line number */}
                  <span className="w-12 px-2 py-0.5 text-right text-[11px] text-slate-600 select-none border-r border-slate-900 shrink-0">
                    {line.oldLineNumber || ''}
                  </span>
                  {/* New line number */}
                  <span className="w-12 px-2 py-0.5 text-right text-[11px] text-slate-600 select-none border-r border-slate-900 shrink-0">
                    {line.newLineNumber || ''}
                  </span>
                  {/* Operator indicator */}
                  <span
                    className={`w-6 py-0.5 text-center font-bold select-none shrink-0 ${
                      line.type === 'add'
                        ? 'text-emerald-400'
                        : line.type === 'delete'
                        ? 'text-rose-400'
                        : 'text-slate-600'
                    }`}
                  >
                    {line.type === 'add' ? '+' : line.type === 'delete' ? '-' : ' '}
                  </span>
                  {/* Line text */}
                  <pre className="flex-1 py-0.5 px-2 overflow-x-auto whitespace-pre font-mono">
                    {line.content}
                  </pre>
                </div>
              ))}
            </div>
          ))
        ) : (
          /* SPLIT (SIDE-BY-SIDE) DIFF VIEW */
          parsedDiff.hunks.map((hunk, hIdx) => {
            // Partition into original (old) vs modified (new) parallel lines
            const deletions = hunk.lines.filter((l) => l.type === 'delete' || l.type === 'context');
            const additions = hunk.lines.filter((l) => l.type === 'add' || l.type === 'context');
            const maxRows = Math.max(deletions.length, additions.length);

            return (
              <div key={`split-hunk-${hIdx}`} className="divide-y divide-slate-900/60">
                {/* Hunk Header */}
                <div className="px-4 py-1.5 bg-blue-950/30 text-blue-400 text-[11px] font-mono border-y border-blue-900/40 select-none">
                  {hunk.header}
                </div>

                <div className="grid grid-cols-2 divide-x divide-slate-800">
                  {/* Column 1: Original Code */}
                  <div className="divide-y divide-slate-900/40">
                    <div className="px-3 py-1 bg-slate-900 text-[10px] uppercase tracking-wider text-slate-500 font-sans font-semibold">
                      Original Source
                    </div>
                    {Array.from({ length: maxRows }).map((_, idx) => {
                      const line = deletions[idx];
                      if (!line) {
                        return (
                          <div key={`empty-left-${idx}`} className="h-6 bg-slate-950/40"></div>
                        );
                      }
                      return (
                        <div
                          key={`split-left-${idx}`}
                          className={`flex items-start text-xs font-mono leading-relaxed ${
                            line.type === 'delete'
                              ? 'bg-rose-950/30 text-rose-300'
                              : 'text-slate-400'
                          }`}
                        >
                          <span className="w-10 px-2 py-0.5 text-right text-[11px] text-slate-600 select-none border-r border-slate-900 shrink-0">
                            {line.oldLineNumber || ''}
                          </span>
                          <span className="w-5 py-0.5 text-center text-rose-400 select-none shrink-0">
                            {line.type === 'delete' ? '-' : ' '}
                          </span>
                          <pre className="flex-1 py-0.5 px-2 overflow-x-auto whitespace-pre font-mono">
                            {line.content}
                          </pre>
                        </div>
                      );
                    })}
                  </div>

                  {/* Column 2: Proposed AI Remediation */}
                  <div className="divide-y divide-slate-900/40">
                    <div className="px-3 py-1 bg-purple-950/30 text-[10px] uppercase tracking-wider text-purple-400 font-sans font-semibold flex items-center justify-between">
                      <span>Proposed AI Patch</span>
                      <span className="text-[9px] text-purple-400 font-mono">AI Suggestion</span>
                    </div>
                    {Array.from({ length: maxRows }).map((_, idx) => {
                      const line = additions[idx];
                      if (!line) {
                        return (
                          <div key={`empty-right-${idx}`} className="h-6 bg-slate-950/40"></div>
                        );
                      }
                      return (
                        <div
                          key={`split-right-${idx}`}
                          className={`flex items-start text-xs font-mono leading-relaxed ${
                            line.type === 'add'
                              ? 'bg-emerald-950/30 text-emerald-300'
                              : 'text-slate-400'
                          }`}
                        >
                          <span className="w-10 px-2 py-0.5 text-right text-[11px] text-slate-600 select-none border-r border-slate-900 shrink-0">
                            {line.newLineNumber || ''}
                          </span>
                          <span className="w-5 py-0.5 text-center text-emerald-400 select-none shrink-0">
                            {line.type === 'add' ? '+' : ' '}
                          </span>
                          <pre className="flex-1 py-0.5 px-2 overflow-x-auto whitespace-pre font-mono">
                            {line.content}
                          </pre>
                        </div>
                      );
                    })}
                  </div>
                </div>
              </div>
            );
          })
        )}
      </div>

      {/* Invariant Footer Badge */}
      <div className="px-4 py-2 bg-purple-950/40 border-t border-purple-500/30 flex items-center justify-between text-[11px] text-purple-300 font-sans">
        <div className="flex items-center gap-1.5">
          <FileCheck className="w-3.5 h-3.5 text-purple-400" />
          <span>
            <strong>Quantum Purple Invariant:</strong> AI-generated code proposals require human verification before production merge.
          </span>
        </div>
        <span className="text-slate-500 font-mono">Git Unified RFC 3986</span>
      </div>
    </div>
  );
};
