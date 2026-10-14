import React, { useState, useRef, useEffect } from 'react';
import {
  Terminal,
  Search,
  Pause,
  Play,
  Copy,
  Check,
  Trash2,
  ArrowDownCircle,
  Filter,
} from 'lucide-react';
import { StreamLogEntry, LogLevel } from '../../hooks/useRunEventStream.js';
import { useAppStore } from '../../store/useAppStore.js';

interface StreamingTerminalProps {
  logs: StreamLogEntry[];
  isPaused: boolean;
  onTogglePause: () => void;
  onClear: () => void;
  selectedEngineFilter?: string | null;
  className?: string;
}

export const StreamingTerminal: React.FC<StreamingTerminalProps> = ({
  logs,
  isPaused,
  onTogglePause,
  onClear,
  selectedEngineFilter,
  className = '',
}) => {
  const { showToast } = useAppStore();
  const [search, setSearch] = useState('');
  const [levelFilter, setLevelFilter] = useState<'ALL' | LogLevel>('ALL');
  const [autoScroll, setAutoScroll] = useState(true);
  const [copied, setCopied] = useState(false);
  const terminalEndRef = useRef<HTMLDivElement>(null);
  const containerRef = useRef<HTMLDivElement>(null);

  // Auto-scroll logic
  useEffect(() => {
    if (autoScroll && terminalEndRef.current && !isPaused) {
      terminalEndRef.current.scrollIntoView({ behavior: 'smooth' });
    }
  }, [logs, autoScroll, isPaused]);

  // Handle user scroll up: pause auto-scroll if scrolled away from bottom
  const handleScroll = () => {
    if (!containerRef.current) return;
    const { scrollTop, scrollHeight, clientHeight } = containerRef.current;
    const isAtBottom = scrollHeight - scrollTop - clientHeight < 40;
    if (isAtBottom !== autoScroll) {
      setAutoScroll(isAtBottom);
    }
  };

  const filteredLogs = logs.filter((entry) => {
    // Engine filter
    if (selectedEngineFilter && entry.engineId !== selectedEngineFilter) {
      return false;
    }
    // Level filter
    if (levelFilter !== 'ALL' && entry.level !== levelFilter) {
      return false;
    }
    // Search query
    if (search.trim()) {
      const q = search.toLowerCase();
      const matchMsg = entry.message.toLowerCase().includes(q);
      const matchEngine = entry.engineId?.toLowerCase().includes(q);
      if (!matchMsg && !matchEngine) return false;
    }
    return true;
  });

  const handleCopyLogs = () => {
    const text = filteredLogs
      .map((l) => `[${l.timestamp}] [${l.level}]${l.engineId ? ` [${l.engineId}]` : ''} ${l.message}`)
      .join('\n');

    navigator.clipboard.writeText(text);
    setCopied(true);
    showToast(`Copied ${filteredLogs.length} log lines to clipboard`, 'info');
    setTimeout(() => setCopied(false), 2000);
  };

  const getLevelBadge = (level: LogLevel) => {
    switch (level) {
      case 'ERROR':
        return (
          <span className="px-1.5 py-0.2 rounded font-mono text-[9px] font-bold bg-rose-950/60 text-rose-400 border border-rose-800/60 shrink-0">
            ERR
          </span>
        );
      case 'WARN':
        return (
          <span className="px-1.5 py-0.2 rounded font-mono text-[9px] font-bold bg-amber-950/60 text-amber-400 border border-amber-800/60 shrink-0">
            WARN
          </span>
        );
      case 'PAYLOAD':
        return (
          <span className="px-1.5 py-0.2 rounded font-mono text-[9px] font-bold bg-purple-950/60 text-purple-300 border border-purple-800/60 shrink-0">
            PAYLOAD
          </span>
        );
      default:
        return (
          <span className="px-1.5 py-0.2 rounded font-mono text-[9px] font-bold bg-blue-950/60 text-blue-400 border border-blue-800/60 shrink-0">
            INFO
          </span>
        );
    }
  };

  return (
    <div
      className={`flex flex-col rounded-2xl border border-border/80 bg-black/90 shadow-xl overflow-hidden font-mono text-xs ${className}`}
    >
      {/* Terminal Top Control Bar */}
      <div className="p-3 bg-accent/30 border-b border-border/60 flex flex-wrap items-center justify-between gap-2.5">
        <div className="flex items-center space-x-2">
          <Terminal className="w-4 h-4 text-emerald-400" />
          <span className="font-semibold text-foreground text-xs font-sans flex items-center gap-1.5">
            <span>Streaming Terminal Console</span>
            {isPaused && (
              <span className="text-[10px] uppercase font-mono px-2 py-0.5 rounded bg-amber-950/60 text-amber-400 border border-amber-800/60 animate-pulse">
                Paused
              </span>
            )}
          </span>
          <span className="text-[10px] text-muted-foreground font-mono hidden sm:inline">
            ({filteredLogs.length} lines)
          </span>
        </div>

        {/* Filter & Action Controls */}
        <div className="flex flex-wrap items-center gap-2">
          {/* Search Input */}
          <div className="relative w-36 sm:w-44">
            <Search className="w-3.5 h-3.5 text-muted-foreground absolute left-2.5 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              placeholder="Filter logs..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="w-full pl-7 pr-2 py-1 rounded-md bg-accent/80 border border-border text-[11px] text-foreground focus:outline-none focus:ring-1 focus:ring-primary placeholder:text-muted-foreground/60"
            />
          </div>

          {/* Level Filter Dropdown */}
          <div className="flex items-center space-x-1">
            <Filter className="w-3 h-3 text-muted-foreground" />
            <select
              value={levelFilter}
              onChange={(e) => setLevelFilter(e.target.value as any)}
              className="px-2 py-1 rounded-md bg-accent/80 border border-border text-[11px] text-foreground cursor-pointer focus:outline-none"
            >
              <option value="ALL">All Levels</option>
              <option value="INFO">INFO Only</option>
              <option value="WARN">WARN Only</option>
              <option value="ERROR">ERROR Only</option>
              <option value="PAYLOAD">PAYLOAD Only</option>
            </select>
          </div>

          {/* Auto-Scroll Toggle */}
          <button
            type="button"
            onClick={() => setAutoScroll(!autoScroll)}
            title={autoScroll ? 'Auto-scroll is ON' : 'Auto-scroll is OFF'}
            className={`p-1.5 rounded-md text-xs transition-colors flex items-center gap-1 ${
              autoScroll
                ? 'bg-emerald-950/40 text-emerald-400 border border-emerald-800/50'
                : 'text-muted-foreground hover:bg-accent'
            }`}
          >
            <ArrowDownCircle className="w-3.5 h-3.5" />
            <span className="text-[10px] hidden md:inline">{autoScroll ? 'Scroll: ON' : 'Scroll: OFF'}</span>
          </button>

          {/* Pause / Resume */}
          <button
            type="button"
            onClick={onTogglePause}
            title={isPaused ? 'Resume Streaming' : 'Pause Streaming'}
            className={`p-1.5 rounded-md text-xs transition-colors ${
              isPaused
                ? 'bg-amber-950/50 text-amber-400 border border-amber-800/50'
                : 'text-muted-foreground hover:bg-accent'
            }`}
          >
            {isPaused ? <Play className="w-3.5 h-3.5" /> : <Pause className="w-3.5 h-3.5" />}
          </button>

          {/* Copy Logs */}
          <button
            type="button"
            onClick={handleCopyLogs}
            title="Copy Filtered Logs"
            className="p-1.5 rounded-md text-muted-foreground hover:text-foreground hover:bg-accent transition-colors"
          >
            {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
          </button>

          {/* Clear Buffer */}
          <button
            type="button"
            onClick={onClear}
            title="Clear Log Buffer"
            className="p-1.5 rounded-md text-rose-400 hover:text-rose-300 hover:bg-rose-950/40 transition-colors"
          >
            <Trash2 className="w-3.5 h-3.5" />
          </button>
        </div>
      </div>

      {/* Terminal Viewport */}
      <div
        ref={containerRef}
        onScroll={handleScroll}
        className="flex-1 overflow-y-auto p-4 space-y-1.5 min-h-[350px] max-h-[480px] bg-black/95 text-[11px] leading-relaxed select-text"
      >
        {filteredLogs.length === 0 ? (
          <div className="py-16 text-center text-muted-foreground/60 space-y-1">
            <p>No log records matching filter.</p>
            <p className="text-[10px]">Awaiting engine events from telemetry pipeline...</p>
          </div>
        ) : (
          filteredLogs.map((log) => (
            <div
              key={log.id}
              className={`flex items-start gap-2 py-0.5 px-1.5 rounded hover:bg-white/5 transition-colors ${
                log.level === 'ERROR'
                  ? 'text-rose-300 bg-rose-950/10'
                  : log.level === 'WARN'
                  ? 'text-amber-300 bg-amber-950/10'
                  : log.level === 'PAYLOAD'
                  ? 'text-cyan-300 bg-cyan-950/10'
                  : 'text-zinc-300'
              }`}
            >
              <span className="text-zinc-600 select-none shrink-0 font-mono text-[10px]">
                {log.timestamp}
              </span>

              {getLevelBadge(log.level)}

              {log.engineId && (
                <span className="text-primary font-semibold shrink-0 text-[10px]">
                  [{log.engineId}]
                </span>
              )}

              <span className="break-all flex-1 font-mono">{log.message}</span>
            </div>
          ))
        )}
        <div ref={terminalEndRef} />
      </div>

      {/* Terminal Scanline Footer Strip */}
      <div className="px-3 py-1 bg-accent/20 border-t border-border/40 flex items-center justify-between text-[10px] text-muted-foreground">
        <span className="flex items-center gap-1.5">
          <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" />
          <span>Stream Connection: Active</span>
        </span>
        <span className="font-mono">Obsidian Telemetry Engine V2</span>
      </div>
    </div>
  );
};
