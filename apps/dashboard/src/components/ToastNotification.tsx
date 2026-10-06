import React from 'react';
import { useAppStore } from '../store/useAppStore.js';
import { CheckCircle2, AlertCircle, Info, X } from 'lucide-react';

export const ToastNotification: React.FC = () => {
  const { toast, hideToast } = useAppStore();

  if (!toast) return null;

  const isSuccess = toast.type === 'success';
  const isError = toast.type === 'error';

  return (
    <div className="fixed bottom-6 right-6 z-50 animate-fade-in select-none max-w-md">
      <div
        className={`flex items-center gap-3 px-4 py-3 rounded-xl border shadow-2xl backdrop-blur-xl ${
          isSuccess
            ? 'bg-emerald-950/80 border-emerald-500/40 text-emerald-200 glow-emerald'
            : isError
              ? 'bg-rose-950/80 border-rose-500/40 text-rose-200 glow-rose'
              : 'bg-blue-950/80 border-blue-500/40 text-blue-200 glow-blue'
        }`}
      >
        {isSuccess ? (
          <CheckCircle2 className="w-5 h-5 text-emerald-400 shrink-0" />
        ) : isError ? (
          <AlertCircle className="w-5 h-5 text-rose-400 shrink-0" />
        ) : (
          <Info className="w-5 h-5 text-blue-400 shrink-0" />
        )}

        <div className="text-xs font-medium leading-relaxed pr-2">{toast.message}</div>

        <button
          onClick={hideToast}
          aria-label="Dismiss Notification"
          className="p-1 rounded-md text-foreground/70 hover:text-foreground hover:bg-white/10 transition-colors shrink-0"
        >
          <X className="w-3.5 h-3.5" />
        </button>
      </div>
    </div>
  );
};
