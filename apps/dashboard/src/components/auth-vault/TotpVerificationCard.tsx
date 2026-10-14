import React, { useState, useEffect } from 'react';
import {
  KeyRound,
  Copy,
  Check,
  Eye,
  EyeOff,
  ShieldCheck,
  ShieldAlert,
  Clock,
  Sparkles,
  Info,
} from 'lucide-react';
import {
  generateTotpCode,
  generateRandomTotpSecret,
  getTotpRemainingSeconds,
} from '../../api/authVault.js';
import { useAppStore } from '../../store/useAppStore.js';

interface TotpVerificationCardProps {
  initialSecret?: string;
  onSecretChange?: (secret: string) => void;
}

export const TotpVerificationCard: React.FC<TotpVerificationCardProps> = ({
  initialSecret = 'JBSWY3DPEHPK3PXP',
  onSecretChange,
}) => {
  const { showToast } = useAppStore();

  const [secret, setSecret] = useState<string>(initialSecret);
  const [isSecretVisible, setIsSecretVisible] = useState<boolean>(false);
  const [currentCode, setCurrentCode] = useState<string>('------');
  const [remainingSeconds, setRemainingSeconds] = useState<number>(30);
  const [copiedCode, setCopiedCode] = useState<boolean>(false);
  const [testInputCode, setTestInputCode] = useState<string>('');
  const [verificationOutcome, setVerificationOutcome] = useState<'VALID' | 'INVALID' | null>(null);

  // Update TOTP code and countdown timer
  useEffect(() => {
    let isMounted = true;

    const updateCodeAndTimer = async () => {
      const remaining = getTotpRemainingSeconds(30);
      if (isMounted) setRemainingSeconds(remaining);

      try {
        const code = await generateTotpCode(secret);
        if (isMounted) setCurrentCode(code);
      } catch {
        if (isMounted) setCurrentCode('ERROR!');
      }
    };

    updateCodeAndTimer();
    const interval = setInterval(updateCodeAndTimer, 1000);

    return () => {
      isMounted = false;
      clearInterval(interval);
    };
  }, [secret]);

  const handleSecretChange = (newSecret: string) => {
    const cleaned = newSecret.toUpperCase().replace(/\s/g, '');
    setSecret(cleaned);
    if (onSecretChange) onSecretChange(cleaned);
  };

  const handleGenerateRandomSecret = () => {
    const randomSeed = generateRandomTotpSecret(16);
    setSecret(randomSeed);
    if (onSecretChange) onSecretChange(randomSeed);
    showToast('Generated fresh Base32 TOTP secret seed', 'info');
  };

  const copyCodeToClipboard = () => {
    if (currentCode && currentCode !== '------' && currentCode !== 'ERROR!') {
      navigator.clipboard.writeText(currentCode);
      setCopiedCode(true);
      showToast('TOTP 6-digit code copied to clipboard', 'info');
      setTimeout(() => setCopiedCode(false), 2000);
    }
  };

  const verifyTestCode = () => {
    const sanitized = testInputCode.trim();
    if (!sanitized) return;
    if (sanitized === currentCode) {
      setVerificationOutcome('VALID');
      showToast('Passcode Verified: Active TOTP token matches current window', 'success');
    } else {
      setVerificationOutcome('INVALID');
      showToast('Passcode Mismatch: Code does not match active interval', 'error');
    }
  };

  // Circular timer calculations (radius 18, circumference ~113.1)
  const radius = 18;
  const circumference = 2 * Math.PI * radius;
  const strokeDashoffset = circumference - (remainingSeconds / 30) * circumference;

  return (
    <div className="p-5 rounded-xl bg-card border border-border space-y-5 shadow-sm">
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 border-b border-border/70 pb-3">
        <div>
          <div className="flex items-center gap-2 mb-0.5">
            <KeyRound className="w-5 h-5 text-cyan-400" />
            <h3 className="text-sm font-bold text-foreground">
              Automated MFA / RFC 6238 TOTP Token Simulator
            </h3>
          </div>
          <p className="text-xs text-muted-foreground">
            Generate and verify 30-second time-based one-time passcodes for multi-factor authenticated targets.
          </p>
        </div>

        <button
          type="button"
          onClick={handleGenerateRandomSecret}
          className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-accent hover:bg-accent/80 text-foreground text-xs font-medium border border-border transition-colors shadow-sm"
        >
          <Sparkles className="w-3.5 h-3.5 text-cyan-400" />
          <span>New Base32 Seed</span>
        </button>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-12 gap-6 items-center">
        {/* Passcode Display Box */}
        <div className="md:col-span-6 p-5 rounded-xl bg-background/80 border border-border/80 flex flex-col items-center justify-center space-y-3 relative overflow-hidden">
          <div className="flex items-center justify-between w-full">
            <span className="text-[11px] font-bold uppercase tracking-wider text-muted-foreground flex items-center gap-1.5">
              <Clock className="w-3.5 h-3.5 text-cyan-400" />
              Active Passcode
            </span>

            {/* Circular Countdown Progress */}
            <div className="flex items-center gap-1.5">
              <div className="relative w-8 h-8 flex items-center justify-center">
                <svg className="w-8 h-8 transform -rotate-90">
                  <circle
                    cx="16"
                    cy="16"
                    r={radius}
                    stroke="currentColor"
                    strokeWidth="3"
                    className="text-accent"
                    fill="transparent"
                  />
                  <circle
                    cx="16"
                    cy="16"
                    r={radius}
                    stroke="currentColor"
                    strokeWidth="3"
                    strokeDasharray={circumference}
                    strokeDashoffset={strokeDashoffset}
                    strokeLinecap="round"
                    className={remainingSeconds <= 5 ? 'text-rose-500' : 'text-cyan-400'}
                    fill="transparent"
                  />
                </svg>
                <span className="absolute text-[10px] font-mono font-bold text-foreground">
                  {remainingSeconds}
                </span>
              </div>
              <span className="text-[11px] font-mono text-muted-foreground">{remainingSeconds}s</span>
            </div>
          </div>

          {/* 6-Digit Passcode */}
          <div className="py-2">
            <span className="text-3xl sm:text-4xl font-mono font-extrabold tracking-widest text-cyan-300 drop-shadow-sm select-all">
              {currentCode.length === 6
                ? `${currentCode.slice(0, 3)} ${currentCode.slice(3, 6)}`
                : currentCode}
            </span>
          </div>

          {/* Copy Button */}
          <button
            type="button"
            onClick={copyCodeToClipboard}
            className="flex items-center gap-1.5 px-4 py-1.5 rounded-lg bg-cyan-600/15 hover:bg-cyan-600/25 text-cyan-300 border border-cyan-500/40 text-xs font-medium transition-colors shadow-sm"
          >
            {copiedCode ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
            <span>Copy Passcode</span>
          </button>
        </div>

        {/* Secret Seed Configuration & Validation */}
        <div className="md:col-span-6 space-y-4">
          <div className="space-y-1.5">
            <div className="flex items-center justify-between">
              <label className="text-[11px] font-bold uppercase tracking-wider text-muted-foreground">
                Base32 Secret Seed Key
              </label>
              <button
                type="button"
                onClick={() => setIsSecretVisible(!isSecretVisible)}
                className="text-[11px] text-muted-foreground hover:text-foreground flex items-center gap-1"
              >
                {isSecretVisible ? <EyeOff className="w-3 h-3" /> : <Eye className="w-3 h-3" />}
                <span>{isSecretVisible ? 'Mask Key' : 'Reveal Key'}</span>
              </button>
            </div>

            <div className="relative">
              <input
                type={isSecretVisible ? 'text' : 'password'}
                value={secret}
                onChange={(e) => handleSecretChange(e.target.value)}
                placeholder="e.g. JBSWY3DPEHPK3PXP"
                className="w-full px-3 py-1.5 rounded-lg bg-background border border-border text-xs font-mono text-foreground focus:outline-none focus:ring-1 focus:ring-cyan-500 tracking-wider"
              />
            </div>
            <span className="text-[11px] text-muted-foreground block">
              16 or 32 character Base32 encoded cryptographic key (RFC 4648).
            </span>
          </div>

          {/* Manual Verification Sandbox */}
          <div className="space-y-1.5 pt-2 border-t border-border/60">
            <label className="text-[11px] font-bold uppercase tracking-wider text-muted-foreground block">
              Verify Authenticator Sync
            </label>
            <div className="flex items-center gap-2">
              <input
                type="text"
                maxLength={6}
                value={testInputCode}
                onChange={(e) => setTestInputCode(e.target.value)}
                placeholder="Enter 6-digit code"
                className="w-36 px-3 py-1.5 rounded-lg bg-background border border-border text-xs font-mono text-foreground text-center tracking-widest focus:outline-none focus:ring-1 focus:ring-cyan-500"
              />
              <button
                type="button"
                onClick={verifyTestCode}
                className="px-3 py-1.5 rounded-lg bg-accent hover:bg-accent/80 text-foreground text-xs font-medium border border-border transition-colors"
              >
                Verify Code
              </button>

              {verificationOutcome === 'VALID' && (
                <span className="flex items-center gap-1 text-xs text-emerald-400 font-medium font-mono animate-fade-in">
                  <ShieldCheck className="w-4 h-4 text-emerald-400" />
                  Synced
                </span>
              )}
              {verificationOutcome === 'INVALID' && (
                <span className="flex items-center gap-1 text-xs text-rose-400 font-medium font-mono animate-fade-in">
                  <ShieldAlert className="w-4 h-4 text-rose-400" />
                  Mismatch
                </span>
              )}
            </div>
          </div>
        </div>
      </div>

      <div className="p-3 rounded-lg bg-accent/30 border border-border text-xs text-muted-foreground flex items-start gap-2.5">
        <Info className="w-4 h-4 text-cyan-400 flex-shrink-0 mt-0.5" />
        <div>
          <span className="font-semibold text-foreground">Zero-Touch Automated Injection:</span> When you configure this TOTP secret in an Authentication Flow, the security runner automatically generates fresh 6-digit codes during test execution and injects them via <code>{'{{totp}}'}</code> into login payloads without manual operator intervention.
        </div>
      </div>
    </div>
  );
};
