import React, { useEffect } from 'react';
import { 
  ShieldAlert, 
  X, 
  ShieldX, 
  Server, 
  AlertTriangle, 
  Globe2, 
  Activity,
  CheckCircle2,
  Terminal,
  Volume2
} from 'lucide-react';
import { LogEntry } from '../types/soc';
import { Language } from '../utils/i18n';
import { getIpGeoLocation } from '../utils/geoData';

interface SecurityAlertModalProps {
  threatLog: LogEntry | null;
  onClose: () => void;
  lang: Language;
  onBlockIp: (ip: string) => void;
  isIpBlocked: boolean;
  onIsolateHost: (host: string) => void;
  isHostIsolated: boolean;
  onViewInForensics: (log: LogEntry) => void;
}

export const SecurityAlertModal: React.FC<SecurityAlertModalProps> = ({
  threatLog,
  onClose,
  lang,
  onBlockIp,
  isIpBlocked,
  onIsolateHost,
  isHostIsolated,
  onViewInForensics
}) => {
  // Play subtle warning chime via Web Audio API
  useEffect(() => {
    if (!threatLog) return;
    try {
      const audioCtx = new (window.AudioContext || (window as any).webkitAudioContext)();
      const osc = audioCtx.createOscillator();
      const gain = audioCtx.createGain();

      osc.type = 'triangle';
      osc.frequency.setValueAtTime(587.33, audioCtx.currentTime); // D5
      osc.frequency.setValueAtTime(880, audioCtx.currentTime + 0.12); // A5

      gain.gain.setValueAtTime(0.15, audioCtx.currentTime);
      gain.gain.exponentialRampToValueAtTime(0.01, audioCtx.currentTime + 0.35);

      osc.connect(gain);
      gain.connect(audioCtx.destination);
      osc.start();
      osc.stop(audioCtx.currentTime + 0.4);
    } catch {
      // AudioContext unavailable or restricted by browser policy
    }
  }, [threatLog]);

  if (!threatLog) return null;

  const geo = getIpGeoLocation(threatLog.sourceIp);

  return (
    <div 
      className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/80 backdrop-blur-md animate-in fade-in"
      role="alertdialog"
      aria-modal="true"
      aria-labelledby="alert-dialog-title"
    >
      <div className="relative w-full max-w-2xl rounded-2xl bg-slate-900 border-2 border-rose-500/80 shadow-2xl shadow-rose-950/40 p-6 space-y-5 text-slate-100">
        {/* Header Alert Banner */}
        <div className="flex items-start justify-between gap-4 border-b border-rose-500/30 pb-4">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-xl bg-rose-500/20 border border-rose-500/50 flex items-center justify-center text-rose-400 shrink-0 animate-pulse">
              <ShieldAlert className="w-6 h-6" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="text-[10px] font-mono font-bold uppercase px-2 py-0.5 rounded bg-rose-500 text-white">
                  {lang === 'pa' ? 'ਗੰਭੀਰ ਸੁਰੱਖਿਆ ਚੇਤਾਵਨੀ' : 'CRITICAL THREAT ALERT'}
                </span>
                <span className="text-xs font-mono text-rose-400">
                  {threatLog.severity.toUpperCase()}
                </span>
              </div>
              <h2 id="alert-dialog-title" className="text-base font-bold text-white mt-1">
                {threatLog.ruleMatched?.name || `${threatLog.category.toUpperCase()} Attack Detected`}
              </h2>
            </div>
          </div>

          <button
            onClick={onClose}
            className="p-1.5 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800 transition-colors"
            aria-label="Dismiss alert"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Breakdown Grid: What, Where, Who */}
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 text-xs font-mono">
          {/* Who */}
          <div className="p-3 rounded-xl bg-slate-950 border border-slate-800">
            <div className="text-[11px] text-slate-400 font-sans font-semibold flex items-center gap-1.5">
              <Globe2 className="w-3.5 h-3.5 text-cyan-400" />
              <span>{lang === 'pa' ? 'ਹਮਲਾਵਰ (Attacker)' : 'Threat Actor IP'}</span>
            </div>
            <div className="text-rose-400 font-bold mt-1 text-sm">{threatLog.sourceIp}</div>
            <div className="text-[10px] text-slate-400 mt-0.5">{geo.city}, {geo.country}</div>
          </div>

          {/* Where */}
          <div className="p-3 rounded-xl bg-slate-950 border border-slate-800">
            <div className="text-[11px] text-slate-400 font-sans font-semibold flex items-center gap-1.5">
              <Server className="w-3.5 h-3.5 text-indigo-400" />
              <span>{lang === 'pa' ? 'ਨਿਸ਼ਾਨਾ (Target Host)' : 'Targeted Asset'}</span>
            </div>
            <div className="text-white font-bold mt-1 text-sm">{threatLog.sourceHost}</div>
            <div className="text-[10px] text-slate-400 mt-0.5 font-sans">
              Source: <span className="uppercase">{threatLog.source}</span>
            </div>
          </div>

          {/* Technique */}
          <div className="p-3 rounded-xl bg-slate-950 border border-slate-800">
            <div className="text-[11px] text-slate-400 font-sans font-semibold flex items-center gap-1.5">
              <Terminal className="w-3.5 h-3.5 text-amber-400" />
              <span>{lang === 'pa' ? 'ਤਕਨੀਕ (Technique)' : 'MITRE ATT&CK'}</span>
            </div>
            <div className="text-amber-400 font-bold mt-1 text-sm">
              {threatLog.ruleMatched?.mitreId || 'T1190'}
            </div>
            <div className="text-[10px] text-slate-400 mt-0.5 font-sans">
              {threatLog.ruleMatched?.mitreTactic || threatLog.category}
            </div>
          </div>
        </div>

        {/* What was found (Forensic detail explanation) */}
        <div className="p-4 rounded-xl bg-slate-950 border border-slate-800 space-y-2 text-xs">
          <div className="font-semibold text-rose-300 flex items-center gap-1.5">
            <AlertTriangle className="w-4 h-4 text-rose-400" />
            <span>
              {lang === 'pa' ? 'ਕੀ ਫੜਿਆ ਗਿਆ (Detected Security Risk):' : 'Forensic Detection Summary:'}
            </span>
          </div>
          <p className="text-slate-300 leading-relaxed font-sans">
            {threatLog.ruleMatched?.description || 
              `An unauthorized malicious payload matching known attack vectors was intercepted from ${threatLog.sourceIp} against internal asset ${threatLog.sourceHost}.`}
          </p>

          <div className="mt-2 pt-2 border-t border-slate-800/80">
            <div className="text-slate-400 font-semibold font-sans mb-1">
              {lang === 'pa' ? 'ਸਿਫਾਰਸ਼ ਕੀਤੀ ਤੁਰੰਤ ਕਾਰਵਾਈ (Remediation):' : 'Mandatory SOC Remediation:'}
            </div>
            <p className="text-emerald-400 font-sans">
              {threatLog.ruleMatched?.remediation || 'Immediately block IP at perimeter and isolate host via EDR.'}
            </p>
          </div>
        </div>

        {/* Immediate Containment Actions */}
        <div className="flex flex-wrap items-center justify-between gap-3 pt-2">
          <div className="flex items-center gap-2 flex-wrap">
            <button
              onClick={() => onBlockIp(threatLog.sourceIp)}
              disabled={isIpBlocked}
              className={`px-3.5 py-2 rounded-lg text-xs font-semibold flex items-center gap-1.5 transition-colors ${
                isIpBlocked
                  ? 'bg-slate-800 text-slate-500 cursor-not-allowed'
                  : 'bg-rose-600 hover:bg-rose-500 text-white shadow-md shadow-rose-950/30'
              }`}
            >
              <ShieldX className="w-4 h-4" />
              <span>
                {isIpBlocked ? (lang === 'pa' ? 'IP ਬਲਾਕਡ ਹੈ' : 'IP Already Blocked') : (lang === 'pa' ? 'IP ਤੁਰੰਤ ਬਲਾਕ ਕਰੋ' : 'Block Attacker IP')}
              </span>
            </button>

            <button
              onClick={() => onIsolateHost(threatLog.sourceHost)}
              disabled={isHostIsolated}
              className={`px-3.5 py-2 rounded-lg text-xs font-semibold flex items-center gap-1.5 transition-colors ${
                isHostIsolated
                  ? 'bg-slate-800 text-slate-500 cursor-not-allowed'
                  : 'bg-amber-600 hover:bg-amber-500 text-white shadow-md'
              }`}
            >
              <Server className="w-4 h-4" />
              <span>
                {isHostIsolated ? (lang === 'pa' ? 'ਹੋਸਟ ਵੱਖ ਕੀਤਾ ਹੋਇਆ ਹੈ' : 'Host Isolated') : (lang === 'pa' ? 'ਹੋਸਟ ਵੱਖ ਕਰੋ' : 'Isolate Host')}
              </span>
            </button>

            <button
              onClick={() => {
                onViewInForensics(threatLog);
                onClose();
              }}
              className="px-3 py-2 rounded-lg text-xs font-medium bg-slate-800 hover:bg-slate-700 text-slate-200 transition-colors"
            >
              {lang === 'pa' ? 'ਵੇਰਵੇ ਦੇਖੋ' : 'Full Investigation'}
            </button>
          </div>

          <button
            onClick={onClose}
            className="px-4 py-2 rounded-lg text-xs font-semibold bg-slate-800 hover:bg-slate-700 text-white transition-colors"
          >
            {lang === 'pa' ? 'ਮੰਨਿਆ (Acknowledge)' : 'Acknowledge & Close'}
          </button>
        </div>
      </div>
    </div>
  );
};
