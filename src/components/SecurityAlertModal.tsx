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
      className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/85 backdrop-blur-md animate-in fade-in"
      role="alertdialog"
      aria-modal="true"
      aria-labelledby="alert-dialog-title"
    >
      <div className="relative w-full max-w-2xl rounded-2xl bg-neutral-900 border-2 border-yellow-400 shadow-2xl shadow-yellow-500/20 p-6 space-y-5 text-neutral-100">
        {/* Header Alert Banner with Cyber Yellow Accent */}
        <div className="flex items-start justify-between gap-4 border-b border-neutral-800 pb-4">
          <div className="flex items-center gap-3">
            <div className="w-11 h-11 rounded-xl bg-yellow-400 text-neutral-950 font-black border border-yellow-300 flex items-center justify-center shrink-0 shadow-lg shadow-yellow-500/30">
              <ShieldAlert className="w-6 h-6 stroke-[2.5]" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="text-[10px] font-mono font-black uppercase px-2 py-0.5 rounded bg-yellow-400 text-neutral-950 shadow-sm">
                  {lang === 'pa' ? 'ਗੰਭੀਰ ਸੁਰੱਖਿਆ ਚੇਤਾਵਨੀ' : 'CRITICAL THREAT ALERT'}
                </span>
                <span className="text-xs font-mono font-bold text-yellow-400">
                  {threatLog.severity.toUpperCase()}
                </span>
              </div>
              <h2 id="alert-dialog-title" className="text-base font-black text-white mt-1">
                {threatLog.ruleMatched?.name || `${threatLog.category.toUpperCase()} Attack Detected`}
              </h2>
            </div>
          </div>

          <button
            onClick={onClose}
            className="p-1.5 rounded-lg text-neutral-400 hover:text-white hover:bg-neutral-800 transition-colors cursor-pointer"
            aria-label="Dismiss alert"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Breakdown Grid: What, Where, Who */}
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 text-xs font-mono">
          {/* Who */}
          <div className="p-3.5 rounded-xl bg-neutral-950 border border-neutral-800">
            <div className="text-[11px] text-neutral-400 font-sans font-bold flex items-center gap-1.5">
              <Globe2 className="w-3.5 h-3.5 text-yellow-400" />
              <span>{lang === 'pa' ? 'ਹਮਲਾਵਰ (Attacker)' : 'Threat Actor IP'}</span>
            </div>
            <div className="text-yellow-400 font-black mt-1 text-sm">{threatLog.sourceIp}</div>
            <div className="text-[10px] text-neutral-300 mt-0.5">{geo.city}, {geo.country}</div>
          </div>

          {/* Where */}
          <div className="p-3.5 rounded-xl bg-neutral-950 border border-neutral-800">
            <div className="text-[11px] text-neutral-400 font-sans font-bold flex items-center gap-1.5">
              <Server className="w-3.5 h-3.5 text-white" />
              <span>{lang === 'pa' ? 'ਨਿਸ਼ਾਨਾ (Target Host)' : 'Targeted Asset'}</span>
            </div>
            <div className="text-white font-black mt-1 text-sm">{threatLog.sourceHost}</div>
            <div className="text-[10px] text-neutral-300 mt-0.5 font-sans">
              Source: <span className="uppercase font-semibold">{threatLog.source}</span>
            </div>
          </div>

          {/* Technique */}
          <div className="p-3.5 rounded-xl bg-neutral-950 border border-neutral-800">
            <div className="text-[11px] text-neutral-400 font-sans font-bold flex items-center gap-1.5">
              <Terminal className="w-3.5 h-3.5 text-yellow-400" />
              <span>{lang === 'pa' ? 'ਤਕਨੀਕ (Technique)' : 'MITRE ATT&CK'}</span>
            </div>
            <div className="text-yellow-400 font-black mt-1 text-sm">
              {threatLog.ruleMatched?.mitreId || 'T1190'}
            </div>
            <div className="text-[10px] text-neutral-300 mt-0.5 font-sans font-medium">
              {threatLog.ruleMatched?.mitreTactic || threatLog.category}
            </div>
          </div>
        </div>

        {/* What was found (Forensic detail explanation) */}
        <div className="p-4 rounded-xl bg-neutral-950 border border-neutral-800 space-y-2 text-xs">
          <div className="font-bold text-yellow-300 flex items-center gap-1.5">
            <AlertTriangle className="w-4 h-4 text-yellow-400" />
            <span>
              {lang === 'pa' ? 'ਕੀ ਫੜਿਆ ਗਿਆ (Detected Security Risk):' : 'Forensic Detection Summary:'}
            </span>
          </div>
          <p className="text-neutral-200 leading-relaxed font-sans">
            {threatLog.ruleMatched?.description || 
              `An unauthorized malicious payload matching known attack vectors was intercepted from ${threatLog.sourceIp} against internal asset ${threatLog.sourceHost}.`}
          </p>

          <div className="mt-2 pt-2 border-t border-neutral-800">
            <div className="text-neutral-400 font-bold font-sans mb-1">
              {lang === 'pa' ? 'ਸਿਫਾਰਸ਼ ਕੀਤੀ ਤੁਰੰਤ ਕਾਰਵਾਈ (Remediation):' : 'Mandatory SOC Remediation:'}
            </div>
            <p className="text-white font-sans font-medium">
              {threatLog.ruleMatched?.remediation || 'Immediately block IP at perimeter and isolate host via EDR.'}
            </p>
          </div>
        </div>

        {/* Immediate Containment Actions with Yellow & White Contrast */}
        <div className="flex flex-wrap items-center justify-between gap-3 pt-2">
          <div className="flex items-center gap-2 flex-wrap">
            <button
              onClick={() => onBlockIp(threatLog.sourceIp)}
              disabled={isIpBlocked}
              className={`px-4 py-2 rounded-xl text-xs font-bold flex items-center gap-1.5 transition-all cursor-pointer ${
                isIpBlocked
                  ? 'bg-neutral-800 text-neutral-500 cursor-not-allowed border border-neutral-700'
                  : 'bg-yellow-400 hover:bg-yellow-300 text-neutral-950 shadow-md shadow-yellow-500/20 active:scale-95'
              }`}
            >
              <ShieldX className="w-4 h-4 text-neutral-950" />
              <span>
                {isIpBlocked ? (lang === 'pa' ? 'IP ਬਲਾਕਡ ਹੈ' : 'IP Already Blocked') : (lang === 'pa' ? 'IP ਤੁਰੰਤ ਬਲਾਕ ਕਰੋ' : 'Block Attacker IP')}
              </span>
            </button>

            <button
              onClick={() => onIsolateHost(threatLog.sourceHost)}
              disabled={isHostIsolated}
              className={`px-4 py-2 rounded-xl text-xs font-bold flex items-center gap-1.5 transition-all cursor-pointer ${
                isHostIsolated
                  ? 'bg-neutral-800 text-neutral-500 cursor-not-allowed border border-neutral-700'
                  : 'bg-neutral-800 hover:bg-neutral-700 text-white border border-neutral-700'
              }`}
            >
              <Server className="w-4 h-4 text-white" />
              <span>
                {isHostIsolated ? (lang === 'pa' ? 'ਹੋਸਟ ਵੱਖ ਕੀਤਾ ਹੋਇਆ ਹੈ' : 'Host Isolated') : (lang === 'pa' ? 'ਹੋਸਟ ਵੱਖ ਕਰੋ' : 'Isolate Host')}
              </span>
            </button>

            <button
              onClick={() => {
                onViewInForensics(threatLog);
                onClose();
              }}
              className="px-4 py-2 rounded-xl text-xs font-bold bg-white hover:bg-neutral-100 text-neutral-950 transition-all shadow-sm cursor-pointer"
            >
              {lang === 'pa' ? 'ਵੇਰਵੇ ਦੇਖੋ' : 'Full Investigation'}
            </button>
          </div>

          <button
            onClick={onClose}
            className="px-4 py-2 rounded-xl text-xs font-bold bg-neutral-800 hover:bg-neutral-700 text-neutral-300 hover:text-white transition-colors cursor-pointer"
          >
            {lang === 'pa' ? 'ਮੰਨਿਆ (Acknowledge)' : 'Acknowledge & Close'}
          </button>
        </div>
      </div>
    </div>
  );
};
