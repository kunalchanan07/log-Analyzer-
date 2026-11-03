import React, { useState } from 'react';
import { 
  X, 
  ShieldAlert, 
  Check, 
  Copy, 
  ShieldX, 
  Lock, 
  FileCode, 
  ExternalLink,
  Download,
  AlertTriangle,
  Server
} from 'lucide-react';
import { LogEntry, Severity } from '../types/soc';
import { Language, TRANSLATIONS } from '../utils/i18n';

interface LogDetailModalProps {
  log: LogEntry | null;
  onClose: () => void;
  lang: Language;
  onBlockIp: (ip: string) => void;
  isIpBlocked: boolean;
  onIsolateHost: (host: string) => void;
  isHostIsolated: boolean;
  onCreateIncidentFromLog: (log: LogEntry) => void;
}

export const LogDetailModal: React.FC<LogDetailModalProps> = ({
  log,
  onClose,
  lang,
  onBlockIp,
  isIpBlocked,
  onIsolateHost,
  isHostIsolated,
  onCreateIncidentFromLog
}) => {
  const t = TRANSLATIONS[lang];
  const [copied, setCopied] = useState(false);
  const [actionFeedback, setActionFeedback] = useState<string | null>(null);

  if (!log) return null;

  const handleCopyRaw = () => {
    navigator.clipboard.writeText(log.raw);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handleExportStix = () => {
    const stixIndicator = {
      type: 'indicator',
      spec_version: '2.1',
      id: `indicator--${log.id}`,
      created: log.timestamp,
      name: log.ruleMatched?.name || 'Suspicious Telemetry',
      description: log.ruleMatched?.description || log.raw,
      pattern: `[ipv4-addr:value = '${log.sourceIp}']`,
      pattern_type: 'stix',
      valid_from: log.timestamp,
      labels: ['malicious-activity', log.category],
      external_references: [
        {
          source_name: 'mitre-attack',
          external_id: log.ruleMatched?.mitreId || 'T1190'
        }
      ]
    };

    const blob = new Blob([JSON.stringify(stixIndicator, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `stix-indicator-${log.sourceIp}.json`;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  };

  const getSeverityBadgeClass = (sev: Severity) => {
    switch (sev) {
      case 'critical':
        return 'text-rose-400 bg-rose-500/10 border-rose-500/30 font-bold';
      case 'high':
        return 'text-yellow-400 bg-yellow-400/10 border-yellow-400/30 font-bold';
      case 'medium':
        return 'text-amber-300 bg-amber-400/10 border-amber-400/30';
      default:
        return 'text-emerald-400 bg-emerald-500/10 border-emerald-500/30';
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/85 backdrop-blur-md animate-in fade-in duration-200">
      <div 
        className="relative w-full max-w-3xl max-h-[90vh] overflow-y-auto rounded-2xl bg-neutral-900 border border-neutral-700 shadow-2xl p-6 space-y-6"
        role="dialog"
        aria-modal="true"
        aria-labelledby="modal-headline"
      >
        {/* Header */}
        <div className="flex items-start justify-between gap-4 border-b border-neutral-800 pb-4">
          <div>
            <div className="flex items-center gap-2 flex-wrap">
              <span className={`text-[11px] font-mono px-2.5 py-0.5 rounded border uppercase ${getSeverityBadgeClass(log.severity)}`}>
                {log.severity}
              </span>
              <span className="text-xs font-mono text-neutral-400">
                ID: {log.id}
              </span>
              {log.ruleMatched?.mitreId && (
                <span className="text-xs font-mono font-bold text-yellow-400 bg-yellow-400/10 px-2 py-0.5 rounded border border-yellow-400/30">
                  MITRE ATT&CK: {log.ruleMatched.mitreId} ({log.ruleMatched.mitreTactic})
                </span>
              )}
            </div>

            <h2 id="modal-headline" className="text-lg font-black text-white mt-2">
              {log.ruleMatched?.name || `${log.category.toUpperCase()} Log Entry`}
            </h2>
          </div>

          <button
            onClick={onClose}
            className="p-1.5 rounded-lg text-neutral-400 hover:text-white hover:bg-neutral-800 transition-colors cursor-pointer"
            aria-label="Close modal"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Action feedback notification */}
        {actionFeedback && (
          <div className="p-3 rounded-xl bg-yellow-400/10 border border-yellow-400/30 text-yellow-300 text-xs font-medium">
            {actionFeedback}
          </div>
        )}

        {/* Forensic Attributes Grid in Cyber Yellow & Crisp White */}
        <div>
          <h3 className="text-xs font-bold text-white uppercase tracking-wider mb-2 flex items-center gap-1.5">
            <span className="w-1.5 h-1.5 rounded-full bg-yellow-400" />
            <span>{t.parsedAttributes}</span>
          </h3>
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-xs font-mono">
            <div className="p-3.5 rounded-xl bg-neutral-950 border border-neutral-800">
              <div className="text-[11px] text-neutral-400 font-sans font-medium">{t.tabularIp}</div>
              <div className="text-yellow-400 font-black mt-1 truncate">{log.sourceIp}</div>
            </div>

            <div className="p-3.5 rounded-xl bg-neutral-950 border border-neutral-800">
              <div className="text-[11px] text-neutral-400 font-sans font-medium">{t.tabularHost}</div>
              <div className="text-white font-bold mt-1 truncate">{log.sourceHost}</div>
            </div>

            <div className="p-3.5 rounded-xl bg-neutral-950 border border-neutral-800">
              <div className="text-[11px] text-neutral-400 font-sans font-medium">{lang === 'pa' ? 'ਯੂਜ਼ਰ' : 'User Identity'}</div>
              <div className="text-yellow-300 font-bold mt-1 truncate">{log.user || 'SYSTEM / Anonymous'}</div>
            </div>

            <div className="p-3.5 rounded-xl bg-neutral-950 border border-neutral-800">
              <div className="text-[11px] text-neutral-400 font-sans font-medium">{lang === 'pa' ? 'ਭਰੋਸਾ ਸਕੋਰ' : 'Detection Confidence'}</div>
              <div className="text-emerald-400 font-black mt-1 tabular-nums">{log.confidenceScore}%</div>
            </div>
          </div>
        </div>

        {/* Raw Payload Section */}
        <div>
          <div className="flex items-center justify-between mb-2">
            <h3 className="text-xs font-bold text-white uppercase tracking-wider flex items-center gap-1.5">
              <span className="w-1.5 h-1.5 rounded-full bg-yellow-400" />
              <span>{t.rawMessage}</span>
            </h3>
            <button
              onClick={handleCopyRaw}
              className="flex items-center gap-1 text-xs text-neutral-300 hover:text-white transition-colors cursor-pointer font-bold"
            >
              {copied ? <Check className="w-3.5 h-3.5 text-yellow-400" /> : <Copy className="w-3.5 h-3.5 text-yellow-400" />}
              <span>{copied ? (lang === 'pa' ? 'ਕਾਪੀ ਹੋ ਗਿਆ!' : 'Copied!') : (lang === 'pa' ? 'ਕਾਪੀ ਕਰੋ' : 'Copy Payload')}</span>
            </button>
          </div>
          <div className="p-3.5 rounded-xl bg-neutral-950 border border-neutral-800 font-mono text-xs text-neutral-200 break-all leading-relaxed max-h-40 overflow-y-auto">
            {log.raw}
          </div>
        </div>

        {/* Rule Logic & Remediation */}
        {log.ruleMatched && (
          <div className="p-4 rounded-xl bg-neutral-950 border border-neutral-800 space-y-3">
            <div>
              <div className="text-xs font-bold text-white flex items-center gap-1.5">
                <FileCode className="w-4 h-4 text-yellow-400" />
                <span>{t.ruleDescription}</span>
              </div>
              <p className="text-xs text-neutral-300 mt-1 leading-relaxed">
                {log.ruleMatched.description}
              </p>
            </div>

            <div className="pt-2 border-t border-neutral-800">
              <div className="text-xs font-bold text-yellow-300 flex items-center gap-1.5">
                <AlertTriangle className="w-4 h-4 text-yellow-400" />
                <span>{t.recommendedRemediation}</span>
              </div>
              <p className="text-xs text-neutral-200 mt-1 leading-relaxed">
                {log.ruleMatched.remediation}
              </p>
            </div>
          </div>
        )}

        {/* Incident Response Action Bar */}
        <div className="pt-3 border-t border-neutral-800 flex flex-wrap items-center justify-between gap-3">
          <div className="flex items-center gap-2 flex-wrap">
            {/* Block IP */}
            <button
              onClick={() => {
                onBlockIp(log.sourceIp);
                setActionFeedback(
                  lang === 'pa'
                    ? `IP ${log.sourceIp} ਨੂੰ ਫਾਇਰਵਾਲ ਉੱਤੇ ਬਲਾਕ ਕਰ ਦਿੱਤਾ ਗਿਆ ਹੈ!`
                    : `Firewall ACL drop rule applied for IP ${log.sourceIp}!`
                );
              }}
              disabled={isIpBlocked}
              className={`px-3.5 py-2 rounded-xl text-xs font-bold flex items-center gap-1.5 transition-all cursor-pointer ${
                isIpBlocked
                  ? 'bg-neutral-800 text-neutral-500 cursor-not-allowed border border-neutral-700'
                  : 'bg-yellow-400 hover:bg-yellow-300 text-neutral-950 shadow-md shadow-yellow-500/20 active:scale-95'
              }`}
            >
              <ShieldX className="w-3.5 h-3.5 text-neutral-950" />
              <span>{isIpBlocked ? (lang === 'pa' ? 'IP ਬਲਾਕਡ ਹੈ' : 'IP Blocked') : t.blockIp}</span>
            </button>

            {/* Isolate Host */}
            <button
              onClick={() => {
                onIsolateHost(log.sourceHost);
                setActionFeedback(
                  lang === 'pa'
                    ? `ਹੋਸਟ ${log.sourceHost} ਨੂੰ EDR ਨੈੱਟਵਰਕ ਤੋਂ ਵੱਖ ਕਰ ਦਿੱਤਾ ਗਿਆ!`
                    : `Host ${log.sourceHost} isolated via EDR agent!`
                );
              }}
              disabled={isHostIsolated}
              className={`px-3.5 py-2 rounded-xl text-xs font-bold flex items-center gap-1.5 transition-all cursor-pointer ${
                isHostIsolated
                  ? 'bg-neutral-800 text-neutral-500 cursor-not-allowed border border-neutral-700'
                  : 'bg-neutral-800 hover:bg-neutral-700 text-white border border-neutral-700'
              }`}
            >
              <Server className="w-3.5 h-3.5 text-white" />
              <span>{isHostIsolated ? (lang === 'pa' ? 'ਹੋਸਟ ਵੱਖ ਕੀਤਾ ਹੋਇਆ ਹੈ' : 'Host Isolated') : t.isolateHost}</span>
            </button>

            {/* Create Incident */}
            <button
              onClick={() => {
                onCreateIncidentFromLog(log);
                setActionFeedback(
                  lang === 'pa'
                    ? 'ਨਵੀਂ ਜਾਂਚ ਘਟਨਾ (Incident) ਸਫਲਤਾਪੂਰਵਕ ਬਣਾਈ ਗਈ!'
                    : 'New security incident ticket escalated and created!'
                );
              }}
              className="px-3.5 py-2 rounded-xl text-xs font-bold bg-white hover:bg-neutral-100 text-neutral-950 shadow-sm flex items-center gap-1.5 transition-all cursor-pointer"
            >
              <ShieldAlert className="w-3.5 h-3.5 text-neutral-950" />
              <span>{lang === 'pa' ? 'ਘਟਨਾ ਦਰਜ ਕਰੋ (Create Incident)' : 'Escalate to Incident'}</span>
            </button>

            {/* Export STIX */}
            <button
              onClick={handleExportStix}
              className="px-3 py-2 rounded-xl text-xs font-semibold text-neutral-300 bg-neutral-950 border border-neutral-800 hover:border-yellow-400 hover:text-white flex items-center gap-1.5 transition-colors cursor-pointer"
            >
              <Download className="w-3.5 h-3.5 text-yellow-400" />
              <span>{t.exportStix}</span>
            </button>
          </div>

          <button
            onClick={onClose}
            className="px-4 py-2 rounded-xl text-xs font-bold text-neutral-300 hover:text-white bg-neutral-800 hover:bg-neutral-700 transition-colors ml-auto cursor-pointer"
          >
            {t.close}
          </button>
        </div>
      </div>
    </div>
  );
};
