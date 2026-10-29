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
        return 'text-rose-400 bg-rose-500/10 border-rose-500/30';
      case 'high':
        return 'text-amber-400 bg-amber-500/10 border-amber-500/30';
      case 'medium':
        return 'text-sky-400 bg-sky-500/10 border-sky-500/30';
      default:
        return 'text-emerald-400 bg-emerald-500/10 border-emerald-500/30';
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/80 backdrop-blur-sm animate-in fade-in duration-200">
      <div 
        className="relative w-full max-w-3xl max-h-[90vh] overflow-y-auto rounded-2xl bg-slate-900 border border-slate-800 shadow-2xl p-6 space-y-6"
        role="dialog"
        aria-modal="true"
        aria-labelledby="modal-headline"
      >
        {/* Header */}
        <div className="flex items-start justify-between gap-4 border-b border-slate-800 pb-4">
          <div>
            <div className="flex items-center gap-2 flex-wrap">
              <span className={`text-[11px] font-mono font-bold px-2.5 py-0.5 rounded border uppercase ${getSeverityBadgeClass(log.severity)}`}>
                {log.severity}
              </span>
              <span className="text-xs font-mono text-slate-400">
                ID: {log.id}
              </span>
              {log.ruleMatched?.mitreId && (
                <span className="text-xs font-mono text-cyan-400 bg-cyan-950/40 px-2 py-0.5 rounded border border-cyan-500/30">
                  MITRE ATT&CK: {log.ruleMatched.mitreId} ({log.ruleMatched.mitreTactic})
                </span>
              )}
            </div>

            <h2 id="modal-headline" className="text-lg font-bold text-white mt-2">
              {log.ruleMatched?.name || `${log.category.toUpperCase()} Log Entry`}
            </h2>
          </div>

          <button
            onClick={onClose}
            className="p-1.5 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800 transition-colors"
            aria-label="Close modal"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Action feedback notification */}
        {actionFeedback && (
          <div className="p-3 rounded-lg bg-cyan-500/10 border border-cyan-500/30 text-cyan-300 text-xs">
            {actionFeedback}
          </div>
        )}

        {/* Forensic Attributes Grid */}
        <div>
          <h3 className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-2">
            {t.parsedAttributes}
          </h3>
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-xs font-mono">
            <div className="p-3 rounded-lg bg-slate-950 border border-slate-800">
              <div className="text-[11px] text-slate-500 font-sans">{t.tabularIp}</div>
              <div className="text-cyan-400 font-bold mt-1 truncate">{log.sourceIp}</div>
            </div>

            <div className="p-3 rounded-lg bg-slate-950 border border-slate-800">
              <div className="text-[11px] text-slate-500 font-sans">{t.tabularHost}</div>
              <div className="text-slate-200 font-semibold mt-1 truncate">{log.sourceHost}</div>
            </div>

            <div className="p-3 rounded-lg bg-slate-950 border border-slate-800">
              <div className="text-[11px] text-slate-500 font-sans">{lang === 'pa' ? 'ਯੂਜ਼ਰ' : 'User Identity'}</div>
              <div className="text-amber-300 font-semibold mt-1 truncate">{log.user || 'SYSTEM / Anonymous'}</div>
            </div>

            <div className="p-3 rounded-lg bg-slate-950 border border-slate-800">
              <div className="text-[11px] text-slate-500 font-sans">{lang === 'pa' ? 'ਭਰੋਸਾ ਸਕੋਰ' : 'Detection Confidence'}</div>
              <div className="text-emerald-400 font-bold mt-1 tabular-nums">{log.confidenceScore}%</div>
            </div>
          </div>
        </div>

        {/* Raw Payload Section */}
        <div>
          <div className="flex items-center justify-between mb-2">
            <h3 className="text-xs font-semibold text-slate-400 uppercase tracking-wider">
              {t.rawMessage}
            </h3>
            <button
              onClick={handleCopyRaw}
              className="flex items-center gap-1 text-xs text-slate-400 hover:text-white transition-colors"
            >
              {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
              <span>{copied ? (lang === 'pa' ? 'ਕਾਪੀ ਹੋ ਗਿਆ!' : 'Copied!') : (lang === 'pa' ? 'ਕਾਪੀ ਕਰੋ' : 'Copy Payload')}</span>
            </button>
          </div>
          <div className="p-3.5 rounded-xl bg-slate-950 border border-slate-800 font-mono text-xs text-slate-200 break-all leading-relaxed max-h-40 overflow-y-auto">
            {log.raw}
          </div>
        </div>

        {/* Rule Logic & Remediation */}
        {log.ruleMatched && (
          <div className="p-4 rounded-xl bg-slate-950/60 border border-slate-800 space-y-3">
            <div>
              <div className="text-xs font-semibold text-slate-300 flex items-center gap-1.5">
                <FileCode className="w-4 h-4 text-cyan-400" />
                <span>{t.ruleDescription}</span>
              </div>
              <p className="text-xs text-slate-400 mt-1 leading-relaxed">
                {log.ruleMatched.description}
              </p>
            </div>

            <div className="pt-2 border-t border-slate-800/80">
              <div className="text-xs font-semibold text-rose-300 flex items-center gap-1.5">
                <AlertTriangle className="w-4 h-4 text-rose-400" />
                <span>{t.recommendedRemediation}</span>
              </div>
              <p className="text-xs text-slate-300 mt-1 leading-relaxed">
                {log.ruleMatched.remediation}
              </p>
            </div>
          </div>
        )}

        {/* Incident Response Action Bar */}
        <div className="pt-3 border-t border-slate-800 flex flex-wrap items-center justify-between gap-3">
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
              className={`px-3 py-2 rounded-lg text-xs font-semibold flex items-center gap-1.5 transition-colors ${
                isIpBlocked
                  ? 'bg-slate-800 text-slate-500 cursor-not-allowed'
                  : 'bg-rose-600 hover:bg-rose-500 text-white shadow-sm'
              }`}
            >
              <ShieldX className="w-3.5 h-3.5" />
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
              className={`px-3 py-2 rounded-lg text-xs font-semibold flex items-center gap-1.5 transition-colors ${
                isHostIsolated
                  ? 'bg-slate-800 text-slate-500 cursor-not-allowed'
                  : 'bg-amber-600 hover:bg-amber-500 text-white shadow-sm'
              }`}
            >
              <Server className="w-3.5 h-3.5" />
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
              className="px-3 py-2 rounded-lg text-xs font-semibold bg-indigo-600 hover:bg-indigo-500 text-white shadow-sm flex items-center gap-1.5 transition-colors"
            >
              <ShieldAlert className="w-3.5 h-3.5" />
              <span>{lang === 'pa' ? 'ਘਟਨਾ ਦਰਜ ਕਰੋ (Create Incident)' : 'Escalate to Incident'}</span>
            </button>

            {/* Export STIX */}
            <button
              onClick={handleExportStix}
              className="px-3 py-2 rounded-lg text-xs font-medium text-slate-300 bg-slate-950 border border-slate-800 hover:border-slate-700 flex items-center gap-1.5 transition-colors"
            >
              <Download className="w-3.5 h-3.5" />
              <span>{t.exportStix}</span>
            </button>
          </div>

          <button
            onClick={onClose}
            className="px-4 py-2 rounded-lg text-xs font-medium text-slate-300 hover:text-white bg-slate-800 hover:bg-slate-700 transition-colors ml-auto"
          >
            {t.close}
          </button>
        </div>
      </div>
    </div>
  );
};
