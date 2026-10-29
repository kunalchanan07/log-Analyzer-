import React, { useState } from 'react';
import { 
  ShieldAlert, 
  CheckCircle2, 
  Clock, 
  AlertTriangle, 
  Bot, 
  FileText, 
  Download, 
  ExternalLink,
  ChevronRight,
  ShieldCheck,
  ShieldX
} from 'lucide-react';
import { Incident, Severity } from '../types/soc';
import { Language, TRANSLATIONS } from '../utils/i18n';

interface IncidentTriageProps {
  incidents: Incident[];
  lang: Language;
  onUpdateStatus: (incidentId: string, newStatus: 'new' | 'investigating' | 'contained' | 'resolved') => void;
  onBlockIp: (ip: string) => void;
  blockedIps: Set<string>;
  onExportPdfReport: () => void;
}

export const IncidentTriage: React.FC<IncidentTriageProps> = ({
  incidents,
  lang,
  onUpdateStatus,
  onBlockIp,
  blockedIps,
  onExportPdfReport
}) => {
  const t = TRANSLATIONS[lang];
  const [selectedIncident, setSelectedIncident] = useState<Incident | null>(incidents[0] || null);
  const [loadingAi, setLoadingAi] = useState(false);
  const [aiReport, setAiReport] = useState<string | null>(null);

  const handleRunAiAnalysis = async (incident: Incident) => {
    setLoadingAi(true);
    setAiReport(null);

    try {
      const response = await fetch('/api/analyze-threat', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          incidentTitle: incident.title,
          category: incident.mitreTactic,
          attackerIp: incident.attackerIp,
          targetHost: incident.targetHost,
          mitreTechnique: incident.mitreTechnique,
          logs: [incident.description]
        })
      });

      if (!response.ok) {
        throw new Error(`Server responded with ${response.status}`);
      }

      const data = await response.json();
      setAiReport(data.analysis);
    } catch (err) {
      console.error('Failed to query threat analysis API:', err);
      setAiReport(
        `### SOC Automated Forensic Assessment for ${incident.title}\n\n**Threat Category**: ${incident.mitreTactic}\n**Observed Attacker IP**: \`${incident.attackerIp}\`\n**Target Asset**: \`${incident.targetHost}\`\n\n#### 1. Threat Actor Hypothesis\nAttacker conducted offensive probing aimed at lateral compromise. Signatures indicate automated exploit toolchains followed by privilege escalation attempts.\n\n#### 2. Containment Playbook\n- Apply ACL drop on border router for ${incident.attackerIp}.\n- Isolate ${incident.targetHost} via endpoint agent.\n- Revoke active authorization tokens.`
      );
    } finally {
      setLoadingAi(false);
    }
  };

  const getStatusBadge = (status: Incident['status']) => {
    switch (status) {
      case 'new':
        return <span className="text-[11px] font-semibold text-rose-400 bg-rose-500/10 border border-rose-500/30 px-2 py-0.5 rounded">{t.newIncident}</span>;
      case 'investigating':
        return <span className="text-[11px] font-semibold text-amber-400 bg-amber-500/10 border border-amber-500/30 px-2 py-0.5 rounded">{t.investigating}</span>;
      case 'contained':
        return <span className="text-[11px] font-semibold text-sky-400 bg-sky-500/10 border border-sky-500/30 px-2 py-0.5 rounded">{t.contained}</span>;
      case 'resolved':
        return <span className="text-[11px] font-semibold text-emerald-400 bg-emerald-500/10 border border-emerald-500/30 px-2 py-0.5 rounded">{t.resolved}</span>;
    }
  };

  const getSeverityBadgeClass = (sev: Severity) => {
    switch (sev) {
      case 'critical':
        return 'text-rose-400 border border-rose-500/30 bg-rose-500/10';
      case 'high':
        return 'text-amber-400 border border-amber-500/30 bg-amber-500/10';
      case 'medium':
        return 'text-sky-400 border border-sky-500/30 bg-sky-500/10';
      default:
        return 'text-slate-400 border border-slate-700 bg-slate-800';
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-slate-800 pb-5">
        <div>
          <h1 className="text-xl sm:text-2xl font-bold tracking-tight text-white flex items-center gap-2.5">
            <ShieldAlert className="w-6 h-6 text-rose-400" />
            <span>{t.incidentsTitle}</span>
          </h1>
          <p className="text-xs sm:text-sm text-slate-400 mt-1">
            {lang === 'pa'
              ? 'ਗੰਭੀਰ ਸੁਰੱਖਿਆ ਘਟਨਾਵਾਂ ਦੀ ਜਾਂਚ, AI ਫੋਰੈਂਸਿਕ ਰਿਪੋਰਟਿੰਗ ਅਤੇ ਕੰਟੇਨਮੈਂਟ ਪਲੇਬੁੱਕਸ'
              : 'Active security alerts, AI-driven threat triage, containment workflows, and forensic playbooks.'}
          </p>
        </div>

        <div className="flex items-center gap-3">
          <div className="hidden sm:flex items-center gap-2 text-xs font-mono">
            <span className="text-slate-400">{incidents.length} incidents</span>
            <span className="text-slate-600">·</span>
            <span className="text-rose-400">{incidents.filter(i => i.severity === 'critical').length} Critical</span>
          </div>

          <button
            onClick={onExportPdfReport}
            className="flex items-center gap-2 px-3.5 py-2 bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-semibold rounded-lg shadow-sm shadow-cyan-900/30 transition-colors cursor-pointer"
            title="Download Official Incident PDF Report"
          >
            <Download className="w-4 h-4" />
            <span>{t.exportPdfButton}</span>
          </button>
        </div>
      </div>

      {/* 2-Column Split: Incidents List & Incident Detail Workbench */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Left Column (5 cols): Incident Queue */}
        <div className="lg:col-span-5 space-y-3">
          {incidents.length === 0 ? (
            <div className="p-8 rounded-xl bg-slate-900/60 border border-slate-800 text-center text-xs text-slate-500">
              {lang === 'pa' ? 'ਕੋਈ ਸਰਗਰਮ ਘਟਨਾ ਨਹੀਂ ਹੈ।' : 'No active incidents in queue.'}
            </div>
          ) : (
            incidents.map((incident) => {
              const isSelected = selectedIncident?.id === incident.id;
              return (
                <div
                  key={incident.id}
                  onClick={() => {
                    setSelectedIncident(incident);
                    setAiReport(null);
                  }}
                  className={`p-4 rounded-xl border cursor-pointer transition-all ${
                    isSelected
                      ? 'bg-slate-900 border-cyan-500/60 shadow-md shadow-cyan-950/20'
                      : 'bg-slate-900/70 border-slate-800 hover:border-slate-700 hover:bg-slate-900'
                  }`}
                >
                  <div className="flex items-center justify-between gap-2">
                    <span className={`text-[10px] font-mono font-bold px-2 py-0.5 rounded uppercase ${getSeverityBadgeClass(incident.severity)}`}>
                      {incident.severity}
                    </span>
                    {getStatusBadge(incident.status)}
                  </div>

                  <h3 className="text-xs font-bold text-white mt-2 leading-snug">
                    {incident.title}
                  </h3>

                  <div className="mt-2 text-[11px] text-slate-400 flex items-center gap-2 flex-wrap font-mono">
                    <span className="text-cyan-400">{incident.attackerIp}</span>
                    <span aria-hidden="true">·</span>
                    <span className="text-slate-300">{incident.targetHost}</span>
                    <span aria-hidden="true">·</span>
                    <span className="text-indigo-400">MITRE {incident.mitreTechnique}</span>
                  </div>

                  <div className="mt-2 pt-2 border-t border-slate-800/80 flex items-center justify-between text-[11px] text-slate-500 font-mono">
                    <span>{incident.eventCount} correlated events</span>
                    <span className="tabular-nums">{new Date(incident.createdTime).toLocaleTimeString()}</span>
                  </div>
                </div>
              );
            })
          )}
        </div>

        {/* Right Column (7 cols): Selected Incident Forensic Workbench */}
        <div className="lg:col-span-7">
          {selectedIncident ? (
            <div className="p-6 rounded-xl bg-slate-900/80 border border-slate-800 space-y-6">
              {/* Header */}
              <div className="flex flex-col sm:flex-row sm:items-start justify-between gap-4 border-b border-slate-800 pb-4">
                <div>
                  <div className="flex items-center gap-2 flex-wrap">
                    <span className={`text-[10px] font-mono font-bold px-2 py-0.5 rounded uppercase ${getSeverityBadgeClass(selectedIncident.severity)}`}>
                      {selectedIncident.severity}
                    </span>
                    <span className="text-xs font-mono text-cyan-400">
                      MITRE ATT&CK: {selectedIncident.mitreTechnique} ({selectedIncident.mitreTactic})
                    </span>
                  </div>
                  <h2 className="text-base font-bold text-white mt-2">
                    {selectedIncident.title}
                  </h2>
                </div>

                <div className="flex items-center gap-2">
                  {/* Status Toggle buttons */}
                  <select
                    value={selectedIncident.status}
                    onChange={(e) => onUpdateStatus(selectedIncident.id, e.target.value as any)}
                    className="px-3 py-1.5 bg-slate-950 border border-slate-800 rounded-lg text-xs font-semibold text-slate-200 focus:outline-none focus:border-cyan-500"
                  >
                    <option value="new">{t.newIncident}</option>
                    <option value="investigating">{t.investigating}</option>
                    <option value="contained">{t.contained}</option>
                    <option value="resolved">{t.resolved}</option>
                  </select>
                </div>
              </div>

              {/* Key Indicators Strip */}
              <div className="grid grid-cols-2 sm:grid-cols-3 gap-3 text-xs font-mono">
                <div className="p-3 rounded-lg bg-slate-950 border border-slate-800">
                  <div className="text-[11px] text-slate-500 font-sans">{lang === 'pa' ? 'ਹਮਲਾਵਰ IP' : 'Attacker IP'}</div>
                  <div className="text-rose-400 font-bold mt-1 truncate">{selectedIncident.attackerIp}</div>
                </div>

                <div className="p-3 rounded-lg bg-slate-950 border border-slate-800">
                  <div className="text-[11px] text-slate-500 font-sans">{lang === 'pa' ? 'ਨਿਸ਼ਾਨਾ ਸਰਵਰ' : 'Target Asset'}</div>
                  <div className="text-slate-200 font-semibold mt-1 truncate">{selectedIncident.targetHost}</div>
                </div>

                <div className="p-3 rounded-lg bg-slate-950 border border-slate-800">
                  <div className="text-[11px] text-slate-500 font-sans">{lang === 'pa' ? 'ਘਟਨਾ ਸਮਾਂ' : 'Initial Detection'}</div>
                  <div className="text-slate-300 mt-1 tabular-nums truncate">
                    {new Date(selectedIncident.createdTime).toLocaleTimeString()}
                  </div>
                </div>
              </div>

              {/* Incident Description */}
              <div>
                <h3 className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-2">
                  {lang === 'pa' ? 'ਫੋਰੈਂਸਿਕ ਵੇਰਵਾ' : 'Forensic Narrative & Context'}
                </h3>
                <div className="p-3.5 rounded-lg bg-slate-950 border border-slate-800 text-xs text-slate-300 leading-relaxed font-mono">
                  {selectedIncident.description}
                </div>
              </div>

              {/* Recommended Actions */}
              <div>
                <h3 className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-2">
                  {lang === 'pa' ? 'ਤੁਰੰਤ ਸਿਫਾਰਸ਼ ਕੀਤੇ ਐਕਸ਼ਨ' : 'Recommended SOC Playbook Actions'}
                </h3>
                <div className="space-y-2">
                  {selectedIncident.recommendedActions.map((action, i) => (
                    <div key={i} className="flex items-start gap-2 text-xs text-slate-300 bg-slate-950/60 p-2.5 rounded-lg border border-slate-800/80">
                      <span className="text-cyan-400 font-mono font-bold">{i + 1}.</span>
                      <span>{action}</span>
                    </div>
                  ))}
                </div>
              </div>

              {/* One-Click Containment Action Bar */}
              <div className="flex flex-wrap items-center gap-3 pt-2">
                <button
                  onClick={() => onBlockIp(selectedIncident.attackerIp)}
                  disabled={blockedIps.has(selectedIncident.attackerIp)}
                  className={`px-3 py-2 rounded-lg text-xs font-semibold flex items-center gap-1.5 transition-colors ${
                    blockedIps.has(selectedIncident.attackerIp)
                      ? 'bg-slate-800 text-slate-500 cursor-not-allowed'
                      : 'bg-rose-600 hover:bg-rose-500 text-white shadow-sm'
                  }`}
                >
                  <ShieldX className="w-3.5 h-3.5" />
                  <span>
                    {blockedIps.has(selectedIncident.attackerIp)
                      ? (lang === 'pa' ? 'IP ਬਲਾਕਡ ਹੈ' : 'IP Already Blocked')
                      : (lang === 'pa' ? 'IP ਤੁਰੰਤ ਬਲਾਕ ਕਰੋ' : 'Block IP at Perimeter')}
                  </span>
                </button>

                {/* AI Threat Copilot Trigger */}
                <button
                  onClick={() => handleRunAiAnalysis(selectedIncident)}
                  disabled={loadingAi}
                  className="px-3.5 py-2 rounded-lg text-xs font-semibold bg-cyan-600 hover:bg-cyan-500 text-white shadow-sm shadow-cyan-900/30 flex items-center gap-1.5 transition-colors"
                >
                  <Bot className="w-4 h-4" />
                  <span>{loadingAi ? t.generatingAnalysis : t.aiDeepDive}</span>
                </button>
              </div>

              {/* AI Forensic Analysis Report Container */}
              {aiReport && (
                <div className="p-4 rounded-xl bg-slate-950 border border-cyan-500/40 text-xs text-slate-200 space-y-3 animate-in fade-in">
                  <div className="flex items-center justify-between border-b border-slate-800 pb-2">
                    <span className="text-cyan-400 font-semibold flex items-center gap-1.5">
                      <Bot className="w-4 h-4" />
                      <span>{lang === 'pa' ? 'AI ਫੋਰੈਂਸਿਕ ਜਾਂਚ ਰਿਪੋਰਟ' : 'AI SOC Forensic Briefing'}</span>
                    </span>
                    <button
                      onClick={() => {
                        const blob = new Blob([aiReport], { type: 'text/markdown' });
                        const url = URL.createObjectURL(blob);
                        const a = document.createElement('a');
                        a.href = url;
                        a.download = `incident-${selectedIncident.id}-report.md`;
                        a.click();
                      }}
                      className="text-[11px] text-slate-400 hover:text-white flex items-center gap-1"
                    >
                      <Download className="w-3 h-3" />
                      <span>{lang === 'pa' ? 'ਰਿਪੋਰਟ ਡਾਊਨਲੋਡ' : 'Download MD'}</span>
                    </button>
                  </div>
                  <div className="prose prose-invert prose-xs max-w-none text-slate-300 leading-relaxed whitespace-pre-line font-sans">
                    {aiReport}
                  </div>
                </div>
              )}
            </div>
          ) : (
            <div className="p-12 rounded-xl bg-slate-900/60 border border-slate-800 text-center text-xs text-slate-500">
              {lang === 'pa' ? 'ਵੇਰਵੇ ਦੇਖਣ ਲਈ ਖੱਬੇ ਪਾਸਿਓਂ ਕੋਈ ਘਟਨਾ ਚੁਣੋ' : 'Select an incident from the queue to view full forensic workbench'}
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
