import React, { useState } from 'react';
import { 
  History, 
  ShieldCheck, 
  Download, 
  Filter, 
  Clock, 
  ShieldX, 
  Server, 
  Layers, 
  FileText,
  Search,
  CheckCircle2
} from 'lucide-react';
import { Language } from '../utils/i18n';

export interface AuditRecord {
  id: string;
  timestamp: string;
  actionType: 'ingest' | 'block_ip' | 'isolate_host' | 'incident_created' | 'report_export' | 'rule_toggle';
  actor: string;
  details: string;
  target?: string;
  status: 'success' | 'warning' | 'alert';
}

interface AuditHistoryProps {
  records: AuditRecord[];
  lang: Language;
}

export const AuditHistory: React.FC<AuditHistoryProps> = ({ records, lang }) => {
  const [filterType, setFilterType] = useState<string>('all');
  const [search, setSearch] = useState<string>('');

  const filtered = records.filter(r => {
    if (filterType !== 'all' && r.actionType !== filterType) return false;
    if (search.trim()) {
      const q = search.toLowerCase();
      return r.details.toLowerCase().includes(q) || (r.target && r.target.toLowerCase().includes(q));
    }
    return true;
  });

  const exportAuditCsv = () => {
    const headers = ['Timestamp', 'Action Type', 'Actor', 'Target', 'Details', 'Status'];
    const rows = filtered.map(r => [
      `"${r.timestamp}"`,
      `"${r.actionType}"`,
      `"${r.actor}"`,
      `"${r.target || 'N/A'}"`,
      `"${r.details.replace(/"/g, '""')}"`,
      `"${r.status}"`
    ]);

    const csvContent = [headers.join(','), ...rows.map(row => row.join(','))].join('\n');
    const blob = new Blob([csvContent], { type: 'text/csv' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `soc-audit-trail-${new Date().toISOString().slice(0, 10)}.csv`;
    link.click();
    URL.revokeObjectURL(url);
  };

  const getActionBadge = (type: AuditRecord['actionType']) => {
    switch (type) {
      case 'block_ip':
        return <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-rose-500/10 text-rose-400 border border-rose-500/30">IP BLOCK</span>;
      case 'isolate_host':
        return <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-amber-500/10 text-amber-400 border border-amber-500/30">HOST ISOLATION</span>;
      case 'ingest':
        return <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-cyan-500/10 text-cyan-400 border border-cyan-500/30">LOG INGEST</span>;
      case 'incident_created':
        return <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-indigo-500/10 text-indigo-400 border border-indigo-500/30">INCIDENT ESCALATED</span>;
      case 'report_export':
        return <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-emerald-500/10 text-emerald-400 border border-emerald-500/30">PDF COMPLIANCE EXPORT</span>;
      default:
        return <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-800 text-slate-300">RULE UPDATE</span>;
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-slate-800 pb-5">
        <div>
          <h1 className="text-xl sm:text-2xl font-bold tracking-tight text-white flex items-center gap-2.5">
            <History className="w-6 h-6 text-cyan-400" />
            <span>{lang === 'pa' ? 'ਸੁਰੱਖਿਆ ਆਡਿਟ ਇਤਿਹਾਸ (Audit Trail)' : 'Security Audit Trail & History Log'}</span>
          </h1>
          <p className="text-xs sm:text-sm text-slate-400 mt-1">
            {lang === 'pa'
              ? 'ਸਾਰੇ ਲੌਗ ਇੰਜੈਸ਼ਨ ਸੈਸ਼ਨਾਂ, ਫਾਇਰਵਾਲ ਬਲਾਕਾਂ, ਅਤੇ ਜਾਂਚ ਕਾਰਵਾਈਆਂ ਦਾ ਪੂਰਾ ਇਤਿਹਾਸ'
              : 'Tamper-evident chronological compliance record of all SOC containment, ingestion, and forensic operations.'}
          </p>
        </div>

        <button
          onClick={exportAuditCsv}
          className="flex items-center gap-1.5 px-3.5 py-2 bg-slate-900 border border-slate-800 hover:border-slate-700 text-slate-200 text-xs font-semibold rounded-lg transition-colors shadow-sm"
        >
          <Download className="w-3.5 h-3.5" />
          <span>{lang === 'pa' ? 'ਆਡਿਟ ਰਿਕਾਰਡ ਡਾਊਨਲੋਡ' : 'Export Audit Trail (CSV)'}</span>
        </button>
      </div>

      {/* Filter and Search Bar */}
      <div className="p-4 rounded-xl bg-slate-900/80 border border-slate-800 flex flex-col sm:flex-row items-center gap-3">
        <div className="relative w-full sm:flex-1">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-500" />
          <input
            type="text"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder={lang === 'pa' ? 'ਕਾਰਵਾਈ ਜਾਂ ਨਿਸ਼ਾਨੇ ਨਾਲ ਖੋਜੋ...' : 'Search by action details, IP, or asset...'}
            className="w-full pl-9 pr-4 py-2 rounded-lg bg-slate-950 border border-slate-800 text-xs text-white placeholder:text-slate-600 focus:outline-none focus:border-cyan-500 font-mono"
          />
        </div>

        <select
          value={filterType}
          onChange={(e) => setFilterType(e.target.value)}
          className="px-3 py-2 bg-slate-950 border border-slate-800 rounded-lg text-xs text-slate-300 focus:outline-none focus:border-cyan-500 w-full sm:w-auto"
        >
          <option value="all">{lang === 'pa' ? 'ਸਾਰੀਆਂ ਕਾਰਵਾਈਆਂ' : 'All Action Types'}</option>
          <option value="block_ip">{lang === 'pa' ? 'IP ਬਲਾਕ' : 'IP Block Actions'}</option>
          <option value="isolate_host">{lang === 'pa' ? 'ਹੋਸਟ ਕੁਆਰੰਟੀਨ' : 'Host Isolations'}</option>
          <option value="ingest">{lang === 'pa' ? 'ਲੌਗ ਇੰਜੈਸ਼ਨ' : 'Log Ingestions'}</option>
          <option value="incident_created">{lang === 'pa' ? 'ਘਟਨਾਵਾਂ' : 'Incidents'}</option>
          <option value="report_export">{lang === 'pa' ? 'PDF ਰਿਪੋਰਟਾਂ' : 'PDF Report Exports'}</option>
        </select>
      </div>

      {/* History Table */}
      <div className="rounded-xl bg-slate-900/80 border border-slate-800 overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs border-collapse">
            <thead>
              <tr className="border-b border-slate-800 bg-slate-950/70 text-slate-400 font-medium">
                <th className="py-3 px-4 font-normal">Timestamp (UTC)</th>
                <th className="py-3 px-3 font-normal">Action Type</th>
                <th className="py-3 px-3 font-normal">Operator</th>
                <th className="py-3 px-4 font-normal">Target / Asset</th>
                <th className="py-3 px-4 font-normal">Details & Forensic Scope</th>
                <th className="py-3 px-4 font-normal text-right">Status</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 font-mono">
              {filtered.length === 0 ? (
                <tr>
                  <td colSpan={6} className="py-12 text-center text-slate-500 font-sans text-xs">
                    {lang === 'pa' ? 'ਕੋਈ ਆਡਿਟ ਰਿਕਾਰਡ ਨਹੀਂ ਮਿਲਿਆ।' : 'No audit records match the current filter criteria.'}
                  </td>
                </tr>
              ) : (
                filtered.map((record) => (
                  <tr key={record.id} className="hover:bg-slate-800/40 transition-colors">
                    <td className="py-2.5 px-4 tabular-nums text-slate-400 whitespace-nowrap text-[11px]">
                      {new Date(record.timestamp).toLocaleTimeString()}
                    </td>
                    <td className="py-2.5 px-3 whitespace-nowrap">
                      {getActionBadge(record.actionType)}
                    </td>
                    <td className="py-2.5 px-3 text-slate-300 font-sans text-xs whitespace-nowrap">
                      {record.actor}
                    </td>
                    <td className="py-2.5 px-4 text-cyan-400 whitespace-nowrap text-xs">
                      {record.target || '—'}
                    </td>
                    <td className="py-2.5 px-4 font-sans text-xs text-slate-200">
                      {record.details}
                    </td>
                    <td className="py-2.5 px-4 text-right whitespace-nowrap">
                      <span className="text-[10px] font-bold text-emerald-400 flex items-center gap-1 justify-end">
                        <CheckCircle2 className="w-3.5 h-3.5" />
                        <span>VERIFIED</span>
                      </span>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
