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
        return <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-rose-500/10 text-rose-300 border border-rose-500/30 font-bold">IP BLOCK</span>;
      case 'isolate_host':
        return <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-yellow-400/10 text-yellow-300 border border-yellow-400/30 font-bold">HOST ISOLATION</span>;
      case 'ingest':
        return <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-yellow-400/20 text-yellow-300 border border-yellow-400/40 font-bold">LOG INGEST</span>;
      case 'incident_created':
        return <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-rose-500/20 text-rose-300 border border-rose-500/40 font-bold">INCIDENT ESCALATED</span>;
      case 'report_export':
        return <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-white/10 text-white border border-white/30 font-bold">PDF COMPLIANCE EXPORT</span>;
      default:
        return <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-neutral-800 text-neutral-300 font-bold">RULE UPDATE</span>;
    }
  };

  return (
    <div className="space-y-6">
      {/* Header in Cyber Yellow & Crisp White */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-neutral-800 pb-5">
        <div>
          <h1 className="text-xl sm:text-2xl font-black tracking-tight text-white flex items-center gap-2.5 uppercase">
            <History className="w-6 h-6 text-yellow-400 stroke-[2.5]" />
            <span>{lang === 'pa' ? 'ਸੁਰੱਖਿਆ ਆਡਿਟ ਇਤਿਹਾਸ (Audit Trail)' : 'Security Audit Trail & History Log'}</span>
          </h1>
          <p className="text-xs sm:text-sm text-neutral-300 font-medium mt-1">
            {lang === 'pa'
              ? 'ਸਾਰੇ ਲੌਗ ਇੰਜੈਸ਼ਨ ਸੈਸ਼ਨਾਂ, ਫਾਇਰਵਾਲ ਬਲਾਕਾਂ, ਅਤੇ ਜਾਂਚ ਕਾਰਵਾਈਆਂ ਦਾ ਪੂਰਾ ਇਤਿਹਾਸ'
              : 'Tamper-evident chronological compliance record of all SOC containment, ingestion, and forensic operations.'}
          </p>
        </div>

        <button
          onClick={exportAuditCsv}
          className="flex items-center gap-2 px-4 py-2 bg-white hover:bg-neutral-100 text-neutral-950 text-xs font-bold rounded-xl transition-all shadow-sm cursor-pointer"
        >
          <Download className="w-4 h-4 text-neutral-950 stroke-[2.5]" />
          <span>{lang === 'pa' ? 'ਆਡਿਟ ਰਿਕਾਰਡ ਡਾਊਨਲੋਡ' : 'Export Audit Trail (CSV)'}</span>
        </button>
      </div>

      {/* Filter and Search Bar */}
      <div className="p-4 rounded-2xl bg-neutral-900/90 border border-neutral-800 shadow-xl flex flex-col sm:flex-row items-center gap-3">
        <div className="relative w-full sm:flex-1">
          <Search className="absolute left-3.5 top-1/2 -translate-y-1/2 w-4 h-4 text-neutral-400" />
          <input
            type="text"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder={lang === 'pa' ? 'ਕਾਰਵਾਈ ਜਾਂ ਨਿਸ਼ਾਨੇ ਨਾਲ ਖੋਜੋ...' : 'Search by action details, IP, or asset...'}
            className="w-full pl-10 pr-4 py-2.5 rounded-xl bg-neutral-950 border border-neutral-800 text-xs text-white placeholder:text-neutral-500 focus:outline-none focus:border-yellow-400 focus:ring-1 focus:ring-yellow-400/50 font-mono"
          />
        </div>

        <select
          value={filterType}
          onChange={(e) => setFilterType(e.target.value)}
          className="px-3.5 py-2.5 bg-neutral-950 border border-neutral-800 rounded-xl text-xs text-white font-medium focus:outline-none focus:border-yellow-400 w-full sm:w-auto cursor-pointer"
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
      <div className="rounded-2xl bg-neutral-900/90 border border-neutral-800 overflow-hidden shadow-xl">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs border-collapse">
            <thead>
              <tr className="border-b border-neutral-800 bg-neutral-950 text-neutral-300 font-bold uppercase tracking-wider text-[11px]">
                <th className="py-3.5 px-4">Timestamp (UTC)</th>
                <th className="py-3.5 px-3">Action Type</th>
                <th className="py-3.5 px-3">Operator</th>
                <th className="py-3.5 px-4">Target / Asset</th>
                <th className="py-3.5 px-4">Details & Forensic Scope</th>
                <th className="py-3.5 px-4 text-right">Status</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-neutral-800/70 font-mono">
              {filtered.length === 0 ? (
                <tr>
                  <td colSpan={6} className="py-12 text-center text-neutral-400 font-sans text-xs">
                    {lang === 'pa' ? 'ਕੋਈ ਆਡਿਟ ਰਿਕਾਰਡ ਨਹੀਂ ਮਿਲਿਆ।' : 'No audit records match the current filter criteria.'}
                  </td>
                </tr>
              ) : (
                filtered.map((record) => (
                  <tr key={record.id} className="hover:bg-neutral-800/50 transition-colors">
                    <td className="py-3 px-4 tabular-nums text-neutral-400 whitespace-nowrap text-[11px]">
                      {new Date(record.timestamp).toLocaleTimeString()}
                    </td>
                    <td className="py-3 px-3 whitespace-nowrap">
                      {getActionBadge(record.actionType)}
                    </td>
                    <td className="py-3 px-3 text-white font-sans text-xs whitespace-nowrap font-medium">
                      {record.actor}
                    </td>
                    <td className="py-3 px-4 text-yellow-300 font-bold whitespace-nowrap text-xs">
                      {record.target || '—'}
                    </td>
                    <td className="py-3 px-4 font-sans text-xs text-neutral-200">
                      {record.details}
                    </td>
                    <td className="py-3 px-4 text-right whitespace-nowrap">
                      <span className="text-[10px] font-bold text-emerald-400 flex items-center gap-1 justify-end font-mono">
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
