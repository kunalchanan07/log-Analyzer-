import React, { useState, useMemo } from 'react';
import { 
  Search, 
  Filter, 
  Download, 
  ExternalLink, 
  RotateCcw,
  ShieldAlert,
  ChevronLeft,
  ChevronRight,
  Database
} from 'lucide-react';
import { LogEntry, Severity, LogSource } from '../types/soc';
import { Language, TRANSLATIONS } from '../utils/i18n';

interface LogExplorerProps {
  logs: LogEntry[];
  lang: Language;
  onSelectLog: (log: LogEntry) => void;
}

export const LogExplorer: React.FC<LogExplorerProps> = ({ logs, lang, onSelectLog }) => {
  const t = TRANSLATIONS[lang];

  const [searchQuery, setSearchQuery] = useState('');
  const [selectedSeverity, setSelectedSeverity] = useState<Severity | 'all'>('all');
  const [selectedSource, setSelectedSource] = useState<LogSource | 'all'>('all');
  const [statusFilter, setStatusFilter] = useState<'all' | 'malicious' | 'clean'>('all');
  const [page, setPage] = useState(1);
  const pageSize = 20;

  // Filter logs based on inputs
  const filteredLogs = useMemo(() => {
    return logs.filter(log => {
      // Free text search
      if (searchQuery.trim()) {
        const query = searchQuery.toLowerCase();
        const matchesQuery = 
          log.raw.toLowerCase().includes(query) ||
          log.sourceIp.toLowerCase().includes(query) ||
          log.sourceHost.toLowerCase().includes(query) ||
          (log.user && log.user.toLowerCase().includes(query)) ||
          (log.ruleMatched && log.ruleMatched.name.toLowerCase().includes(query)) ||
          (log.ruleMatched && log.ruleMatched.mitreId.toLowerCase().includes(query));
        if (!matchesQuery) return false;
      }

      // Severity filter
      if (selectedSeverity !== 'all' && log.severity !== selectedSeverity) {
        return false;
      }

      // Source filter
      if (selectedSource !== 'all' && log.source !== selectedSource) {
        return false;
      }

      // Status filter
      if (statusFilter === 'malicious' && !log.isMalicious && !log.isSuspicious) {
        return false;
      }
      if (statusFilter === 'clean' && (log.isMalicious || log.isSuspicious)) {
        return false;
      }

      return true;
    });
  }, [logs, searchQuery, selectedSeverity, selectedSource, statusFilter]);

  const totalPages = Math.ceil(filteredLogs.length / pageSize) || 1;
  const paginatedLogs = filteredLogs.slice((page - 1) * pageSize, page * pageSize);

  const resetFilters = () => {
    setSearchQuery('');
    setSelectedSeverity('all');
    setSelectedSource('all');
    setStatusFilter('all');
    setPage(1);
  };

  const handleExportCsv = () => {
    const headers = ['Timestamp', 'Severity', 'Source', 'Host', 'Source IP', 'Category', 'MITRE ID', 'Raw Message'];
    const rows = filteredLogs.map(l => [
      `"${l.timestamp}"`,
      `"${l.severity}"`,
      `"${l.source}"`,
      `"${l.sourceHost}"`,
      `"${l.sourceIp}"`,
      `"${l.category}"`,
      `"${l.ruleMatched?.mitreId || 'N/A'}"`,
      `"${l.raw.replace(/"/g, '""')}"`
    ]);

    const csvContent = [headers.join(','), ...rows.map(r => r.join(','))].join('\n');
    const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.setAttribute('href', url);
    link.setAttribute('download', `soc-logs-export-${new Date().toISOString().slice(0, 10)}.csv`);
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
      case 'low':
        return 'text-slate-400 bg-slate-800 border-slate-700';
      default:
        return 'text-emerald-400 bg-emerald-500/10 border-emerald-500/30';
    }
  };

  return (
    <div className="space-y-6">
      {/* Page Title & Export */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-slate-800 pb-5">
        <div>
          <h1 className="text-xl sm:text-2xl font-bold tracking-tight text-white flex items-center gap-2.5">
            <Database className="w-6 h-6 text-cyan-400" />
            <span>{t.explorerTitle}</span>
          </h1>
          <p className="text-xs sm:text-sm text-slate-400 mt-1">
            {lang === 'pa' 
              ? 'ਸਾਰੇ ਇੰਟਰਪ੍ਰਾਈਜ਼ ਲੌਗਸ ਨੂੰ ਖੋਜੋ, ਫਿਲਟਰ ਕਰੋ ਅਤੇ ਸ਼ੱਕੀ ਘਟਨਾਵਾਂ ਦਾ ਫੋਰੈਂਸਿਕ ਵਿਸ਼ਲੇਸ਼ਣ ਕਰੋ' 
              : 'Search across all enterprise log sources, apply multi-dimensional filters, and inspect payload signatures.'}
          </p>
        </div>

        <div className="flex items-center gap-3">
          <button
            onClick={handleExportCsv}
            className="flex items-center gap-1.5 px-3 py-2 bg-slate-900 border border-slate-800 hover:border-slate-700 text-slate-200 text-xs font-semibold rounded-lg transition-colors"
          >
            <Download className="w-3.5 h-3.5" />
            <span>{lang === 'pa' ? 'CSV ਐਕਸਪੋਰਟ' : 'Export CSV'}</span>
          </button>
        </div>
      </div>

      {/* Filter and Search Bar */}
      <div className="p-4 rounded-xl bg-slate-900/80 border border-slate-800 space-y-3">
        <div className="flex flex-col md:flex-row items-center gap-3">
          {/* Free Text Search */}
          <div className="relative w-full md:flex-1">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-500" />
            <input
              type="text"
              value={searchQuery}
              onChange={(e) => {
                setSearchQuery(e.target.value);
                setPage(1);
              }}
              placeholder={t.searchPlaceholder}
              className="w-full pl-9 pr-4 py-2 rounded-lg bg-slate-950 border border-slate-800 text-xs text-white placeholder:text-slate-600 focus:outline-none focus:border-cyan-500 transition-colors font-mono"
            />
          </div>

          {/* Quick Filters */}
          <div className="flex items-center gap-2 w-full md:w-auto flex-wrap">
            {/* Severity dropdown */}
            <select
              value={selectedSeverity}
              onChange={(e) => {
                setSelectedSeverity(e.target.value as any);
                setPage(1);
              }}
              className="px-3 py-2 bg-slate-950 border border-slate-800 rounded-lg text-xs text-slate-300 focus:outline-none focus:border-cyan-500"
            >
              <option value="all">{t.allSeverities}</option>
              <option value="critical">{t.critical}</option>
              <option value="high">{t.high}</option>
              <option value="medium">{t.medium}</option>
              <option value="low">{t.low}</option>
              <option value="info">{t.info}</option>
            </select>

            {/* Source dropdown */}
            <select
              value={selectedSource}
              onChange={(e) => {
                setSelectedSource(e.target.value as any);
                setPage(1);
              }}
              className="px-3 py-2 bg-slate-950 border border-slate-800 rounded-lg text-xs text-slate-300 focus:outline-none focus:border-cyan-500"
            >
              <option value="all">{t.allSources}</option>
              <option value="web">Web (Nginx/HTTP)</option>
              <option value="auth">Linux Auth (SSHD)</option>
              <option value="firewall">Firewall (CEF)</option>
              <option value="edr">Endpoint EDR</option>
              <option value="cloudtrail">AWS CloudTrail</option>
              <option value="syslog">Syslog</option>
            </select>

            {/* Status dropdown */}
            <select
              value={statusFilter}
              onChange={(e) => {
                setStatusFilter(e.target.value as any);
                setPage(1);
              }}
              className="px-3 py-2 bg-slate-950 border border-slate-800 rounded-lg text-xs text-slate-300 focus:outline-none focus:border-cyan-500"
            >
              <option value="all">{t.allStatuses}</option>
              <option value="malicious">{t.onlyMalicious}</option>
              <option value="clean">{t.onlyClean}</option>
            </select>

            {/* Reset */}
            <button
              onClick={resetFilters}
              className="p-2 bg-slate-950 border border-slate-800 rounded-lg text-slate-400 hover:text-white transition-colors"
              title="Reset Filters"
            >
              <RotateCcw className="w-3.5 h-3.5" />
            </button>
          </div>
        </div>

        {/* Filter Results Summary */}
        <div className="flex items-center justify-between text-xs text-slate-400 pt-2 border-t border-slate-800/60">
          <div>
            <span>{lang === 'pa' ? 'ਦਿਖਾਏ ਗਏ ਲੌਗਸ:' : 'Showing:'}</span>{' '}
            <span className="font-mono tabular-nums text-white font-semibold">
              {filteredLogs.length}
            </span>{' '}
            <span>{lang === 'pa' ? 'ਵਿੱਚੋਂ' : 'of'}</span>{' '}
            <span className="font-mono tabular-nums text-slate-300">{logs.length}</span>{' '}
            <span>{lang === 'pa' ? 'ਕੁੱਲ' : 'total'}</span>
          </div>

          <div className="flex items-center gap-2">
            <span className="text-[11px] text-rose-400 font-mono">
              {filteredLogs.filter(l => l.isMalicious).length} Malicious
            </span>
            <span className="text-slate-600">·</span>
            <span className="text-[11px] text-amber-400 font-mono">
              {filteredLogs.filter(l => l.isSuspicious).length} Suspicious
            </span>
          </div>
        </div>
      </div>

      {/* High-Density Log Table */}
      <div className="rounded-xl bg-slate-900/80 border border-slate-800 overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs border-collapse">
            <thead>
              <tr className="border-b border-slate-800 bg-slate-950/70 text-slate-400 font-medium">
                <th className="py-3 px-4 font-normal">{t.tabularTimestamp}</th>
                <th className="py-3 px-3 font-normal">{t.tabularSeverity}</th>
                <th className="py-3 px-3 font-normal">{t.tabularSource}</th>
                <th className="py-3 px-4 font-normal">{t.tabularHost}</th>
                <th className="py-3 px-4 font-normal">{t.tabularIp}</th>
                <th className="py-3 px-4 font-normal">{t.tabularCategory}</th>
                <th className="py-3 px-4 font-normal">{t.tabularMitre}</th>
                <th className="py-3 px-4 font-normal text-right">{t.tabularActions}</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 font-mono">
              {paginatedLogs.length === 0 ? (
                <tr>
                  <td colSpan={8} className="py-12 text-center text-slate-500 font-sans text-xs">
                    {t.noLogsFound}
                  </td>
                </tr>
              ) : (
                paginatedLogs.map((log) => (
                  <tr
                    key={log.id}
                    onClick={() => onSelectLog(log)}
                    className="hover:bg-slate-800/40 cursor-pointer transition-colors group"
                  >
                    <td className="py-2.5 px-4 tabular-nums text-slate-400 whitespace-nowrap text-[11px]">
                      {new Date(log.timestamp).toLocaleTimeString()}
                    </td>

                    <td className="py-2.5 px-3 whitespace-nowrap">
                      <span className={`text-[10px] font-bold px-2 py-0.5 rounded border ${getSeverityBadgeClass(log.severity)}`}>
                        {log.severity.toUpperCase()}
                      </span>
                    </td>

                    <td className="py-2.5 px-3 text-slate-300 font-sans text-xs capitalize whitespace-nowrap">
                      {log.source}
                    </td>

                    <td className="py-2.5 px-4 text-slate-200 whitespace-nowrap text-xs">
                      {log.sourceHost}
                    </td>

                    <td className="py-2.5 px-4 text-cyan-400 whitespace-nowrap text-xs">
                      {log.sourceIp}
                    </td>

                    <td className="py-2.5 px-4 font-sans text-xs text-slate-200 whitespace-nowrap">
                      {log.ruleMatched ? (
                        <span className="text-white font-medium group-hover:text-cyan-300 transition-colors">
                          {log.ruleMatched.name}
                        </span>
                      ) : (
                        <span className="text-slate-400">Normal Request</span>
                      )}
                    </td>

                    <td className="py-2.5 px-4 whitespace-nowrap text-xs">
                      {log.ruleMatched?.mitreId ? (
                        <span className="text-indigo-400 font-mono">
                          {log.ruleMatched.mitreId}
                        </span>
                      ) : (
                        <span className="text-slate-600">—</span>
                      )}
                    </td>

                    <td className="py-2.5 px-4 text-right whitespace-nowrap">
                      <button
                        onClick={(e) => {
                          e.stopPropagation();
                          onSelectLog(log);
                        }}
                        className="text-slate-400 hover:text-cyan-400 text-xs flex items-center gap-1 ml-auto font-sans"
                        aria-label="Inspect log details"
                      >
                        <span>{t.details}</span>
                        <ExternalLink className="w-3.5 h-3.5" />
                      </button>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>

        {/* Pagination Strip */}
        <div className="p-3 border-t border-slate-800 bg-slate-950/40 flex items-center justify-between text-xs text-slate-400">
          <div>
            <span>Page</span>{' '}
            <span className="font-mono tabular-nums text-white">{page}</span>{' '}
            <span>of</span>{' '}
            <span className="font-mono tabular-nums text-white">{totalPages}</span>
          </div>

          <div className="flex items-center gap-1.5">
            <button
              onClick={() => setPage(p => Math.max(1, p - 1))}
              disabled={page === 1}
              className={`p-1.5 rounded border border-slate-800 ${
                page === 1 ? 'text-slate-600 cursor-not-allowed' : 'text-slate-300 hover:bg-slate-800 hover:text-white'
              }`}
              aria-label="Previous Page"
            >
              <ChevronLeft className="w-4 h-4" />
            </button>
            <button
              onClick={() => setPage(p => Math.min(totalPages, p + 1))}
              disabled={page === totalPages}
              className={`p-1.5 rounded border border-slate-800 ${
                page === totalPages ? 'text-slate-600 cursor-not-allowed' : 'text-slate-300 hover:bg-slate-800 hover:text-white'
              }`}
              aria-label="Next Page"
            >
              <ChevronRight className="w-4 h-4" />
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};
