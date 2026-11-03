import React, { useState, useMemo, useEffect } from 'react';
import { 
  Search, 
  Filter, 
  Download, 
  ExternalLink, 
  RotateCcw, 
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
  initialQuery?: string;
}

export const LogExplorer: React.FC<LogExplorerProps> = ({ logs, lang, onSelectLog, initialQuery }) => {
  const t = TRANSLATIONS[lang];

  const [searchQuery, setSearchQuery] = useState(initialQuery || '');
  const [selectedSeverity, setSelectedSeverity] = useState<Severity | 'all'>('all');
  const [selectedSource, setSelectedSource] = useState<LogSource | 'all'>('all');
  const [statusFilter, setStatusFilter] = useState<'all' | 'malicious' | 'clean'>('all');
  const [page, setPage] = useState(1);
  const pageSize = 20;

  useEffect(() => {
    if (initialQuery !== undefined) {
      setSearchQuery(initialQuery);
      setPage(1);
    }
  }, [initialQuery]);

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

    const csvContent = 'data:text/csv;charset=utf-8,' + [headers.join(','), ...rows.map(e => e.join(','))].join('\n');
    const encodedUri = encodeURI(csvContent);
    const link = document.createElement('a');
    link.setAttribute('href', encodedUri);
    link.setAttribute('download', `soc_telemetry_logs_${new Date().toISOString().slice(0, 10)}.csv`);
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  };

  const getSeverityBadgeClass = (sev: Severity) => {
    switch (sev) {
      case 'critical':
        return 'text-rose-400 bg-rose-500/10 border-rose-500/30';
      case 'high':
        return 'text-yellow-400 bg-yellow-400/10 border-yellow-400/30 font-bold';
      case 'medium':
        return 'text-amber-300 bg-amber-400/10 border-amber-400/30';
      case 'low':
        return 'text-neutral-400 bg-neutral-800 border-neutral-700';
      default:
        return 'text-emerald-400 bg-emerald-500/10 border-emerald-500/30';
    }
  };

  return (
    <div className="space-y-6">
      {/* Page Title & Export in Cyber Yellow & Crisp White */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-neutral-800 pb-5">
        <div>
          <h1 className="text-xl sm:text-2xl font-black tracking-tight text-white flex items-center gap-2.5 uppercase">
            <Database className="w-6 h-6 text-yellow-400 stroke-[2.5]" />
            <span>{t.explorerTitle}</span>
          </h1>
          <p className="text-xs sm:text-sm text-neutral-300 font-medium mt-1">
            {lang === 'pa' 
              ? 'ਸਾਰੇ ਇੰਟਰਪ੍ਰਾਈਜ਼ ਲੌਗਸ ਨੂੰ ਖੋਜੋ, ਫਿਲਟਰ ਕਰੋ ਅਤੇ ਸ਼ੱਕੀ ਘਟਨਾਵਾਂ ਦਾ ਫੋਰੈਂਸਿਕ ਵਿਸ਼ਲੇਸ਼ਣ ਕਰੋ' 
              : 'Search across all enterprise log sources, apply multi-dimensional filters, and inspect payload signatures.'}
          </p>
        </div>

        <div className="flex items-center gap-3">
          <button
            onClick={handleExportCsv}
            className="flex items-center gap-1.5 px-3.5 py-2 bg-white hover:bg-neutral-100 text-neutral-950 text-xs font-bold rounded-xl transition-all shadow-sm cursor-pointer"
          >
            <Download className="w-3.5 h-3.5 text-neutral-950 stroke-[2.5]" />
            <span>{lang === 'pa' ? 'CSV ਐਕਸਪੋਰਟ' : 'Export CSV'}</span>
          </button>
        </div>
      </div>

      {/* Filter and Search Bar */}
      <div className="p-4 rounded-2xl bg-neutral-900/90 border border-neutral-800 shadow-xl space-y-3">
        <div className="flex flex-col md:flex-row items-center gap-3">
          {/* Free Text Search with Yellow Focus Ring */}
          <div className="relative w-full md:flex-1">
            <Search className="absolute left-3.5 top-1/2 -translate-y-1/2 w-4 h-4 text-neutral-400" />
            <input
              type="text"
              value={searchQuery}
              onChange={(e) => {
                setSearchQuery(e.target.value);
                setPage(1);
              }}
              placeholder={t.searchPlaceholder}
              className="w-full pl-10 pr-4 py-2.5 rounded-xl bg-neutral-950 border border-neutral-800 text-xs text-white placeholder:text-neutral-500 focus:outline-none focus:border-yellow-400 focus:ring-1 focus:ring-yellow-400/50 transition-colors font-mono"
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
              className="px-3 py-2 bg-neutral-950 border border-neutral-800 rounded-xl text-xs text-white focus:outline-none focus:border-yellow-400 font-medium"
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
              className="px-3 py-2 bg-neutral-950 border border-neutral-800 rounded-xl text-xs text-white focus:outline-none focus:border-yellow-400 font-medium"
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
              className="px-3 py-2 bg-neutral-950 border border-neutral-800 rounded-xl text-xs text-white focus:outline-none focus:border-yellow-400 font-medium"
            >
              <option value="all">{t.allStatuses}</option>
              <option value="malicious">{t.onlyMalicious}</option>
              <option value="clean">{t.onlyClean}</option>
            </select>

            {/* Reset */}
            <button
              onClick={resetFilters}
              className="p-2.5 bg-neutral-950 border border-neutral-800 rounded-xl text-neutral-300 hover:text-white hover:border-yellow-400 transition-colors cursor-pointer"
              title="Reset Filters"
            >
              <RotateCcw className="w-3.5 h-3.5" />
            </button>
          </div>
        </div>

        {/* Filter Results Summary */}
        <div className="flex items-center justify-between text-xs text-neutral-400 pt-2 border-t border-neutral-800">
          <div>
            <span>{lang === 'pa' ? 'ਦਿਖਾਏ ਗਏ ਲੌਗਸ:' : 'Showing:'}</span>{' '}
            <span className="font-mono tabular-nums text-white font-bold">
              {filteredLogs.length}
            </span>{' '}
            <span>{lang === 'pa' ? 'ਵਿੱਚੋਂ' : 'of'}</span>{' '}
            <span className="font-mono tabular-nums text-neutral-300">{logs.length}</span>{' '}
            <span>{lang === 'pa' ? 'ਕੁੱਲ' : 'total'}</span>
          </div>

          <div className="flex items-center gap-2">
            <span className="text-[11px] text-rose-400 font-mono font-bold">
              {filteredLogs.filter(l => l.isMalicious).length} Malicious
            </span>
            <span className="text-neutral-600">·</span>
            <span className="text-[11px] text-yellow-400 font-mono font-bold">
              {filteredLogs.filter(l => l.isSuspicious).length} Suspicious
            </span>
          </div>
        </div>
      </div>

      {/* High-Density Log Table */}
      <div className="rounded-2xl bg-neutral-900/90 border border-neutral-800 overflow-hidden shadow-xl">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs border-collapse">
            <thead>
              <tr className="border-b border-neutral-800 bg-neutral-950 text-neutral-300 font-bold uppercase tracking-wider text-[11px]">
                <th className="py-3.5 px-4">{t.tabularTimestamp}</th>
                <th className="py-3.5 px-3">{t.tabularSeverity}</th>
                <th className="py-3.5 px-3">{t.tabularSource}</th>
                <th className="py-3.5 px-4">{t.tabularHost}</th>
                <th className="py-3.5 px-4">{t.tabularIp}</th>
                <th className="py-3.5 px-4">{t.tabularCategory}</th>
                <th className="py-3.5 px-4">{t.tabularMitre}</th>
                <th className="py-3.5 px-4 text-right">{t.tabularActions}</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-neutral-800/70 font-mono">
              {paginatedLogs.length === 0 ? (
                <tr>
                  <td colSpan={8} className="py-12 text-center text-neutral-400 font-sans text-xs">
                    {t.noLogsFound}
                  </td>
                </tr>
              ) : (
                paginatedLogs.map((log) => (
                  <tr
                    key={log.id}
                    onClick={() => onSelectLog(log)}
                    className="hover:bg-neutral-800/50 cursor-pointer transition-colors group"
                  >
                    <td className="py-3 px-4 tabular-nums text-neutral-400 whitespace-nowrap text-[11px]">
                      {new Date(log.timestamp).toLocaleTimeString()}
                    </td>

                    <td className="py-3 px-3 whitespace-nowrap">
                      <span className={`text-[10px] font-bold px-2 py-0.5 rounded border ${getSeverityBadgeClass(log.severity)}`}>
                        {log.severity.toUpperCase()}
                      </span>
                    </td>

                    <td className="py-3 px-3 text-neutral-300 font-sans text-xs capitalize whitespace-nowrap">
                      {log.source}
                    </td>

                    <td className="py-3 px-4 text-white font-medium whitespace-nowrap text-xs">
                      {log.sourceHost}
                    </td>

                    <td className="py-3 px-4 text-yellow-300 font-bold whitespace-nowrap text-xs">
                      {log.sourceIp}
                    </td>

                    <td className="py-3 px-4 font-sans text-xs text-neutral-200 whitespace-nowrap">
                      {log.ruleMatched ? (
                        <span className="text-white font-bold group-hover:text-yellow-300 transition-colors">
                          {log.ruleMatched.name}
                        </span>
                      ) : (
                        <span className="text-neutral-400">Normal Request</span>
                      )}
                    </td>

                    <td className="py-3 px-4 whitespace-nowrap text-xs">
                      {log.ruleMatched?.mitreId ? (
                        <span className="text-yellow-400 font-mono font-bold bg-yellow-400/10 px-1.5 py-0.5 rounded border border-yellow-400/30">
                          {log.ruleMatched.mitreId}
                        </span>
                      ) : (
                        <span className="text-neutral-600">—</span>
                      )}
                    </td>

                    <td className="py-3 px-4 text-right whitespace-nowrap">
                      <button
                        onClick={(e) => {
                          e.stopPropagation();
                          onSelectLog(log);
                        }}
                        className="text-neutral-300 hover:text-yellow-400 text-xs font-bold flex items-center gap-1 ml-auto font-sans transition-colors cursor-pointer"
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
        <div className="p-3.5 border-t border-neutral-800 bg-neutral-950 flex items-center justify-between text-xs text-neutral-400 font-mono">
          <div>
            <span>Page</span>{' '}
            <span className="tabular-nums text-white font-bold">{page}</span>{' '}
            <span>of</span>{' '}
            <span className="tabular-nums text-white font-bold">{totalPages}</span>
          </div>

          <div className="flex items-center gap-2">
            <button
              onClick={() => setPage(p => Math.max(1, p - 1))}
              disabled={page === 1}
              className={`p-1.5 rounded-lg border border-neutral-800 ${
                page === 1 ? 'text-neutral-600 cursor-not-allowed' : 'text-neutral-200 hover:bg-neutral-800 hover:text-white cursor-pointer'
              }`}
              aria-label="Previous Page"
            >
              <ChevronLeft className="w-4 h-4" />
            </button>
            <button
              onClick={() => setPage(p => Math.min(totalPages, p + 1))}
              disabled={page === totalPages}
              className={`p-1.5 rounded-lg border border-neutral-800 ${
                page === totalPages ? 'text-neutral-600 cursor-not-allowed' : 'text-neutral-200 hover:bg-neutral-800 hover:text-white cursor-pointer'
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
