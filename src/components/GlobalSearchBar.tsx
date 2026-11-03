import React, { useState, useEffect, useMemo, useRef } from 'react';
import { 
  Search, 
  X, 
  Server, 
  ShieldAlert, 
  FileText, 
  CornerDownLeft, 
  ArrowUp, 
  ArrowDown, 
  AlertTriangle,
  Radio,
  Tag
} from 'lucide-react';
import { LogEntry, Incident } from '../types/soc';
import { Language, TRANSLATIONS } from '../utils/i18n';
import { extractHostStats, searchHostStats, searchIncidents, searchLogs } from '../utils/searchEngine';

interface GlobalSearchBarProps {
  logs: LogEntry[];
  incidents: Incident[];
  lang: Language;
  onSelectLog: (log: LogEntry) => void;
  onSelectIncident: (incident: Incident) => void;
  onSelectHost: (host: string) => void;
}

type SearchCategory = 'all' | 'logs' | 'incidents' | 'hosts';

interface SearchItem {
  id: string;
  type: 'host' | 'incident' | 'log';
  title: string;
  subtitle: string;
  badge?: string;
  badgeColor?: string;
  meta?: string;
  rawItem: LogEntry | Incident | string;
}

export const GlobalSearchBar: React.FC<GlobalSearchBarProps> = ({
  logs,
  incidents,
  lang,
  onSelectLog,
  onSelectIncident,
  onSelectHost
}) => {
  const t = TRANSLATIONS[lang];
  const [isOpen, setIsOpen] = useState(false);
  const [query, setQuery] = useState('');
  const [category, setCategory] = useState<SearchCategory>('all');
  const [activeIndex, setActiveIndex] = useState(0);

  const inputRef = useRef<HTMLInputElement>(null);
  const resultsContainerRef = useRef<HTMLDivElement>(null);

  // Extract unique hosts and their metadata
  const hostStats = useMemo(() => {
    return extractHostStats(logs, incidents);
  }, [logs, incidents]);

  // Global hotkey listener: Cmd+K / Ctrl+K / '/'
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      // Ignore if user is already typing in an input/textarea and didn't press Cmd/Ctrl
      const target = e.target as HTMLElement | null;
      const isInput = target && (target.tagName === 'INPUT' || target.tagName === 'TEXTAREA');

      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'k') {
        e.preventDefault();
        setIsOpen(prev => !prev);
      } else if (e.key === '/' && !isInput) {
        e.preventDefault();
        setIsOpen(true);
      } else if (e.key === 'Escape' && isOpen) {
        e.preventDefault();
        setIsOpen(false);
      }
    };

    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [isOpen]);

  // Auto-focus input when opened
  useEffect(() => {
    if (isOpen) {
      setTimeout(() => {
        inputRef.current?.focus();
      }, 50);
    } else {
      setQuery('');
      setActiveIndex(0);
    }
  }, [isOpen]);

  // Filter and build unified search items
  const searchResults = useMemo(() => {
    const cleanQuery = query.trim().toLowerCase();
    const items: SearchItem[] = [];

    // 1. Hostnames
    if (category === 'all' || category === 'hosts') {
      const matchedHosts = searchHostStats(hostStats, query);
      matchedHosts.forEach(stats => {
        let badgeColor = 'bg-slate-700/60 text-slate-300 border-slate-600';
        if (stats.hasCritical) {
          badgeColor = 'bg-rose-500/20 text-rose-300 border-rose-500/40';
        } else if (stats.hasMalicious) {
          badgeColor = 'bg-amber-500/20 text-amber-300 border-amber-500/40';
        }

        items.push({
          id: `host-${stats.hostname}`,
          type: 'host',
          title: stats.hostname,
          subtitle: `${stats.count} event telemetry records • Asset Endpoint`,
          badge: stats.hasCritical ? 'Critical Target' : stats.hasMalicious ? 'Threat Active' : 'Asset Online',
          badgeColor,
          meta: 'Host',
          rawItem: stats.hostname
        });
      });
    }

    // 2. Incidents
    if (category === 'all' || category === 'incidents') {
      const matchedIncidents = searchIncidents(incidents, query);
      matchedIncidents.forEach(inc => {
        const badgeColor = 
          inc.severity === 'critical'
            ? 'bg-rose-500/20 text-rose-300 border-rose-500/40'
            : inc.severity === 'high'
            ? 'bg-amber-500/20 text-amber-300 border-amber-500/40'
            : 'bg-cyan-500/20 text-cyan-300 border-cyan-500/40';

        items.push({
          id: `incident-${inc.id}`,
          type: 'incident',
          title: `${inc.id}: ${inc.title}`,
          subtitle: `Target: ${inc.targetHost} | Attacker: ${inc.attackerIp} | MITRE: ${inc.mitreTechnique}`,
          badge: inc.severity.toUpperCase(),
          badgeColor,
          meta: `Incident • ${inc.status}`,
          rawItem: inc
        });
      });
    }

    // 3. Log entries (snappy limit to 25)
    if (category === 'all' || category === 'logs') {
      const matchedLogs = searchLogs(logs, query, 25);
      matchedLogs.forEach(log => {
        const badgeColor = 
          log.severity === 'critical'
            ? 'bg-rose-500/20 text-rose-300 border-rose-500/40'
            : log.severity === 'high'
            ? 'bg-amber-500/20 text-amber-300 border-amber-500/40'
            : log.severity === 'medium'
            ? 'bg-yellow-500/20 text-yellow-300 border-yellow-500/40'
            : 'bg-emerald-500/20 text-emerald-300 border-emerald-500/40';

        const titleText = log.ruleMatched 
          ? `${log.ruleMatched.name} (${log.ruleMatched.mitreId})`
          : log.raw.slice(0, 80);

        items.push({
          id: `log-${log.id}`,
          type: 'log',
          title: titleText,
          subtitle: `${log.timestamp.slice(11, 19)} UTC | Host: ${log.sourceHost} | IP: ${log.sourceIp}`,
          badge: log.severity.toUpperCase(),
          badgeColor,
          meta: `Log [${log.source.toUpperCase()}]`,
          rawItem: log
        });
      });
    }

    return items;
  }, [query, category, hostStats, incidents, logs]);

  // Keep active index within bounds
  useEffect(() => {
    setActiveIndex(0);
  }, [query, category]);

  // Handle keyboard navigation inside search list
  const handleInputKeyDown = (e: React.KeyboardEvent<HTMLInputElement>) => {
    if (e.key === 'ArrowDown') {
      e.preventDefault();
      setActiveIndex(prev => (prev < searchResults.length - 1 ? prev + 1 : 0));
    } else if (e.key === 'ArrowUp') {
      e.preventDefault();
      setActiveIndex(prev => (prev > 0 ? prev - 1 : searchResults.length - 1));
    } else if (e.key === 'Enter') {
      e.preventDefault();
      if (searchResults[activeIndex]) {
        executeSelection(searchResults[activeIndex]);
      }
    }
  };

  // Scroll active item into view
  useEffect(() => {
    if (!resultsContainerRef.current) return;
    const activeEl = resultsContainerRef.current.querySelector(`[data-index="${activeIndex}"]`) as HTMLElement;
    if (activeEl) {
      activeEl.scrollIntoView({ block: 'nearest' });
    }
  }, [activeIndex]);

  const executeSelection = (item: SearchItem) => {
    setIsOpen(false);
    if (item.type === 'host') {
      onSelectHost(item.rawItem as string);
    } else if (item.type === 'incident') {
      onSelectIncident(item.rawItem as Incident);
    } else if (item.type === 'log') {
      onSelectLog(item.rawItem as LogEntry);
    }
  };

  const quickQueries = [
    '185.220.101.5',
    'prod-web-ingress',
    'SQL Injection',
    'vssadmin',
    'auth-bastion-01',
    'T1190'
  ];

  return (
    <>
      {/* Search Input Trigger in TopBar */}
      <div className="relative flex-1 max-w-xs md:max-w-sm lg:max-w-md hidden sm:block">
        <button
          type="button"
          onClick={() => setIsOpen(true)}
          className="w-full h-9 px-3 flex items-center justify-between text-xs rounded-lg bg-neutral-900/90 border border-neutral-800 text-neutral-300 hover:text-white hover:border-yellow-400/50 transition-all cursor-pointer shadow-inner group"
          aria-label={t.globalSearchPlaceholder}
        >
          <div className="flex items-center gap-2 overflow-hidden text-left">
            <Search className="w-4 h-4 text-neutral-400 group-hover:text-yellow-400 transition-colors shrink-0" />
            <span className="truncate">{t.globalSearchPlaceholder}</span>
          </div>
          <div className="flex items-center gap-1 shrink-0 ml-2">
            <kbd className="hidden md:inline-flex items-center px-1.5 py-0.5 text-[10px] font-mono font-bold text-yellow-300 bg-yellow-400/10 border border-yellow-400/30 rounded shadow-xs">
              ⌘K
            </kbd>
          </div>
        </button>
      </div>

      {/* Mobile Icon Button */}
      <button
        type="button"
        onClick={() => setIsOpen(true)}
        className="sm:hidden p-2 text-neutral-300 hover:text-white bg-neutral-900 border border-neutral-800 rounded-lg hover:border-yellow-400 transition-colors cursor-pointer"
        aria-label="Open Global Search"
      >
        <Search className="w-4 h-4 text-yellow-400" />
      </button>

      {/* Modal Backdrop & Command Palette */}
      {isOpen && (
        <div 
          className="fixed inset-0 z-50 flex items-start justify-center pt-12 sm:pt-20 px-4 bg-black/80 backdrop-blur-md animate-in fade-in duration-150"
          onClick={() => setIsOpen(false)}
        >
          <div 
            className="w-full max-w-2xl bg-neutral-900 border border-neutral-700 rounded-xl shadow-2xl shadow-yellow-500/5 overflow-hidden text-neutral-100 flex flex-col max-h-[85vh] animate-in zoom-in-95 duration-150"
            onClick={e => e.stopPropagation()}
            role="dialog"
            aria-modal="true"
            aria-label={t.globalSearchTitle}
          >
            {/* Search Input Bar */}
            <div className="p-3.5 border-b border-neutral-800 flex items-center gap-3 bg-neutral-950/80">
              <Search className="w-5 h-5 text-yellow-400 shrink-0 ml-1" />
              <input
                ref={inputRef}
                type="text"
                value={query}
                onChange={e => setQuery(e.target.value)}
                onKeyDown={handleInputKeyDown}
                placeholder={lang === 'pa' ? 'IP, ਹੋਸਟ, ਘਟਨਾ ਜਾਂ ਸੁਨੇਹਾ ਖੋਜੋ...' : 'Search logs, incidents, hostnames, IPs, MITRE techniques...'}
                className="w-full bg-transparent text-sm sm:text-base text-white placeholder-neutral-400 focus:outline-none"
              />
              {query && (
                <button
                  type="button"
                  onClick={() => setQuery('')}
                  className="p-1 text-neutral-400 hover:text-white rounded cursor-pointer"
                  title="Clear input"
                >
                  <X className="w-4 h-4" />
                </button>
              )}
              <button
                type="button"
                onClick={() => setIsOpen(false)}
                className="px-2 py-1 text-xs text-neutral-300 hover:text-white bg-neutral-800 hover:bg-neutral-700 border border-neutral-700 rounded cursor-pointer shrink-0"
              >
                ESC
              </button>
            </div>

            {/* Category Filter Pills */}
            <div className="px-3.5 py-2 border-b border-neutral-800 bg-neutral-900 flex items-center gap-1.5 overflow-x-auto text-xs">
              <span className="text-[11px] font-semibold text-neutral-400 uppercase tracking-wider mr-1 shrink-0">
                Filter:
              </span>
              <button
                type="button"
                onClick={() => setCategory('all')}
                className={`px-2.5 py-1 rounded-md font-semibold transition-colors cursor-pointer shrink-0 ${
                  category === 'all'
                    ? 'bg-yellow-400 text-neutral-950 shadow-sm'
                    : 'text-neutral-300 hover:text-white hover:bg-neutral-800'
                }`}
              >
                {t.searchCategoryAll} ({searchResults.length})
              </button>
              <button
                type="button"
                onClick={() => setCategory('logs')}
                className={`px-2.5 py-1 rounded-md font-semibold transition-colors cursor-pointer shrink-0 flex items-center gap-1.5 ${
                  category === 'logs'
                    ? 'bg-yellow-400 text-neutral-950 shadow-sm'
                    : 'text-neutral-300 hover:text-white hover:bg-neutral-800'
                }`}
              >
                <FileText className="w-3.5 h-3.5" />
                <span>{t.searchCategoryLogs}</span>
              </button>
              <button
                type="button"
                onClick={() => setCategory('incidents')}
                className={`px-2.5 py-1 rounded-md font-semibold transition-colors cursor-pointer shrink-0 flex items-center gap-1.5 ${
                  category === 'incidents'
                    ? 'bg-yellow-400 text-neutral-950 shadow-sm'
                    : 'text-neutral-300 hover:text-white hover:bg-neutral-800'
                }`}
              >
                <ShieldAlert className="w-3.5 h-3.5" />
                <span>{t.searchCategoryIncidents} ({incidents.length})</span>
              </button>
              <button
                type="button"
                onClick={() => setCategory('hosts')}
                className={`px-2.5 py-1 rounded-md font-semibold transition-colors cursor-pointer shrink-0 flex items-center gap-1.5 ${
                  category === 'hosts'
                    ? 'bg-yellow-400 text-neutral-950 shadow-sm'
                    : 'text-neutral-300 hover:text-white hover:bg-neutral-800'
                }`}
              >
                <Server className="w-3.5 h-3.5" />
                <span>{t.searchCategoryHosts} ({hostStats.length})</span>
              </button>
            </div>

            {/* Results Area */}
            <div 
              ref={resultsContainerRef}
              className="flex-1 overflow-y-auto max-h-[50vh] p-2 space-y-1 divide-y divide-slate-800/40"
            >
              {searchResults.length === 0 ? (
                <div className="py-10 text-center px-4">
                  <AlertTriangle className="w-8 h-8 text-slate-500 mx-auto mb-2.5 opacity-60" />
                  <p className="text-sm font-medium text-slate-300">{t.searchNoResults}</p>
                  <p className="text-xs text-slate-400 mt-1 max-w-sm mx-auto">
                    {lang === 'pa' 
                      ? 'ਕੋਈ ਹੋਰ ਨਾਮ, IP ਪਤਾ ਜਾਂ ਨਿਯਮ ਲਿਖ ਕੇ ਦੇਖੋ ਜਾਂ ਹੇਠਾਂ ਦਿੱਤੇ ਤੇਜ਼ ਸੁਝਾਵਾਂ ਦੀ ਵਰਤੋਂ ਕਰੋ।'
                      : 'Try querying an IP address (e.g. 185.220.101.5), a server hostname, or threat keyword.'}
                  </p>

                  {/* Suggested Queries */}
                  <div className="mt-4 flex flex-wrap items-center justify-center gap-1.5 max-w-md mx-auto">
                    {quickQueries.map(q => (
                      <button
                        key={q}
                        type="button"
                        onClick={() => setQuery(q)}
                        className="px-2 py-1 text-xs bg-slate-800/80 hover:bg-slate-800 border border-slate-700/70 text-slate-300 rounded cursor-pointer transition-colors"
                      >
                        {q}
                      </button>
                    ))}
                  </div>
                </div>
              ) : (
                searchResults.map((item, idx) => {
                  const isActive = idx === activeIndex;
                  return (
                    <div
                      key={item.id}
                      data-index={idx}
                      onClick={() => executeSelection(item)}
                      onMouseEnter={() => setActiveIndex(idx)}
                      className={`p-2.5 rounded-lg flex items-center justify-between gap-3 cursor-pointer transition-all ${
                        isActive 
                          ? 'bg-yellow-400/10 border-l-4 border-l-yellow-400 border-neutral-700 text-white' 
                          : 'hover:bg-neutral-800/60 text-neutral-200 border-l-4 border-l-transparent border-transparent'
                      }`}
                    >
                      <div className="flex items-start gap-3 min-w-0">
                        {/* Type Icon */}
                        <div className={`w-8 h-8 rounded-lg flex items-center justify-center shrink-0 mt-0.5 ${
                          item.type === 'host'
                            ? 'bg-yellow-400/10 text-yellow-400 border border-yellow-400/30'
                            : item.type === 'incident'
                            ? 'bg-rose-500/10 text-rose-400 border border-rose-500/30'
                            : 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/30'
                        }`}>
                          {item.type === 'host' && <Server className="w-4 h-4" />}
                          {item.type === 'incident' && <ShieldAlert className="w-4 h-4" />}
                          {item.type === 'log' && <FileText className="w-4 h-4" />}
                        </div>

                        {/* Title & Subtitle */}
                        <div className="min-w-0">
                          <div className="flex items-center gap-2">
                            <span className="text-xs font-bold text-white truncate">
                              {item.title}
                            </span>
                            {item.badge && (
                              <span className={`text-[10px] font-mono px-1.5 py-0.2 rounded border font-bold shrink-0 ${item.badgeColor}`}>
                                {item.badge}
                              </span>
                            )}
                          </div>
                          <div className="text-[11px] text-neutral-400 truncate mt-0.5 font-mono">
                            {item.subtitle}
                          </div>
                        </div>
                      </div>

                      {/* Right Meta & Action */}
                      <div className="flex items-center gap-2 shrink-0">
                        <span className="text-[10px] font-mono text-neutral-400 uppercase hidden sm:inline">
                          {item.meta}
                        </span>
                        <CornerDownLeft className={`w-3.5 h-3.5 transition-opacity ${isActive ? 'opacity-100 text-yellow-400' : 'opacity-0'}`} />
                      </div>
                    </div>
                  );
                })
              )}
            </div>

            {/* Quick Queries row when query is empty */}
            {!query && (
              <div className="p-2.5 border-t border-neutral-800 bg-neutral-950/60 flex items-center gap-2 overflow-x-auto text-xs">
                <span className="text-[11px] text-neutral-400 font-semibold shrink-0 flex items-center gap-1">
                  <Tag className="w-3 h-3 text-yellow-400" />
                  {t.searchQuickFilters}:
                </span>
                {quickQueries.map(q => (
                  <button
                    key={q}
                    type="button"
                    onClick={() => setQuery(q)}
                    className="px-2 py-0.5 text-[11px] font-mono bg-neutral-800 hover:bg-neutral-700 text-neutral-200 hover:text-yellow-300 rounded border border-neutral-700 cursor-pointer transition-colors shrink-0"
                  >
                    {q}
                  </button>
                ))}
              </div>
            )}

            {/* Footer with keyboard guidance */}
            <div className="p-2.5 border-t border-neutral-800 bg-neutral-950/80 flex items-center justify-between text-[11px] text-neutral-400">
              <span className="font-mono text-neutral-300">
                {t.searchHint}
              </span>
              <div className="flex items-center gap-1 font-mono text-[10px] text-yellow-300">
                <span className="px-1 py-0.5 bg-neutral-800 rounded border border-neutral-700">↑</span>
                <span className="px-1 py-0.5 bg-neutral-800 rounded border border-neutral-700">↓</span>
                <span className="px-1.5 py-0.5 bg-neutral-800 rounded border border-neutral-700">ENTER</span>
              </div>
            </div>
          </div>
        </div>
      )}
    </>
  );
};
