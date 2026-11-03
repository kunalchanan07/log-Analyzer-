import React from 'react';
import { 
  Shield, 
  Radio, 
  Globe, 
  Sun, 
  Moon, 
  Lock, 
  Unlock, 
  FileDown
} from 'lucide-react';
import { Language, TRANSLATIONS } from '../utils/i18n';
import { GlobalSearchBar } from './GlobalSearchBar';
import { LogEntry, Incident } from '../types/soc';

interface TopBarProps {
  activeTab: 'dashboard' | 'collector' | 'explorer' | 'incidents' | 'rules' | 'audit';
  setActiveTab: (tab: 'dashboard' | 'collector' | 'explorer' | 'incidents' | 'rules' | 'audit') => void;
  lang: Language;
  setLang: (lang: Language) => void;
  onOpenCollectorDrawer?: () => void;
  criticalIncidentCount: number;
  isStreaming: boolean;
  theme: 'dark' | 'light';
  setTheme: (theme: 'dark' | 'light') => void;
  dlpEnabled: boolean;
  setDlpEnabled: (enabled: boolean) => void;
  onExportPdfReport: () => void;
  logs: LogEntry[];
  incidents: Incident[];
  onSelectLog: (log: LogEntry) => void;
  onSelectIncident: (incident: Incident) => void;
  onSelectHost: (host: string) => void;
}

export const TopBar: React.FC<TopBarProps> = ({
  activeTab,
  setActiveTab,
  lang,
  setLang,
  onOpenCollectorDrawer,
  criticalIncidentCount,
  isStreaming,
  theme,
  setTheme,
  dlpEnabled,
  setDlpEnabled,
  onExportPdfReport,
  logs,
  incidents,
  onSelectLog,
  onSelectIncident,
  onSelectHost
}) => {
  const t = TRANSLATIONS[lang];

  return (
    <header className="sticky top-0 z-40 bg-neutral-950/95 dark:bg-neutral-950/95 backdrop-blur-md border-b border-neutral-800 transition-colors">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-16 flex items-center justify-between gap-3 lg:gap-6">
        {/* Zone 1: Brand Wordmark with Cyber Yellow & Crisp White */}
        <div className="flex items-center gap-3 shrink-0">
          <button 
            onClick={() => setActiveTab('dashboard')}
            className="flex items-center gap-2.5 text-left group focus-visible:outline-none cursor-pointer"
            aria-label="Log Analyzer Home"
          >
            <div className="w-9 h-9 rounded-lg bg-yellow-400 text-neutral-950 font-black border border-yellow-300 flex items-center justify-center shadow-md shadow-yellow-500/20 group-hover:bg-yellow-300 transition-all">
              <Shield className="w-5 h-5 fill-neutral-950 stroke-neutral-950" />
            </div>
            <div>
              <div className="text-sm sm:text-base font-extrabold tracking-tight text-white flex items-center gap-2">
                <span className="uppercase tracking-wider">{t.appTitle}</span>
                <span className="text-[10px] font-mono text-yellow-400 font-bold border border-yellow-400/40 px-1.5 py-0.5 rounded bg-yellow-400/10">
                  PRO v2.5
                </span>
              </div>
              <div className="text-[10px] text-neutral-300 font-medium hidden sm:flex items-center gap-1.5">
                <span className="w-1.5 h-1.5 rounded-full bg-yellow-400 animate-pulse" />
                <span>{t.appSubtitle}</span>
              </div>
            </div>
          </button>
        </div>

        {/* Zone 2: Navigation Links with Yellow & White Contrast */}
        <nav className="hidden lg:flex items-center gap-5 text-xs font-semibold" aria-label="Main Navigation">
          <button
            onClick={() => setActiveTab('dashboard')}
            className={`whitespace-nowrap transition-all py-1.5 ${
              activeTab === 'dashboard'
                ? 'text-yellow-400 font-bold border-b-2 border-yellow-400 shadow-[0_1px_0_0_#facc15]'
                : 'text-neutral-300 hover:text-white'
            }`}
          >
            {t.navDashboard}
          </button>

          <button
            onClick={() => setActiveTab('collector')}
            className={`whitespace-nowrap transition-all py-1.5 flex items-center gap-1.5 ${
              activeTab === 'collector'
                ? 'text-yellow-400 font-bold border-b-2 border-yellow-400 shadow-[0_1px_0_0_#facc15]'
                : 'text-neutral-300 hover:text-white'
            }`}
          >
            <span>{t.navCollector}</span>
            {isStreaming && (
              <span className="inline-block w-2 h-2 rounded-full bg-yellow-400 animate-ping" title="Ingestion active" />
            )}
          </button>

          <button
            onClick={() => setActiveTab('explorer')}
            className={`whitespace-nowrap transition-all py-1.5 ${
              activeTab === 'explorer'
                ? 'text-yellow-400 font-bold border-b-2 border-yellow-400 shadow-[0_1px_0_0_#facc15]'
                : 'text-neutral-300 hover:text-white'
            }`}
          >
            {t.navLogs}
          </button>

          <button
            onClick={() => setActiveTab('incidents')}
            className={`whitespace-nowrap transition-all py-1.5 flex items-center gap-1.5 ${
              activeTab === 'incidents'
                ? 'text-yellow-400 font-bold border-b-2 border-yellow-400 shadow-[0_1px_0_0_#facc15]'
                : 'text-neutral-300 hover:text-white'
            }`}
          >
            <span>{t.navIncidents}</span>
            {criticalIncidentCount > 0 && (
              <span className="text-[10px] font-mono font-bold px-1.5 py-0.2 rounded bg-rose-500/20 text-rose-300 border border-rose-500/40">
                {criticalIncidentCount}
              </span>
            )}
          </button>

          <button
            onClick={() => setActiveTab('rules')}
            className={`whitespace-nowrap transition-all py-1.5 ${
              activeTab === 'rules'
                ? 'text-yellow-400 font-bold border-b-2 border-yellow-400 shadow-[0_1px_0_0_#facc15]'
                : 'text-neutral-300 hover:text-white'
            }`}
          >
            {t.navRules}
          </button>

          <button
            onClick={() => setActiveTab('audit')}
            className={`whitespace-nowrap transition-all py-1.5 ${
              activeTab === 'audit'
                ? 'text-yellow-400 font-bold border-b-2 border-yellow-400 shadow-[0_1px_0_0_#facc15]'
                : 'text-neutral-300 hover:text-white'
            }`}
          >
            {t.navAudit}
          </button>
        </nav>

        {/* Global SOC Search Bar (Cmd+K / Ctrl+K) */}
        <GlobalSearchBar
          logs={logs}
          incidents={incidents}
          lang={lang}
          onSelectLog={onSelectLog}
          onSelectIncident={onSelectIncident}
          onSelectHost={onSelectHost}
        />

        {/* Zone 3: Security Controls, PDF Export & Language */}
        <div className="flex items-center gap-2 sm:gap-2.5 shrink-0">
          {/* DLP Masking Toggle */}
          <button
            onClick={() => setDlpEnabled(!dlpEnabled)}
            className={`hidden sm:flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg text-xs font-semibold border transition-colors ${
              dlpEnabled 
                ? 'bg-yellow-400/10 text-yellow-300 border-yellow-400/40 font-mono' 
                : 'bg-neutral-900 text-neutral-400 border-neutral-800'
            }`}
            title="DLP Sensitive Data Redaction"
          >
            {dlpEnabled ? <Lock className="w-3.5 h-3.5 text-yellow-400" /> : <Unlock className="w-3.5 h-3.5 text-neutral-500" />}
            <span className="text-[11px] font-mono">{dlpEnabled ? 'DLP REDACTED' : 'DLP OFF'}</span>
          </button>

          {/* Export PDF Compliance Report Button in Crisp White */}
          <button
            onClick={onExportPdfReport}
            className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-bold text-neutral-950 bg-white hover:bg-neutral-100 border border-white/80 rounded-lg transition-all shadow-sm hover:shadow"
            title="Download Official Incident PDF Report"
            aria-label="Export Compliance PDF Report"
          >
            <FileDown className="w-3.5 h-3.5 text-neutral-950" />
            <span className="hidden md:inline font-mono text-[11px]">EXPORT PDF</span>
          </button>

          {/* Theme Toggle (Dark Mode / Light Mode) */}
          <button
            onClick={() => setTheme(theme === 'dark' ? 'light' : 'dark')}
            className="p-1.5 text-neutral-300 hover:text-white bg-neutral-900 border border-neutral-800 rounded-lg hover:border-neutral-700 transition-colors"
            title={`Switch to ${theme === 'dark' ? 'Light' : 'Dark'} Mode`}
            aria-label="Toggle theme"
          >
            {theme === 'dark' ? <Sun className="w-4 h-4 text-yellow-400" /> : <Moon className="w-4 h-4 text-neutral-300" />}
          </button>

          {/* Language Toggle */}
          <button
            onClick={() => setLang(lang === 'en' ? 'pa' : 'en')}
            className="flex items-center gap-1.5 px-2.5 py-1.5 text-xs font-medium text-neutral-200 bg-neutral-900 border border-neutral-800 rounded-lg hover:border-neutral-700 hover:text-white transition-colors"
            aria-label={`Switch to ${lang === 'en' ? 'Punjabi' : 'English'}`}
          >
            <Globe className="w-3.5 h-3.5 text-yellow-400" />
            <span className="font-semibold">{t.languageSwitch}</span>
          </button>

          {/* Quick Side Ingest Drawer in Cyber Yellow */}
          <button
            onClick={onOpenCollectorDrawer}
            className="hidden sm:flex items-center gap-1.5 px-3 py-1.5 text-xs font-bold text-neutral-950 bg-yellow-400 hover:bg-yellow-300 rounded-lg transition-all whitespace-nowrap shadow-md shadow-yellow-500/20 active:scale-95 cursor-pointer"
          >
            <Radio className="w-3.5 h-3.5 text-neutral-950 stroke-[2.5]" />
            <span>{lang === 'pa' ? 'ਇੰਜੈਸਟ ਪੈਨਲ' : 'Ingest Logs'}</span>
          </button>
        </div>
      </div>

      {/* Responsive mobile nav strip */}
      <div className="lg:hidden flex items-center px-4 py-2 border-t border-neutral-900 bg-neutral-950 text-xs overflow-x-auto gap-4">
        <button
          onClick={() => setActiveTab('dashboard')}
          className={`whitespace-nowrap py-1 ${activeTab === 'dashboard' ? 'text-yellow-400 font-bold border-b border-yellow-400' : 'text-neutral-400'}`}
        >
          {t.navDashboard}
        </button>
        <button
          onClick={() => setActiveTab('collector')}
          className={`whitespace-nowrap py-1 ${activeTab === 'collector' ? 'text-yellow-400 font-bold border-b border-yellow-400' : 'text-neutral-400'}`}
        >
          {t.navCollector}
        </button>
        <button
          onClick={() => setActiveTab('explorer')}
          className={`whitespace-nowrap py-1 ${activeTab === 'explorer' ? 'text-yellow-400 font-bold border-b border-yellow-400' : 'text-neutral-400'}`}
        >
          {t.navLogs}
        </button>
        <button
          onClick={() => setActiveTab('incidents')}
          className={`whitespace-nowrap py-1 ${activeTab === 'incidents' ? 'text-yellow-400 font-bold border-b border-yellow-400' : 'text-neutral-400'}`}
        >
          {t.navIncidents} ({criticalIncidentCount})
        </button>
        <button
          onClick={() => setActiveTab('rules')}
          className={`whitespace-nowrap py-1 ${activeTab === 'rules' ? 'text-yellow-400 font-bold border-b border-yellow-400' : 'text-neutral-400'}`}
        >
          {t.navRules}
        </button>
        <button
          onClick={() => setActiveTab('audit')}
          className={`whitespace-nowrap py-1 ${activeTab === 'audit' ? 'text-yellow-400 font-bold border-b border-yellow-400' : 'text-neutral-400'}`}
        >
          {t.navAudit}
        </button>
      </div>
    </header>
  );
};
