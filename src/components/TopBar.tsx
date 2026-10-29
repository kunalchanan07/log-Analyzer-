import React from 'react';
import { 
  Shield, 
  Radio, 
  Globe, 
  Sun, 
  Moon, 
  Lock, 
  Unlock, 
  FileDown, 
  History 
} from 'lucide-react';
import { Language, TRANSLATIONS } from '../utils/i18n';

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
  onExportPdfReport
}) => {
  const t = TRANSLATIONS[lang];

  return (
    <header className="sticky top-0 z-40 bg-slate-950/90 dark:bg-slate-950/90 backdrop-blur-md border-b border-slate-800 transition-colors">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-16 flex items-center justify-between gap-4 lg:gap-8">
        {/* Zone 1: Brand Wordmark */}
        <div className="flex items-center gap-3 shrink-0">
          <button 
            onClick={() => setActiveTab('dashboard')}
            className="flex items-center gap-2.5 text-left group focus-visible:outline-none cursor-pointer"
            aria-label="Log Analyzer Home"
          >
            <div className="w-9 h-9 rounded-lg bg-cyan-500/10 border border-cyan-500/30 flex items-center justify-center text-cyan-400 group-hover:border-cyan-400 transition-colors">
              <Shield className="w-5 h-5" />
            </div>
            <div>
              <div className="text-sm sm:text-base font-bold tracking-tight text-white flex items-center gap-2">
                <span>{t.appTitle}</span>
                <span className="text-[10px] font-mono text-cyan-400 font-semibold border border-cyan-500/30 px-1.5 py-0.2 rounded bg-cyan-950/40">
                  v2.5
                </span>
              </div>
              <div className="text-[10px] text-slate-400 hidden sm:block">
                {t.appSubtitle}
              </div>
            </div>
          </button>
        </div>

        {/* Zone 2: Navigation Links */}
        <nav className="hidden lg:flex items-center gap-5 text-xs font-medium" aria-label="Main Navigation">
          <button
            onClick={() => setActiveTab('dashboard')}
            className={`whitespace-nowrap transition-colors py-1 ${
              activeTab === 'dashboard'
                ? 'text-cyan-400 font-semibold border-b-2 border-cyan-400'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            {t.navDashboard}
          </button>

          <button
            onClick={() => setActiveTab('collector')}
            className={`whitespace-nowrap transition-colors py-1 flex items-center gap-1.5 ${
              activeTab === 'collector'
                ? 'text-cyan-400 font-semibold border-b-2 border-cyan-400'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <span>{t.navCollector}</span>
            {isStreaming && (
              <span className="inline-block w-2 h-2 rounded-full bg-emerald-400 animate-pulse" title="Ingestion active" />
            )}
          </button>

          <button
            onClick={() => setActiveTab('explorer')}
            className={`whitespace-nowrap transition-colors py-1 ${
              activeTab === 'explorer'
                ? 'text-cyan-400 font-semibold border-b-2 border-cyan-400'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            {t.navLogs}
          </button>

          <button
            onClick={() => setActiveTab('incidents')}
            className={`whitespace-nowrap transition-colors py-1 flex items-center gap-1.5 ${
              activeTab === 'incidents'
                ? 'text-cyan-400 font-semibold border-b-2 border-cyan-400'
                : 'text-slate-400 hover:text-slate-200'
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
            className={`whitespace-nowrap transition-colors py-1 ${
              activeTab === 'rules'
                ? 'text-cyan-400 font-semibold border-b-2 border-cyan-400'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            {t.navRules}
          </button>

          <button
            onClick={() => setActiveTab('audit')}
            className={`whitespace-nowrap transition-colors py-1 ${
              activeTab === 'audit'
                ? 'text-cyan-400 font-semibold border-b-2 border-cyan-400'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            {t.navAudit}
          </button>
        </nav>

        {/* Zone 3: Security Controls, PDF Export & Language */}
        <div className="flex items-center gap-2 sm:gap-2.5 shrink-0">
          {/* DLP Masking Toggle */}
          <button
            onClick={() => setDlpEnabled(!dlpEnabled)}
            className={`hidden sm:flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg text-xs font-semibold border transition-colors ${
              dlpEnabled 
                ? 'bg-emerald-500/10 text-emerald-300 border-emerald-500/30' 
                : 'bg-slate-900 text-slate-400 border-slate-800'
            }`}
            title="DLP Sensitive Data Redaction"
          >
            {dlpEnabled ? <Lock className="w-3.5 h-3.5 text-emerald-400" /> : <Unlock className="w-3.5 h-3.5 text-slate-500" />}
            <span className="text-[11px] font-mono">{dlpEnabled ? 'DLP REDACTED' : 'DLP OFF'}</span>
          </button>

          {/* Export PDF Compliance Report Button */}
          <button
            onClick={onExportPdfReport}
            className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-semibold text-slate-200 bg-slate-900 border border-slate-700 hover:border-cyan-400 hover:text-white rounded-lg transition-colors shadow-sm"
            title="Download Official Incident PDF Report"
            aria-label="Export Compliance PDF Report"
          >
            <FileDown className="w-3.5 h-3.5 text-cyan-400" />
            <span className="hidden md:inline font-mono text-[11px]">EXPORT PDF</span>
          </button>

          {/* Theme Toggle (Dark Mode / Light Mode) */}
          <button
            onClick={() => setTheme(theme === 'dark' ? 'light' : 'dark')}
            className="p-1.5 text-slate-400 hover:text-white bg-slate-900 border border-slate-800 rounded-lg transition-colors"
            title={`Switch to ${theme === 'dark' ? 'Light' : 'Dark'} Mode`}
            aria-label="Toggle theme"
          >
            {theme === 'dark' ? <Sun className="w-4 h-4 text-amber-400" /> : <Moon className="w-4 h-4 text-cyan-400" />}
          </button>

          {/* Language Toggle */}
          <button
            onClick={() => setLang(lang === 'en' ? 'pa' : 'en')}
            className="flex items-center gap-1.5 px-2.5 py-1.5 text-xs font-medium text-slate-300 bg-slate-900 border border-slate-800 rounded-lg hover:border-slate-700 hover:text-white transition-colors"
            aria-label={`Switch to ${lang === 'en' ? 'Punjabi' : 'English'}`}
          >
            <Globe className="w-3.5 h-3.5 text-slate-400" />
            <span>{t.languageSwitch}</span>
          </button>

          {/* Quick Side Ingest Drawer */}
          <button
            onClick={onOpenCollectorDrawer}
            className="hidden sm:flex items-center gap-1.5 px-3 py-1.5 text-xs font-semibold text-white bg-cyan-600 hover:bg-cyan-500 rounded-lg transition-colors whitespace-nowrap shadow-sm shadow-cyan-900/30"
          >
            <Radio className="w-3.5 h-3.5" />
            <span>{lang === 'pa' ? 'ਇੰਜੈਸਟ ਪੈਨਲ' : 'Ingest Logs'}</span>
          </button>
        </div>
      </div>

      {/* Responsive mobile nav strip */}
      <div className="lg:hidden flex items-center px-4 py-2 border-t border-slate-900 bg-slate-950 text-xs overflow-x-auto gap-4">
        <button
          onClick={() => setActiveTab('dashboard')}
          className={`whitespace-nowrap py-1 ${activeTab === 'dashboard' ? 'text-cyan-400 font-bold' : 'text-slate-400'}`}
        >
          {t.navDashboard}
        </button>
        <button
          onClick={() => setActiveTab('collector')}
          className={`whitespace-nowrap py-1 ${activeTab === 'collector' ? 'text-cyan-400 font-bold' : 'text-slate-400'}`}
        >
          {t.navCollector}
        </button>
        <button
          onClick={() => setActiveTab('explorer')}
          className={`whitespace-nowrap py-1 ${activeTab === 'explorer' ? 'text-cyan-400 font-bold' : 'text-slate-400'}`}
        >
          {t.navLogs}
        </button>
        <button
          onClick={() => setActiveTab('incidents')}
          className={`whitespace-nowrap py-1 ${activeTab === 'incidents' ? 'text-cyan-400 font-bold' : 'text-slate-400'}`}
        >
          {t.navIncidents} ({criticalIncidentCount})
        </button>
        <button
          onClick={() => setActiveTab('rules')}
          className={`whitespace-nowrap py-1 ${activeTab === 'rules' ? 'text-cyan-400 font-bold' : 'text-slate-400'}`}
        >
          {t.navRules}
        </button>
        <button
          onClick={() => setActiveTab('audit')}
          className={`whitespace-nowrap py-1 ${activeTab === 'audit' ? 'text-cyan-400 font-bold' : 'text-slate-400'}`}
        >
          {t.navAudit}
        </button>
      </div>
    </header>
  );
};
