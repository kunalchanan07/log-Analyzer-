import React from 'react';
import { Shield, ShieldAlert, Radio, Globe } from 'lucide-react';
import { Language, TRANSLATIONS } from '../utils/i18n';

interface TopBarProps {
  activeTab: 'dashboard' | 'collector' | 'explorer' | 'incidents' | 'rules';
  setActiveTab: (tab: 'dashboard' | 'collector' | 'explorer' | 'incidents' | 'rules') => void;
  lang: Language;
  setLang: (lang: Language) => void;
  onOpenCollectorDrawer?: () => void;
  criticalIncidentCount: number;
  isStreaming: boolean;
}

export const TopBar: React.FC<TopBarProps> = ({
  activeTab,
  setActiveTab,
  lang,
  setLang,
  onOpenCollectorDrawer,
  criticalIncidentCount,
  isStreaming
}) => {
  const t = TRANSLATIONS[lang];

  return (
    <header className="sticky top-0 z-40 bg-slate-950/90 backdrop-blur-md border-b border-slate-800">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-16 flex items-center justify-between gap-8">
        {/* Zone 1: Brand Wordmark */}
        <div className="flex items-center gap-3 shrink-0">
          <button 
            onClick={() => setActiveTab('dashboard')}
            className="flex items-center gap-2.5 text-left group focus-visible:outline-none"
            aria-label="AegisSOC Home"
          >
            <div className="w-9 h-9 rounded-lg bg-cyan-500/10 border border-cyan-500/30 flex items-center justify-center text-cyan-400 group-hover:border-cyan-400 transition-colors">
              <Shield className="w-5 h-5" />
            </div>
            <div>
              <div className="text-base font-bold tracking-tight text-white flex items-center gap-2">
                <span>{t.appTitle}</span>
                <span className="text-[11px] font-mono text-cyan-400 font-medium tracking-normal border border-cyan-500/30 px-1.5 py-0.5 rounded">SIEM</span>
              </div>
              <div className="text-[11px] text-slate-400 hidden sm:block">
                {t.appSubtitle}
              </div>
            </div>
          </button>
        </div>

        {/* Zone 2: Navigation Links (Clean single-line text with subtle hover effect) */}
        <nav className="hidden md:flex items-center gap-6 text-sm font-medium" aria-label="Main Navigation">
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
        </nav>

        {/* Zone 3: Actions & Language Switch */}
        <div className="flex items-center gap-3 shrink-0">
          {/* Quick Language Toggle */}
          <button
            onClick={() => setLang(lang === 'en' ? 'pa' : 'en')}
            className="flex items-center gap-1.5 px-2.5 py-1.5 text-xs font-medium text-slate-300 bg-slate-900 border border-slate-800 rounded-lg hover:border-slate-700 hover:text-white transition-colors"
            title="Switch Language / ਭਾਸ਼ਾ ਬਦਲੋ"
            aria-label={`Switch to ${lang === 'en' ? 'Punjabi' : 'English'}`}
          >
            <Globe className="w-3.5 h-3.5 text-slate-400" />
            <span>{t.languageSwitch}</span>
          </button>

          {/* Log Collector Quick Drawer button */}
          <button
            onClick={onOpenCollectorDrawer}
            className="hidden sm:flex items-center gap-2 px-3.5 py-1.5 text-xs font-semibold text-white bg-cyan-600 hover:bg-cyan-500 active:bg-cyan-700 rounded-lg transition-colors shadow-sm shadow-cyan-900/30 whitespace-nowrap"
            aria-label="Open Ingest & Collector Panel"
          >
            <Radio className="w-3.5 h-3.5" />
            <span>{lang === 'pa' ? 'ਲੌਗ ਇੰਜੈਸਟ ਪੈਨਲ' : 'Ingest Logs'}</span>
          </button>
        </div>
      </div>
      
      {/* Mobile navigation row for responsive phones */}
      <div className="md:hidden flex items-center justify-between px-4 py-2 border-t border-slate-900 bg-slate-950 text-xs overflow-x-auto gap-4">
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
      </div>
    </header>
  );
};
