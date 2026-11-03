import React from 'react';
import { 
  ShieldAlert, 
  AlertTriangle, 
  Activity, 
  Layers, 
  Zap, 
  Flame, 
  ExternalLink, 
  Lock, 
  Globe2, 
  Server, 
  Clock, 
  CheckCircle2,
  ChevronRight,
  ShieldCheck,
  Radio,
  Download,
  Crosshair
} from 'lucide-react';
import { LogEntry, Severity, ThreatCategory } from '../types/soc';
import { Language, TRANSLATIONS } from '../utils/i18n';
import { ThreatOriginMap } from './ThreatOriginMap';

interface SocDashboardProps {
  logs: LogEntry[];
  lang: Language;
  onSelectLog: (log: LogEntry) => void;
  onNavigateToExplorer: () => void;
  onNavigateToCollector: () => void;
  onBlockIp: (ip: string) => void;
  blockedIps: Set<string>;
}

export const SocDashboard: React.FC<SocDashboardProps> = ({
  logs,
  lang,
  onSelectLog,
  onNavigateToExplorer,
  onNavigateToCollector,
  onBlockIp,
  blockedIps
}) => {
  const t = TRANSLATIONS[lang];

  const totalLogs = logs.length;
  const maliciousLogs = logs.filter(l => l.isMalicious);
  const suspiciousLogs = logs.filter(l => l.isSuspicious);
  const criticalCount = logs.filter(l => l.severity === 'critical').length;
  const highCount = logs.filter(l => l.severity === 'high').length;

  // Calculate attack vector distribution
  const categoryCounts: Record<ThreatCategory, number> = {
    normal: 0,
    sqli: 0,
    xss: 0,
    brute_force: 0,
    ransomware: 0,
    privilege_escalation: 0,
    c2_beacon: 0,
    port_scan: 0,
    directory_traversal: 0,
    unauthorized_access: 0
  };

  logs.forEach(l => {
    categoryCounts[l.category] = (categoryCounts[l.category] || 0) + 1;
  });

  // Top Attacker IPs
  const ipCounts: Record<string, { count: number; category: string; severity: Severity }> = {};
  logs.filter(l => l.isMalicious || l.isSuspicious).forEach(l => {
    if (!ipCounts[l.sourceIp]) {
      ipCounts[l.sourceIp] = { count: 0, category: l.category, severity: l.severity };
    }
    ipCounts[l.sourceIp].count += 1;
  });

  const topAttackerIps = Object.entries(ipCounts)
    .sort((a, b) => b[1].count - a[1].count)
    .slice(0, 5);

  // Top Targeted Hosts
  const hostCounts: Record<string, number> = {};
  logs.filter(l => l.isMalicious || l.isSuspicious).forEach(l => {
    hostCounts[l.sourceHost] = (hostCounts[l.sourceHost] || 0) + 1;
  });

  const topTargetedHosts = Object.entries(hostCounts)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 4);

  // Recent detected threats (malicious or suspicious first)
  const recentDetections = logs
    .filter(l => l.isMalicious || l.isSuspicious)
    .slice(0, 7);

  const getSeverityBadgeClass = (sev: Severity) => {
    switch (sev) {
      case 'critical':
        return 'text-rose-400 border border-rose-500/40 bg-rose-500/10 font-bold';
      case 'high':
        return 'text-yellow-400 border border-yellow-400/40 bg-yellow-400/10 font-bold';
      case 'medium':
        return 'text-amber-300 border border-amber-400/30 bg-amber-400/10';
      case 'low':
        return 'text-neutral-300 border border-neutral-700 bg-neutral-800';
      default:
        return 'text-emerald-400 border border-emerald-500/30 bg-emerald-500/10';
    }
  };

  return (
    <div className="space-y-6">
      {/* Top Threat Posture Header Strip */}
      <div className="p-4 sm:p-5 rounded-2xl bg-gradient-to-r from-neutral-900 via-neutral-900 to-neutral-950 border border-neutral-800 relative overflow-hidden shadow-xl">
        {/* Ambient cyber yellow glow */}
        <div className="absolute top-0 right-0 w-96 h-32 bg-yellow-400/5 rounded-full blur-3xl pointer-events-none" />
        
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4 relative z-10">
          <div className="space-y-1">
            <div className="flex items-center gap-2">
              <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-[11px] font-mono font-bold bg-yellow-400 text-neutral-950 shadow-sm">
                <span className="w-1.5 h-1.5 rounded-full bg-neutral-950 animate-ping" />
                ACTIVE SOC RADAR
              </span>
              <span className="text-xs text-neutral-400 font-mono">
                SIEM & THREAT INTELLIGENCE
              </span>
            </div>
            <h1 className="text-xl sm:text-2xl font-black tracking-tight text-white flex items-center gap-2 uppercase">
              <span>{lang === 'pa' ? 'ਸੁਰੱਖਿਆ ਸੰਚਾਲਨ ਕੇਂਦਰ ਕੰਸੋਲ' : 'SOC Command & Intelligence Center'}</span>
            </h1>
            <p className="text-xs sm:text-sm text-neutral-300 font-medium max-w-2xl">
              {lang === 'pa'
                ? 'ਰੀਅਲ-ਟਾਈਮ ਖਤਰਾ ਵਿਸ਼ਲੇਸ਼ਣ, ਹਮਲਾਵਰ IPs ਦੀ ਪਛਾਣ ਅਤੇ MITRE ATT&CK ਅਨੁਕੂਲਤਾ'
                : 'Real-time telemetry ingestion, threat hunting, automated payload signature matching, and incident triage.'}
            </p>
          </div>

          <div className="flex items-center gap-2.5 flex-wrap">
            {/* DEFCON Threat Badge */}
            <div className="flex items-center gap-2 px-3 py-2 rounded-xl bg-neutral-950 border border-yellow-400/30 text-xs">
              <span className="w-2.5 h-2.5 rounded-full bg-yellow-400 animate-pulse shadow-[0_0_8px_#facc15]" />
              <div className="text-left font-mono">
                <span className="text-[10px] text-neutral-400 block uppercase">{t.threatLevel}</span>
                <span className="text-yellow-400 font-bold">{t.elevated}</span>
              </div>
            </div>

            {/* Quick Collector Navigation Button */}
            <button
              onClick={onNavigateToCollector}
              className="px-3.5 py-2 rounded-xl text-xs font-bold bg-yellow-400 hover:bg-yellow-300 text-neutral-950 transition-all flex items-center gap-1.5 shadow-md shadow-yellow-500/20 active:scale-95 cursor-pointer"
            >
              <Radio className="w-4 h-4 stroke-[2.5]" />
              <span>{lang === 'pa' ? 'ਲੌਗ ਇੰਜੈਸਟ ਸਟ੍ਰੀਮ' : 'Collector Stream'}</span>
              <ChevronRight className="w-4 h-4" />
            </button>
          </div>
        </div>
      </div>

      {/* KPI Cards Strip with High-Contrast White and Cyber Yellow */}
      <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-3 sm:gap-4">
        {/* KPI 1: Ingested */}
        <div className="p-4 rounded-xl bg-neutral-900/90 border border-neutral-800 border-t-2 border-t-white hover:border-neutral-700 transition-all shadow-md">
          <div className="flex items-center justify-between text-xs text-neutral-400 font-medium">
            <span>{t.kpiTotalEvents}</span>
            <Layers className="w-4 h-4 text-white" />
          </div>
          <div className="mt-2 text-2xl sm:text-3xl font-black font-mono tabular-nums text-white">
            {totalLogs.toLocaleString()}
          </div>
          <div className="mt-1 text-[11px] text-neutral-300 font-medium flex items-center gap-1">
            <span className="w-1.5 h-1.5 rounded-full bg-white" />
            <span>{lang === 'pa' ? 'ਸਾਰੇ ਸਰੋਤ' : 'Normalized'}</span>
          </div>
        </div>

        {/* KPI 2: Malicious */}
        <div className="p-4 rounded-xl bg-neutral-900/90 border border-neutral-800 border-t-2 border-t-rose-500 hover:border-rose-500/50 transition-all shadow-md">
          <div className="flex items-center justify-between text-xs text-neutral-400 font-medium">
            <span>{t.kpiMalicious}</span>
            <ShieldAlert className="w-4 h-4 text-rose-400" />
          </div>
          <div className="mt-2 text-2xl sm:text-3xl font-black font-mono tabular-nums text-rose-400">
            {maliciousLogs.length}
          </div>
          <div className="mt-1 text-[11px] text-rose-300 font-mono font-semibold tabular-nums">
            {totalLogs > 0 ? ((maliciousLogs.length / totalLogs) * 100).toFixed(1) : 0}% of logs
          </div>
        </div>

        {/* KPI 3: Suspicious */}
        <div className="p-4 rounded-xl bg-neutral-900/90 border border-neutral-800 border-t-2 border-t-yellow-400 hover:border-yellow-400/50 transition-all shadow-md">
          <div className="flex items-center justify-between text-xs text-neutral-400 font-medium">
            <span>{t.kpiSuspicious}</span>
            <AlertTriangle className="w-4 h-4 text-yellow-400" />
          </div>
          <div className="mt-2 text-2xl sm:text-3xl font-black font-mono tabular-nums text-yellow-400">
            {suspiciousLogs.length}
          </div>
          <div className="mt-1 text-[11px] text-yellow-300 font-medium">
            {lang === 'pa' ? 'ਐਨੋਮਲੀ ਸਕੋਰ' : 'Behavioral triggers'}
          </div>
        </div>

        {/* KPI 4: Critical Incidents */}
        <div className="p-4 rounded-xl bg-neutral-900/90 border border-neutral-800 border-t-2 border-t-white hover:border-neutral-700 transition-all shadow-md">
          <div className="flex items-center justify-between text-xs text-neutral-400 font-medium">
            <span>{t.kpiCriticalIncidents}</span>
            <Flame className="w-4 h-4 text-rose-500" />
          </div>
          <div className="mt-2 text-2xl sm:text-3xl font-black font-mono tabular-nums text-white">
            {criticalCount}
          </div>
          <div className="mt-1 text-[11px] text-rose-400 font-bold">
            {criticalCount > 0 ? (lang === 'pa' ? 'ਤੁਰੰਤ ਐਕਸ਼ਨ ਲੋੜੀਂਦਾ' : 'P1 High Impact') : 'Nominal'}
          </div>
        </div>

        {/* KPI 5: EPS */}
        <div className="p-4 rounded-xl bg-neutral-900/90 border border-neutral-800 border-t-2 border-t-yellow-400 hover:border-yellow-400/50 transition-all shadow-md">
          <div className="flex items-center justify-between text-xs text-neutral-400 font-medium">
            <span>{t.kpiEps}</span>
            <Activity className="w-4 h-4 text-yellow-400" />
          </div>
          <div className="mt-2 text-2xl sm:text-3xl font-black font-mono tabular-nums text-white">
            36 <span className="text-xs font-sans text-neutral-400 font-normal">EPS</span>
          </div>
          <div className="mt-1 text-[11px] text-yellow-300 font-mono flex items-center gap-1 font-semibold">
            <span className="w-1.5 h-1.5 rounded-full bg-yellow-400" />
            <span>0 dropped</span>
          </div>
        </div>

        {/* KPI 6: Average Threat Score */}
        <div className="p-4 rounded-xl bg-neutral-900/90 border border-neutral-800 border-t-2 border-t-white hover:border-neutral-700 transition-all shadow-md">
          <div className="flex items-center justify-between text-xs text-neutral-400 font-medium">
            <span>{t.kpiThreatScore}</span>
            <Zap className="w-4 h-4 text-yellow-400" />
          </div>
          <div className="mt-2 text-2xl sm:text-3xl font-black font-mono tabular-nums text-white">
            {maliciousLogs.length > 0 ? (
              <span className="text-yellow-400">94<span className="text-sm font-sans text-neutral-400">/100</span></span>
            ) : (
              <span>12<span className="text-sm font-sans text-neutral-400">/100</span></span>
            )}
          </div>
          <div className="mt-1 text-[11px] text-neutral-300 font-medium">
            {lang === 'pa' ? 'ਸੀਵੀਅਰ ਥ੍ਰੈਟ ਇੰਡੈਕਸ' : 'Risk assessment'}
          </div>
        </div>
      </div>

      {/* Global Threat Origins World Map (D3.js Visualization) */}
      <ThreatOriginMap
        logs={logs}
        lang={lang}
        onSelectLog={onSelectLog}
        onBlockIp={onBlockIp}
        blockedIps={blockedIps}
      />

      {/* Main Grid: Detections Stream & Analytics */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Left Column (8 cols): Real-Time Threat Detections Feed */}
        <div className="lg:col-span-8 space-y-6">
          <div className="p-5 rounded-2xl bg-neutral-900/90 border border-neutral-800 shadow-xl">
            <div className="flex items-center justify-between mb-4 border-b border-neutral-800 pb-3">
              <div>
                <h2 className="text-sm font-extrabold text-white flex items-center gap-2 uppercase tracking-wide">
                  <ShieldAlert className="w-4 h-4 text-yellow-400" />
                  <span>{t.recentThreats}</span>
                  <span className="text-xs font-mono font-bold bg-yellow-400/10 text-yellow-300 border border-yellow-400/30 px-2 py-0.5 rounded-full">
                    {recentDetections.length} ACTIVE
                  </span>
                </h2>
                <div className="text-xs text-neutral-400 mt-1">
                  {lang === 'pa' ? 'ਹਮਲਾਵਰ ਹਰਕਤਾਂ ਅਤੇ ਸ਼ੱਕੀ ਪੈਟਰਨਜ਼ ਦਾ ਵੇਰਵਾ' : 'Live stream of identified malicious payloads & suspicious signatures'}
                </div>
              </div>

              <button
                onClick={onNavigateToExplorer}
                className="text-xs text-neutral-200 hover:text-yellow-400 font-bold flex items-center gap-1 transition-colors px-2 py-1 rounded-lg hover:bg-neutral-800 cursor-pointer"
              >
                <span>{t.viewAllLogs}</span>
                <ChevronRight className="w-3.5 h-3.5 text-yellow-400" />
              </button>
            </div>

            {/* Threat List Table */}
            {recentDetections.length === 0 ? (
              <div className="py-12 text-center text-neutral-400 text-xs">
                {lang === 'pa' ? 'ਕੋਈ ਸਰਗਰਮ ਖਤਰਾ ਨਹੀਂ ਮਿਲਿਆ। ਕਲੈਕਟਰ ਵਿੱਚੋਂ ਹਮਲਾ ਸੀਨਰੀਓ ਚਲਾਓ।' : 'No threats detected yet. Ingest logs or trigger an attack simulation in the Collector.'}
              </div>
            ) : (
              <div className="divide-y divide-neutral-800/80">
                {recentDetections.map((log) => (
                  <div
                    key={log.id}
                    onClick={() => onSelectLog(log)}
                    className="py-3 px-3 rounded-xl hover:bg-neutral-800/60 cursor-pointer transition-all flex flex-col sm:flex-row sm:items-center justify-between gap-3 group border border-transparent hover:border-yellow-400/20"
                  >
                    <div className="space-y-1 min-w-0">
                      <div className="flex items-center gap-2 flex-wrap">
                        <span className={`text-[10px] font-mono px-2 py-0.5 rounded uppercase ${getSeverityBadgeClass(log.severity)}`}>
                          {log.severity}
                        </span>

                        <span className="text-xs font-bold text-white group-hover:text-yellow-300 transition-colors">
                          {log.ruleMatched?.name || log.category}
                        </span>

                        {log.ruleMatched?.mitreId && (
                          <span className="text-[11px] font-mono font-bold text-yellow-400 bg-yellow-400/10 px-1.5 py-0.2 rounded border border-yellow-400/30">
                            MITRE {log.ruleMatched.mitreId}
                          </span>
                        )}
                      </div>

                      {/* Log raw preview */}
                      <div className="text-xs font-mono text-neutral-300 truncate max-w-xl">
                        {log.raw}
                      </div>

                      {/* Metadata row with clean unboxed text and bullet separators */}
                      <div className="flex items-center gap-2 text-[11px] text-neutral-400 font-mono">
                        <span className="text-white font-medium">{log.sourceIp}</span>
                        <span aria-hidden="true" className="text-yellow-400">·</span>
                        <span className="text-neutral-300">{log.sourceHost}</span>
                        <span aria-hidden="true" className="text-yellow-400">·</span>
                        <span className="tabular-nums text-neutral-400">{new Date(log.timestamp).toLocaleTimeString()}</span>
                      </div>
                    </div>

                    <div className="shrink-0 flex items-center gap-2 sm:self-center">
                      <span className="text-xs font-mono font-bold text-neutral-300 group-hover:text-yellow-400 flex items-center gap-1 transition-colors">
                        <span>{t.details}</span>
                        <ExternalLink className="w-3.5 h-3.5" />
                      </span>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>

          {/* Attack Vector Breakdown with Yellow Progress Bars */}
          <div className="p-5 rounded-2xl bg-neutral-900/90 border border-neutral-800 shadow-xl">
            <div className="flex items-center justify-between mb-4 border-b border-neutral-800 pb-3">
              <h2 className="text-sm font-extrabold text-white uppercase tracking-wide flex items-center gap-2">
                <Crosshair className="w-4 h-4 text-yellow-400" />
                <span>{t.attackVectors}</span>
              </h2>
              <span className="text-xs font-mono text-neutral-400">
                ATT&CK TAXONOMY
              </span>
            </div>

            <div className="grid grid-cols-2 sm:grid-cols-3 gap-3">
              {[
                { label: 'SQL Injection', count: categoryCounts.sqli, code: 'T1190', max: 20 },
                { label: 'Ransomware VSS', count: categoryCounts.ransomware, code: 'T1490', max: 10 },
                { label: 'SSH Brute Force', count: categoryCounts.brute_force, code: 'T1110', max: 25 },
                { label: 'C2 Beaconing', count: categoryCounts.c2_beacon, code: 'T1071', max: 15 },
                { label: 'Port Scanning', count: categoryCounts.port_scan, code: 'T1046', max: 20 },
                { label: 'Path Traversal', count: categoryCounts.directory_traversal, code: 'T1006', max: 15 },
              ].map(item => {
                const percent = Math.min(100, Math.round((item.count / Math.max(item.max, 1)) * 100));
                return (
                  <div key={item.label} className="p-3.5 rounded-xl bg-neutral-950 border border-neutral-800 hover:border-yellow-400/40 transition-all">
                    <div className="flex items-center justify-between text-xs text-neutral-300 font-medium">
                      <span className="truncate">{item.label}</span>
                      <span className="font-mono text-[10px] text-yellow-400 font-bold">{item.code}</span>
                    </div>
                    <div className="mt-2 flex items-baseline justify-between">
                      <span className="text-xl font-black font-mono tabular-nums text-white">
                        {item.count}
                      </span>
                      <span className="text-[10px] font-mono text-neutral-400">
                        {item.count > 0 ? `${item.count} events` : '0 active'}
                      </span>
                    </div>
                    {/* Yellow Progress indicator */}
                    <div className="w-full bg-neutral-800 rounded-full h-1.5 mt-2 overflow-hidden">
                      <div 
                        className="bg-yellow-400 h-1.5 rounded-full transition-all duration-500" 
                        style={{ width: `${item.count > 0 ? Math.max(10, percent) : 0}%` }}
                      />
                    </div>
                  </div>
                );
              })}
            </div>
          </div>
        </div>

        {/* Right Column (4 cols): Top Adversary IPs & Asset Health */}
        <div className="lg:col-span-4 space-y-6">
          {/* Top Threat Actor IPs with Yellow Ranking */}
          <div className="p-5 rounded-2xl bg-neutral-900/90 border border-neutral-800 shadow-xl">
            <div className="flex items-center justify-between mb-4 border-b border-neutral-800 pb-3">
              <h2 className="text-sm font-extrabold text-white flex items-center gap-2 uppercase tracking-wide">
                <Globe2 className="w-4 h-4 text-yellow-400" />
                <span>{t.topAttackerIps}</span>
              </h2>
              <span className="text-[10px] font-mono text-yellow-400 font-bold bg-yellow-400/10 px-2 py-0.5 rounded border border-yellow-400/30">
                ACTIVE C2/BOTS
              </span>
            </div>

            <div className="space-y-3">
              {topAttackerIps.length === 0 ? (
                <div className="text-xs text-neutral-400 py-4 text-center">
                  {lang === 'pa' ? 'ਕੋਈ ਹਮਲਾਵਰ IP ਨਹੀਂ ਮਿਲਿਆ' : 'No threat IPs identified'}
                </div>
              ) : (
                topAttackerIps.map(([ip, data], index) => {
                  const isBlocked = blockedIps.has(ip);
                  return (
                    <div 
                      key={ip} 
                      className="p-3 rounded-xl bg-neutral-950 border border-neutral-800 hover:border-neutral-700 flex items-center justify-between gap-3 text-xs transition-all"
                    >
                      <div className="flex items-center gap-2.5 min-w-0">
                        <span className="w-5 h-5 rounded-md bg-yellow-400 text-neutral-950 font-black font-mono text-[10px] flex items-center justify-center shrink-0">
                          #{index + 1}
                        </span>
                        <div className="min-w-0">
                          <div className="font-mono font-bold text-white flex items-center gap-2 truncate">
                            <span>{ip}</span>
                            {isBlocked && (
                              <span className="text-[9px] text-rose-300 font-bold border border-rose-500/40 bg-rose-500/20 px-1 py-0.2 rounded font-mono">
                                BLOCKED
                              </span>
                            )}
                          </div>
                          <div className="text-[11px] text-neutral-400 mt-0.5 flex items-center gap-1.5 font-mono">
                            <span className="text-white font-medium">{data.count} hits</span>
                            <span className="text-yellow-400">·</span>
                            <span className="text-yellow-300 font-semibold">{data.category}</span>
                          </div>
                        </div>
                      </div>

                      <button
                        onClick={() => onBlockIp(ip)}
                        disabled={isBlocked}
                        className={`px-2.5 py-1.5 rounded-lg text-[11px] font-bold transition-all shrink-0 cursor-pointer ${
                          isBlocked
                            ? 'bg-neutral-800 text-neutral-500 cursor-not-allowed border border-neutral-700'
                            : 'bg-yellow-400 hover:bg-yellow-300 text-neutral-950 shadow-sm shadow-yellow-500/20 active:scale-95'
                        }`}
                        aria-label={`Block IP ${ip}`}
                      >
                        {isBlocked ? (lang === 'pa' ? 'ਬਲਾਕਡ' : 'Blocked') : (lang === 'pa' ? 'ਬਲਾਕ ਕਰੋ' : 'Block IP')}
                      </button>
                    </div>
                  );
                })
              )}
            </div>
          </div>

          {/* High-Value Target Assets */}
          <div className="p-5 rounded-2xl bg-neutral-900/90 border border-neutral-800 shadow-xl">
            <div className="flex items-center justify-between mb-4 border-b border-neutral-800 pb-3">
              <h2 className="text-sm font-extrabold text-white flex items-center gap-2 uppercase tracking-wide">
                <Server className="w-4 h-4 text-white" />
                <span>{t.targetedAssets}</span>
              </h2>
              <span className="text-[10px] font-mono text-neutral-400">
                TIER 1 TARGETS
              </span>
            </div>

            <div className="space-y-2.5">
              {topTargetedHosts.length === 0 ? (
                <div className="text-xs text-neutral-400 py-3 text-center">
                  {lang === 'pa' ? 'ਸਾਰੇ ਸਰਵਰ ਸੁਰੱਖਿਅਤ ਹਨ' : 'All assets operational'}
                </div>
              ) : (
                topTargetedHosts.map(([host, count]) => (
                  <div key={host} className="p-3 rounded-xl bg-neutral-950 border border-neutral-800 flex items-center justify-between text-xs">
                    <div>
                      <div className="font-mono text-white font-bold flex items-center gap-1.5">
                        <span className="w-2 h-2 rounded-full bg-yellow-400 animate-pulse" />
                        <span>{host}</span>
                      </div>
                      <div className="text-[11px] text-neutral-400 mt-0.5 font-mono">{count} telemetry alerts</div>
                    </div>
                    <span className="text-[10px] font-mono font-bold text-yellow-300 bg-yellow-400/10 px-2 py-0.5 rounded border border-yellow-400/30">
                      UNDER PROBE
                    </span>
                  </div>
                ))
              )}
            </div>
          </div>

          {/* MITRE ATT&CK Matrix Quick Card */}
          <div className="p-5 rounded-2xl bg-neutral-900/90 border border-neutral-800 shadow-xl">
            <div className="flex items-center justify-between mb-3 border-b border-neutral-800 pb-3">
              <h2 className="text-sm font-extrabold text-white flex items-center gap-2 uppercase tracking-wide">
                <ShieldCheck className="w-4 h-4 text-yellow-400" />
                <span>{t.mitreMatrixTitle}</span>
              </h2>
              <span className="text-[10px] font-mono font-bold text-yellow-400 bg-yellow-400/10 px-1.5 py-0.5 rounded border border-yellow-400/30">
                v14.1
              </span>
            </div>
            <div className="text-xs text-neutral-300 space-y-2">
              <div className="flex justify-between items-center py-1.5 border-b border-neutral-800/80 text-[11px]">
                <span className="font-medium text-white">T1190: Exploit Public App</span>
                <span className="font-mono text-yellow-400 font-bold">Mitigated</span>
              </div>
              <div className="flex justify-between items-center py-1.5 border-b border-neutral-800/80 text-[11px]">
                <span className="font-medium text-white">T1110: Brute Force</span>
                <span className="font-mono text-yellow-400 font-bold">Throttled</span>
              </div>
              <div className="flex justify-between items-center py-1.5 border-b border-neutral-800/80 text-[11px]">
                <span className="font-medium text-white">T1490: Inhibit System Recovery</span>
                <span className="font-mono text-yellow-400 font-bold">Guarded</span>
              </div>
              <div className="flex justify-between items-center py-1.5 text-[11px]">
                <span className="font-medium text-white">T1071: Standard App Protocol C2</span>
                <span className="font-mono text-yellow-400 font-bold">Detected</span>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
