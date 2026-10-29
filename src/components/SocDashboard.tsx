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
  ShieldCheck
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
        return 'text-rose-400 border border-rose-500/30 bg-rose-500/10';
      case 'high':
        return 'text-amber-400 border border-amber-500/30 bg-amber-500/10';
      case 'medium':
        return 'text-sky-400 border border-sky-500/30 bg-sky-500/10';
      case 'low':
        return 'text-slate-400 border border-slate-700 bg-slate-800/40';
      default:
        return 'text-emerald-400 border border-emerald-500/30 bg-emerald-500/10';
    }
  };

  return (
    <div className="space-y-6">
      {/* Overview Header Strip */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-slate-800 pb-5">
        <div>
          <h1 className="text-xl sm:text-2xl font-bold tracking-tight text-white flex items-center gap-2">
            <span>{lang === 'pa' ? 'ਸੁਰੱਖਿਆ ਸੰਚਾਲਨ ਕੇਂਦਰ ਕੰਸੋਲ' : 'SOC Command & Monitoring Console'}</span>
          </h1>
          <p className="text-xs sm:text-sm text-slate-400 mt-1">
            {lang === 'pa'
              ? 'ਰੀਅਲ-ਟਾਈਮ ਖਤਰਾ ਵਿਸ਼ਲੇਸ਼ਣ, ਹਮਲਾਵਰ IPs ਦੀ ਪਛਾਣ ਅਤੇ MITRE ATT&CK ਅਨੁਕੂਲਤਾ'
              : 'Real-time threat detection, automated telemetry normalization, and MITRE ATT&CK threat hunting'}
          </p>
        </div>

        <div className="flex items-center gap-3">
          <div className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-slate-900 border border-slate-800 text-xs text-slate-300">
            <span className="w-2 h-2 rounded-full bg-rose-500 animate-ping" />
            <span className="font-semibold">{t.threatLevel}:</span>
            <span className="text-rose-400 font-mono font-bold">{t.elevated}</span>
          </div>

          <button
            onClick={onNavigateToCollector}
            className="px-3 py-1.5 rounded-lg text-xs font-semibold bg-slate-900 hover:bg-slate-800 border border-slate-700 text-slate-200 transition-colors flex items-center gap-1.5"
          >
            <span>{lang === 'pa' ? 'ਕਲੈਕਟਰ ਸਟ੍ਰੀਮ' : 'Collector Stream'}</span>
            <ChevronRight className="w-3.5 h-3.5" />
          </button>
        </div>
      </div>

      {/* KPI Cards Strip */}
      <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-3 sm:gap-4">
        {/* KPI 1: Ingested */}
        <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800">
          <div className="flex items-center justify-between text-xs text-slate-400">
            <span>{t.kpiTotalEvents}</span>
            <Layers className="w-4 h-4 text-cyan-400" />
          </div>
          <div className="mt-2 text-2xl font-bold font-mono tabular-nums text-white">
            {totalLogs.toLocaleString()}
          </div>
          <div className="mt-1 text-[11px] text-slate-400">
            {lang === 'pa' ? 'ਸਾਰੇ ਸਰੋਤ' : 'Normalized'}
          </div>
        </div>

        {/* KPI 2: Malicious */}
        <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800">
          <div className="flex items-center justify-between text-xs text-slate-400">
            <span>{t.kpiMalicious}</span>
            <ShieldAlert className="w-4 h-4 text-rose-400" />
          </div>
          <div className="mt-2 text-2xl font-bold font-mono tabular-nums text-rose-400">
            {maliciousLogs.length}
          </div>
          <div className="mt-1 text-[11px] text-rose-300/80 font-mono tabular-nums">
            {totalLogs > 0 ? ((maliciousLogs.length / totalLogs) * 100).toFixed(1) : 0}% of logs
          </div>
        </div>

        {/* KPI 3: Suspicious */}
        <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800">
          <div className="flex items-center justify-between text-xs text-slate-400">
            <span>{t.kpiSuspicious}</span>
            <AlertTriangle className="w-4 h-4 text-amber-400" />
          </div>
          <div className="mt-2 text-2xl font-bold font-mono tabular-nums text-amber-400">
            {suspiciousLogs.length}
          </div>
          <div className="mt-1 text-[11px] text-amber-300/80">
            {lang === 'pa' ? 'ਐਨੋਮਲੀ ਸਕੋਰ' : 'Behavioral triggers'}
          </div>
        </div>

        {/* KPI 4: Critical Incidents */}
        <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800">
          <div className="flex items-center justify-between text-xs text-slate-400">
            <span>{t.kpiCriticalIncidents}</span>
            <Flame className="w-4 h-4 text-rose-500" />
          </div>
          <div className="mt-2 text-2xl font-bold font-mono tabular-nums text-white">
            {criticalCount}
          </div>
          <div className="mt-1 text-[11px] text-rose-400 font-semibold">
            {criticalCount > 0 ? (lang === 'pa' ? 'ਤੁਰੰਤ ਐਕਸ਼ਨ ਲੋੜੀਂਦਾ' : 'P1 High Impact') : 'Nominal'}
          </div>
        </div>

        {/* KPI 5: EPS */}
        <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800">
          <div className="flex items-center justify-between text-xs text-slate-400">
            <span>{t.kpiEps}</span>
            <Activity className="w-4 h-4 text-emerald-400" />
          </div>
          <div className="mt-2 text-2xl font-bold font-mono tabular-nums text-white">
            36 <span className="text-xs font-sans text-slate-400">EPS</span>
          </div>
          <div className="mt-1 text-[11px] text-slate-400 flex items-center gap-1">
            <span className="w-1.5 h-1.5 rounded-full bg-emerald-400" />
            <span>0 dropped</span>
          </div>
        </div>

        {/* KPI 6: Average Threat Score */}
        <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800">
          <div className="flex items-center justify-between text-xs text-slate-400">
            <span>{t.kpiThreatScore}</span>
            <Zap className="w-4 h-4 text-cyan-400" />
          </div>
          <div className="mt-2 text-2xl font-bold font-mono tabular-nums text-cyan-400">
            {maliciousLogs.length > 0 ? '94/100' : '12/100'}
          </div>
          <div className="mt-1 text-[11px] text-slate-400">
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
          <div className="p-5 rounded-xl bg-slate-900/80 border border-slate-800">
            <div className="flex items-center justify-between mb-4">
              <div>
                <h2 className="text-sm font-semibold text-white flex items-center gap-2">
                  <ShieldAlert className="w-4 h-4 text-rose-400" />
                  <span>{t.recentThreats}</span>
                </h2>
                <div className="text-xs text-slate-400 mt-0.5">
                  {lang === 'pa' ? 'ਹਮਲਾਵਰ ਹਰਕਤਾਂ ਅਤੇ ਸ਼ੱਕੀ ਪੈਟਰਨਜ਼ ਦਾ ਵੇਰਵਾ' : 'Live stream of identified malicious payloads & suspicious signatures'}
                </div>
              </div>

              <button
                onClick={onNavigateToExplorer}
                className="text-xs text-cyan-400 hover:text-cyan-300 font-medium flex items-center gap-1 transition-colors"
              >
                <span>{t.viewAllLogs}</span>
                <ChevronRight className="w-3.5 h-3.5" />
              </button>
            </div>

            {/* Threat List Table */}
            {recentDetections.length === 0 ? (
              <div className="py-12 text-center text-slate-500 text-xs">
                {lang === 'pa' ? 'ਕੋਈ ਸਰਗਰਮ ਖਤਰਾ ਨਹੀਂ ਮਿਲਿਆ। ਕਲੈਕਟਰ ਵਿੱਚੋਂ ਹਮਲਾ ਸੀਨਰੀਓ ਚਲਾਓ।' : 'No threats detected yet. Ingest logs or trigger an attack simulation in the Collector.'}
              </div>
            ) : (
              <div className="divide-y divide-slate-800/80">
                {recentDetections.map((log) => (
                  <div
                    key={log.id}
                    onClick={() => onSelectLog(log)}
                    className="py-3 px-2 rounded-lg hover:bg-slate-800/50 cursor-pointer transition-all flex flex-col sm:flex-row sm:items-center justify-between gap-3 group"
                  >
                    <div className="space-y-1 min-w-0">
                      <div className="flex items-center gap-2 flex-wrap">
                        <span className={`text-[10px] font-mono font-bold px-2 py-0.5 rounded uppercase ${getSeverityBadgeClass(log.severity)}`}>
                          {log.severity}
                        </span>

                        <span className="text-xs font-semibold text-white group-hover:text-cyan-300 transition-colors">
                          {log.ruleMatched?.name || log.category}
                        </span>

                        {log.ruleMatched?.mitreId && (
                          <span className="text-[11px] font-mono text-cyan-400/80">
                            MITRE {log.ruleMatched.mitreId}
                          </span>
                        )}
                      </div>

                      {/* Log raw preview */}
                      <div className="text-xs font-mono text-slate-400 truncate max-w-xl">
                        {log.raw}
                      </div>

                      {/* Metadata row with clean unboxed text and bullet separators */}
                      <div className="flex items-center gap-2 text-[11px] text-slate-500 font-mono">
                        <span className="text-slate-400">{log.sourceIp}</span>
                        <span aria-hidden="true">·</span>
                        <span className="text-slate-400">{log.sourceHost}</span>
                        <span aria-hidden="true">·</span>
                        <span className="tabular-nums">{new Date(log.timestamp).toLocaleTimeString()}</span>
                      </div>
                    </div>

                    <div className="shrink-0 flex items-center gap-2 sm:self-center">
                      <span className="text-xs font-mono tabular-nums text-slate-400 group-hover:text-cyan-400 flex items-center gap-1">
                        <span>{t.details}</span>
                        <ExternalLink className="w-3.5 h-3.5" />
                      </span>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>

          {/* Attack Vector Breakdown */}
          <div className="p-5 rounded-xl bg-slate-900/80 border border-slate-800">
            <h2 className="text-sm font-semibold text-white mb-3">
              {t.attackVectors}
            </h2>
            <div className="grid grid-cols-2 sm:grid-cols-3 gap-3">
              {[
                { label: 'SQL Injection', count: categoryCounts.sqli, code: 'T1190', color: 'rose' },
                { label: 'Ransomware VSS', count: categoryCounts.ransomware, code: 'T1490', color: 'rose' },
                { label: 'SSH Brute Force', count: categoryCounts.brute_force, code: 'T1110', color: 'amber' },
                { label: 'C2 Beaconing', count: categoryCounts.c2_beacon, code: 'T1071', color: 'amber' },
                { label: 'Port Scanning', count: categoryCounts.port_scan, code: 'T1046', color: 'sky' },
                { label: 'Path Traversal', count: categoryCounts.directory_traversal, code: 'T1006', color: 'indigo' },
              ].map(item => (
                <div key={item.label} className="p-3 rounded-lg bg-slate-950 border border-slate-800">
                  <div className="flex items-center justify-between text-xs text-slate-400">
                    <span className="truncate">{item.label}</span>
                    <span className="font-mono text-[10px] text-slate-500">{item.code}</span>
                  </div>
                  <div className="mt-1.5 text-lg font-bold font-mono tabular-nums text-white">
                    {item.count}
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* Right Column (4 cols): Top Adversary IPs & Asset Health */}
        <div className="lg:col-span-4 space-y-6">
          {/* Top Threat Actor IPs */}
          <div className="p-5 rounded-xl bg-slate-900/80 border border-slate-800">
            <div className="flex items-center justify-between mb-3">
              <h2 className="text-sm font-semibold text-white flex items-center gap-2">
                <Globe2 className="w-4 h-4 text-cyan-400" />
                <span>{t.topAttackerIps}</span>
              </h2>
            </div>

            <div className="space-y-3">
              {topAttackerIps.length === 0 ? (
                <div className="text-xs text-slate-500 py-4 text-center">
                  {lang === 'pa' ? 'ਕੋਈ ਹਮਲਾਵਰ IP ਨਹੀਂ ਮਿਲਿਆ' : 'No threat IPs identified'}
                </div>
              ) : (
                topAttackerIps.map(([ip, data]) => {
                  const isBlocked = blockedIps.has(ip);
                  return (
                    <div 
                      key={ip} 
                      className="p-2.5 rounded-lg bg-slate-950 border border-slate-800 flex items-center justify-between gap-3 text-xs"
                    >
                      <div>
                        <div className="font-mono font-bold text-slate-200 flex items-center gap-2">
                          <span>{ip}</span>
                          {isBlocked && (
                            <span className="text-[10px] text-rose-400 border border-rose-500/30 px-1 py-0.2 rounded font-sans">
                              BLOCKED
                            </span>
                          )}
                        </div>
                        <div className="text-[11px] text-slate-400 mt-0.5">
                          <span>{data.count} hits</span>
                          <span className="mx-1">·</span>
                          <span className="text-rose-400">{data.category}</span>
                        </div>
                      </div>

                      <button
                        onClick={() => onBlockIp(ip)}
                        disabled={isBlocked}
                        className={`px-2.5 py-1 rounded text-[11px] font-semibold transition-colors ${
                          isBlocked
                            ? 'bg-slate-800 text-slate-500 cursor-not-allowed'
                            : 'bg-rose-600/20 text-rose-300 border border-rose-500/40 hover:bg-rose-600 hover:text-white'
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
          <div className="p-5 rounded-xl bg-slate-900/80 border border-slate-800">
            <h2 className="text-sm font-semibold text-white flex items-center gap-2 mb-3">
              <Server className="w-4 h-4 text-cyan-400" />
              <span>{t.targetedAssets}</span>
            </h2>

            <div className="space-y-2">
              {topTargetedHosts.length === 0 ? (
                <div className="text-xs text-slate-500 py-3 text-center">
                  {lang === 'pa' ? 'ਸਾਰੇ ਸਰਵਰ ਸੁਰੱਖਿਅਤ ਹਨ' : 'All assets operational'}
                </div>
              ) : (
                topTargetedHosts.map(([host, count]) => (
                  <div key={host} className="p-2.5 rounded-lg bg-slate-950 border border-slate-800 flex items-center justify-between text-xs">
                    <div>
                      <div className="font-mono text-slate-200 font-semibold">{host}</div>
                      <div className="text-[11px] text-slate-500">{count} security events</div>
                    </div>
                    <span className="text-[10px] font-mono font-bold text-amber-400 bg-amber-500/10 px-2 py-0.5 rounded border border-amber-500/20">
                      TARGETED
                    </span>
                  </div>
                ))
              )}
            </div>
          </div>

          {/* MITRE ATT&CK Matrix Quick Card */}
          <div className="p-5 rounded-xl bg-slate-900/80 border border-slate-800">
            <h2 className="text-sm font-semibold text-white flex items-center gap-2 mb-2">
              <ShieldCheck className="w-4 h-4 text-cyan-400" />
              <span>{t.mitreMatrixTitle}</span>
            </h2>
            <div className="text-xs text-slate-400 space-y-2">
              <div className="flex justify-between items-center py-1 border-b border-slate-800 text-[11px]">
                <span>T1190: Exploit Public App</span>
                <span className="font-mono text-cyan-400">Active</span>
              </div>
              <div className="flex justify-between items-center py-1 border-b border-slate-800 text-[11px]">
                <span>T1110: Brute Force</span>
                <span className="font-mono text-cyan-400">Active</span>
              </div>
              <div className="flex justify-between items-center py-1 border-b border-slate-800 text-[11px]">
                <span>T1490: Inhibit System Recovery</span>
                <span className="font-mono text-cyan-400">Active</span>
              </div>
              <div className="flex justify-between items-center py-1 text-[11px]">
                <span>T1071: Standard App Protocol C2</span>
                <span className="font-mono text-cyan-400">Active</span>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
