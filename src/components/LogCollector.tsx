import React, { useState } from 'react';
import { 
  Radio, 
  Play, 
  Pause, 
  Upload, 
  FileText, 
  Zap, 
  ShieldAlert, 
  RotateCcw, 
  CheckCircle2, 
  HardDrive,
  Server,
  Layers,
  Activity
} from 'lucide-react';
import { LogEntry, LogSource } from '../types/soc';
import { parseLogLine } from '../utils/detectionEngine';
import { Language, TRANSLATIONS } from '../utils/i18n';

interface LogCollectorProps {
  lang: Language;
  onIngestLogs: (newLogs: LogEntry[]) => void;
  isStreaming: boolean;
  setIsStreaming: (streaming: boolean) => void;
  streamSpeed: number;
  setStreamSpeed: (speed: number) => void;
  totalIngestedCount: number;
  maliciousCount: number;
  suspiciousCount: number;
  onClearLogs: () => void;
  onInjectScenario: (scenarioType: string) => void;
}

export const LogCollector: React.FC<LogCollectorProps> = ({
  lang,
  onIngestLogs,
  isStreaming,
  setIsStreaming,
  streamSpeed,
  setStreamSpeed,
  totalIngestedCount,
  maliciousCount,
  suspiciousCount,
  onClearLogs,
  onInjectScenario
}) => {
  const t = TRANSLATIONS[lang];
  const [rawText, setRawText] = useState('');
  const [ingestSuccessMessage, setIngestSuccessMessage] = useState<string | null>(null);
  const [activeSources, setActiveSources] = useState<Record<LogSource, boolean>>({
    web: true,
    auth: true,
    firewall: true,
    edr: true,
    cloudtrail: true,
    syslog: true
  });

  const toggleSource = (source: LogSource) => {
    setActiveSources(prev => ({ ...prev, [source]: !prev[source] }));
  };

  const handleManualIngest = () => {
    if (!rawText.trim()) return;
    const lines = rawText.split('\n').filter(l => l.trim().length > 0);
    const parsedEntries = lines.map(line => parseLogLine(line));

    onIngestLogs(parsedEntries);
    const malicious = parsedEntries.filter(p => p.isMalicious).length;
    const suspicious = parsedEntries.filter(p => p.isSuspicious).length;

    setIngestSuccessMessage(
      lang === 'pa'
        ? `ਸਫਲਤਾਪੂਰਵਕ ${parsedEntries.length} ਲੌਗ ਸ਼ਾਮਲ ਕੀਤੇ! (ਖਤਰਨਾਕ: ${malicious}, ਸ਼ੱਕੀ: ${suspicious})`
        : `Successfully ingested ${parsedEntries.length} logs! (${malicious} Malicious, ${suspicious} Suspicious flagged)`
    );
    setRawText('');
    setTimeout(() => setIngestSuccessMessage(null), 4000);
  };

  const handleFileUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    const reader = new FileReader();
    reader.onload = (event) => {
      const content = event.target?.result as string;
      if (content) {
        const lines = content.split('\n').filter(l => l.trim().length > 0);
        const parsed = lines.map(line => parseLogLine(line));
        onIngestLogs(parsed);

        const malicious = parsed.filter(p => p.isMalicious).length;
        setIngestSuccessMessage(
          lang === 'pa'
            ? `ਫਾਈਲ "${file.name}" ਤੋਂ ${parsed.length} ਲੌਗ ਸ਼ਾਮਲ ਕੀਤੇ! (${malicious} ਖਤਰਨਾਕ ਫੜੇ ਗਏ)`
            : `Ingested ${parsed.length} logs from "${file.name}"! (${malicious} threats detected)`
        );
        setTimeout(() => setIngestSuccessMessage(null), 4000);
      }
    };
    reader.readAsText(file);
    e.target.value = '';
  };

  const loadSamplePayload = (type: 'sqli' | 'ransom' | 'brute' | 'json') => {
    switch (type) {
      case 'sqli':
        setRawText('185.220.101.5 - - [28/Oct/2026:12:10:00 +0000] "GET /api/v1/auth/login?user=admin%27%20OR%20%271%27=%271 HTTP/1.1" 200 4501 "-" "sqlmap/1.6"\n185.220.101.5 - - [28/Oct/2026:12:10:05 +0000] "POST /api/v1/query HTTP/1.1" 500 120 "SELECT null, password, email FROM corp_users UNION SELECT 1,2,3" "Mozilla/5.0"');
        break;
      case 'ransom':
        setRawText('Sysmon Event 1: Host=FIN-WORKSTATION-09 Image=C:\\Windows\\System32\\vssadmin.exe Command="vssadmin delete shadows /all /quiet" Parent=C:\\Windows\\System32\\cmd.exe\nEventID 7045: Service Install: A service was installed. Service Name: EncryptorService.exe Path: C:\\ProgramData\\lock.exe');
        break;
      case 'brute':
        setRawText('Oct 28 12:11:01 auth-bastion-01 sshd[901]: Failed password for invalid user root from 45.145.185.10 port 44212 ssh2\nOct 28 12:11:03 auth-bastion-01 sshd[902]: Failed password for invalid user admin from 45.145.185.10 port 44214 ssh2\nOct 28 12:11:05 auth-bastion-01 sshd[903]: Failed password for invalid user oracle from 45.145.185.10 port 44216 ssh2');
        break;
      case 'json':
        setRawText('{"timestamp": "2026-10-28T12:12:00Z", "source": "web", "src_ip": "194.26.29.112", "host": "prod-api-01", "endpoint": "/download", "query": "../../etc/passwd", "status": 403}');
        break;
    }
  };

  return (
    <div className="space-y-6">
      {/* Header Info */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-slate-800 pb-5">
        <div>
          <h1 className="text-xl sm:text-2xl font-bold tracking-tight text-white flex items-center gap-2.5">
            <Radio className="w-6 h-6 text-cyan-400" />
            <span>{t.collectorTitle}</span>
          </h1>
          <p className="text-sm text-slate-400 mt-1">
            {t.collectorSubtitle}
          </p>
        </div>

        {/* Global Stream Status / Action */}
        <div className="flex items-center gap-3">
          <button
            onClick={() => setIsStreaming(!isStreaming)}
            className={`flex items-center gap-2 px-4 py-2 rounded-lg text-xs font-semibold transition-colors shadow-sm ${
              isStreaming
                ? 'bg-amber-600/20 text-amber-300 border border-amber-500/40 hover:bg-amber-600/30'
                : 'bg-emerald-600 text-white hover:bg-emerald-500'
            }`}
            aria-label={isStreaming ? t.pause : t.resume}
          >
            {isStreaming ? (
              <>
                <Pause className="w-4 h-4" />
                <span>{t.pause}</span>
              </>
            ) : (
              <>
                <Play className="w-4 h-4" />
                <span>{t.resume}</span>
              </>
            )}
          </button>

          <button
            onClick={onClearLogs}
            className="flex items-center gap-1.5 px-3 py-2 rounded-lg text-xs font-medium text-slate-400 bg-slate-900 border border-slate-800 hover:text-slate-200 hover:border-slate-700 transition-colors"
            title="Clear all stored logs"
            aria-label={t.clearBuffer}
          >
            <RotateCcw className="w-3.5 h-3.5" />
            <span>{t.clearBuffer}</span>
          </button>
        </div>
      </div>

      {/* Collector Telemetry KPI Cards */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800">
          <div className="flex items-center justify-between text-xs text-slate-400">
            <span>{lang === 'pa' ? 'ਇੰਜੈਸ਼ਨ ਦਰ' : 'Ingestion Rate'}</span>
            <Activity className="w-4 h-4 text-cyan-400" />
          </div>
          <div className="mt-2 text-2xl font-bold font-mono tabular-nums text-white">
            {isStreaming ? (18 * streamSpeed) : 0} <span className="text-xs text-slate-400 font-sans font-normal">EPS</span>
          </div>
          <div className="mt-1 text-xs text-slate-400 flex items-center gap-1.5">
            <span className={`w-2 h-2 rounded-full ${isStreaming ? 'bg-emerald-400 animate-pulse' : 'bg-slate-600'}`} />
            <span>{isStreaming ? t.streamRunning : t.streamPaused}</span>
          </div>
        </div>

        <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800">
          <div className="flex items-center justify-between text-xs text-slate-400">
            <span>{lang === 'pa' ? 'ਕੁੱਲ ਇਕੱਠੇ ਲੌਗਸ' : 'Total Ingested'}</span>
            <Layers className="w-4 h-4 text-indigo-400" />
          </div>
          <div className="mt-2 text-2xl font-bold font-mono tabular-nums text-white">
            {totalIngestedCount.toLocaleString()}
          </div>
          <div className="mt-1 text-xs text-slate-400">
            <span>{lang === 'pa' ? 'ਬਫਰ ਮੈਮੋਰੀ:' : 'Buffer Memory:'}</span> <span className="font-mono tabular-nums">4.2 MB</span>
          </div>
        </div>

        <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800">
          <div className="flex items-center justify-between text-xs text-slate-400">
            <span>{lang === 'pa' ? 'ਖਤਰਨਾਕ ਫੜੇ ਗਏ' : 'Malicious Threats'}</span>
            <ShieldAlert className="w-4 h-4 text-rose-400" />
          </div>
          <div className="mt-2 text-2xl font-bold font-mono tabular-nums text-rose-400">
            {maliciousCount}
          </div>
          <div className="mt-1 text-xs text-rose-300/80">
            <span>{lang === 'pa' ? 'ਤੁਰੰਤ ਜਾਂਚ ਲੋੜੀਂਦੀ' : 'Requires immediate triage'}</span>
          </div>
        </div>

        <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800">
          <div className="flex items-center justify-between text-xs text-slate-400">
            <span>{lang === 'pa' ? 'ਸ਼ੱਕੀ ਐਨੋਮਲੀਜ਼' : 'Suspicious Anomalies'}</span>
            <Zap className="w-4 h-4 text-amber-400" />
          </div>
          <div className="mt-2 text-2xl font-bold font-mono tabular-nums text-amber-400">
            {suspiciousCount}
          </div>
          <div className="mt-1 text-xs text-slate-400">
            <span>{lang === 'pa' ? 'ਵਿਵਹਾਰਕ ਖੋਜ' : 'Behavioral analysis matches'}</span>
          </div>
        </div>
      </div>

      {/* Main 2-Column Split: Attack Simulator & Manual Ingestion */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Left Column (5 cols): Stream Control & Attack Scenario Presets */}
        <div className="lg:col-span-5 space-y-6">
          {/* Attack Scenario Injector */}
          <div className="p-5 rounded-xl bg-slate-900/80 border border-slate-800">
            <h2 className="text-sm font-semibold text-white flex items-center gap-2">
              <Zap className="w-4 h-4 text-cyan-400" />
              <span>{t.simulateAttack}</span>
            </h2>
            <p className="text-xs text-slate-400 mt-1">
              {t.selectScenario}
            </p>

            <div className="mt-4 space-y-2.5">
              <button
                onClick={() => onInjectScenario('sqli')}
                className="w-full text-left p-3 rounded-lg bg-slate-950 border border-slate-800 hover:border-cyan-500/60 hover:bg-slate-900/70 transition-all flex items-center justify-between group"
              >
                <div>
                  <div className="text-xs font-semibold text-slate-200 group-hover:text-cyan-300">
                    {t.scenarioSqli}
                  </div>
                  <div className="text-[11px] text-slate-500 mt-0.5">
                    MITRE T1190 · SQL Injection & Directory Traversal
                  </div>
                </div>
                <span className="text-[10px] font-mono font-bold text-rose-400 px-2 py-0.5 rounded bg-rose-500/10 border border-rose-500/20">
                  CRITICAL
                </span>
              </button>

              <button
                onClick={() => onInjectScenario('ransom')}
                className="w-full text-left p-3 rounded-lg bg-slate-950 border border-slate-800 hover:border-cyan-500/60 hover:bg-slate-900/70 transition-all flex items-center justify-between group"
              >
                <div>
                  <div className="text-xs font-semibold text-slate-200 group-hover:text-cyan-300">
                    {t.scenarioRansom}
                  </div>
                  <div className="text-[11px] text-slate-500 mt-0.5">
                    MITRE T1490 · Inhibit System Recovery & VSS deletion
                  </div>
                </div>
                <span className="text-[10px] font-mono font-bold text-rose-400 px-2 py-0.5 rounded bg-rose-500/10 border border-rose-500/20">
                  CRITICAL
                </span>
              </button>

              <button
                onClick={() => onInjectScenario('brute')}
                className="w-full text-left p-3 rounded-lg bg-slate-950 border border-slate-800 hover:border-cyan-500/60 hover:bg-slate-900/70 transition-all flex items-center justify-between group"
              >
                <div>
                  <div className="text-xs font-semibold text-slate-200 group-hover:text-cyan-300">
                    {t.scenarioBrute}
                  </div>
                  <div className="text-[11px] text-slate-500 mt-0.5">
                    MITRE T1110 · Automated SSH / Bastion Password Spray
                  </div>
                </div>
                <span className="text-[10px] font-mono font-bold text-amber-400 px-2 py-0.5 rounded bg-amber-500/10 border border-amber-500/20">
                  HIGH
                </span>
              </button>

              <button
                onClick={() => onInjectScenario('c2')}
                className="w-full text-left p-3 rounded-lg bg-slate-950 border border-slate-800 hover:border-cyan-500/60 hover:bg-slate-900/70 transition-all flex items-center justify-between group"
              >
                <div>
                  <div className="text-xs font-semibold text-slate-200 group-hover:text-cyan-300">
                    {t.scenarioC2}
                  </div>
                  <div className="text-[11px] text-slate-500 mt-0.5">
                    MITRE T1071 · Cobalt Strike Beaconing & Data Outflow
                  </div>
                </div>
                <span className="text-[10px] font-mono font-bold text-amber-400 px-2 py-0.5 rounded bg-amber-500/10 border border-amber-500/20">
                  HIGH
                </span>
              </button>

              <button
                onClick={() => onInjectScenario('portscan')}
                className="w-full text-left p-3 rounded-lg bg-slate-950 border border-slate-800 hover:border-cyan-500/60 hover:bg-slate-900/70 transition-all flex items-center justify-between group"
              >
                <div>
                  <div className="text-xs font-semibold text-slate-200 group-hover:text-cyan-300">
                    {t.scenarioPortScan}
                  </div>
                  <div className="text-[11px] text-slate-500 mt-0.5">
                    MITRE T1046 · Perimeter Port Probing & SYN sweep
                  </div>
                </div>
                <span className="text-[10px] font-mono font-bold text-sky-400 px-2 py-0.5 rounded bg-sky-500/10 border border-sky-500/20">
                  MEDIUM
                </span>
              </button>

              <button
                onClick={() => onInjectScenario('benign')}
                className="w-full text-left p-3 rounded-lg bg-slate-950 border border-slate-800 hover:border-slate-700 hover:bg-slate-900/50 transition-all flex items-center justify-between group"
              >
                <div>
                  <div className="text-xs font-semibold text-slate-300 group-hover:text-white">
                    {t.scenarioBenign}
                  </div>
                  <div className="text-[11px] text-slate-500 mt-0.5">
                    Clean enterprise authenticated traffic & asset queries
                  </div>
                </div>
                <span className="text-[10px] font-mono text-slate-400 px-2 py-0.5 rounded bg-slate-800 border border-slate-700">
                  CLEAN
                </span>
              </button>
            </div>

            {/* Stream Speed Selector */}
            <div className="mt-5 pt-4 border-t border-slate-800 flex items-center justify-between">
              <span className="text-xs text-slate-400">{t.streamSpeed}:</span>
              <div className="flex items-center gap-1 bg-slate-950 p-1 rounded-lg border border-slate-800">
                {[1, 2, 5].map((speed) => (
                  <button
                    key={speed}
                    onClick={() => setStreamSpeed(speed)}
                    className={`px-2.5 py-1 text-xs font-mono rounded transition-colors ${
                      streamSpeed === speed
                        ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40 font-bold'
                        : 'text-slate-400 hover:text-white'
                    }`}
                  >
                    {speed}x
                  </button>
                ))}
              </div>
            </div>
          </div>

          {/* Active Collector Sources */}
          <div className="p-5 rounded-xl bg-slate-900/80 border border-slate-800">
            <h2 className="text-sm font-semibold text-white flex items-center gap-2">
              <Server className="w-4 h-4 text-cyan-400" />
              <span>{t.activeSources}</span>
            </h2>
            <div className="mt-3 grid grid-cols-2 gap-2 text-xs">
              {(
                [
                  ['web', 'Web Ingress (Nginx)'],
                  ['auth', 'Linux Auth (SSHD/Sudo)'],
                  ['firewall', 'Perimeter Firewall (CEF)'],
                  ['edr', 'Endpoint EDR (Sysmon)'],
                  ['cloudtrail', 'AWS CloudTrail'],
                  ['syslog', 'Core Syslog RFC5424']
                ] as [LogSource, string][]
              ).map(([src, label]) => (
                <button
                  key={src}
                  onClick={() => toggleSource(src)}
                  className={`p-2 rounded-lg border text-left flex items-center justify-between transition-colors ${
                    activeSources[src]
                      ? 'bg-slate-950 border-cyan-500/40 text-slate-200'
                      : 'bg-slate-950/40 border-slate-800/80 text-slate-500'
                  }`}
                >
                  <span className="truncate">{label}</span>
                  <span className={`w-1.5 h-1.5 rounded-full ${activeSources[src] ? 'bg-cyan-400' : 'bg-slate-700'}`} />
                </button>
              ))}
            </div>
          </div>
        </div>

        {/* Right Column (7 cols): Manual Ingestion & Upload */}
        <div className="lg:col-span-7 space-y-6">
          <div className="p-5 rounded-xl bg-slate-900/80 border border-slate-800">
            <div className="flex items-center justify-between">
              <h2 className="text-sm font-semibold text-white flex items-center gap-2">
                <FileText className="w-4 h-4 text-cyan-400" />
                <span>{t.manualIngest}</span>
              </h2>

              {/* Sample Presets to quickly test */}
              <div className="flex items-center gap-1.5 text-xs text-slate-400">
                <span className="hidden sm:inline text-[11px]">{lang === 'pa' ? 'ਨਮੂਨਾ ਲੋਡ ਕਰੋ:' : 'Load Sample:'}</span>
                <button
                  onClick={() => loadSamplePayload('sqli')}
                  className="px-2 py-1 bg-slate-950 border border-slate-800 rounded text-[11px] text-cyan-300 hover:border-cyan-500 transition-colors"
                >
                  SQLi
                </button>
                <button
                  onClick={() => loadSamplePayload('ransom')}
                  className="px-2 py-1 bg-slate-950 border border-slate-800 rounded text-[11px] text-rose-300 hover:border-rose-500 transition-colors"
                >
                  Ransomware
                </button>
                <button
                  onClick={() => loadSamplePayload('brute')}
                  className="px-2 py-1 bg-slate-950 border border-slate-800 rounded text-[11px] text-amber-300 hover:border-amber-500 transition-colors"
                >
                  BruteForce
                </button>
                <button
                  onClick={() => loadSamplePayload('json')}
                  className="px-2 py-1 bg-slate-950 border border-slate-800 rounded text-[11px] text-slate-300 hover:border-slate-600 transition-colors"
                >
                  JSON
                </button>
              </div>
            </div>

            {/* Success Banner */}
            {ingestSuccessMessage && (
              <div className="mt-3 p-3 rounded-lg bg-emerald-500/10 border border-emerald-500/30 text-emerald-300 text-xs flex items-center gap-2">
                <CheckCircle2 className="w-4 h-4 shrink-0 text-emerald-400" />
                <span>{ingestSuccessMessage}</span>
              </div>
            )}

            {/* Textarea */}
            <div className="mt-3">
              <textarea
                value={rawText}
                onChange={(e) => setRawText(e.target.value)}
                placeholder={t.pasteLogPlaceholder}
                rows={9}
                className="w-full rounded-lg bg-slate-950 border border-slate-800 p-3 text-xs font-mono text-slate-200 placeholder:text-slate-600 focus:outline-none focus:border-cyan-500 transition-colors"
              />
            </div>

            {/* Actions: File upload & Ingest button */}
            <div className="mt-4 flex flex-col sm:flex-row items-center justify-between gap-3">
              <label className="w-full sm:w-auto flex items-center justify-center gap-2 px-3 py-2 bg-slate-950 border border-slate-800 hover:border-slate-700 text-slate-300 hover:text-white rounded-lg text-xs cursor-pointer transition-colors">
                <Upload className="w-4 h-4 text-cyan-400" />
                <span>{t.uploadFile}</span>
                <input
                  type="file"
                  accept=".log,.txt,.json,.csv"
                  onChange={handleFileUpload}
                  className="hidden"
                />
              </label>

              <button
                onClick={handleManualIngest}
                disabled={!rawText.trim()}
                className={`w-full sm:w-auto px-5 py-2 rounded-lg text-xs font-semibold flex items-center justify-center gap-2 transition-all ${
                  rawText.trim()
                    ? 'bg-cyan-600 hover:bg-cyan-500 text-white shadow-sm shadow-cyan-900/30 cursor-pointer'
                    : 'bg-slate-800 text-slate-500 cursor-not-allowed'
                }`}
              >
                <HardDrive className="w-4 h-4" />
                <span>{t.ingestButton}</span>
              </button>
            </div>
          </div>

          {/* Architecture / Ingestion Guide */}
          <div className="p-4 rounded-xl bg-slate-950/60 border border-slate-900 text-xs text-slate-400 space-y-2">
            <div className="font-semibold text-slate-300">
              {lang === 'pa' ? 'ਲੌਗ ਕੁਲੈਕਟਰ ਜਾਣਕਾਰੀ:' : 'Log Collector Pipeline Architecture:'}
            </div>
            <p>
              {lang === 'pa'
                ? 'ਕੁਲੈਕਟਰ ਇੰਜਣ ਆਉਣ ਵਾਲੇ ਹਰ ਲੌਗ ਨੂੰ ਪਾਰਸ ਕਰਦਾ ਹੈ, ਸਰੋਤ IP, ਹੋਸਟ ਅਤੇ ਵਰਤੋਂਕਾਰ ਦੀ ਪਛਾਣ ਕਰਦਾ ਹੈ, ਅਤੇ MITRE ATT&CK ਤਕਨੀਕਾਂ ਨਾਲ ਮੈਚ ਕਰਕੇ ਸ਼ੱਕੀ/ਖਤਰਨਾਕ ਅਟੈਕਸ ਤੁਰੰਤ ਫਲੈਗ ਕਰਦਾ ਹੈ।'
                : 'The AegisSOC collector pipeline ingests unstructured streams, extracts telemetry headers (IPv4, Host, Process, User), and evaluates live detection rules matching MITRE ATT&CK framework vectors.'}
            </p>
          </div>
        </div>
      </div>
    </div>
  );
};
