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
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-neutral-800 pb-5">
        <div>
          <h1 className="text-xl sm:text-2xl font-black tracking-tight text-white flex items-center gap-2.5 uppercase">
            <Radio className="w-6 h-6 text-yellow-400 stroke-[2.5]" />
            <span>{t.collectorTitle}</span>
          </h1>
          <p className="text-xs sm:text-sm text-neutral-300 font-medium mt-1">
            {t.collectorSubtitle}
          </p>
        </div>

        {/* Global Stream Status / Action in Cyber Yellow & Crisp White */}
        <div className="flex items-center gap-3">
          <button
            onClick={() => setIsStreaming(!isStreaming)}
            className={`flex items-center gap-2 px-4 py-2 rounded-xl text-xs font-bold transition-all shadow-md active:scale-95 cursor-pointer ${
              isStreaming
                ? 'bg-yellow-400 hover:bg-yellow-300 text-neutral-950 shadow-yellow-500/20'
                : 'bg-white hover:bg-neutral-100 text-neutral-950'
            }`}
            aria-label={isStreaming ? t.pause : t.resume}
          >
            {isStreaming ? (
              <>
                <Pause className="w-4 h-4 text-neutral-950 stroke-[2.5]" />
                <span>{t.pause}</span>
              </>
            ) : (
              <>
                <Play className="w-4 h-4 text-neutral-950 stroke-[2.5]" />
                <span>{t.resume}</span>
              </>
            )}
          </button>

          <button
            onClick={onClearLogs}
            className="flex items-center gap-1.5 px-3 py-2 rounded-xl text-xs font-semibold text-neutral-300 bg-neutral-900 border border-neutral-800 hover:border-neutral-700 hover:text-white transition-colors cursor-pointer"
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
        <div className="p-4 rounded-xl bg-neutral-900/90 border border-neutral-800 border-t-2 border-t-yellow-400 shadow-md">
          <div className="flex items-center justify-between text-xs text-neutral-400 font-medium">
            <span>{lang === 'pa' ? 'ਇੰਜੈਸ਼ਨ ਦਰ' : 'Ingestion Rate'}</span>
            <Activity className="w-4 h-4 text-yellow-400" />
          </div>
          <div className="mt-2 text-2xl sm:text-3xl font-black font-mono tabular-nums text-white">
            {isStreaming ? (18 * streamSpeed) : 0} <span className="text-xs text-neutral-400 font-sans font-normal">EPS</span>
          </div>
          <div className="mt-1 text-xs text-neutral-300 flex items-center gap-1.5 font-medium">
            <span className={`w-2 h-2 rounded-full ${isStreaming ? 'bg-yellow-400 animate-ping' : 'bg-neutral-600'}`} />
            <span>{isStreaming ? t.streamRunning : t.streamPaused}</span>
          </div>
        </div>

        <div className="p-4 rounded-xl bg-neutral-900/90 border border-neutral-800 border-t-2 border-t-white shadow-md">
          <div className="flex items-center justify-between text-xs text-neutral-400 font-medium">
            <span>{lang === 'pa' ? 'ਕੁੱਲ ਇਕੱਠੇ ਲੌਗਸ' : 'Total Ingested'}</span>
            <Layers className="w-4 h-4 text-white" />
          </div>
          <div className="mt-2 text-2xl sm:text-3xl font-black font-mono tabular-nums text-white">
            {totalIngestedCount.toLocaleString()}
          </div>
          <div className="mt-1 text-xs text-neutral-300">
            <span>{lang === 'pa' ? 'ਬਫਰ ਮੈਮੋਰੀ:' : 'Buffer Memory:'}</span> <span className="font-mono tabular-nums font-semibold text-white">4.2 MB</span>
          </div>
        </div>

        <div className="p-4 rounded-xl bg-neutral-900/90 border border-neutral-800 border-t-2 border-t-rose-500 shadow-md">
          <div className="flex items-center justify-between text-xs text-neutral-400 font-medium">
            <span>{lang === 'pa' ? 'ਖਤਰਨਾਕ ਫੜੇ ਗਏ' : 'Malicious Threats'}</span>
            <ShieldAlert className="w-4 h-4 text-rose-400" />
          </div>
          <div className="mt-2 text-2xl sm:text-3xl font-black font-mono tabular-nums text-rose-400">
            {maliciousCount}
          </div>
          <div className="mt-1 text-xs text-rose-300 font-semibold">
            <span>{lang === 'pa' ? 'ਤੁਰੰਤ ਜਾਂਚ ਲੋੜੀਂਦੀ' : 'Requires immediate triage'}</span>
          </div>
        </div>

        <div className="p-4 rounded-xl bg-neutral-900/90 border border-neutral-800 border-t-2 border-t-yellow-400 shadow-md">
          <div className="flex items-center justify-between text-xs text-neutral-400 font-medium">
            <span>{lang === 'pa' ? 'ਸ਼ੱਕੀ ਐਨੋਮਲੀਜ਼' : 'Suspicious Anomalies'}</span>
            <Zap className="w-4 h-4 text-yellow-400" />
          </div>
          <div className="mt-2 text-2xl sm:text-3xl font-black font-mono tabular-nums text-yellow-400">
            {suspiciousCount}
          </div>
          <div className="mt-1 text-xs text-neutral-300 font-medium">
            <span>{lang === 'pa' ? 'ਵਿਵਹਾਰਕ ਖੋਜ' : 'Behavioral analysis matches'}</span>
          </div>
        </div>
      </div>

      {/* Main 2-Column Split: Attack Simulator & Manual Ingestion */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Left Column (5 cols): Stream Control & Attack Scenario Presets */}
        <div className="lg:col-span-5 space-y-6">
          {/* Attack Scenario Injector */}
          <div className="p-5 rounded-2xl bg-neutral-900/90 border border-neutral-800 shadow-xl">
            <h2 className="text-sm font-extrabold text-white flex items-center gap-2 uppercase tracking-wide">
              <Zap className="w-4 h-4 text-yellow-400" />
              <span>{t.simulateAttack}</span>
            </h2>
            <p className="text-xs text-neutral-400 mt-1">
              {t.selectScenario}
            </p>

            <div className="mt-4 space-y-2.5">
              <button
                onClick={() => onInjectScenario('sqli')}
                className="w-full text-left p-3.5 rounded-xl bg-neutral-950 border border-neutral-800 hover:border-yellow-400 hover:bg-neutral-900 transition-all flex items-center justify-between group cursor-pointer"
              >
                <div>
                  <div className="text-xs font-bold text-white group-hover:text-yellow-300 transition-colors">
                    {t.scenarioSqli}
                  </div>
                  <div className="text-[11px] text-neutral-400 mt-0.5 font-mono">
                    MITRE T1190 · SQL Injection & Directory Traversal
                  </div>
                </div>
                <span className="text-[10px] font-mono font-bold text-rose-300 px-2 py-0.5 rounded bg-rose-500/20 border border-rose-500/40">
                  CRITICAL
                </span>
              </button>

              <button
                onClick={() => onInjectScenario('ransom')}
                className="w-full text-left p-3.5 rounded-xl bg-neutral-950 border border-neutral-800 hover:border-yellow-400 hover:bg-neutral-900 transition-all flex items-center justify-between group cursor-pointer"
              >
                <div>
                  <div className="text-xs font-bold text-white group-hover:text-yellow-300 transition-colors">
                    {t.scenarioRansom}
                  </div>
                  <div className="text-[11px] text-neutral-400 mt-0.5 font-mono">
                    MITRE T1490 · Inhibit System Recovery & VSS deletion
                  </div>
                </div>
                <span className="text-[10px] font-mono font-bold text-rose-300 px-2 py-0.5 rounded bg-rose-500/20 border border-rose-500/40">
                  CRITICAL
                </span>
              </button>

              <button
                onClick={() => onInjectScenario('brute')}
                className="w-full text-left p-3.5 rounded-xl bg-neutral-950 border border-neutral-800 hover:border-yellow-400 hover:bg-neutral-900 transition-all flex items-center justify-between group cursor-pointer"
              >
                <div>
                  <div className="text-xs font-bold text-white group-hover:text-yellow-300 transition-colors">
                    {t.scenarioBrute}
                  </div>
                  <div className="text-[11px] text-neutral-400 mt-0.5 font-mono">
                    MITRE T1110 · Automated SSH / Bastion Password Spray
                  </div>
                </div>
                <span className="text-[10px] font-mono font-bold text-yellow-300 px-2 py-0.5 rounded bg-yellow-400/20 border border-yellow-400/40">
                  HIGH
                </span>
              </button>

              <button
                onClick={() => onInjectScenario('c2')}
                className="w-full text-left p-3.5 rounded-xl bg-neutral-950 border border-neutral-800 hover:border-yellow-400 hover:bg-neutral-900 transition-all flex items-center justify-between group cursor-pointer"
              >
                <div>
                  <div className="text-xs font-bold text-white group-hover:text-yellow-300 transition-colors">
                    {t.scenarioC2}
                  </div>
                  <div className="text-[11px] text-neutral-400 mt-0.5 font-mono">
                    MITRE T1071 · Cobalt Strike Beaconing & Data Outflow
                  </div>
                </div>
                <span className="text-[10px] font-mono font-bold text-yellow-300 px-2 py-0.5 rounded bg-yellow-400/20 border border-yellow-400/40">
                  HIGH
                </span>
              </button>

              <button
                onClick={() => onInjectScenario('portscan')}
                className="w-full text-left p-3.5 rounded-xl bg-neutral-950 border border-neutral-800 hover:border-yellow-400 hover:bg-neutral-900 transition-all flex items-center justify-between group cursor-pointer"
              >
                <div>
                  <div className="text-xs font-bold text-white group-hover:text-yellow-300 transition-colors">
                    {t.scenarioPortScan}
                  </div>
                  <div className="text-[11px] text-neutral-400 mt-0.5 font-mono">
                    MITRE T1046 · Perimeter Port Probing & SYN sweep
                  </div>
                </div>
                <span className="text-[10px] font-mono font-bold text-amber-300 px-2 py-0.5 rounded bg-amber-400/20 border border-amber-400/40">
                  MEDIUM
                </span>
              </button>

              <button
                onClick={() => onInjectScenario('benign')}
                className="w-full text-left p-3.5 rounded-xl bg-neutral-950 border border-neutral-800 hover:border-neutral-700 hover:bg-neutral-900 transition-all flex items-center justify-between group cursor-pointer"
              >
                <div>
                  <div className="text-xs font-bold text-neutral-300 group-hover:text-white">
                    {t.scenarioBenign}
                  </div>
                  <div className="text-[11px] text-neutral-400 mt-0.5 font-mono">
                    Clean enterprise authenticated traffic & asset queries
                  </div>
                </div>
                <span className="text-[10px] font-mono font-bold text-neutral-300 px-2 py-0.5 rounded bg-neutral-800 border border-neutral-700">
                  CLEAN
                </span>
              </button>
            </div>

            {/* Stream Speed Selector */}
            <div className="mt-5 pt-4 border-t border-neutral-800 flex items-center justify-between">
              <span className="text-xs font-bold text-neutral-300">{t.streamSpeed}:</span>
              <div className="flex items-center gap-1 bg-neutral-950 p-1 rounded-lg border border-neutral-800">
                {[1, 2, 5].map((speed) => (
                  <button
                    key={speed}
                    onClick={() => setStreamSpeed(speed)}
                    className={`px-3 py-1 text-xs font-mono rounded-md font-bold transition-all cursor-pointer ${
                      streamSpeed === speed
                        ? 'bg-yellow-400 text-neutral-950 shadow-sm'
                        : 'text-neutral-400 hover:text-white'
                    }`}
                  >
                    {speed}x
                  </button>
                ))}
              </div>
            </div>
          </div>

          {/* Active Collector Sources */}
          <div className="p-5 rounded-2xl bg-neutral-900/90 border border-neutral-800 shadow-xl">
            <h2 className="text-sm font-extrabold text-white flex items-center gap-2 uppercase tracking-wide">
              <Server className="w-4 h-4 text-yellow-400" />
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
                  className={`p-2.5 rounded-xl border text-left flex items-center justify-between transition-all cursor-pointer ${
                    activeSources[src]
                      ? 'bg-neutral-950 border-yellow-400/40 text-white font-medium'
                      : 'bg-neutral-950/40 border-neutral-800 text-neutral-500'
                  }`}
                >
                  <span className="truncate">{label}</span>
                  <span className={`w-2 h-2 rounded-full ${activeSources[src] ? 'bg-yellow-400 shadow-[0_0_6px_#facc15]' : 'bg-neutral-700'}`} />
                </button>
              ))}
            </div>
          </div>
        </div>

        {/* Right Column (7 cols): Manual Ingestion & Upload */}
        <div className="lg:col-span-7 space-y-6">
          <div className="p-5 rounded-2xl bg-neutral-900/90 border border-neutral-800 shadow-xl">
            <div className="flex items-center justify-between flex-wrap gap-2">
              <h2 className="text-sm font-extrabold text-white flex items-center gap-2 uppercase tracking-wide">
                <FileText className="w-4 h-4 text-yellow-400" />
                <span>{t.manualIngest}</span>
              </h2>

              {/* Sample Presets to quickly test */}
              <div className="flex items-center gap-1.5 text-xs text-neutral-400">
                <span className="hidden sm:inline text-[11px] font-semibold text-neutral-300">{lang === 'pa' ? 'ਨਮੂਨਾ ਲੋਡ ਕਰੋ:' : 'Load Sample:'}</span>
                <button
                  onClick={() => loadSamplePayload('sqli')}
                  className="px-2.5 py-1 bg-neutral-950 border border-neutral-800 rounded-md text-[11px] font-mono text-yellow-300 hover:border-yellow-400 transition-colors cursor-pointer font-bold"
                >
                  SQLi
                </button>
                <button
                  onClick={() => loadSamplePayload('ransom')}
                  className="px-2.5 py-1 bg-neutral-950 border border-neutral-800 rounded-md text-[11px] font-mono text-rose-300 hover:border-rose-400 transition-colors cursor-pointer font-bold"
                >
                  Ransomware
                </button>
                <button
                  onClick={() => loadSamplePayload('brute')}
                  className="px-2.5 py-1 bg-neutral-950 border border-neutral-800 rounded-md text-[11px] font-mono text-yellow-300 hover:border-yellow-400 transition-colors cursor-pointer font-bold"
                >
                  BruteForce
                </button>
                <button
                  onClick={() => loadSamplePayload('json')}
                  className="px-2.5 py-1 bg-neutral-950 border border-neutral-800 rounded-md text-[11px] font-mono text-white hover:border-white transition-colors cursor-pointer font-bold"
                >
                  JSON
                </button>
              </div>
            </div>

            {/* Success Banner */}
            {ingestSuccessMessage && (
              <div className="mt-3 p-3 rounded-xl bg-yellow-400/10 border border-yellow-400/40 text-yellow-300 text-xs flex items-center gap-2 font-medium">
                <CheckCircle2 className="w-4 h-4 shrink-0 text-yellow-400" />
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
                className="w-full rounded-xl bg-neutral-950 border border-neutral-800 p-3.5 text-xs font-mono text-white placeholder:text-neutral-500 focus:outline-none focus:border-yellow-400 focus:ring-1 focus:ring-yellow-400/50 transition-colors"
              />
            </div>

            {/* Actions: File upload & Ingest button */}
            <div className="mt-4 flex flex-col sm:flex-row items-center justify-between gap-3">
              <label className="w-full sm:w-auto flex items-center justify-center gap-2 px-4 py-2 bg-neutral-950 border border-neutral-800 hover:border-neutral-700 text-neutral-300 hover:text-white rounded-xl text-xs cursor-pointer transition-colors font-semibold">
                <Upload className="w-4 h-4 text-yellow-400" />
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
                className={`w-full sm:w-auto px-6 py-2.5 rounded-xl text-xs font-bold flex items-center justify-center gap-2 transition-all ${
                  rawText.trim()
                    ? 'bg-yellow-400 hover:bg-yellow-300 text-neutral-950 shadow-md shadow-yellow-500/20 active:scale-95 cursor-pointer'
                    : 'bg-neutral-800 text-neutral-500 cursor-not-allowed border border-neutral-700'
                }`}
              >
                <HardDrive className="w-4 h-4 text-neutral-950 stroke-[2.5]" />
                <span>{t.ingestButton}</span>
              </button>
            </div>
          </div>

          {/* Architecture / Ingestion Guide */}
          <div className="p-4 rounded-2xl bg-neutral-950 border border-neutral-800 text-xs text-neutral-400 space-y-2">
            <div className="font-bold text-white flex items-center gap-2">
              <span className="w-2 h-2 rounded-full bg-yellow-400" />
              <span>{lang === 'pa' ? 'ਲੌਗ ਕੁਲੈਕਟਰ ਜਾਣਕਾਰੀ:' : 'Log Collector Pipeline Architecture:'}</span>
            </div>
            <p className="leading-relaxed">
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
