import React, { useState, useEffect, useRef } from 'react';
import { TopBar } from './components/TopBar';
import { SocDashboard } from './components/SocDashboard';
import { LogCollector } from './components/LogCollector';
import { LogExplorer } from './components/LogExplorer';
import { IncidentTriage } from './components/IncidentTriage';
import { RulesManager } from './components/RulesManager';
import { LogDetailModal } from './components/LogDetailModal';
import { 
  LogEntry, 
  Incident, 
  DetectionRule 
} from './types/soc';
import { 
  DEFAULT_DETECTION_RULES, 
  generateSampleLogs, 
  parseLogLine 
} from './utils/detectionEngine';
import { Language } from './utils/i18n';
import { X, Radio } from 'lucide-react';

export default function App() {
  const [lang, setLang] = useState<Language>('en');
  const [activeTab, setActiveTab] = useState<'dashboard' | 'collector' | 'explorer' | 'incidents' | 'rules'>('dashboard');
  
  // State
  const [logs, setLogs] = useState<LogEntry[]>(() => generateSampleLogs());
  const [rules, setRules] = useState<DetectionRule[]>(DEFAULT_DETECTION_RULES);
  const [selectedLog, setSelectedLog] = useState<LogEntry | null>(null);
  const [isCollectorDrawerOpen, setIsCollectorDrawerOpen] = useState(false);
  const [isStreaming, setIsStreaming] = useState(true);
  const [streamSpeed, setStreamSpeed] = useState<number>(1);
  const [blockedIps, setBlockedIps] = useState<Set<string>>(new Set(['185.220.101.5']));
  const [isolatedHosts, setIsolatedHosts] = useState<Set<string>>(new Set());

  // Incidents
  const [incidents, setIncidents] = useState<Incident[]>([
    {
      id: 'INC-2026-081',
      title: 'Automated Database Exfiltration Attempt via SQL Injection',
      severity: 'critical',
      status: 'investigating',
      createdTime: new Date(Date.now() - 1000 * 60 * 18).toISOString(),
      updatedTime: new Date().toISOString(),
      attackerIp: '185.220.101.5',
      targetHost: 'prod-web-ingress',
      mitreTechnique: 'T1190',
      mitreTactic: 'Initial Access',
      eventCount: 14,
      description: 'Host prod-web-ingress experienced parameterized UNION SELECT injections from known scanning network 185.220.101.5 extracting admin_users table.',
      recommendedActions: [
        'Enforce perimeter firewall block for IP 185.220.101.5',
        'Deploy WAF signature rule blocking UNION SELECT patterns',
        'Audit database access logs for successful query extractions'
      ],
      logIds: []
    },
    {
      id: 'INC-2026-082',
      title: 'Ransomware Preparation: Volume Shadow Copy Deletion',
      severity: 'critical',
      status: 'new',
      createdTime: new Date(Date.now() - 1000 * 60 * 8).toISOString(),
      updatedTime: new Date().toISOString(),
      attackerIp: '10.0.4.15',
      targetHost: 'HR-PC-04',
      mitreTechnique: 'T1490',
      mitreTactic: 'Impact',
      eventCount: 5,
      description: 'Endpoint HR-PC-04 executed vssadmin delete shadows /all /quiet via PowerShell parent process. Threat operator attempting to prevent backup restoration.',
      recommendedActions: [
        'Immediately disconnect HR-PC-04 from corporate network via EDR isolation',
        'Revoke active Kerberos and AD domain credentials for account corp\\asmith',
        'Collect memory dump and initiate ransomware containment protocol'
      ],
      logIds: []
    },
    {
      id: 'INC-2026-083',
      title: 'Distributed SSH Password Spraying on Bastion Gateway',
      severity: 'high',
      status: 'contained',
      createdTime: new Date(Date.now() - 1000 * 60 * 45).toISOString(),
      updatedTime: new Date().toISOString(),
      attackerIp: '45.145.185.10',
      targetHost: 'auth-bastion-01',
      mitreTechnique: 'T1110',
      mitreTactic: 'Credential Access',
      eventCount: 38,
      description: 'Rapid sequential authentication failures across common dictionary usernames (root, admin, deploy, test) within a 60-second window.',
      recommendedActions: [
        'Null-route source IP 45.145.185.10 at border gateway',
        'Audit SSHD configuration to disallow root password login entirely',
        'Verify no accounts were successfully authenticated during attack burst'
      ],
      logIds: []
    }
  ]);

  // Append new logs to state
  const handleIngestLogs = (newEntries: LogEntry[]) => {
    setLogs(prev => [...newEntries, ...prev].slice(0, 500));
  };

  // Clear all logs
  const handleClearLogs = () => {
    setLogs([]);
  };

  // Attack scenario simulation
  const handleInjectScenario = (scenarioType: string) => {
    const now = new Date().toISOString();
    let sampleLines: string[] = [];

    switch (scenarioType) {
      case 'sqli':
        sampleLines = [
          `185.220.101.5 - - [${now}] "GET /api/v1/search?term=' OR 1=1-- HTTP/1.1" 200 6210 "-" "sqlmap/1.6"`,
          `185.220.101.5 - - [${now}] "GET /api/v1/search?term=1' UNION SELECT null,username,password FROM accounts-- HTTP/1.1" 200 8910 "-" "sqlmap/1.6"`,
          `185.220.101.5 - - [${now}] "GET /files/download?path=../../../../etc/shadow HTTP/1.1" 403 240 "-" "curl/7.88"`
        ];
        break;
      case 'ransom':
        sampleLines = [
          `Sysmon Event 1: Host=FIN-SRV-02 User=corp\\jfinance Process=C:\\Windows\\System32\\vssadmin.exe Command="vssadmin delete shadows /all /quiet" Parent=cmd.exe`,
          `Sysmon Event 1: Host=FIN-SRV-02 User=corp\\jfinance Process=C:\\Windows\\System32\\bcdedit.exe Command="bcdedit /set {default} recoveryenabled No" Parent=cmd.exe`,
          `Sysmon Event 11: File Created: Path=C:\\Data\\Financial_2026.xlsx.locked`
        ];
        break;
      case 'brute':
        sampleLines = [
          `auth-bastion-01 sshd[11041]: Failed password for invalid user root from 45.145.185.10 port 38210 ssh2`,
          `auth-bastion-01 sshd[11042]: Failed password for invalid user admin from 45.145.185.10 port 38212 ssh2`,
          `auth-bastion-01 sshd[11043]: Failed password for invalid user oracle from 45.145.185.10 port 38214 ssh2`,
          `auth-bastion-01 sshd[11044]: Failed password for invalid user test from 45.145.185.10 port 38216 ssh2`
        ];
        break;
      case 'c2':
        sampleLines = [
          `91.240.118.232 - - [${now}] "POST /beacon.bin HTTP/1.1" 404 150 "-" "Mozilla/5.0 (compatible; CobaltStrike/4.8)"`,
          `CEF:0|PaloAlto|PAN-OS|v10.1|THREAT|C2 Beacon Activity|8|src=10.0.2.45 dst=91.240.118.232 dpt=443 proto=tcp act=alert msg=CobaltStrike egress beacon detected`
        ];
        break;
      case 'portscan':
        sampleLines = [
          `CEF:0|Fortinet|FortiGate|v7.0|1024|Port Scan Detected|6|src=103.149.28.18 dst=10.0.0.1 spt=51200 dpt=22 proto=tcp act=drop`,
          `CEF:0|Fortinet|FortiGate|v7.0|1024|Port Scan Detected|6|src=103.149.28.18 dst=10.0.0.1 spt=51201 dpt=23 proto=tcp act=drop`,
          `CEF:0|Fortinet|FortiGate|v7.0|1024|Port Scan Detected|6|src=103.149.28.18 dst=10.0.0.1 spt=51202 dpt=445 proto=tcp act=drop`
        ];
        break;
      default:
        sampleLines = [
          `192.168.1.100 - - [${now}] "GET /index.html HTTP/1.1" 200 4501 "https://internal.corp/" "Mozilla/5.0"`,
          `auth-bastion-01 sshd[11099]: Accepted publickey for sre_engineer from 10.0.1.20 port 54210 ssh2`,
          `prod-api-01 app: Transaction processed successfully id=tx_94819 status=200 latency=18ms`
        ];
        break;
    }

    const parsed = sampleLines.map(line => parseLogLine(line));
    handleIngestLogs(parsed);

    // If critical threat, create or update incident
    const criticalLogs = parsed.filter(p => p.severity === 'critical');
    if (criticalLogs.length > 0) {
      const first = criticalLogs[0];
      const newInc: Incident = {
        id: `INC-2026-${Math.floor(100 + Math.random() * 900)}`,
        title: first.ruleMatched?.name || 'Active Critical Security Breach Attempt',
        severity: 'critical',
        status: 'new',
        createdTime: now,
        updatedTime: now,
        attackerIp: first.sourceIp,
        targetHost: first.sourceHost,
        mitreTechnique: first.ruleMatched?.mitreId || 'T1190',
        mitreTactic: first.ruleMatched?.mitreTactic || 'Execution',
        eventCount: parsed.length,
        description: `Correlated ${parsed.length} offensive events targeting host ${first.sourceHost}. Signature: ${first.ruleMatched?.name}.`,
        recommendedActions: [
          `Isolate host ${first.sourceHost} from internal VLAN`,
          `Block IP address ${first.sourceIp} on edge perimeter`,
          'Review session persistence tokens'
        ],
        logIds: parsed.map(p => p.id)
      };
      setIncidents(prev => [newInc, ...prev]);
    }
  };

  // Continuous background stream simulation
  useEffect(() => {
    if (!isStreaming) return;

    const intervalTime = Math.max(800, 3000 / streamSpeed);
    const interval = setInterval(() => {
      const benignTemplates = [
        `192.168.1.${Math.floor(10 + Math.random() * 200)} - - [${new Date().toISOString()}] "GET /api/v2/metrics HTTP/1.1" 200 ${Math.floor(2000 + Math.random() * 4000)} "https://corp.internal/" "Mozilla/5.0"`,
        `10.0.2.${Math.floor(5 + Math.random() * 50)} - - [${new Date().toISOString()}] "GET /dashboard/live HTTP/1.1" 200 1420 "https://corp.internal/" "Chrome/124.0"`,
        `auth-bastion-01 sshd[${Math.floor(1000 + Math.random() * 9000)}]: Accepted publickey for devops_bot from 10.0.1.15 port ${Math.floor(40000 + Math.random() * 15000)} ssh2`,
        `prod-api-ingress nginx: 172.16.0.4 - - [${new Date().toISOString()}] "POST /graphql HTTP/1.1" 200 480 "-" "ApolloClient"`
      ];

      // 10% chance to emit suspicious probe
      if (Math.random() < 0.12) {
        benignTemplates.push(
          `185.220.101.5 - - [${new Date().toISOString()}] "GET /?id=1%20UNION%20SELECT%20null,password%20FROM%20users-- HTTP/1.1" 200 8400 "-" "sqlmap/1.6"`
        );
      }

      const selected = benignTemplates[Math.floor(Math.random() * benignTemplates.length)];
      const entry = parseLogLine(selected);
      handleIngestLogs([entry]);
    }, intervalTime);

    return () => clearInterval(interval);
  }, [isStreaming, streamSpeed]);

  // Actions
  const handleBlockIp = (ip: string) => {
    setBlockedIps(prev => new Set(prev).add(ip));
  };

  const handleIsolateHost = (host: string) => {
    setIsolatedHosts(prev => new Set(prev).add(host));
  };

  const handleCreateIncidentFromLog = (log: LogEntry) => {
    const newInc: Incident = {
      id: `INC-2026-${Math.floor(100 + Math.random() * 900)}`,
      title: log.ruleMatched?.name || `Suspicious Activity on ${log.sourceHost}`,
      severity: log.severity === 'info' ? 'medium' : log.severity,
      status: 'new',
      createdTime: new Date().toISOString(),
      updatedTime: new Date().toISOString(),
      attackerIp: log.sourceIp,
      targetHost: log.sourceHost,
      mitreTechnique: log.ruleMatched?.mitreId || 'T1000',
      mitreTactic: log.ruleMatched?.mitreTactic || 'Initial Access',
      eventCount: 1,
      description: `Manual SOC escalation from log event: ${log.raw}`,
      recommendedActions: [
        `Review user sessions from ${log.sourceIp}`,
        `Inspect active network socket connections on ${log.sourceHost}`
      ],
      logIds: [log.id]
    };
    setIncidents(prev => [newInc, ...prev]);
    setActiveTab('incidents');
    setSelectedLog(null);
  };

  const handleToggleRule = (ruleId: string) => {
    setRules(prev =>
      prev.map(r => (r.id === ruleId ? { ...r, enabled: !r.enabled } : r))
    );
  };

  const handleAddRule = (newRule: DetectionRule) => {
    setRules(prev => [newRule, ...prev]);
  };

  const handleUpdateIncidentStatus = (incidentId: string, newStatus: Incident['status']) => {
    setIncidents(prev =>
      prev.map(i => (i.id === incidentId ? { ...i, status: newStatus, updatedTime: new Date().toISOString() } : i))
    );
  };

  const criticalIncidentCount = incidents.filter(i => i.severity === 'critical' && i.status !== 'resolved').length;
  const maliciousCount = logs.filter(l => l.isMalicious).length;
  const suspiciousCount = logs.filter(l => l.isSuspicious).length;

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col">
      {/* Top Bar adhering to 3-zone standard */}
      <TopBar
        activeTab={activeTab}
        setActiveTab={setActiveTab}
        lang={lang}
        setLang={setLang}
        onOpenCollectorDrawer={() => setIsCollectorDrawerOpen(true)}
        criticalIncidentCount={criticalIncidentCount}
        isStreaming={isStreaming}
      />

      {/* Main Content Area */}
      <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-6">
        {activeTab === 'dashboard' && (
          <SocDashboard
            logs={logs}
            lang={lang}
            onSelectLog={(log) => setSelectedLog(log)}
            onNavigateToExplorer={() => setActiveTab('explorer')}
            onNavigateToCollector={() => setActiveTab('collector')}
            onBlockIp={handleBlockIp}
            blockedIps={blockedIps}
          />
        )}

        {activeTab === 'collector' && (
          <LogCollector
            lang={lang}
            onIngestLogs={handleIngestLogs}
            isStreaming={isStreaming}
            setIsStreaming={setIsStreaming}
            streamSpeed={streamSpeed}
            setStreamSpeed={setStreamSpeed}
            totalIngestedCount={logs.length}
            maliciousCount={maliciousCount}
            suspiciousCount={suspiciousCount}
            onClearLogs={handleClearLogs}
            onInjectScenario={handleInjectScenario}
          />
        )}

        {activeTab === 'explorer' && (
          <LogExplorer
            logs={logs}
            lang={lang}
            onSelectLog={(log) => setSelectedLog(log)}
          />
        )}

        {activeTab === 'incidents' && (
          <IncidentTriage
            incidents={incidents}
            lang={lang}
            onUpdateStatus={handleUpdateIncidentStatus}
            onBlockIp={handleBlockIp}
            blockedIps={blockedIps}
          />
        )}

        {activeTab === 'rules' && (
          <RulesManager
            rules={rules}
            lang={lang}
            onToggleRule={handleToggleRule}
            onAddRule={handleAddRule}
          />
        )}
      </main>

      {/* Side-Panel Log Ingest Drawer (Directly answering "ਜਿਹੜਾ ਲੋਗਸ ਨੂੰ ਇੱਕ ਸਾਈਡ ਤੇ ਇਕੱਠਾ ਕਰ ਸਕੇ ਉਹਦਾ ਅਲੱਗ ਹੋਵੇ") */}
      {isCollectorDrawerOpen && (
        <div className="fixed inset-0 z-50 flex justify-end bg-slate-950/70 backdrop-blur-sm animate-in fade-in">
          <div className="w-full max-w-2xl bg-slate-900 border-l border-slate-800 h-full p-6 overflow-y-auto space-y-6 shadow-2xl">
            <div className="flex items-center justify-between border-b border-slate-800 pb-4">
              <div className="flex items-center gap-2">
                <Radio className="w-5 h-5 text-cyan-400" />
                <h2 className="text-base font-bold text-white">
                  {lang === 'pa' ? 'ਸਾਈਡ ਲੌਗ ਕਲੈਕਟਰ' : 'Side Log Ingestion Drawer'}
                </h2>
              </div>
              <button
                onClick={() => setIsCollectorDrawerOpen(false)}
                className="p-1 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800"
                aria-label="Close drawer"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            {/* Ingestion controls inside drawer */}
            <LogCollector
              lang={lang}
              onIngestLogs={(newLogs) => {
                handleIngestLogs(newLogs);
              }}
              isStreaming={isStreaming}
              setIsStreaming={setIsStreaming}
              streamSpeed={streamSpeed}
              setStreamSpeed={setStreamSpeed}
              totalIngestedCount={logs.length}
              maliciousCount={maliciousCount}
              suspiciousCount={suspiciousCount}
              onClearLogs={handleClearLogs}
              onInjectScenario={handleInjectScenario}
            />
          </div>
        </div>
      )}

      {/* Forensic Log Detail Modal */}
      {selectedLog && (
        <LogDetailModal
          log={selectedLog}
          onClose={() => setSelectedLog(null)}
          lang={lang}
          onBlockIp={handleBlockIp}
          isIpBlocked={blockedIps.has(selectedLog.sourceIp)}
          onIsolateHost={handleIsolateHost}
          isHostIsolated={isolatedHosts.has(selectedLog.sourceHost)}
          onCreateIncidentFromLog={handleCreateIncidentFromLog}
        />
      )}

      {/* Footer */}
      <footer className="border-t border-slate-900 bg-slate-950/80 py-4 text-center text-xs text-slate-400">
        <div className="max-w-7xl mx-auto px-4 flex flex-col sm:flex-row items-center justify-between gap-2">
          <div className="flex items-center gap-2">
            <span>AegisSOC Platform</span>
            <span>·</span>
            <span>Enterprise SIEM & Log Analyzer</span>
          </div>
          <div>
            <span>MITRE ATT&CK v14 Compliant</span>
            <span className="mx-2">·</span>
            <span className="font-mono text-cyan-400">Status: Nominal</span>
          </div>
        </div>
      </footer>
    </div>
  );
}
