import React, { useState, useEffect, useMemo } from 'react';
import { TopBar } from './components/TopBar';
import { SocDashboard } from './components/SocDashboard';
import { LogCollector } from './components/LogCollector';
import { LogExplorer } from './components/LogExplorer';
import { IncidentTriage } from './components/IncidentTriage';
import { RulesManager } from './components/RulesManager';
import { LogDetailModal } from './components/LogDetailModal';
import { SecurityAlertModal } from './components/SecurityAlertModal';
import { AuditHistory, AuditRecord } from './components/AuditHistory';
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
import { redactSensitiveData } from './utils/masking';
import { generateIncidentPdfReport } from './utils/pdfReport';
import { X, Radio } from 'lucide-react';

export default function App() {
  const [lang, setLang] = useState<Language>('en');
  const [activeTab, setActiveTab] = useState<'dashboard' | 'collector' | 'explorer' | 'incidents' | 'rules' | 'audit'>('dashboard');
  const [theme, setTheme] = useState<'dark' | 'light'>('dark');
  const [dlpEnabled, setDlpEnabled] = useState<boolean>(true);

  // Sync theme class with HTML document element
  useEffect(() => {
    if (theme === 'dark') {
      document.documentElement.classList.add('dark');
      document.documentElement.classList.remove('light');
    } else {
      document.documentElement.classList.add('light');
      document.documentElement.classList.remove('dark');
    }
  }, [theme]);
  
  // State
  const [logs, setLogs] = useState<LogEntry[]>(() => generateSampleLogs());
  const [rules, setRules] = useState<DetectionRule[]>(DEFAULT_DETECTION_RULES);
  const [selectedLog, setSelectedLog] = useState<LogEntry | null>(null);
  const [alertThreatLog, setAlertThreatLog] = useState<LogEntry | null>(null);
  const [isCollectorDrawerOpen, setIsCollectorDrawerOpen] = useState(false);
  const [isStreaming, setIsStreaming] = useState(true);
  const [streamSpeed, setStreamSpeed] = useState<number>(1);
  const [blockedIps, setBlockedIps] = useState<Set<string>>(new Set(['185.220.101.5']));
  const [isolatedHosts, setIsolatedHosts] = useState<Set<string>>(new Set());

  // Security Audit History Records
  const [auditRecords, setAuditRecords] = useState<AuditRecord[]>([
    {
      id: 'AUD-1001',
      timestamp: new Date(Date.now() - 1000 * 60 * 65).toISOString(),
      actionType: 'ingest',
      actor: 'system.daemon',
      target: 'syslog-collector-01',
      details: 'Started continuous syslog and CEF stream receiver on port 514 UDP/TCP.',
      status: 'success'
    },
    {
      id: 'AUD-1002',
      timestamp: new Date(Date.now() - 1000 * 60 * 42).toISOString(),
      actionType: 'block_ip',
      actor: 'kunal.soc.lead',
      target: '185.220.101.5',
      details: 'Automated perimeter firewall block enacted following critical SQL injection attempt on prod-web-ingress.',
      status: 'warning'
    },
    {
      id: 'AUD-1003',
      timestamp: new Date(Date.now() - 1000 * 60 * 25).toISOString(),
      actionType: 'incident_created',
      actor: 'detection.engine',
      target: 'INC-2026-081',
      details: 'Triaged automated high-severity incident: Database Exfiltration via SQLi (MITRE T1190).',
      status: 'alert'
    },
    {
      id: 'AUD-1004',
      timestamp: new Date(Date.now() - 1000 * 60 * 12).toISOString(),
      actionType: 'report_export',
      actor: 'kunal.soc.lead',
      target: 'Executive Summary',
      details: 'Generated and signed SOC 2 / ISO 27001 executive compliance PDF report.',
      status: 'success'
    }
  ]);

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

  // Sensitive data DLP redaction layer: when DLP is active, redact all raw payloads
  const displayedLogs = useMemo(() => {
    if (!dlpEnabled) return logs;
    return logs.map(log => ({
      ...log,
      raw: redactSensitiveData(log.raw)
    }));
  }, [logs, dlpEnabled]);

  // Append new logs to state and trigger pop-up alert if critical/high malicious event is found
  const handleIngestLogs = (newEntries: LogEntry[]) => {
    setLogs(prev => [...newEntries, ...prev].slice(0, 500));

    // Check for high-threat entries to trigger immediate warning popup
    const urgentThreat = newEntries.find(e => (e.isMalicious || e.isSuspicious) && (e.severity === 'critical' || e.severity === 'high'));
    if (urgentThreat && !alertThreatLog) {
      setAlertThreatLog(urgentThreat);
    }

    // Record Ingestion Audit Entry
    if (newEntries.length > 0) {
      const maliciousCount = newEntries.filter(e => e.isMalicious).length;
      const auditEntry: AuditRecord = {
        id: `AUD-${Date.now()}-${Math.floor(100 + Math.random() * 900)}`,
        timestamp: new Date().toISOString(),
        actionType: 'ingest',
        actor: 'ingest.pipeline',
        target: `${newEntries.length} log events`,
        details: `Ingested batch of ${newEntries.length} records. Detected ${maliciousCount} malicious and ${newEntries.filter(e => e.isSuspicious).length} suspicious events.`,
        status: maliciousCount > 0 ? 'alert' : 'success'
      };
      setAuditRecords(prev => [auditEntry, ...prev.slice(0, 100)]);
    }
  };

  // Clear all logs
  const handleClearLogs = () => {
    setLogs([]);
    const auditEntry: AuditRecord = {
      id: `AUD-${Date.now()}-${Math.floor(100 + Math.random() * 900)}`,
      timestamp: new Date().toISOString(),
      actionType: 'ingest',
      actor: 'kunal.soc.lead',
      details: 'Collector active memory buffer cleared by operator.',
      status: 'warning'
    };
    setAuditRecords(prev => [auditEntry, ...prev]);
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

    // If critical threat, create or update incident and pop alert
    const criticalLogs = parsed.filter(p => p.severity === 'critical' || p.severity === 'high');
    if (criticalLogs.length > 0) {
      const first = criticalLogs[0];
      setAlertThreatLog(first);

      const newInc: Incident = {
        id: `INC-2026-${Math.floor(100 + Math.random() * 900)}`,
        title: first.ruleMatched?.name || 'Active Critical Security Breach Attempt',
        severity: first.severity,
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

      const auditEntry: AuditRecord = {
        id: `AUD-${Date.now()}-${Math.floor(100 + Math.random() * 900)}`,
        timestamp: now,
        actionType: 'incident_created',
        actor: 'simulation.engine',
        target: newInc.id,
        details: `Simulated attack scenario "${scenarioType}" injected: ${newInc.title} targeting ${newInc.targetHost}.`,
        status: 'alert'
      };
      setAuditRecords(prev => [auditEntry, ...prev]);
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

      // 8% chance to emit suspicious probe
      if (Math.random() < 0.08) {
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
    setBlockedIps(prev => {
      const next = new Set(prev);
      next.add(ip);
      return next;
    });

    const auditEntry: AuditRecord = {
      id: `AUD-${Date.now()}-${Math.floor(100 + Math.random() * 900)}`,
      timestamp: new Date().toISOString(),
      actionType: 'block_ip',
      actor: 'kunal.soc.lead',
      target: ip,
      details: `Perimeter firewall ACL rule applied: Dropping all traffic from ${ip}.`,
      status: 'warning'
    };
    setAuditRecords(prev => [auditEntry, ...prev]);
  };

  const handleIsolateHost = (host: string) => {
    setIsolatedHosts(prev => {
      const next = new Set(prev);
      next.add(host);
      return next;
    });

    const auditEntry: AuditRecord = {
      id: `AUD-${Date.now()}-${Math.floor(100 + Math.random() * 900)}`,
      timestamp: new Date().toISOString(),
      actionType: 'isolate_host',
      actor: 'kunal.soc.lead',
      target: host,
      details: `Endpoint quarantined from enterprise network: Host ${host} isolated via EDR agent.`,
      status: 'alert'
    };
    setAuditRecords(prev => [auditEntry, ...prev]);
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

    const auditEntry: AuditRecord = {
      id: `AUD-${Date.now()}-${Math.floor(100 + Math.random() * 900)}`,
      timestamp: new Date().toISOString(),
      actionType: 'incident_created',
      actor: 'kunal.soc.lead',
      target: newInc.id,
      details: `Operator manually escalated incident ${newInc.id} from log entry on ${log.sourceHost}.`,
      status: 'warning'
    };
    setAuditRecords(prev => [auditEntry, ...prev]);

    setActiveTab('incidents');
    setSelectedLog(null);
  };

  const handleToggleRule = (ruleId: string) => {
    setRules(prev =>
      prev.map(r => {
        if (r.id === ruleId) {
          const nextState = !r.enabled;
          const auditEntry: AuditRecord = {
            id: `AUD-${Date.now()}-${Math.floor(100 + Math.random() * 900)}`,
            timestamp: new Date().toISOString(),
            actionType: 'rule_toggle',
            actor: 'kunal.soc.lead',
            target: r.id,
            details: `Detection rule ${r.id} (${r.name}) ${nextState ? 'enabled' : 'disabled'}.`,
            status: 'success'
          };
          setAuditRecords(recs => [auditEntry, ...recs]);
          return { ...r, enabled: nextState };
        }
        return r;
      })
    );
  };

  const handleAddRule = (newRule: DetectionRule) => {
    setRules(prev => [newRule, ...prev]);
    const auditEntry: AuditRecord = {
      id: `AUD-${Date.now()}-${Math.floor(100 + Math.random() * 900)}`,
      timestamp: new Date().toISOString(),
      actionType: 'rule_toggle',
      actor: 'kunal.soc.lead',
      target: newRule.id,
      details: `Created new custom detection signature: ${newRule.name} (Severity: ${newRule.severity}).`,
      status: 'success'
    };
    setAuditRecords(prev => [auditEntry, ...prev]);
  };

  const handleUpdateIncidentStatus = (incidentId: string, newStatus: Incident['status']) => {
    setIncidents(prev =>
      prev.map(i => (i.id === incidentId ? { ...i, status: newStatus, updatedTime: new Date().toISOString() } : i))
    );
    const auditEntry: AuditRecord = {
      id: `AUD-${Date.now()}-${Math.floor(100 + Math.random() * 900)}`,
      timestamp: new Date().toISOString(),
      actionType: 'incident_created',
      actor: 'kunal.soc.lead',
      target: incidentId,
      details: `Incident ${incidentId} workflow status updated to "${newStatus}".`,
      status: newStatus === 'resolved' ? 'success' : 'warning'
    };
    setAuditRecords(prev => [auditEntry, ...prev]);
  };

  // Executive Compliance PDF Report Export
  const handleExportPdfReport = () => {
    generateIncidentPdfReport(incidents, {
      analystName: 'Kunal (Lead SOC Analyst)',
      organization: 'Global Enterprise SOC & Cyber Defense Center',
      complianceStandard: 'SOC 2 Type II / ISO 27001:2022 / NIST SP 800-61 Rev 2'
    });

    const highSeverityCount = incidents.filter(i => i.severity === 'critical' || i.severity === 'high').length;
    const auditEntry: AuditRecord = {
      id: `AUD-${Date.now()}-${Math.floor(100 + Math.random() * 900)}`,
      timestamp: new Date().toISOString(),
      actionType: 'report_export',
      actor: 'kunal.soc.lead',
      target: 'Executive Incident Compliance Report',
      details: `Official PDF compliance report downloaded documenting ${highSeverityCount} high-severity incidents for external audit and compliance records.`,
      status: 'success'
    };
    setAuditRecords(prev => [auditEntry, ...prev]);
  };

  // Global Search navigation state
  const [explorerFilterQuery, setExplorerFilterQuery] = useState<string>('');
  const [activeIncidentId, setActiveIncidentId] = useState<string | null>(null);

  const handleSearchSelectLog = (log: LogEntry) => {
    setSelectedLog(log);
    setActiveTab('explorer');
  };

  const handleSearchSelectIncident = (incident: Incident) => {
    setActiveIncidentId(incident.id);
    setActiveTab('incidents');
  };

  const handleSearchSelectHost = (host: string) => {
    setExplorerFilterQuery(host);
    setActiveTab('explorer');
  };

  const criticalIncidentCount = incidents.filter(i => i.severity === 'critical' && i.status !== 'resolved').length;
  const maliciousCount = logs.filter(l => l.isMalicious).length;
  const suspiciousCount = logs.filter(l => l.isSuspicious).length;

  return (
    <div className={`min-h-screen flex flex-col transition-colors duration-200 ${
      theme === 'dark' 
        ? 'bg-slate-950 text-slate-100 dark' 
        : 'bg-slate-50 text-slate-900 light'
    }`}>
      {/* Top Bar adhering to 3-zone standard */}
      <TopBar
        activeTab={activeTab}
        setActiveTab={setActiveTab}
        lang={lang}
        setLang={setLang}
        onOpenCollectorDrawer={() => setIsCollectorDrawerOpen(true)}
        criticalIncidentCount={criticalIncidentCount}
        isStreaming={isStreaming}
        theme={theme}
        setTheme={setTheme}
        dlpEnabled={dlpEnabled}
        setDlpEnabled={setDlpEnabled}
        onExportPdfReport={handleExportPdfReport}
        logs={displayedLogs}
        incidents={incidents}
        onSelectLog={handleSearchSelectLog}
        onSelectIncident={handleSearchSelectIncident}
        onSelectHost={handleSearchSelectHost}
      />

      {/* Main Content Area */}
      <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-6">
        {activeTab === 'dashboard' && (
          <SocDashboard
            logs={displayedLogs}
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
            logs={displayedLogs}
            lang={lang}
            onSelectLog={(log) => setSelectedLog(log)}
            initialQuery={explorerFilterQuery}
          />
        )}

        {activeTab === 'incidents' && (
          <IncidentTriage
            incidents={incidents}
            lang={lang}
            onUpdateStatus={handleUpdateIncidentStatus}
            onBlockIp={handleBlockIp}
            blockedIps={blockedIps}
            onExportPdfReport={handleExportPdfReport}
            selectedIncidentId={activeIncidentId}
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

        {activeTab === 'audit' && (
          <AuditHistory
            records={auditRecords}
            lang={lang}
          />
        )}
      </main>

      {/* Side-Panel Log Ingest Drawer */}
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
                className="p-1 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800 cursor-pointer"
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

      {/* High-Severity Security Alert Pop-Up Modal */}
      {alertThreatLog && (
        <SecurityAlertModal
          threatLog={alertThreatLog}
          onClose={() => setAlertThreatLog(null)}
          lang={lang}
          onBlockIp={handleBlockIp}
          isIpBlocked={blockedIps.has(alertThreatLog.sourceIp)}
          onIsolateHost={handleIsolateHost}
          isHostIsolated={isolatedHosts.has(alertThreatLog.sourceHost)}
          onViewInForensics={(log) => {
            setAlertThreatLog(null);
            setSelectedLog(log);
          }}
        />
      )}

      {/* Footer */}
      <footer className="border-t border-slate-900 bg-slate-950/80 py-4 text-center text-xs text-slate-400 transition-colors">
        <div className="max-w-7xl mx-auto px-4 flex flex-col sm:flex-row items-center justify-between gap-2">
          <div className="flex items-center gap-2">
            <span className="font-semibold text-slate-200">Log Analyzer by Kunal</span>
            <span>·</span>
            <span>Enterprise SIEM & SOC Intelligence</span>
          </div>
          <div>
            <span>MITRE ATT&CK v14 Compliant</span>
            <span className="mx-2">·</span>
            <span className="font-mono text-cyan-400 font-medium">Status: Active Monitoring</span>
          </div>
        </div>
      </footer>
    </div>
  );
}
