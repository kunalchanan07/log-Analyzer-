import test from 'node:test';
import assert from 'node:assert';
import { extractHostStats, searchHostStats, searchIncidents, searchLogs } from './searchEngine';
import { LogEntry, Incident } from '../types/soc';

const mockLogs: LogEntry[] = [
  {
    id: 'log-1',
    timestamp: '2026-03-30T10:00:00Z',
    source: 'web',
    raw: 'GET /api/v1/search?term=UNION SELECT password FROM users',
    sourceHost: 'prod-web-ingress',
    sourceIp: '185.220.101.5',
    severity: 'critical',
    category: 'sqli',
    isMalicious: true,
    isSuspicious: true,
    confidenceScore: 95,
    ruleMatched: {
      id: 'RULE-SQLI-001',
      name: 'SQL Injection Attempt',
      mitreId: 'T1190',
      mitreTactic: 'Initial Access',
      description: 'SQLi detected',
      remediation: 'WAF rule'
    }
  },
  {
    id: 'log-2',
    timestamp: '2026-03-30T10:05:00Z',
    source: 'auth',
    raw: 'Failed password for invalid user root from 45.145.185.10',
    sourceHost: 'auth-bastion-01',
    sourceIp: '45.145.185.10',
    severity: 'high',
    category: 'brute_force',
    isMalicious: true,
    isSuspicious: true,
    confidenceScore: 85,
    user: 'root'
  },
  {
    id: 'log-3',
    timestamp: '2026-03-30T10:10:00Z',
    source: 'web',
    raw: 'GET /index.html 200 OK',
    sourceHost: 'prod-web-ingress',
    sourceIp: '192.168.1.100',
    severity: 'info',
    category: 'normal',
    isMalicious: false,
    isSuspicious: false,
    confidenceScore: 0
  }
];

const mockIncidents: Incident[] = [
  {
    id: 'INC-2026-081',
    title: 'Automated Database Exfiltration Attempt via SQL Injection',
    severity: 'critical',
    status: 'investigating',
    createdTime: '2026-03-30T10:00:00Z',
    updatedTime: '2026-03-30T10:00:00Z',
    attackerIp: '185.220.101.5',
    targetHost: 'prod-web-ingress',
    mitreTechnique: 'T1190',
    mitreTactic: 'Initial Access',
    eventCount: 14,
    description: 'Host experienced parameterized UNION SELECT injections',
    recommendedActions: [],
    logIds: []
  },
  {
    id: 'INC-2026-082',
    title: 'Ransomware Preparation: Volume Shadow Copy Deletion',
    severity: 'critical',
    status: 'new',
    createdTime: '2026-03-30T10:00:00Z',
    updatedTime: '2026-03-30T10:00:00Z',
    attackerIp: '10.0.4.15',
    targetHost: 'HR-PC-04',
    mitreTechnique: 'T1490',
    mitreTactic: 'Impact',
    eventCount: 5,
    description: 'vssadmin delete shadows executed',
    recommendedActions: [],
    logIds: []
  }
];

test('extractHostStats correctly aggregates hosts and flags malicious status', () => {
  const hosts = extractHostStats(mockLogs, mockIncidents);
  const webHost = hosts.find(h => h.hostname === 'prod-web-ingress');
  const hrHost = hosts.find(h => h.hostname === 'HR-PC-04');

  assert.ok(webHost, 'Expected prod-web-ingress to exist');
  assert.strictEqual(webHost?.count, 2);
  assert.strictEqual(webHost?.hasMalicious, true);
  assert.strictEqual(webHost?.hasCritical, true);

  assert.ok(hrHost, 'Expected HR-PC-04 from incidents to exist');
  assert.strictEqual(hrHost?.hasCritical, true);
});

test('searchHostStats filters by partial hostname', () => {
  const hosts = extractHostStats(mockLogs, mockIncidents);
  const results = searchHostStats(hosts, 'bastion');
  assert.strictEqual(results.length, 1);
  assert.strictEqual(results[0].hostname, 'auth-bastion-01');
});

test('searchIncidents finds by MITRE technique, IP or title keyword', () => {
  const byMitre = searchIncidents(mockIncidents, 'T1190');
  assert.strictEqual(byMitre.length, 1);
  assert.strictEqual(byMitre[0].id, 'INC-2026-081');

  const byIp = searchIncidents(mockIncidents, '10.0.4.15');
  assert.strictEqual(byIp.length, 1);
  assert.strictEqual(byIp[0].id, 'INC-2026-082');

  const byKeyword = searchIncidents(mockIncidents, 'ransomware');
  assert.strictEqual(byKeyword.length, 1);
  assert.strictEqual(byKeyword[0].id, 'INC-2026-082');
});

test('searchLogs matches source IP, user, matched rule and payload content', () => {
  const byIp = searchLogs(mockLogs, '185.220.101.5');
  assert.strictEqual(byIp.length, 1);
  assert.strictEqual(byIp[0].id, 'log-1');

  const byUser = searchLogs(mockLogs, 'root');
  assert.strictEqual(byUser.length, 1);
  assert.strictEqual(byUser[0].id, 'log-2');

  const byRule = searchLogs(mockLogs, 'SQL Injection');
  assert.strictEqual(byRule.length, 1);
  assert.strictEqual(byRule[0].id, 'log-1');

  const byPayload = searchLogs(mockLogs, 'UNION SELECT');
  assert.strictEqual(byPayload.length, 1);
  assert.strictEqual(byPayload[0].id, 'log-1');
});
