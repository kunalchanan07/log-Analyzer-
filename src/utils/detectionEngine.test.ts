import test from 'node:test';
import assert from 'node:assert/strict';
import { parseLogLine, extractIp, extractTimestamp, evaluateRules, DEFAULT_DETECTION_RULES } from './detectionEngine';

test('extractIp accurately extracts IPv4 addresses from various log strings', () => {
  const line1 = 'Oct 28 12:05:22 auth-bastion-01 sshd[4912]: Failed password for invalid user root from 45.145.185.10 port 49122 ssh2';
  assert.equal(extractIp(line1), '45.145.185.10');

  const line2 = '185.220.101.5 - - [28/Oct/2026:12:04:11 +0000] "GET /index.php HTTP/1.1" 200';
  assert.equal(extractIp(line2), '185.220.101.5');

  const lineNoIp = 'System reboot initiated by user localadmin';
  assert.equal(extractIp(lineNoIp), null);
});

test('SQL Injection detection triggers RULE-SQLI-001 and maps to MITRE T1190', () => {
  const sqliLog = '185.220.101.5 - - "GET /products?id=1 UNION SELECT null,username,password FROM users-- HTTP/1.1" 200';
  const result = parseLogLine(sqliLog);

  assert.equal(result.isMalicious, true);
  assert.equal(result.category, 'sqli');
  assert.equal(result.severity, 'critical');
  assert.ok(result.ruleMatched);
  assert.equal(result.ruleMatched?.id, 'RULE-SQLI-001');
  assert.equal(result.ruleMatched?.mitreId, 'T1190');
});

test('XSS script payload detection triggers RULE-XSS-002', () => {
  const xssLog = '194.26.29.112 - - "POST /comment HTTP/1.1" 200 "<script>alert(document.cookie)</script>"';
  const result = parseLogLine(xssLog);

  assert.equal(result.isMalicious, true);
  assert.equal(result.category, 'xss');
  assert.equal(result.severity, 'high');
  assert.ok(result.ruleMatched);
  assert.equal(result.ruleMatched?.id, 'RULE-XSS-002');
});

test('Ransomware shadow copy deletion triggers RULE-RANSOM-004 and maps to MITRE T1490', () => {
  const ransomLog = 'Sysmon Event 1: Host=Finance-02 Command="vssadmin delete shadows /all /quiet"';
  const result = parseLogLine(ransomLog);

  assert.equal(result.isMalicious, true);
  assert.equal(result.category, 'ransomware');
  assert.equal(result.severity, 'critical');
  assert.ok(result.ruleMatched);
  assert.equal(result.ruleMatched?.mitreId, 'T1490');
});

test('SSH Brute Force attempts trigger RULE-BRUTE-003 and maps to MITRE T1110', () => {
  const bruteLog = 'Oct 28 12:05:22 auth-bastion-01 sshd[4912]: Failed password for invalid user root from 45.145.185.10 port 49122 ssh2';
  const result = parseLogLine(bruteLog);

  assert.equal(result.isMalicious, true);
  assert.equal(result.category, 'brute_force');
  assert.ok(result.ruleMatched);
  assert.equal(result.ruleMatched?.mitreId, 'T1110');
  assert.equal(result.user, 'root');
});

test('Normal benign log is classified as info / clean', () => {
  const normalLog = '192.168.1.50 - - "GET /static/css/theme.css HTTP/1.1" 200 4096 "https://company.org" "Mozilla/5.0"';
  const result = parseLogLine(normalLog);

  assert.equal(result.isMalicious, false);
  assert.equal(result.isSuspicious, false);
  assert.equal(result.severity, 'info');
  assert.equal(result.category, 'normal');
});

test('JSON structured logs are parsed with extracted metadata', () => {
  const jsonLog = JSON.stringify({
    timestamp: '2026-10-28T12:00:00Z',
    src_ip: '194.26.29.112',
    host: 'db-cluster-01',
    user: 'sysadmin',
    message: 'cat /etc/passwd path traversal attempt ../../etc/passwd'
  });
  const result = parseLogLine(jsonLog);

  assert.equal(result.sourceHost, 'db-cluster-01');
  assert.equal(result.sourceIp, '194.26.29.112');
  assert.equal(result.user, 'sysadmin');
  assert.equal(result.isMalicious, true);
  assert.equal(result.category, 'directory_traversal');
});
