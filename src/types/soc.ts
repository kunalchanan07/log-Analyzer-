export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';

export type LogSource = 'web' | 'auth' | 'firewall' | 'edr' | 'cloudtrail' | 'syslog';

export type ThreatCategory = 
  | 'normal' 
  | 'brute_force' 
  | 'sqli' 
  | 'xss' 
  | 'ransomware' 
  | 'privilege_escalation' 
  | 'c2_beacon' 
  | 'port_scan' 
  | 'directory_traversal' 
  | 'unauthorized_access';

export interface RuleMatch {
  id: string;
  name: string;
  mitreId: string;
  mitreTactic: string;
  description: string;
  remediation: string;
}

export interface LogEntry {
  id: string;
  timestamp: string;
  source: LogSource;
  raw: string;
  sourceHost: string;
  sourceIp: string;
  destinationIp?: string;
  destinationPort?: number;
  user?: string;
  severity: Severity;
  category: ThreatCategory;
  isMalicious: boolean;
  isSuspicious: boolean;
  confidenceScore: number;
  ruleMatched?: RuleMatch;
  metadata?: Record<string, string | number | boolean>;
}

export interface Incident {
  id: string;
  title: string;
  severity: Severity;
  status: 'new' | 'investigating' | 'contained' | 'resolved';
  createdTime: string;
  updatedTime: string;
  attackerIp: string;
  targetHost: string;
  mitreTechnique: string;
  mitreTactic: string;
  eventCount: number;
  description: string;
  recommendedActions: string[];
  logIds: string[];
  aiAnalysis?: string;
}

export interface DetectionRule {
  id: string;
  name: string;
  severity: Severity;
  category: ThreatCategory;
  mitreId: string;
  mitreTactic: string;
  pattern: string;
  regexString?: string;
  enabled: boolean;
  hits: number;
  description: string;
  remediation: string;
}

export interface CollectorStats {
  status: 'running' | 'paused';
  eps: number;
  totalEvents: number;
  maliciousCount: number;
  suspiciousCount: number;
  cleanCount: number;
  activeSources: LogSource[];
  bufferMemoryMb: number;
}
