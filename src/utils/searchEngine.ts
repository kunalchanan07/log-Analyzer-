import { LogEntry, Incident } from '../types/soc';

export interface HostStat {
  hostname: string;
  count: number;
  hasMalicious: boolean;
  hasCritical: boolean;
}

export function extractHostStats(logs: LogEntry[], incidents: Incident[]): HostStat[] {
  const map = new Map<string, { count: number; hasMalicious: boolean; hasCritical: boolean }>();

  for (const log of logs) {
    const h = log.sourceHost || 'unknown-host';
    const current = map.get(h) || { count: 0, hasMalicious: false, hasCritical: false };
    current.count += 1;
    if (log.isMalicious) current.hasMalicious = true;
    if (log.severity === 'critical') current.hasCritical = true;
    map.set(h, current);
  }

  for (const inc of incidents) {
    if (inc.targetHost) {
      const current = map.get(inc.targetHost) || { count: 0, hasMalicious: true, hasCritical: false };
      if (inc.severity === 'critical') current.hasCritical = true;
      map.set(inc.targetHost, current);
    }
  }

  return Array.from(map.entries()).map(([hostname, stats]) => ({
    hostname,
    ...stats
  }));
}

export function searchHostStats(hostStats: HostStat[], query: string): HostStat[] {
  const clean = query.trim().toLowerCase();
  if (!clean) return hostStats;
  return hostStats.filter(h => h.hostname.toLowerCase().includes(clean));
}

export function searchIncidents(incidents: Incident[], query: string): Incident[] {
  const clean = query.trim().toLowerCase();
  if (!clean) return incidents;
  return incidents.filter(inc => {
    return (
      inc.title.toLowerCase().includes(clean) ||
      inc.id.toLowerCase().includes(clean) ||
      inc.attackerIp.toLowerCase().includes(clean) ||
      inc.targetHost.toLowerCase().includes(clean) ||
      inc.mitreTechnique.toLowerCase().includes(clean) ||
      inc.mitreTactic.toLowerCase().includes(clean) ||
      inc.description.toLowerCase().includes(clean)
    );
  });
}

export function searchLogs(logs: LogEntry[], query: string, limit: number = 25): LogEntry[] {
  const clean = query.trim().toLowerCase();
  if (!clean) return logs.slice(0, limit);

  const results: LogEntry[] = [];
  for (const log of logs) {
    if (results.length >= limit) break;
    const matches =
      log.raw.toLowerCase().includes(clean) ||
      log.sourceIp.toLowerCase().includes(clean) ||
      log.sourceHost.toLowerCase().includes(clean) ||
      (log.user && log.user.toLowerCase().includes(clean)) ||
      (log.ruleMatched && log.ruleMatched.name.toLowerCase().includes(clean)) ||
      (log.ruleMatched && log.ruleMatched.mitreId.toLowerCase().includes(clean)) ||
      log.category.toLowerCase().includes(clean);

    if (matches) {
      results.push(log);
    }
  }
  return results;
}
