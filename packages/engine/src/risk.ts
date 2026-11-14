/**
 * Port risk ranking for the exposure report. The list is deliberately short
 * and conventional: remote administration, databases and caches, container
 * and cluster control planes, then common admin panels. Anything else is
 * "medium"; plain web ports are "low".
 */
import type { PortRange } from './types.js';

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';

export const SEVERITY_ORDER: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];

interface PortRisk {
  from: number;
  to: number;
  name: string;
  severity: Severity;
  protocol?: 'tcp' | 'udp';
}

const RISKS: PortRisk[] = [
  // Remote administration
  { from: 22, to: 22, name: 'SSH', severity: 'critical' },
  { from: 23, to: 23, name: 'Telnet', severity: 'critical' },
  { from: 3389, to: 3389, name: 'RDP', severity: 'critical' },
  { from: 5900, to: 5900, name: 'VNC', severity: 'critical' },
  { from: 5985, to: 5986, name: 'WinRM', severity: 'critical' },
  { from: 135, to: 135, name: 'MS RPC', severity: 'critical' },
  { from: 139, to: 139, name: 'NetBIOS', severity: 'critical' },
  { from: 445, to: 445, name: 'SMB', severity: 'critical' },
  // Databases and caches
  { from: 1433, to: 1433, name: 'SQL Server', severity: 'critical' },
  { from: 1521, to: 1521, name: 'Oracle', severity: 'critical' },
  { from: 3306, to: 3306, name: 'MySQL/MariaDB', severity: 'critical' },
  { from: 5432, to: 5432, name: 'PostgreSQL', severity: 'critical' },
  { from: 27017, to: 27019, name: 'MongoDB', severity: 'critical' },
  { from: 6379, to: 6379, name: 'Redis', severity: 'critical' },
  { from: 11211, to: 11211, name: 'Memcached', severity: 'critical' },
  { from: 9200, to: 9200, name: 'Elasticsearch/OpenSearch', severity: 'critical' },
  { from: 9300, to: 9300, name: 'Elasticsearch transport', severity: 'critical' },
  { from: 5984, to: 5984, name: 'CouchDB', severity: 'critical' },
  { from: 9042, to: 9042, name: 'Cassandra', severity: 'critical' },
  { from: 8086, to: 8086, name: 'InfluxDB', severity: 'critical' },
  // Container and cluster control planes
  { from: 2375, to: 2376, name: 'Docker API', severity: 'critical' },
  { from: 6443, to: 6443, name: 'Kubernetes API', severity: 'critical' },
  { from: 10250, to: 10250, name: 'kubelet', severity: 'critical' },
  { from: 2379, to: 2380, name: 'etcd', severity: 'critical' },
  // Admin panels and infrastructure services
  { from: 21, to: 21, name: 'FTP', severity: 'high' },
  { from: 111, to: 111, name: 'rpcbind', severity: 'high' },
  { from: 161, to: 161, name: 'SNMP', severity: 'high', protocol: 'udp' },
  { from: 389, to: 389, name: 'LDAP', severity: 'high' },
  { from: 636, to: 636, name: 'LDAPS', severity: 'high' },
  { from: 873, to: 873, name: 'rsync', severity: 'high' },
  { from: 2049, to: 2049, name: 'NFS', severity: 'high' },
  { from: 3000, to: 3000, name: 'Grafana / dev server', severity: 'high' },
  { from: 4848, to: 4848, name: 'GlassFish admin', severity: 'high' },
  { from: 5601, to: 5601, name: 'Kibana', severity: 'high' },
  { from: 5672, to: 5672, name: 'AMQP', severity: 'high' },
  { from: 7001, to: 7001, name: 'WebLogic', severity: 'high' },
  { from: 8000, to: 8000, name: 'HTTP alt / dev server', severity: 'high' },
  { from: 8080, to: 8080, name: 'HTTP alt / admin panel', severity: 'high' },
  { from: 8200, to: 8200, name: 'Vault', severity: 'high' },
  { from: 8443, to: 8443, name: 'HTTPS alt / admin panel', severity: 'high' },
  { from: 8500, to: 8500, name: 'Consul', severity: 'high' },
  { from: 8888, to: 8888, name: 'Jupyter / dev server', severity: 'high' },
  { from: 9000, to: 9000, name: 'admin panel (Portainer, SonarQube, ...)', severity: 'high' },
  { from: 9090, to: 9090, name: 'Prometheus / admin panel', severity: 'high' },
  { from: 9092, to: 9092, name: 'Kafka', severity: 'high' },
  { from: 10000, to: 10000, name: 'Webmin', severity: 'high' },
  { from: 15672, to: 15672, name: 'RabbitMQ management', severity: 'high' },
  { from: 50000, to: 50000, name: 'Jenkins agent', severity: 'high' },
  // Web
  { from: 80, to: 80, name: 'HTTP', severity: 'low' },
  { from: 443, to: 443, name: 'HTTPS', severity: 'low' },
];

const WIDE_RANGE = 1000;

export interface RiskAssessment {
  severity: Severity;
  reasons: string[];
}

function worse(a: Severity, b: Severity): Severity {
  return SEVERITY_ORDER.indexOf(a) <= SEVERITY_ORDER.indexOf(b) ? a : b;
}

export function assessPorts(protocol: string, ports: PortRange | undefined): RiskAssessment {
  if (protocol === 'icmp') return { severity: 'info', reasons: ['ICMP echo'] };
  if (!ports) return { severity: 'medium', reasons: [`IP protocol ${protocol}`] };
  const reasons: string[] = [];
  let severity: Severity | undefined;
  for (const r of RISKS) {
    if (r.protocol && r.protocol !== protocol) continue;
    if (r.to < ports.from || r.from > ports.to) continue;
    severity = severity ? worse(severity, r.severity) : r.severity;
    if (r.severity === 'critical' || r.severity === 'high') reasons.push(`${r.name} (${r.from === r.to ? r.from : `${r.from}-${r.to}`})`);
  }
  const width = ports.to - ports.from + 1;
  if (width >= WIDE_RANGE) {
    severity = severity ? worse(severity, 'high') : 'high';
    reasons.unshift(`wide port range (${width} ports)`);
  }
  if (!severity) {
    // Anything not recognised: not a known risky service, but not plain web either.
    severity = 'medium';
  }
  // A range that only covers web ports stays low; a range that also includes
  // unknown ports is at least medium.
  if (severity === 'low' && width > 1 && !RISKS.some((r) => r.severity === 'low' && r.from <= ports.from && ports.to <= r.to)) {
    severity = 'medium';
  }
  return { severity, reasons };
}

/**
 * What kind of service a port range is. Used to decide which reachable
 * services let an attacker take over a host (remote administration and
 * control planes) and which hold data worth reaching.
 */
export type ServiceCategory = 'admin' | 'data' | 'control' | 'web' | 'wide' | 'other';

const ADMIN = /^(SSH|Telnet|RDP|VNC|WinRM|MS RPC|NetBIOS|SMB)$/;
const DATA = /^(SQL Server|Oracle|MySQL\/MariaDB|PostgreSQL|MongoDB|Redis|Memcached|Elasticsearch\/OpenSearch|Elasticsearch transport|CouchDB|Cassandra|InfluxDB)$/;
const CONTROL = /^(Docker API|Kubernetes API|kubelet|etcd)$/;

export function categorize(protocol: string, ports: PortRange | undefined): ServiceCategory {
  if (!ports) return protocol === 'icmp' ? 'other' : 'wide';
  if (ports.to - ports.from + 1 >= WIDE_RANGE) return 'wide';
  const names = RISKS.filter((r) => (!r.protocol || r.protocol === protocol) && r.from <= ports.to && r.to >= ports.from).map((r) => r.name);
  if (names.some((n) => ADMIN.test(n))) return 'admin';
  if (names.some((n) => DATA.test(n))) return 'data';
  if (names.some((n) => CONTROL.test(n))) return 'control';
  if (names.length && names.every((n) => n === 'HTTP' || n === 'HTTPS')) return 'web';
  return 'other';
}

/** Services that, once reached, normally let an attacker run commands on the host. */
export function isPivotService(protocol: string, ports: PortRange | undefined): boolean {
  const c = categorize(protocol, ports);
  return c === 'admin' || c === 'control' || c === 'wide';
}

/** Human name of the best-known service in a port range, if any. */
export function serviceName(protocol: string, ports: PortRange | undefined): string | undefined {
  if (!ports) return undefined;
  const r = RISKS.find((x) => (!x.protocol || x.protocol === protocol) && x.from <= ports.to && x.to >= ports.from && x.from >= ports.from && x.to <= ports.to);
  return r?.name;
}

export function compareSeverity(a: Severity, b: Severity): number {
  return SEVERITY_ORDER.indexOf(a) - SEVERITY_ORDER.indexOf(b);
}
