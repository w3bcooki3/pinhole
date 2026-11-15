/**
 * A reference evaluator for one question: can this internet address open a
 * TCP or UDP connection to this interface on this port? Written from the AWS
 * documentation, one packet at a time, sharing no code with the engine, so
 * the fuzz test can hold the engine to it.
 *
 * Inbound from the internet to an interface in a VPC:
 *  - the interface has a public IPv4 address;
 *  - the VPC has an attached internet gateway;
 *  - the subnet's route table (its own association, or the VPC's main table)
 *    sends the client's address to that gateway, by longest prefix match,
 *    so the reply can leave (an inactive route matches but goes nowhere);
 *  - the subnet's network ACL (its own, or the VPC's default) allows the
 *    packet in: entries in ascending order, the first that matches decides,
 *    and nothing matching means deny;
 *  - some inbound rule of some security group on the interface matches.
 * Outbound network ACL entries are generated to allow everything, so the
 * reply always gets out.
 */
type Raw = any; // eslint-disable-line @typescript-eslint/no-explicit-any

export function ip(text: string): number {
  return text.split('.').reduce((n, o) => n * 256 + Number(o), 0);
}
export function inCidr(addr: number, cidr: string): boolean {
  const [base, len] = cidr.split('/');
  const size = 2 ** (32 - Number(len));
  const start = Math.floor(ip(base!) / size) * size;
  return addr >= start && addr < start + size;
}
const PROTO: Record<string, string> = { tcp: '6', udp: '17' };

export function referenceReach(snap: Raw, eniId: string, client: string, protocol: 'tcp' | 'udp', port: number): boolean {
  const ec2 = snap.ec2;
  const eni = ec2.NetworkInterfaces.find((e: Raw) => e.NetworkInterfaceId === eniId);
  if (!eni) return false;
  if (!eni.PrivateIpAddresses.some((p: Raw) => p.Association?.PublicIp)) return false;
  const c = ip(client);
  const vpc = eni.VpcId;
  const igw = (ec2.InternetGateways ?? []).find((g: Raw) => (g.Attachments ?? []).some((a: Raw) => a.VpcId === vpc && (a.State === 'available' || a.State === 'attached')));
  if (!igw) return false;

  const tables = ec2.RouteTables.filter((t: Raw) => t.VpcId === vpc);
  const table = tables.find((t: Raw) => (t.Associations ?? []).some((a: Raw) => a.SubnetId === eni.SubnetId)) ?? tables.find((t: Raw) => (t.Associations ?? []).some((a: Raw) => a.Main));
  if (!table) return false;
  let best: Raw;
  let bestLen = -1;
  for (const r of table.Routes) {
    if (!r.DestinationCidrBlock || !inCidr(c, r.DestinationCidrBlock)) continue;
    const len = Number(r.DestinationCidrBlock.split('/')[1]);
    if (len > bestLen) (best = r), (bestLen = len);
  }
  if (!best || best.State === 'blackhole' || best.GatewayId !== igw.InternetGatewayId) return false;

  const acls = ec2.NetworkAcls.filter((n: Raw) => n.VpcId === vpc);
  const acl = acls.find((n: Raw) => (n.Associations ?? []).some((a: Raw) => a.SubnetId === eni.SubnetId)) ?? acls.find((n: Raw) => n.IsDefault);
  if (!acl) return false;
  const inbound = acl.Entries.filter((e: Raw) => !e.Egress).sort((a: Raw, b: Raw) => a.RuleNumber - b.RuleNumber);
  let allowed = false;
  for (const e of inbound) {
    if (e.Protocol !== '-1' && e.Protocol !== PROTO[protocol]) continue;
    if (e.Protocol !== '-1' && e.PortRange && (port < e.PortRange.From || port > e.PortRange.To)) continue;
    if (!e.CidrBlock || !inCidr(c, e.CidrBlock)) continue;
    allowed = e.RuleAction === 'allow';
    break;
  }
  if (!allowed) return false;

  const groups = new Set(eni.Groups.map((g: Raw) => g.GroupId));
  return (ec2.SecurityGroupRules ?? []).some((r: Raw) => {
    if (r.IsEgress || !groups.has(r.GroupId)) return false;
    if (r.IpProtocol !== '-1' && r.IpProtocol !== protocol) return false;
    if (r.IpProtocol !== '-1' && (port < r.FromPort || port > r.ToPort)) return false;
    return !!r.CidrIpv4 && inCidr(c, r.CidrIpv4);
  });
}

/**
 * A reference for AWS Network Firewall, for policies without content
 * matching: one connection from `client`:`eph` to `server`:`port`.
 * Written from the developer guide's description of the two engines
 * (firewall-rules-engines.html, suricata-rule-evaluation-order.html),
 * sharing no code with the engine.
 */
export interface RefStateless { priority: number; action: 'pass' | 'drop' | 'forward'; protocols: number[]; sources: string[]; srcPorts: [number, number][]; dstPorts: [number, number][] }
export interface RefStateful { action: 'pass' | 'drop' | 'reject' | 'alert'; proto: 'tcp' | 'udp' | 'ip'; src: string; dst: string; dstPort: string; both: boolean }
export interface RefPolicy { stateless: RefStateless[]; statelessDefault: 'pass' | 'drop' | 'forward'; stateful: RefStateful[]; strict: boolean; defaults: string[]; home: string }

export function referenceFirewall(p: RefPolicy, client: number, server: number, proto: number, port: number, eph: number): boolean {
  const req = { src: client, sport: eph, dst: server, dport: port };
  const rep = { src: server, sport: port, dst: client, dport: eph };
  const inRange = (v: number, list: [number, number][]) => !list.length || list.some(([a, b]) => v >= a && v <= b);
  const forwarded: (typeof req)[] = [];
  for (const pkt of [req, rep]) {
    const rule = [...p.stateless].sort((a, b) => a.priority - b.priority).find((r) => (!r.protocols.length || r.protocols.includes(proto)) && (!r.sources.length || r.sources.some((c) => inCidr(pkt.src, c))) && inRange(pkt.sport, r.srcPorts) && inRange(pkt.dport, r.dstPorts));
    const action = rule ? rule.action : p.statelessDefault;
    if (action === 'drop') return false;
    if (action === 'forward') forwarded.push(pkt);
  }
  if (!forwarded.length) return true;
  const addr = (spec: string, ip: number) => (spec === 'any' ? true : spec === '$HOME_NET' ? inCidr(ip, p.home) : spec === '$EXTERNAL_NET' ? !inCidr(ip, p.home) : inCidr(ip, spec));
  const portOk = (spec: string, v: number) => {
    if (spec === 'any') return true;
    const [a, b] = spec.includes(':') ? spec.split(':').map(Number) : [Number(spec), Number(spec)];
    return v >= a! && v <= b!;
  };
  const protoOk = (r: RefStateful) => r.proto === 'ip' || (r.proto === 'tcp' ? proto === 6 : proto === 17);
  const matches = (r: RefStateful, pkt: typeof req) =>
    protoOk(r) && ((addr(r.src, pkt.src) && addr(r.dst, pkt.dst) && portOk(r.dstPort, pkt.dport)) || (r.both && addr(r.dst, pkt.src) && addr(r.src, pkt.dst) && portOk(r.dstPort, pkt.sport)));
  const rank = { pass: 0, drop: 1, reject: 2, alert: 3 };
  const rules = p.strict ? p.stateful : [...p.stateful].sort((a, b) => rank[a.action] - rank[b.action]);
  for (const pkt of forwarded) {
    for (const r of rules) {
      if (!matches(r, pkt) || r.action === 'alert') continue;
      return r.action === 'pass';
    }
  }
  return !(p.strict && p.defaults.some((d) => d === 'aws:drop_strict' || d === 'aws:drop_established'));
}
