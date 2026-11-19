import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { analyzeBlastRadius, analyzeEgress, analyzeExposure, analyzeHygiene, analyzeSavings, findingKey, ingest, normalize } from '../src/index.js';
import { firstJsonError } from '../src/ingest.js';

const here = dirname(fileURLToPath(import.meta.url));
const fixtureText = (name: string) => readFileSync(join(here, '../../../fixtures', name, 'snapshot.json'), 'utf8');
const fixture = (name: string) => JSON.parse(fixtureText(name)) as Record<string, any>;
const enc = (s: string) => new TextEncoder().encode(s);
const utf16le = (s: string, bom = true) => {
  const b = new Uint8Array((bom ? 2 : 0) + s.length * 2);
  if (bom) b.set([0xff, 0xfe]);
  for (let i = 0; i < s.length; i++) {
    b[(bom ? 2 : 0) + i * 2] = s.charCodeAt(i) & 0xff;
    b[(bom ? 2 : 0) + i * 2 + 1] = s.charCodeAt(i) >> 8;
  }
  return b;
};
const findings = (snap: unknown) => analyzeExposure(normalize(snap as any)).findings.map(findingKey).sort();
const one = (r: ReturnType<typeof ingest>) => {
  expect(r.errors).toEqual([]);
  expect(r.snapshots).toHaveLength(1);
  return r.snapshots[0]!.snapshot;
};

describe('reading snapshots in every encoding and shape people have', () => {
  const text = fixtureText('07-alb-private-targets');
  const want = findings(JSON.parse(text));

  it('reads UTF-8, with and without a byte order mark', () => {
    expect(findings(one(ingest([{ name: 'a.json', bytes: enc(text) }])))).toEqual(want);
    expect(findings(one(ingest([{ name: 'a.json', bytes: new Uint8Array([0xef, 0xbb, 0xbf, ...enc(text)]) }])))).toEqual(want);
  });

  it('reads UTF-16, as Windows PowerShell writes with >, with and without a byte order mark', () => {
    expect(findings(one(ingest([{ name: 'ps.json', bytes: utf16le(text) }])))).toEqual(want);
    expect(findings(one(ingest([{ name: 'ps.json', bytes: utf16le(text, false) }])))).toEqual(want);
  });

  it('reads hand-edited JSON with comments and trailing commas, and says so', () => {
    const edited = text.replace('{', '{ // copied from prod\n /* note */').replace(/\]\s*\}\s*$/, '],\n}');
    const r = ingest([{ name: 'edited.json', text: edited }]);
    expect(findings(one(r))).toEqual(want);
    expect(r.notes.join(' ')).toMatch(/comments and trailing commas/);
  });

  it('keeps a "//" inside a string as it is', () => {
    const s = JSON.parse(text);
    s.source = 'https://example.com//x /* not a comment */';
    const r = ingest([{ name: 'a.json', text: JSON.stringify(s) + '\n// trailing comment' }]);
    expect((one(r) as any).source).toBe('https://example.com//x /* not a comment */');
  });

  it('reads several snapshots joined in one file, or in an array', () => {
    const b = fixtureText('09-lateral-movement');
    const joined = ingest([{ name: 'all.json', text: `${text}\n${b}` }]);
    expect(joined.errors).toEqual([]);
    expect(joined.snapshots).toHaveLength(2);
    expect(joined.notes.join(' ')).toMatch(/2 JSON documents/);
    expect(ingest([{ name: 'arr.json', text: `[${text},${b}]` }]).snapshots).toHaveLength(2);
  });

  it('reads a snapshot without schemaVersion, and says so', () => {
    const s = JSON.parse(text);
    delete s.schemaVersion;
    const r = ingest([{ name: 'old.json', text: JSON.stringify(s) }]);
    expect(findings(one(r))).toEqual(want);
    expect(r.notes.join(' ')).toMatch(/no schemaVersion/);
  });
});

describe('assembling plain AWS CLI output into a snapshot', () => {
  // Split a fixture back into the files `aws ec2 describe-…` and `aws elbv2 describe-…` would write.
  const asCliFiles = (fx: Record<string, any>) => {
    const files: { name: string; text: string }[] = [];
    for (const [k, v] of Object.entries(fx.ec2 ?? {})) {
      if (k === 'Instances') files.push({ name: 'instances.json', text: JSON.stringify({ Reservations: [{ ReservationId: 'r-1', Instances: v }] }) });
      else if (k === 'VpcEndpointServiceConfigurations') files.push({ name: 'svc.json', text: JSON.stringify({ ServiceConfigurations: v }) });
      else if (Array.isArray(v)) files.push({ name: `${k}.json`, text: JSON.stringify({ [k]: v }, null, 4) });
    }
    for (const k of ['LoadBalancers', 'Listeners', 'TargetGroups']) if (fx.elbv2?.[k]) files.push({ name: `${k}.json`, text: JSON.stringify({ [k]: fx.elbv2[k] }) });
    return files;
  };

  it('gives the same internet exposure as the collected snapshot', () => {
    for (const name of ['02-sg-to-sg-reference', '08-nlb-client-ip-preservation', '17-savings']) {
      const fx = fixture(name);
      const r = ingest(asCliFiles(fx));
      const snap = one(r) as any;
      // The account and Region come from owner IDs, zones and ARNs in the data; fixture 17 has them.
      if (name === '17-savings') {
        expect(snap.accountId).toBe(fx.accountId);
        expect(snap.region).toBe(fx.region);
      }
      // Target health is per target group and cannot come from plain CLI output; compare without it.
      const fxNoHealth = { ...fx, elbv2: fx.elbv2 ? { ...fx.elbv2, TargetHealth: undefined, TargetGroupAttributes: undefined } : undefined };
      expect(findings(snap), name).toEqual(findings(fxNoHealth));
    }
  });

  it('finds the same savings from AWS CLI output as from the collected snapshot', () => {
    const fx = fixture('17-savings');
    const snap = one(ingest(asCliFiles(fx)));
    const key = (s: unknown) => analyzeSavings(normalize(s as any)).findings.map((f) => `${f.code} ${f.resourceId}`).filter((k) => !k.startsWith('idle-load-balancer')).sort();
    expect(key(snap)).toEqual(key(fx));
  });

  it('merges the same output loaded twice, and says when a file was cut short by paging', () => {
    const fx = fixture('02-sg-to-sg-reference');
    const files = asCliFiles(fx);
    const sg = files.find((f) => f.name === 'SecurityGroups.json')!;
    const r = ingest([...files, { name: 'again.json', text: sg.text }, { name: 'page1.json', text: JSON.stringify({ Subnets: [], NextToken: 'abc' }) }]);
    expect((one(r) as any).ec2.SecurityGroups).toHaveLength(fx.ec2.SecurityGroups.length);
    expect(r.notes.join(' ')).toMatch(/page1\.json was cut short by paging/);
  });

  it('names what is missing', () => {
    const r = ingest([{ name: 'sg.json', text: JSON.stringify({ SecurityGroups: fixture('02-sg-to-sg-reference').ec2.SecurityGroups }) }]);
    expect(r.snapshots).toHaveLength(1);
    expect(r.notes.join(' ')).toMatch(/no Vpcs, Subnets, RouteTables/);
  });

  it('keeps files from different accounts apart', () => {
    const a = fixture('17-savings');
    const b = JSON.parse(JSON.stringify(a).replaceAll(a.accountId, '999988887777'));
    const r = ingest([{ name: 'a.json', text: JSON.stringify({ Vpcs: a.ec2.Vpcs }) }, { name: 'b.json', text: JSON.stringify({ Vpcs: b.ec2.Vpcs }) }]);
    expect(r.snapshots.map((s) => (s.snapshot as any).accountId).sort()).toEqual(['999988887777', a.accountId].sort());
  });

  it('reads Network Firewall describe output', () => {
    const fx = fixture('12-network-firewall');
    const files = asCliFiles(fx);
    for (const f of fx.networkFirewall.Firewalls) files.push({ name: 'fw.json', text: JSON.stringify(f) });
    for (const p of Object.values(fx.networkFirewall.FirewallPolicies)) files.push({ name: 'policy.json', text: JSON.stringify(p) });
    for (const g of Object.values(fx.networkFirewall.RuleGroups)) files.push({ name: 'rg.json', text: JSON.stringify(g) });
    expect(findings(one(ingest(files)))).toEqual(findings(fx));
  });
});

describe('secrets never get in', () => {
  it('removes VPN tunnel keys and credentials from raw output and from snapshots', () => {
    const vpn = {
      VpnConnections: [
        {
          VpnConnectionId: 'vpn-1', State: 'available', Type: 'ipsec.1', VpnGatewayId: 'vgw-1',
          CustomerGatewayConfiguration: '<vpn_connection><ike><pre_shared_key>s3cr3t-psk</pre_shared_key></ike></vpn_connection>',
          Options: { TunnelOptions: [{ OutsideIpAddress: '203.0.113.1', PreSharedKey: 's3cr3t-psk' }] },
        },
      ],
      Vpcs: [{ VpcId: 'vpc-1', CidrBlock: '10.0.0.0/16', OwnerId: '111122223333' }],
    };
    const r = ingest([{ name: 'vpn.json', text: JSON.stringify(vpn) }]);
    expect(JSON.stringify(r.snapshots)).not.toMatch(/s3cr3t/);
    expect(r.notes.join(' ')).toMatch(/2 secrets were removed/);
    const snap = fixture('07-alb-private-targets');
    snap.leaked = { AwsSecretAccessKey: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY', Password: 'hunter2' };
    expect(JSON.stringify(ingest([{ name: 's.json', text: JSON.stringify(snap) }]).snapshots)).not.toMatch(/wJalrXUtnFEMI|hunter2/);
  });
});

describe('files that are not snapshots get a message that says what they are', () => {
  const err = (input: { name: string; text?: string; bytes?: Uint8Array }) => {
    const r = ingest([input]);
    expect(r.snapshots).toHaveLength(0);
    expect(r.errors).toHaveLength(1);
    return r.errors[0]!;
  };
  it.each([
    ['empty', { name: 'e.json', text: '  \n' }, /is empty/],
    ['AWS CLI table output', { name: 't.txt', text: '-----------------------\n|  DescribeVpcs  |\n+-----------+\n|  vpc-1  |\n' }, /table output.*--output json/],
    ['AWS CLI text output', { name: 't.txt', text: 'VPCS\t10.0.0.0/16\tdefault\tvpc-1\n' }, /text output.*--output json/],
    ['YAML', { name: 'y.yaml', text: 'Vpcs:\n- VpcId: vpc-1\n' }, /YAML/],
    ['HTML', { name: 'p.html', text: '<!DOCTYPE html><html><body>x</body></html>' }, /HTML page/],
    ['Terraform code', { name: 'main.tf', text: 'resource "aws_vpc" "main" {\n  cidr_block = "10.0.0.0/16"\n}' }, /Terraform code/],
    ['a Terraform plan', { name: 'plan.json', text: JSON.stringify({ format_version: '1.2', planned_values: {} }) }, /Terraform plan/],
    ['an IAM policy', { name: 'p.json', text: JSON.stringify({ Version: '2012-10-17', Statement: [] }) }, /IAM policy/],
    ['classic ELB output', { name: 'elb.json', text: JSON.stringify({ LoadBalancerDescriptions: [] }) }, /Classic Load Balancer/],
    ['unrelated JSON', { name: 'x.json', text: JSON.stringify({ hello: 'world' }) }, /none of the fields Pinhole reads \(it has hello\)/],
    ['broken JSON, with where', { name: 'b.json', text: '{\n  "Vpcs": [\n    {"VpcId": "vpc-1",}\n    oops\n' }, /not valid JSON \(problem at line \d+, column \d+\)/],
    ['ZIP', { name: 'x.zip', bytes: new Uint8Array([0x50, 0x4b, 3, 4, 0, 0]) }, /ZIP archive/],
    ['gzip', { name: 'x.json.gz', bytes: new Uint8Array([0x1f, 0x8b, 8, 0]) }, /gzip/],
    ['too deeply nested', { name: 'deep.json', text: '['.repeat(200_000) + ']'.repeat(200_000) }, /nested too deeply|not valid JSON|none of the fields|not an object/],
  ])('%s', (_what, input, re) => {
    expect(err(input)).toMatch(re);
  });

  it('a snapshot with a wrong field says which field', () => {
    const s = fixture('07-alb-private-targets');
    s.ec2.Subnets[0].CidrBlock = 42;
    expect(err({ name: 's.json', text: JSON.stringify(s) })).toMatch(/s\.json: .*Subnets/);
  });
});

describe('finding where JSON goes wrong', () => {
  it('agrees with JSON.parse on every text, and points at the first bad character', () => {
    let seed = 9;
    const rnd = () => (seed = (seed * 48271) % 2147483647) / 2147483647;
    const parts = ['{', '}', '[', ']', '"a"', '"b\\"c"', ':', ',', '1', '-0.5e3', '01', 'true', 'nul', ' ', '\n', '"\\u00e9"', '"\\x"', '1.', '.5', '"'];
    for (let k = 0; k < 20000; k++) {
      const t = Array.from({ length: 1 + Math.floor(rnd() * 9) }, () => parts[Math.floor(rnd() * parts.length)]).join('');
      let valid = true;
      try {
        JSON.parse(t);
      } catch {
        valid = false;
      }
      expect(firstJsonError(t) === -1, t).toBe(valid);
    }
    expect(firstJsonError('{\n  "a": [1, 2\n')).toBe(15);
    expect(firstJsonError('{"a":1,}')).toBe(7);
  });
});

describe('hostile input', () => {
  it('cannot pollute object prototypes, through snapshots or raw output', () => {
    const s = fixture('17-savings');
    const evil = JSON.stringify(s).replace('"ec2":{', '"ec2":{"__proto__":{"polluted":1},"constructor":{"prototype":{"polluted":1}},');
    ingest([{ name: 'evil.json', text: evil }]);
    ingest([{ name: 'raw.json', text: '{"__proto__":{"polluted":1},"toString":[{"x":1}],"constructor":[],"Vpcs":[{"VpcId":"vpc-1","CidrBlock":"10.0.0.0/16","OwnerId":"111122223333","__proto__":{"polluted":1}}]}' }]);
    const tg = JSON.stringify(s).replace('"TargetHealth":{', '"TargetHealth":{"__proto__":[{"Target":{"Id":"i-x"}}],');
    const r = ingest([{ name: 'tg.json', text: tg }]);
    if (r.snapshots.length) analyzeExposure(normalize(r.snapshots[0]!.snapshot));
    expect(({} as any).polluted).toBeUndefined();
    expect((Object.prototype as any).polluted).toBeUndefined();
  });

  it('control and bidirectional characters in names are neutralised, and refused in IDs', () => {
    const s = fixture('07-alb-private-targets');
    s.ec2.SecurityGroups[0].GroupName = 'web\u001b[31mRED‮gnp.exe';
    const name = (one(ingest([{ name: 's.json', text: JSON.stringify(s) }])) as any).ec2.SecurityGroups[0].GroupName as string;
    expect(name).not.toMatch(/[\u001b‮]/);
    expect(name).toContain('RED');
    const t = fixture('07-alb-private-targets');
    t.ec2.Subnets[0].SubnetId = 'subnet-1‮';
    expect(ingest([{ name: 't.json', text: JSON.stringify(t) }]).errors.join(' ')).toMatch(/SubnetId/);
  });

  it('survives random damage: every result is a clean error or a snapshot every analysis can read', () => {
    let seed = 1;
    const rnd = () => (seed = (seed * 48271) % 2147483647) / 2147483647;
    const pick = <T>(a: T[]) => a[Math.floor(rnd() * a.length)]!;
    const nasty = [null, true, -1, 1e308, NaN, '', ' ', '0.0.0.0/0', '::/0', '999.1.1.1/40', 'a'.repeat(5000), '\u0000', '<script>', [], {}, [null], { __proto__: 1 }, 65536, -65535, '10.0.0.0/33'];
    const mutate = (v: any, depth = 0): void => {
      if (!v || typeof v !== 'object' || depth > 6) return;
      const keys = Object.keys(v);
      if (!keys.length) return;
      for (let i = 0; i < 3; i++) {
        const k = pick(keys);
        const r = rnd();
        if (r < 0.25) delete v[k];
        else if (r < 0.55) v[k] = pick(nasty);
        else mutate(v[k], depth + 1);
      }
    };
    const names = ['07-alb-private-targets', '09-lateral-movement', '12-network-firewall', '14-outbound', '15-hybrid', '16-privatelink', '17-savings'];
    let read = 0;
    for (let n = 0; n < 300; n++) {
      const s = fixture(pick(names));
      mutate(s);
      const r = ingest([{ name: `fuzz${n}.json`, text: JSON.stringify(s) }]);
      for (const e of r.errors) expect(typeof e).toBe('string');
      for (const { snapshot } of r.snapshots) {
        read++;
        const m = normalize(snapshot);
        const x = analyzeExposure(m);
        analyzeBlastRadius(m, x, { maxPairs: 2000 });
        analyzeEgress(m);
        analyzeHygiene(m, x);
        analyzeSavings(m, { exposure: x });
      }
    }
    expect(read).toBeGreaterThan(20);
  });
});
