'use strict';
/*
 * Tests for server.js scan() + resolveHost().
 * Zero-dependency: uses the built-in node:test runner and node:assert.
 *   run with:  node --test
 *
 * The panel HTTP calls (global fetch) and DNS resolver (dns.promises) are
 * stubbed so the test is deterministic and never touches the network.
 * DoH is disabled (DOH=0) so resolution goes purely through the stubbed
 * system resolver.
 */

process.env.DOH = '0';                 // must be set before requiring server.js
const test = require('node:test');
const assert = require('node:assert');
const dns = require('dns');

const { scan, resolveHost } = require('../server.js');

// ---- DNS stub (server.js captured dns.promises by reference) ----
const A = { 'de.example.com': ['1.2.3.4'], 'a.example.com': ['1.2.3.4'], 'b.example.com': ['5.6.7.8'] };
const AAAA = { 'v6.example.com': ['2001:db8::1'] };
dns.promises.resolve4 = async (name) => { if (A[name]) return A[name]; throw new Error('ENOTFOUND ' + name); };
dns.promises.resolve6 = async (name) => { if (AAAA[name]) return AAAA[name]; throw new Error('ENOTFOUND ' + name); };

// ---- panel API stub ----
const PROFILES = { response: { configProfiles: [{
  uuid: 'p1', name: 'Main',
  inbounds: [{ uuid: 'i1', tag: 'VLESS', port: 443, type: 'vless' }, { uuid: 'i2', tag: 'TROJAN', port: 8443, type: 'trojan' }],
}] } };

const NODES = { response: [
  { uuid: 'n1', name: 'DE-1', address: '1.2.3.4', port: 443, countryCode: 'DE', isConnected: true, isDisabled: false, usersOnline: 5,
    isTrafficTrackingActive: true, trafficUsedBytes: 900, trafficLimitBytes: 1000, notifyPercent: 80,
    configProfile: { activeConfigProfileUuid: 'p1', activeInbounds: [{ uuid: 'i1', tag: 'VLESS' }] } },
  { uuid: 'n2', name: 'NL-1', address: '5.6.7.8', countryCode: 'NL', isConnected: true, isDisabled: false, usersOnline: 3,
    isTrafficTrackingActive: true, trafficUsedBytes: 1200, trafficLimitBytes: 1000,
    configProfile: { activeInbounds: [{ uuid: 'i1', tag: 'VLESS' }, { uuid: 'i2', tag: 'TROJAN' }] } },
  { uuid: 'n3', name: 'DE-1b', address: '1.2.3.4', countryCode: 'DE', isConnected: true,           // shares IP with n1
    configProfile: { activeInbounds: [{ uuid: 'i1', tag: 'VLESS' }] } },
  { uuid: 'n4', name: 'v6node', address: '2001:db8::1', countryCode: 'DE', isConnected: true,        // IPv6-only node
    configProfile: { activeInbounds: [{ uuid: 'i1', tag: 'VLESS' }] } },
] };

const HOSTS = { response: [
  { uuid: 'h1', remark: 'de host', isDisabled: false, port: 443, address: 'de.example.com', inbound: { configProfileInboundUuid: 'i1' } },
  { uuid: 'h2', remark: 'balancer', isDisabled: false, address: 'a.example.com, b.example.com, dead.example.com', inbound: { configProfileInboundUuid: 'i1' } },
  { uuid: 'h3', remark: 'de host on trojan', isDisabled: false, address: 'de.example.com', inbound: { configProfileInboundUuid: 'i2' } },
  { uuid: 'h4', remark: 'v6 host', isDisabled: false, address: 'v6.example.com', inbound: { configProfileInboundUuid: 'i1' } },
  { uuid: 'h5', remark: 'v6 literal', isDisabled: false, address: '[2001:db8::1]:8443', inbound: { configProfileInboundUuid: 'i1' } },
] };

const METRICS = { response: { nodes: [
  { nodeUuid: 'n1', usersOnline: 5, inboundsStats: [{ tag: 'VLESS', upload: '1000', download: '2000' }], outboundsStats: [] },
  { nodeUuid: 'n2', usersOnline: 3, inboundsStats: [{ tag: 'VLESS', upload: '500', download: '500' }, { tag: 'TROJAN', upload: '10', download: '20' }], outboundsStats: [] },
] } };

const STATS = { response: { onlineStats: { onlineNow: 8 } } };

global.fetch = async (url) => {
  const u = String(url);
  const J = (obj) => ({ ok: true, status: 200, text: async () => JSON.stringify(obj) });
  if (u.endsWith('/api/hosts')) return J(HOSTS);
  if (u.endsWith('/api/nodes')) return J(NODES);
  if (u.endsWith('/api/config-profiles')) return J(PROFILES);
  if (u.endsWith('/api/system/stats')) return J(STATS);
  if (u.endsWith('/api/system/nodes/metrics')) return J(METRICS);
  throw new Error('unexpected fetch: ' + u);
};

// shared scan result
let out;
test('scan() runs against the stubbed panel', async () => {
  out = await scan('panel.test', 'tok');
  assert.ok(out && Array.isArray(out.issues), 'scan returns issues array');
});

const types = () => out.issues.map(i => i.type);
const has = (t) => types().includes(t);
const ofType = (t) => out.issues.filter(i => i.type === t);

test('detects DNS_DEAD only for the unresolvable domain', () => {
  const dead = ofType('DNS_DEAD');
  assert.deepStrictEqual(dead.map(i => i.domain), ['dead.example.com']);
});

test('detects PARTIAL_BALANCER on the mixed-health balancer host', () => {
  const pb = ofType('PARTIAL_BALANCER');
  assert.strictEqual(pb.length, 1);
  assert.strictEqual(pb[0].hostRemark, 'balancer');
  assert.match(pb[0].message, /dead\.example\.com/);
});

test('detects DUP_NODE_IP for the shared IPv4', () => {
  const dn = ofType('DUP_NODE_IP');
  assert.strictEqual(dn.length, 1);
  assert.match(dn[0].message, /1\.2\.3\.4/);
});

test('detects DUP_DOMAIN across two different inbounds', () => {
  const dd = ofType('DUP_DOMAIN');
  assert.strictEqual(dd.length, 1);
  assert.strictEqual(dd[0].domain, 'de.example.com');
});

test('detects node traffic limit issues', () => {
  assert.ok(ofType('TRAFFIC_NEAR_LIMIT').some(i => i.nodeName === 'DE-1'), 'DE-1 near limit (90%)');
  assert.ok(ofType('TRAFFIC_EXCEEDED').some(i => i.nodeName === 'NL-1'), 'NL-1 exceeded');
});

test('does NOT raise false positives', () => {
  for (const t of ['FOREIGN_IP', 'HOST_NO_NODES', 'STALE_IP_HOST', 'NODE_NOT_IN_DNS', 'NODE_DOWN']) {
    assert.ok(!has(t), `unexpected ${t}: ${JSON.stringify(ofType(t))}`);
  }
});

test('IPv6/AAAA domain resolves and matches the IPv6 node (no false DNS_DEAD/FOREIGN_IP)', () => {
  // v6.example.com must not appear in any DNS issue
  const v6issues = out.issues.filter(i => i.domain === 'v6.example.com' || (i.message || '').includes('v6.example.com'));
  assert.strictEqual(v6issues.length, 0, JSON.stringify(v6issues));
  const n4 = out.nodes.find(n => n.uuid === 'n4');
  assert.strictEqual(n4.reachableByDomain, true, 'IPv6 node is reachable by the AAAA domain');
});

test('live throughput is parsed and summed per node', () => {
  const n1 = out.nodes.find(n => n.uuid === 'n1');
  const n2 = out.nodes.find(n => n.uuid === 'n2');
  assert.strictEqual(n1.up, 1000); assert.strictEqual(n1.down, 2000);
  assert.strictEqual(n2.up, 510);  assert.strictEqual(n2.down, 520);   // VLESS 500/500 + TROJAN 10/20
});

test('traffic is attributed to hosts via the host -> inbound -> node chain', () => {
  const h1 = out.hosts.find(h => h.uuid === 'h1');   // inbound VLESS, served by n1..n4
  assert.strictEqual(h1.up, 1500);   // n1 1000 + n2 500
  assert.strictEqual(h1.down, 2500); // n1 2000 + n2 500
});

test('stats expose traffic totals', () => {
  assert.strictEqual(out.stats.totalUp, 1510);   // n1 1000 + n2 510
  assert.strictEqual(out.stats.totalDown, 2520);  // n1 2000 + n2 520
  assert.strictEqual(out.stats.totalUsedBytes, 2100); // 900 + 1200
});

test('resolveHost handles IPv6 literals and bracketed host:port', async () => {
  assert.deepStrictEqual(await resolveHost('1.2.3.4'), { ips: ['1.2.3.4'], source: 'literal' });
  assert.deepStrictEqual(await resolveHost('2001:db8::1'), { ips: ['2001:db8::1'], source: 'literal' });
  assert.deepStrictEqual(await resolveHost('[2001:db8::1]:443'), { ips: ['2001:db8::1'], source: 'literal' });
});

test('resolveHost merges A and AAAA from the system resolver', async () => {
  const v6 = await resolveHost('v6.example.com');
  assert.strictEqual(v6.source, 'system');
  assert.deepStrictEqual(v6.ips, ['2001:db8::1']);
  const dead = await resolveHost('dead.example.com');
  assert.strictEqual(dead.ips.length, 0);
});
