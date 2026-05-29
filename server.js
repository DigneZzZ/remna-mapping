'use strict';
/*
 * VPN Topology Mapper — backend
 * Zero-dependency Node (>=18) service.
 *   - Serves the dark animated frontend (public/index.html)
 *   - POST /api/scan { panelUrl, token }  ->  topology graph + detected issues
 *
 * The panel token is used ONLY to call the panel you point it at. It is never
 * stored on disk and never sent anywhere else. DNS resolution uses the host's
 * system resolver; if that fails for a name, it falls back to DNS-over-HTTPS
 * (dns.google) — only the hostname is sent, never the token.
 */

const http = require('http');
const dnsp = require('dns').promises;
const net = require('net');
const fs = require('fs');
const path = require('path');

const PORT = parseInt(process.env.PORT || '8088', 10);
const DOH = process.env.DOH !== '0';            // DoH fallback on by default
const DNS_TIMEOUT_MS = parseInt(process.env.DNS_TIMEOUT_MS || '4000', 10);

// Accept both IPv4 and IPv6 literals (net.isIP returns 4, 6, or 0).
const isIp = (s) => typeof s === 'string' && net.isIP(s.trim()) !== 0;
// Strip a trailing :port without mangling a bare IPv6 literal (whose own
// colons must survive):
//   [2001:db8::1]:443 -> 2001:db8::1     1.2.3.4:443 -> 1.2.3.4
//   2001:db8::1        -> 2001:db8::1     host.tld:443 -> host.tld
function stripPort(s) {
  s = String(s).trim();
  const m = s.match(/^\[(.+)\](?::\d+)?$/);     // bracketed IPv6, optional port
  if (m) return m[1];
  if (net.isIP(s) === 6) return s;              // bare IPv6 — leave colons alone
  return s.replace(/:\d+$/, '');                // IPv4 or hostname with :port
}

// ---------- helpers ----------
function normalizePanelUrl(u) {
  if (!u) throw new Error('panelUrl is required');
  u = String(u).trim().replace(/\/+$/, '');
  if (!/^https?:\/\//i.test(u)) u = 'https://' + u;
  return u;
}

function withTimeout(promise, ms, onTimeoutValue) {
  let t;
  const timeout = new Promise((res) => { t = setTimeout(() => res(onTimeoutValue), ms); });
  return Promise.race([promise.finally(() => clearTimeout(t)), timeout]);
}

async function panelGet(base, token, p) {
  const url = base + p;
  const ctrl = new AbortController();
  const to = setTimeout(() => ctrl.abort(), 20000);
  try {
    const r = await fetch(url, {
      headers: { Authorization: 'Bearer ' + token, 'Content-Type': 'application/json' },
      signal: ctrl.signal,
    });
    const text = await r.text();
    let body; try { body = JSON.parse(text); } catch { body = text; }
    return { ok: r.ok, status: r.status, body };
  } finally { clearTimeout(to); }
}

// Resolve a hostname -> { ips:[], source, error }
async function resolveHost(name) {
  name = stripPort(name).trim();
  if (isIp(name)) return { ips: [name], source: 'literal' };
  // 1) system resolver — A and AAAA in parallel (either failing is non-fatal)
  try {
    const [v4, v6] = await Promise.all([
      withTimeout(dnsp.resolve4(name).catch(() => null), DNS_TIMEOUT_MS, null),
      withTimeout(dnsp.resolve6(name).catch(() => null), DNS_TIMEOUT_MS, null),
    ]);
    const ips = [...(v4 || []), ...(v6 || [])];
    if (ips.length) return { ips, source: 'system' };
  } catch (e) { /* fall through */ }
  // 2) DoH fallback — A and AAAA (only the hostname is sent, never the token)
  if (DOH) {
    try {
      const q = (type) => withTimeout(
        fetch(`https://dns.google/resolve?name=${encodeURIComponent(name)}&type=${type}`,
          { headers: { accept: 'application/dns-json' } }).then(x => x.json()).catch(() => null),
        DNS_TIMEOUT_MS, null);
      const [ra, raaaa] = await Promise.all([q('A'), q('AAAA')]);
      const pick = (r, t) => (r && (r.Answer || []).filter(a => a.type === t).map(a => a.data)) || [];
      const ips = [...pick(ra, 1), ...pick(raaaa, 28)];   // A = type 1, AAAA = type 28
      if (ips.length) return { ips, source: 'doh' };
      if (ra || raaaa) {
        const status = (ra && ra.Status != null) ? ra.Status : (raaaa && raaaa.Status);
        return { ips: [], source: 'doh', error: 'NXDOMAIN/NoData (status ' + status + ')' };
      }
    } catch (e) { return { ips: [], source: 'doh', error: e.message }; }
  }
  return { ips: [], source: 'none', error: 'no A/AAAA records' };
}

function splitAddress(addr) {
  if (!addr) return [];
  return String(addr).split(',').map(s => s.trim()).filter(Boolean);
}

// ---------- core scan ----------
async function scan(panelUrl, token) {
  const base = normalizePanelUrl(panelUrl);
  const [hostsR, nodesR, profR, statsR, metricsR] = await Promise.all([
    panelGet(base, token, '/api/hosts'),
    panelGet(base, token, '/api/nodes'),
    panelGet(base, token, '/api/config-profiles').catch(() => ({ ok: false })),
    panelGet(base, token, '/api/system/stats').catch(() => ({ ok: false })),
    panelGet(base, token, '/api/system/nodes/metrics').catch(() => ({ ok: false })),
  ]);

  if (!hostsR.ok) throw new Error('GET /api/hosts failed: HTTP ' + hostsR.status + ' ' + JSON.stringify(hostsR.body).slice(0, 200));
  if (!nodesR.ok) throw new Error('GET /api/nodes failed: HTTP ' + nodesR.status + ' ' + JSON.stringify(nodesR.body).slice(0, 200));

  const rawHosts = (hostsR.body && hostsR.body.response) || [];
  const rawNodes = (nodesR.body && nodesR.body.response) || [];

  // inbound metadata (uuid -> {tag,port,type})
  const inboundMeta = {};
  const profs = profR && profR.ok && profR.body && profR.body.response && profR.body.response.configProfiles || [];
  for (const pr of profs) for (const ib of (pr.inbounds || [])) {
    inboundMeta[ib.uuid] = { uuid: ib.uuid, tag: ib.tag, port: ib.port, type: ib.type, profileUuid: pr.uuid, profileName: pr.name };
  }

  // ---- live throughput per node (× inbound tag) from Prometheus-backed metrics ----
  const metricsByUuid = new Map();   // nodeUuid -> { up, down, byTag: {tag:{up,down}} }
  {
    const num = (v) => { const n = Number(v); return Number.isFinite(n) ? n : 0; };
    const mnodes = (metricsR && metricsR.ok && metricsR.body && metricsR.body.response && metricsR.body.response.nodes) || [];
    for (const mn of mnodes) {
      const byTag = {}; let up = 0, down = 0;
      for (const s of (mn.inboundsStats || [])) {
        const u = num(s.upload), d = num(s.download);
        up += u; down += d;
        const t = byTag[s.tag] || (byTag[s.tag] = { up: 0, down: 0 });
        t.up += u; t.down += d;
      }
      if (mn.nodeUuid) metricsByUuid.set(mn.nodeUuid, { up, down, byTag });
    }
  }

  // ---- nodes ----
  const nodeIpIndex = new Map();   // ip -> nodeUuid (first wins)
  const ipToNodes = new Map();     // ip -> [nodeUuid,...] (to detect shared IPs)
  const nodes = rawNodes.map(n => {
    const ips = new Set();
    if (isIp(n.address)) ips.add(n.address);
    if (isIp(n.name)) ips.add(n.name);
    const serves = (n.configProfile && n.configProfile.activeInbounds || []).map(i => i.uuid);
    for (const i of (n.configProfile && n.configProfile.activeInbounds || [])) if (!inboundMeta[i.uuid]) inboundMeta[i.uuid] = { uuid: i.uuid, tag: i.tag, port: i.port, type: i.type };
    const m = metricsByUuid.get(n.uuid) || { up: 0, down: 0, byTag: {} };
    return {
      uuid: n.uuid, name: n.name, mgmtAddress: n.address, port: n.port,
      ips: [...ips], country: n.countryCode || null,
      connected: !!n.isConnected, disabled: !!n.isDisabled,
      usersOnline: n.usersOnline || 0,
      usedBytes: n.trafficUsedBytes != null ? Number(n.trafficUsedBytes) : null,
      limitBytes: n.trafficLimitBytes != null ? Number(n.trafficLimitBytes) : null,
      trackingActive: !!n.isTrafficTrackingActive,
      resetDay: n.trafficResetDay != null ? n.trafficResetDay : null,
      notifyPercent: n.notifyPercent != null ? n.notifyPercent : null,
      up: m.up, down: m.down, inboundTraffic: m.byTag,
      serves, domains: [],
    };
  });
  for (const nd of nodes) for (const ip of nd.ips) {
    if (!nodeIpIndex.has(ip)) nodeIpIndex.set(ip, nd.uuid);
    (ipToNodes.get(ip) || ipToNodes.set(ip, []).get(ip)).push(nd.uuid);
  }

  // ---- collect every unique hostname to resolve ----
  const toResolve = new Set();
  for (const h of rawHosts) for (const tok of splitAddress(h.address)) { const c = stripPort(tok); if (!isIp(c)) toResolve.add(c); }
  const resolveMap = {};
  await Promise.all([...toResolve].map(async d => { resolveMap[d] = await resolveHost(d); }));

  // ---- hosts ----
  const issues = [];
  const allResolvedIps = new Set();      // every IP any host-domain points to
  const hosts = rawHosts.map(h => {
    const inb = h.inbound && h.inbound.configProfileInboundUuid || null;
    const meta = inb ? inboundMeta[inb] : null;
    const addresses = splitAddress(h.address).map(tok => {
      const clean = stripPort(tok);
      if (isIp(clean)) {
        const nodeUuid = nodeIpIndex.get(clean) || null;
        allResolvedIps.add(clean);
        if (!nodeUuid) issues.push({ severity: 'warn', type: 'STALE_IP_HOST', host: h.uuid, hostRemark: h.remark, message: `Host "${h.remark}" points at IP ${clean} which is not any node in the panel.` });
        return { raw: tok, kind: 'ip', ips: [{ ip: clean, nodeUuid }] };
      }
      const res = resolveMap[clean] || { ips: [], source: 'none', error: 'unresolved' };
      const ips = res.ips.map(ip => { allResolvedIps.add(ip); return { ip, nodeUuid: nodeIpIndex.get(ip) || null }; });
      // domain-level DNS issues are emitted once per domain below (deduplicated)
      return { raw: tok, kind: 'domain', domain: clean, source: res.source, error: res.error || null, ips };
    });
    // attach domain names to matched nodes
    for (const a of addresses) for (const x of a.ips) if (x.nodeUuid) {
      const nd = nodes.find(n => n.uuid === x.nodeUuid);
      const label = a.domain || a.raw;
      if (nd && !nd.domains.includes(label)) nd.domains.push(label);
    }
    const servingNodeUuids = inb ? nodes.filter(n => n.serves.includes(inb)).map(n => n.uuid) : [];
    if (inb && servingNodeUuids.length === 0 && !h.isDisabled)
      issues.push({ severity: 'error', type: 'HOST_NO_NODES', host: h.uuid, hostRemark: h.remark, message: `Host "${h.remark}" uses inbound ${meta ? meta.tag : inb} but no node serves that inbound.` });
    // attributed live throughput: this host's inbound tag, summed over the nodes that serve it
    const tag = meta ? meta.tag : null;
    let hUp = 0, hDown = 0;
    if (tag) for (const u of servingNodeUuids) { const nd = nodes.find(n => n.uuid === u); const t = nd && nd.inboundTraffic[tag]; if (t) { hUp += t.up; hDown += t.down; } }
    return {
      uuid: h.uuid, remark: h.remark, disabled: !!h.isDisabled, port: h.port,
      inboundUuid: inb, inboundTag: meta ? meta.tag : (inb ? inb.slice(0, 8) : null),
      addresses, servingNodeUuids, up: hUp, down: hDown,
    };
  });

  // ---- domain-level DNS issues (deduplicated, one per domain, with affected hosts) ----
  const domainHosts = {};
  for (const h of hosts) for (const a of h.addresses) if (a.kind === 'domain') (domainHosts[a.domain] = domainHosts[a.domain] || []).push(h.remark);
  for (const dom of Object.keys(resolveMap)) {
    const res = resolveMap[dom];
    const usedBy = [...new Set(domainHosts[dom] || [])];
    if (!res.ips.length) {
      issues.push({ severity: 'error', type: 'DNS_DEAD', domain: dom, hosts: usedBy, message: `Domain ${dom} does not resolve to any IP (${res.error || 'no records'}). Used by: ${usedBy.join(', ') || '—'}.` });
    } else {
      const foreign = res.ips.filter(ip => !nodeIpIndex.has(ip));
      if (foreign.length) issues.push({ severity: 'warn', type: 'FOREIGN_IP', domain: dom, ips: foreign, hosts: usedBy, message: `Domain ${dom} resolves to ${foreign.length} IP(s) not registered as nodes: ${foreign.join(', ')}. Used by: ${usedBy.join(', ') || '—'}.` });
    }
  }

  // ---- per-node reachability + soft signals ----
  // reachableByDomain: some host-domain resolves to one of the node's IPs.
  const inboundsWithDomainHost = new Set();
  for (const h of hosts) if (h.inboundUuid && h.addresses.some(a => a.kind === 'domain')) inboundsWithDomainHost.add(h.inboundUuid);
  for (const nd of nodes) {
    nd.reachableByDomain = nd.ips.some(ip => allResolvedIps.has(ip));
    if (!nd.connected && !nd.disabled)
      issues.push({ severity: 'info', type: 'NODE_DOWN', node: nd.uuid, nodeName: nd.name, message: `Node "${nd.name}" is currently disconnected.` });
    // INFO only: serves a domain-backed inbound yet no domain points at it.
    // Often legitimate (internal bridge / relay backends), so not a warning.
    if (!nd.disabled && nd.ips.length && !nd.reachableByDomain && nd.serves.some(i => inboundsWithDomainHost.has(i)))
      issues.push({ severity: 'info', type: 'NODE_NOT_IN_DNS', node: nd.uuid, nodeName: nd.name, message: `Node "${nd.name}" (${nd.ips.join('/')}) isn't referenced by any host domain. Expected for bridge/relay backends — verify if it should be in a balancer domain.` });
  }

  // ---- duplicate node IPs (same public IP on >1 node) ----
  for (const [ip, us] of ipToNodes) {
    const uniq = [...new Set(us)];
    if (uniq.length > 1) {
      const names = uniq.map(u => (nodes.find(n => n.uuid === u) || {}).name).filter(Boolean);
      issues.push({ severity: 'warn', type: 'DUP_NODE_IP', node: uniq[0], nodeName: names[0] || null, message: `IP ${ip} is shared by ${uniq.length} nodes: ${names.join(', ')}.` });
    }
  }

  // ---- same domain across >1 different inbound (same-inbound reuse is legit redundancy) ----
  const domainInbounds = {};   // domain -> Set(inboundUuid)
  const domainRemarks = {};    // domain -> [host remarks]
  for (const h of hosts) for (const a of h.addresses) if (a.kind === 'domain') {
    (domainInbounds[a.domain] = domainInbounds[a.domain] || new Set());
    if (h.inboundUuid) domainInbounds[a.domain].add(h.inboundUuid);
    (domainRemarks[a.domain] = domainRemarks[a.domain] || []).push(h.remark);
  }
  for (const dom of Object.keys(domainInbounds)) {
    if (domainInbounds[dom].size > 1) {
      const tags = [...domainInbounds[dom]].map(u => (inboundMeta[u] && inboundMeta[u].tag) || String(u).slice(0, 8));
      issues.push({ severity: 'info', type: 'DUP_DOMAIN', domain: dom, hosts: [...new Set(domainRemarks[dom])], message: `Domain ${dom} is used across ${domainInbounds[dom].size} different inbounds (${tags.join(', ')}). Verify this is intentional.` });
    }
  }

  // ---- partial balancer: a multi-address host where some members are healthy and some aren't ----
  for (const h of hosts) {
    if (h.addresses.length < 2) continue;
    let healthy = 0; const bad = [];
    for (const a of h.addresses) {
      if (a.ips.some(x => x.nodeUuid)) healthy++;
      else bad.push(a.domain || a.raw);
    }
    if (healthy > 0 && bad.length > 0)
      issues.push({ severity: 'warn', type: 'PARTIAL_BALANCER', host: h.uuid, hostRemark: h.remark, hosts: [h.remark], message: `Balancer host "${h.remark}" has ${bad.length} of ${h.addresses.length} members not pointing at a live node: ${bad.join(', ')}.` });
  }

  // ---- node traffic limit checks ----
  for (const nd of nodes) {
    if (!nd.trackingActive || !nd.limitBytes || nd.usedBytes == null) continue;
    if (nd.usedBytes >= nd.limitBytes) {
      issues.push({ severity: 'error', type: 'TRAFFIC_EXCEEDED', node: nd.uuid, nodeName: nd.name, message: `Node "${nd.name}" exceeded its traffic limit (${nd.usedBytes} / ${nd.limitBytes} bytes).` });
    } else {
      const pct = nd.notifyPercent || 80;
      if (nd.usedBytes >= nd.limitBytes * pct / 100)
        issues.push({ severity: 'warn', type: 'TRAFFIC_NEAR_LIMIT', node: nd.uuid, nodeName: nd.name, message: `Node "${nd.name}" is at ${Math.round(nd.usedBytes / nd.limitBytes * 100)}% of its traffic limit (notify ≥${pct}%).` });
    }
  }

  // ---- inbound summary ----
  const inbounds = Object.values(inboundMeta).map(m => {
    const serving = nodes.filter(n => n.serves.includes(m.uuid));
    let up = 0, down = 0;
    for (const n of serving) { const t = n.inboundTraffic[m.tag]; if (t) { up += t.up; down += t.down; } }
    return {
      ...m,
      hostCount: hosts.filter(h => h.inboundUuid === m.uuid).length,
      nodeCount: serving.length,
      up, down,
    };
  }).filter(m => m.hostCount > 0 || m.nodeCount > 0);

  const stats = {
    nodesTotal: nodes.length,
    nodesUp: nodes.filter(n => n.connected).length,
    nodesDown: nodes.filter(n => !n.connected && !n.disabled).length,
    nodesDisabled: nodes.filter(n => n.disabled).length,
    usersOnline: nodes.reduce((s, n) => s + (n.usersOnline || 0), 0),
    totalUp: nodes.reduce((s, n) => s + (n.up || 0), 0),
    totalDown: nodes.reduce((s, n) => s + (n.down || 0), 0),
    totalUsedBytes: nodes.reduce((s, n) => s + (n.usedBytes || 0), 0),
    hostsTotal: hosts.length,
    domainsTotal: toResolve.size,
    inboundsTotal: inbounds.length,
    issues: {
      error: issues.filter(i => i.severity === 'error').length,
      warn: issues.filter(i => i.severity === 'warn').length,
      info: issues.filter(i => i.severity === 'info').length,
    },
  };
  // include system stats users if available (cross-check)
  let panelUsersOnline = null;
  try { panelUsersOnline = statsR && statsR.ok && statsR.body.response && (statsR.body.response.onlineStats ? statsR.body.response.onlineStats.onlineNow : undefined); } catch {}

  return { panel: base, scannedAt: new Date().toISOString(), stats, panelUsersOnline, inbounds, nodes, hosts, issues };
}

// ---------- static + http ----------
const PUBLIC = path.join(__dirname, 'public');
const MIME = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8', '.svg': 'image/svg+xml', '.ico': 'image/x-icon' };

function serveStatic(req, res) {
  let p = decodeURIComponent((req.url.split('?')[0]) || '/');
  if (p === '/') p = '/index.html';
  const full = path.join(PUBLIC, path.normalize(p).replace(/^(\.\.[/\\])+/, ''));
  if (!full.startsWith(PUBLIC)) { res.writeHead(403); return res.end('forbidden'); }
  fs.readFile(full, (err, data) => {
    if (err) { res.writeHead(404, { 'content-type': 'text/plain' }); return res.end('not found'); }
    res.writeHead(200, { 'content-type': MIME[path.extname(full)] || 'application/octet-stream' });
    res.end(data);
  });
}

const server = http.createServer((req, res) => {
  if (req.method === 'POST' && req.url === '/api/scan') {
    let body = '';
    req.on('data', c => { body += c; if (body.length > 1e6) req.destroy(); });
    req.on('end', async () => {
      res.setHeader('content-type', 'application/json; charset=utf-8');
      try {
        const { panelUrl, token } = JSON.parse(body || '{}');
        if (!panelUrl || !token) { res.writeHead(400); return res.end(JSON.stringify({ error: 'panelUrl and token are required' })); }
        const out = await scan(panelUrl, token);
        res.writeHead(200); res.end(JSON.stringify(out));
      } catch (e) {
        res.writeHead(500); res.end(JSON.stringify({ error: e.message }));
      }
    });
    return;
  }
  if (req.method === 'GET') return serveStatic(req, res);
  res.writeHead(405); res.end('method not allowed');
});

if (require.main === module) {
  server.listen(PORT, () => console.log(`VPN Topology Mapper running on http://0.0.0.0:${PORT}  (DoH fallback: ${DOH ? 'on' : 'off'})`));
}
module.exports = { scan, resolveHost };
