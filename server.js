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
// Bind to loopback by default so the proxy never exposes itself on the network.
// Set HOST=0.0.0.0 to listen on all interfaces (the Docker image does this; the
// container's own port mapping decides who can reach it).
const HOST = process.env.HOST || '127.0.0.1';
const DOH = process.env.DOH !== '0';            // DoH fallback on by default
const DNS_TIMEOUT_MS = parseInt(process.env.DNS_TIMEOUT_MS || '4000', 10);
// Scale knobs (matter when many users scan at once):
const DNS_CONCURRENCY = parseInt(process.env.DNS_CONCURRENCY || '20', 10);        // max in-flight DNS lookups per scan
const RESOLVE_TTL_MS = parseInt(process.env.RESOLVE_TTL_MS || '30000', 10);       // DNS result cache TTL (0 disables)
const RESOLVE_CACHE_MAX = parseInt(process.env.RESOLVE_CACHE_MAX || '20000', 10); // cache entry cap before prune/clear
const MAX_CONCURRENT_SCANS = parseInt(process.env.MAX_CONCURRENT_SCANS || '20', 10);
const MAX_SCAN_QUEUE = parseInt(process.env.MAX_SCAN_QUEUE || '200', 10);         // queued scans beyond which we return 503
const SCAN_TIMEOUT_MS = parseInt(process.env.SCAN_TIMEOUT_MS || '30000', 10);     // overall per-scan cap -> 504

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

// Parse a byte count that may arrive as a number, a numeric string, or a
// human-readable string ("1.23 GB", "12 KiB", "0"). Remnawave's
// /api/system/nodes/metrics returns inbound up/down PRE-FORMATTED (the panel
// formats them; "0" means zero), so a plain Number() yields NaN -> 0 and the
// UI shows empty traffic. Returns bytes (0 on anything unparseable).
function parseBytes(v) {
  if (v == null) return 0;
  if (typeof v === 'number') return Number.isFinite(v) ? v : 0;
  const s = String(v).trim();
  if (!s || s === '0') return 0;
  const m = s.replace(',', '.').match(/^([\d.]+)\s*([KMGTPE]?)(i?)B?$/i);
  if (!m) { const n = Number(s); return Number.isFinite(n) ? n : 0; }
  const val = parseFloat(m[1]);
  if (!Number.isFinite(val)) return 0;
  const base = m[3] ? 1024 : 1000;   // 'i' (KiB/MiB) -> binary, otherwise decimal
  const pow = { '': 0, K: 1, M: 2, G: 3, T: 4, P: 5, E: 6 }[m[2].toUpperCase()] || 0;
  return Math.round(val * Math.pow(base, pow));
}

// ---------- helpers ----------
function normalizePanelUrl(u) {
  if (!u) throw new Error('panelUrl is required');
  u = String(u).trim().replace(/\/+$/, '');
  if (!/^https?:\/\//i.test(u)) u = 'https://' + u;
  return u;
}

// Some Remnawave deployments sit behind a reverse proxy that ALSO gates the panel API with a
// session/auth cookie (in addition to — or instead of — the API token). This normalizes the
// user-supplied cookie into a single `Cookie:` header value. Accepts either a raw header string
// ("name=value; name2=val2") or a JSON object ({"name":"value"}). Returns null when empty.
function parseCookieHeader(s) {
  if (s == null) return null;
  s = String(s).trim();
  if (!s) return null;
  if (s.startsWith('{')) {
    try { return Object.entries(JSON.parse(s)).map(([k, v]) => `${k}=${v}`).join('; '); } catch { /* fall through to raw */ }
  }
  return s;
}

function withTimeout(promise, ms, onTimeoutValue) {
  let t;
  const timeout = new Promise((res) => { t = setTimeout(() => res(onTimeoutValue), ms); });
  return Promise.race([promise.finally(() => clearTimeout(t)), timeout]);
}

// ---------- concurrency + DNS cache (matter under many simultaneous users) ----------
const resolveCache = new Map();   // hostname -> { res, exp }
function pruneResolveCache() {
  const now = Date.now();
  for (const [k, v] of resolveCache) if (v.exp <= now) resolveCache.delete(k);
  if (resolveCache.size >= RESOLVE_CACHE_MAX) resolveCache.clear();
}
// Run `fn` over items with at most `limit` in flight (bounded fan-out).
async function mapPool(items, limit, fn) {
  const arr = [...items]; let i = 0;
  const worker = async () => { while (i < arr.length) { const idx = i++; await fn(arr[idx], idx); } };
  await Promise.all(Array.from({ length: Math.max(1, Math.min(limit, arr.length || 1)) }, worker));
}
// Cap concurrent scans; queue the overflow, refuse when the queue is full.
let activeScans = 0; const scanWaiters = [];
function acquireScanSlot() {
  if (activeScans < MAX_CONCURRENT_SCANS) { activeScans++; return Promise.resolve(true); }
  if (scanWaiters.length >= MAX_SCAN_QUEUE) return Promise.resolve(false);
  return new Promise((resolve) => scanWaiters.push(resolve));
}
function releaseScanSlot() {
  const next = scanWaiters.shift();
  if (next) next(true); else activeScans--;       // hand the slot to the next waiter, or free it
}
function scanWithTimeout(panelUrl, token, ms, opts) {
  return new Promise((resolve, reject) => {
    const t = setTimeout(() => reject(new Error('scan timed out after ' + ms + 'ms')), ms);
    scan(panelUrl, token, opts).then((v) => { clearTimeout(t); resolve(v); }, (e) => { clearTimeout(t); reject(e); });
  });
}

async function panelGet(base, token, p, extra) {
  const url = base + p;
  const ctrl = new AbortController();
  const to = setTimeout(() => ctrl.abort(), 20000);
  try {
    const headers = { 'Content-Type': 'application/json' };
    if (token) headers.Authorization = 'Bearer ' + token;   // omit only for cookie-only panels
    if (extra) Object.assign(headers, extra);                // e.g. { Cookie: '...' } for proxy-gated panels
    const r = await fetch(url, { headers, signal: ctrl.signal });
    const text = await r.text();
    let body; try { body = JSON.parse(text); } catch { body = text; }
    return { ok: r.ok, status: r.status, body };
  } finally { clearTimeout(to); }
}

// Resolve a hostname -> { ips:[], source, error }
async function resolveHost(name) {
  name = stripPort(name).trim();
  if (isIp(name)) return { ips: [name], source: 'literal' };
  if (RESOLVE_TTL_MS > 0) {
    const c = resolveCache.get(name);
    if (c && c.exp > Date.now()) return c.res;
  }
  const res = await resolveUncached(name);
  if (RESOLVE_TTL_MS > 0) {
    if (resolveCache.size >= RESOLVE_CACHE_MAX) pruneResolveCache();
    resolveCache.set(name, { res, exp: Date.now() + RESOLVE_TTL_MS });
  }
  return res;
}

// system resolver (A+AAAA) then DoH fallback. `name` is already cleaned and known non-literal.
async function resolveUncached(name) {
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
async function scan(panelUrl, token, opts) {
  const base = normalizePanelUrl(panelUrl);
  // Optional Cookie header for panels behind a proxy that also gates the API by session cookie.
  // Sent ONLY to the user's own panel — never stored or logged. (see parseCookieHeader)
  const extra = {};
  if (opts && opts.cookieHeader) { const c = parseCookieHeader(opts.cookieHeader); if (c) extra.Cookie = c; }
  const hdr = Object.keys(extra).length ? extra : undefined;
  const pg = (p) => panelGet(base, token, p, hdr);
  const [hostsR, nodesR, profR, statsR, metricsR] = await Promise.all([
    pg('/api/hosts'),
    pg('/api/nodes'),
    pg('/api/config-profiles').catch(() => ({ ok: false })),
    pg('/api/system/stats').catch(() => ({ ok: false })),
    pg('/api/system/nodes/metrics').catch(() => ({ ok: false })),
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
    const mnodes = (metricsR && metricsR.ok && metricsR.body && metricsR.body.response && metricsR.body.response.nodes) || [];
    for (const mn of mnodes) {
      const byTag = {}; let up = 0, down = 0;
      for (const s of (mn.inboundsStats || [])) {
        const u = parseBytes(s.upload), d = parseBytes(s.download);
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
  const nodeByUuid = new Map(nodes.map(n => [n.uuid, n]));   // O(1) lookups (mirrors nodeIpIndex)

  // ---- collect every unique hostname to resolve ----
  const toResolve = new Set();
  for (const h of rawHosts) for (const tok of splitAddress(h.address)) { const c = stripPort(tok); if (!isIp(c)) toResolve.add(c); }
  const resolveMap = {};
  await mapPool(toResolve, DNS_CONCURRENCY, async (d) => { resolveMap[d] = await resolveHost(d); });

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
      const nd = nodeByUuid.get(x.nodeUuid);
      const label = a.domain || a.raw;
      if (nd && !nd.domains.includes(label)) nd.domains.push(label);
    }
    const servingNodeUuids = inb ? nodes.filter(n => n.serves.includes(inb)).map(n => n.uuid) : [];
    if (inb && servingNodeUuids.length === 0 && !h.isDisabled)
      issues.push({ severity: 'error', type: 'HOST_NO_NODES', host: h.uuid, hostRemark: h.remark, message: `Host "${h.remark}" uses inbound ${meta ? meta.tag : inb} but no node serves that inbound.` });
    // attributed live throughput: this host's inbound tag, summed over the nodes that serve it
    const tag = meta ? meta.tag : null;
    let hUp = 0, hDown = 0;
    if (tag) for (const u of servingNodeUuids) { const nd = nodeByUuid.get(u); const t = nd && nd.inboundTraffic[tag]; if (t) { hUp += t.up; hDown += t.down; } }
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
      const names = uniq.map(u => (nodeByUuid.get(u) || {}).name).filter(Boolean);
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
      let creds;
      try { creds = JSON.parse(body || '{}'); } catch { res.writeHead(400); return res.end(JSON.stringify({ error: 'invalid JSON body' })); }
      const { panelUrl, token, cookieHeader } = creds || {};
      if (!panelUrl || (!token && !cookieHeader)) { res.writeHead(400); return res.end(JSON.stringify({ error: 'panelUrl and a token (or Cookie header) are required' })); }
      const slot = await acquireScanSlot();
      if (!slot) { res.writeHead(503, { 'retry-after': '5' }); return res.end(JSON.stringify({ error: 'server busy — too many concurrent scans, retry shortly' })); }
      try {
        const out = await scanWithTimeout(panelUrl, token, SCAN_TIMEOUT_MS, cookieHeader ? { cookieHeader } : undefined);
        res.writeHead(200); res.end(JSON.stringify(out));
      } catch (e) {
        res.writeHead(/timed out/.test(e.message) ? 504 : 500); res.end(JSON.stringify({ error: e.message }));
      } finally {
        releaseScanSlot();
      }
    });
    return;
  }
  if (req.method === 'GET') return serveStatic(req, res);
  res.writeHead(405); res.end('method not allowed');
});

if (require.main === module) {
  const shown = HOST === '0.0.0.0' || HOST === '::' ? 'localhost' : HOST;   // 0.0.0.0 isn't a usable URL host
  server.listen(PORT, HOST, () => console.log(`VPN Topology Mapper running on http://${shown}:${PORT}  (bind: ${HOST}, DoH fallback: ${DOH ? 'on' : 'off'})`));
}
module.exports = { scan, resolveHost, parseBytes, parseCookieHeader };
