'use client';

import { useState, useEffect, useMemo, useCallback, useRef } from 'react';

// ─── Types ────────────────────────────────────────────────────────────────────

interface NewsItem {
  id: string; title: string; link: string; description: string;
  content: string; pubDate: string; source: string; tags: string[];
  cves: string[]; author: string;
}

type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
type SortBy   = 'newest' | 'severity';
type ViewMode = 'feed' | 'saved' | 'kev' | 'cve-tracker' | 'trends';

interface SeverityResult  { level: Severity; isKev: boolean; }
interface IOCResult        { ips: string[]; hashes: string[]; domains: string[]; }
interface AttackTechnique  { id: string; name: string; }

interface EnrichedItem {
  item: NewsItem; severity: SeverityResult; iocs: IOCResult;
  techniques: AttackTechnique[]; isNew: boolean;
}

interface FeedData {
  items: NewsItem[]; sources: string[]; total: number;
  fromCache: boolean; lastRefresh: string | null;
}

interface CvssInfo { score: number | null; severity: string | null; }

interface NvdEntry {
  id: string; description: string; score: number | null; severity: string | null;
  vector: string | null; published: string; vulnStatus: string; isKev: boolean;
  product: string; productDisplay: string;
}

interface CveStatus { status: string; notes: string; }

interface CveTrackerData {
  entries: NvdEntry[];
  statuses: Record<string, CveStatus>;
  lastFetched: number;
}

// ─── Source & Tag Styles ──────────────────────────────────────────────────────

const SOURCE_STYLES: Record<string, { bg: string; color: string; accent: string }> = {
  'Krebs on Security':     { bg: '#2d1206', color: '#fb923c', accent: '#ea580c' },
  'The Hacker News':       { bg: '#2d0a0a', color: '#f87171', accent: '#dc2626' },
  'BleepingComputer':      { bg: '#07173a', color: '#93c5fd', accent: '#3b82f6' },
  'Dark Reading':          { bg: '#1e0740', color: '#c084fc', accent: '#9333ea' },
  'SecurityWeek':          { bg: '#071e1c', color: '#5eead4', accent: '#0d9488' },
  'Schneier on Security':  { bg: '#2a1800', color: '#fde68a', accent: '#d97706' },
  'SANS ISC':              { bg: '#0a2218', color: '#86efac', accent: '#16a34a' },
  'CISA':                  { bg: '#071432', color: '#bfdbfe', accent: '#2563eb' },
  'Graham Cluley':         { bg: '#200a02', color: '#fdba74', accent: '#c2410c' },
  'Ars Technica Security': { bg: '#0c0a2e', color: '#a5b4fc', accent: '#6366f1' },
  'Naked Security':        { bg: '#022033', color: '#7dd3fc', accent: '#0284c7' },
  'Troy Hunt':             { bg: '#1a0530', color: '#e9d5ff', accent: '#9333ea' },
  'Microsoft MSRC':        { bg: '#031630', color: '#90c8f0', accent: '#0078d4' },
  'CERT.at':               { bg: '#001a10', color: '#6ee7b7', accent: '#059669' },
  'ENISA':                 { bg: '#030d2c', color: '#93c5fd', accent: '#1d4ed8' },
};

const TAG_STYLES: Record<string, { bg: string; color: string; border: string }> = {
  'CVE':             { bg: 'rgba(239,68,68,0.12)',   color: '#fca5a5', border: 'rgba(239,68,68,0.4)' },
  'Zero-Day':        { bg: 'rgba(249,115,22,0.12)',  color: '#fdba74', border: 'rgba(249,115,22,0.4)' },
  'Ransomware':      { bg: 'rgba(168,85,247,0.12)',  color: '#d8b4fe', border: 'rgba(168,85,247,0.4)' },
  'Malware':         { bg: 'rgba(139,92,246,0.12)',  color: '#c4b5fd', border: 'rgba(139,92,246,0.4)' },
  'Phishing':        { bg: 'rgba(236,72,153,0.12)',  color: '#f9a8d4', border: 'rgba(236,72,153,0.4)' },
  'Breach':          { bg: 'rgba(239,68,68,0.10)',   color: '#fca5a5', border: 'rgba(239,68,68,0.35)' },
  'Vulnerability':   { bg: 'rgba(234,179,8,0.10)',   color: '#fde047', border: 'rgba(234,179,8,0.35)' },
  'Patch Tuesday':   { bg: 'rgba(59,130,246,0.10)',  color: '#93c5fd', border: 'rgba(59,130,246,0.3)' },
  'APT':             { bg: 'rgba(245,158,11,0.10)',  color: '#fcd34d', border: 'rgba(245,158,11,0.35)' },
  'Nation-State':    { bg: 'rgba(100,116,139,0.15)', color: '#cbd5e1', border: 'rgba(100,116,139,0.4)' },
  'Supply Chain':    { bg: 'rgba(6,182,212,0.10)',   color: '#67e8f9', border: 'rgba(6,182,212,0.3)' },
  'AI/ML':           { bg: 'rgba(99,102,241,0.10)',  color: '#a5b4fc', border: 'rgba(99,102,241,0.3)' },
  'Cloud':           { bg: 'rgba(14,165,233,0.10)',  color: '#7dd3fc', border: 'rgba(14,165,233,0.3)' },
  'Privacy':         { bg: 'rgba(16,185,129,0.10)',  color: '#6ee7b7', border: 'rgba(16,185,129,0.3)' },
  'ICS/OT':          { bg: 'rgba(234,88,12,0.10)',   color: '#fdba74', border: 'rgba(234,88,12,0.3)' },
  'Azure AD':        { bg: 'rgba(0,120,212,0.12)',   color: '#90c8f0', border: 'rgba(0,120,212,0.4)' },
  'Splunk':          { bg: 'rgba(107,63,160,0.12)',  color: '#d4a8ff', border: 'rgba(107,63,160,0.4)' },
  'NetScaler':       { bg: 'rgba(0,166,255,0.10)',   color: '#67d4ff', border: 'rgba(0,166,255,0.35)' },
  'F5/BIG-IP':       { bg: 'rgba(230,74,25,0.10)',   color: '#ffb08a', border: 'rgba(230,74,25,0.3)' },
  'M365':            { bg: 'rgba(0,120,212,0.08)',   color: '#81b4ea', border: 'rgba(0,120,212,0.3)' },
  'Windows/AD':      { bg: 'rgba(0,164,239,0.10)',   color: '#7dd3fc', border: 'rgba(0,164,239,0.3)' },
  'Financial Sector':{ bg: 'rgba(16,185,129,0.10)',  color: '#34d399', border: 'rgba(16,185,129,0.3)' },
  'Regulatory':      { bg: 'rgba(245,158,11,0.08)',  color: '#fbbf24', border: 'rgba(245,158,11,0.25)' },
};

// ─── MITRE ATT&CK ─────────────────────────────────────────────────────────────

const ATTACK_MAP: Array<{ pattern: RegExp; id: string; name: string }> = [
  { pattern: /phish|spear.?phish/i,                             id: 'T1566', name: 'Phishing' },
  { pattern: /supply chain|dependency confus|typosquat/i,        id: 'T1195', name: 'Supply Chain' },
  { pattern: /ransomware/i,                                      id: 'T1486', name: 'Data Encrypted' },
  { pattern: /credential.?stuff|brute.?force|password.?spray/i,  id: 'T1110', name: 'Brute Force' },
  { pattern: /remote code exec|\brce\b/i,                        id: 'T1059', name: 'Code Execution' },
  { pattern: /sql inject/i,                                      id: 'T1190', name: 'Exploit Public App' },
  { pattern: /zero.?day|0day/i,                                  id: 'T1203', name: 'Client Exploit' },
  { pattern: /backdoor|webshell|web shell/i,                     id: 'T1505', name: 'Server Component' },
  { pattern: /privilege.escalat|\beop\b/i,                       id: 'T1068', name: 'Priv Escalation' },
  { pattern: /exfiltrat|data theft|stolen.?data/i,               id: 'T1041', name: 'Exfiltration' },
  { pattern: /command.and.control|\bc2\b|\bc&c\b|beacon/i,       id: 'T1071', name: 'C2 Protocol' },
  { pattern: /pass.the.hash|kerberoast|lateral movement/i,       id: 'T1550', name: 'Alt Auth Material' },
  { pattern: /defense.evasion|obfuscat/i,                        id: 'T1027', name: 'Obfuscation' },
  { pattern: /watering.hole/i,                                   id: 'T1189', name: 'Drive-by' },
  { pattern: /living.off.the.land|lolbin|lolbas/i,               id: 'T1218', name: 'Signed Binary' },
];

// ─── Stack Tags & Threat Actors ───────────────────────────────────────────────

const STACK_TAGS = ['Azure AD', 'Splunk', 'NetScaler', 'F5/BIG-IP', 'M365', 'Windows/AD'];

const THREAT_ACTORS: Array<{ name: string; regex: RegExp; origin: string; sector: string }> = [
  { name: 'Lazarus Group',      regex: /lazarus|apt.?38|bluenoroff/i,          origin: 'DPRK',        sector: 'Financial / Crypto' },
  { name: 'FIN7',               regex: /\bfin7\b|carbanak/i,                   origin: 'Criminal',    sector: 'Financial / Retail' },
  { name: 'Cl0p',               regex: /\bcl0p\b|\bclop\b/i,                  origin: 'Criminal',    sector: 'Multi-sector' },
  { name: 'LockBit',            regex: /\blockbit\b/i,                         origin: 'Criminal',    sector: 'Multi-sector' },
  { name: 'BlackCat / ALPHV',   regex: /\bblackcat\b|\balphv\b/i,              origin: 'Criminal',    sector: 'Multi-sector' },
  { name: 'Sandworm',           regex: /\bsandworm\b|voodoo.?bear/i,           origin: 'Russia GRU',  sector: 'Critical Infra' },
  { name: 'APT29 / Cozy Bear',  regex: /cozy.?bear|apt.?29|\bnobelium\b/i,    origin: 'Russia SVR',  sector: 'Gov / Finance' },
  { name: 'Scattered Spider',   regex: /scattered.?spider|\boktapus\b/i,       origin: 'Criminal',    sector: 'Financial / Tech' },
  { name: 'Fancy Bear / APT28', regex: /fancy.?bear|apt.?28/i,                 origin: 'Russia GRU',  sector: 'Gov / Defence' },
  { name: 'TA505',              regex: /\bta505\b/i,                           origin: 'Criminal',    sector: 'Financial' },
  { name: 'Volt Typhoon',       regex: /volt.?typhoon/i,                       origin: 'China',       sector: 'Critical Infra' },
  { name: 'Salt Typhoon',       regex: /salt.?typhoon/i,                       origin: 'China',       sector: 'Telecom / Gov' },
  { name: 'REvil',              regex: /\brevil\b|sodinokibi/i,                origin: 'Criminal',    sector: 'Multi-sector' },
  { name: 'Akira',              regex: /\bakira\b.*ransom|\bakira.?group/i,    origin: 'Criminal',    sector: 'Multi-sector' },
];

// ─── Severity Patterns ────────────────────────────────────────────────────────

const CRIT_KEYWORDS =
  /actively exploit|exploited in the wild|emergency.?patch|weaponized|wormable|mass exploitation|under.?attack/i;

const HIGH_KEYWORDS =
  /\brce\b|remote code exec|unauthenticated|pre.?auth|privilege escalat|arbitrary code|critical.?vuln/i;

// ─── Helpers ──────────────────────────────────────────────────────────────────

function getSourceStyle(source: string) {
  return SOURCE_STYLES[source] ?? { bg: '#0d1124', color: '#94a3b8', accent: '#475569' };
}

function getTagStyle(tag: string) {
  return TAG_STYLES[tag] ?? { bg: 'rgba(71,85,105,0.15)', color: '#94a3b8', border: 'rgba(71,85,105,0.3)' };
}

function timeAgo(dateStr: string): string {
  if (!dateStr) return '';
  const ms = Date.now() - new Date(dateStr).getTime();
  if (isNaN(ms)) return '';
  const mins = Math.floor(ms / 60000);
  if (mins < 1) return 'just now';
  if (mins < 60) return `${mins}m ago`;
  const hrs = Math.floor(mins / 60);
  if (hrs < 24) return `${hrs}h ago`;
  const days = Math.floor(hrs / 24);
  if (days < 7) return `${days}d ago`;
  return new Date(dateStr).toLocaleDateString('en-US', { month: 'short', day: 'numeric' });
}

function computeSeverity(item: NewsItem, kevSet: Set<string>): SeverityResult {
  const isKev = item.cves.some(c => kevSet.has(c));
  if (isKev) return { level: 'CRITICAL', isKev: true };
  const text = `${item.title} ${item.description}`;
  if (item.tags.includes('Zero-Day') && item.cves.length > 0) return { level: 'CRITICAL', isKev: false };
  if (item.tags.includes('Zero-Day') && item.tags.includes('Ransomware')) return { level: 'CRITICAL', isKev: false };
  if (CRIT_KEYWORDS.test(text)) return { level: 'CRITICAL', isKev: false };
  if (item.source === 'CISA' && item.tags.includes('Vulnerability')) return { level: 'CRITICAL', isKev: false };
  if (item.source === 'Microsoft MSRC' && item.tags.includes('Zero-Day')) return { level: 'CRITICAL', isKev: false };
  if (item.tags.includes('Zero-Day')) return { level: 'HIGH', isKev: false };
  if (item.tags.includes('Ransomware')) return { level: 'HIGH', isKev: false };
  if (item.tags.includes('APT') || item.tags.includes('Nation-State')) return { level: 'HIGH', isKev: false };
  if (item.tags.includes('ICS/OT') && item.cves.length > 0) return { level: 'HIGH', isKev: false };
  if (item.tags.includes('Supply Chain') && item.tags.includes('Vulnerability')) return { level: 'HIGH', isKev: false };
  if (item.cves.length > 0 && HIGH_KEYWORDS.test(text)) return { level: 'HIGH', isKev: false };
  if (item.tags.includes('CVE') && item.tags.includes('Vulnerability')) return { level: 'HIGH', isKev: false };
  if (item.tags.includes('Breach') && /million|records|users|customers/i.test(text)) return { level: 'HIGH', isKev: false };
  if (item.cves.length > 0) return { level: 'MEDIUM', isKev: false };
  if (item.tags.includes('Vulnerability')) return { level: 'MEDIUM', isKev: false };
  if (item.tags.includes('Malware') || item.tags.includes('Phishing') || item.tags.includes('Breach')) return { level: 'MEDIUM', isKev: false };
  if (item.tags.includes('Patch Tuesday')) return { level: 'MEDIUM', isKev: false };
  return { level: 'LOW', isKev: false };
}

function detectTechniques(text: string): AttackTechnique[] {
  const seen = new Set<string>(); const out: AttackTechnique[] = [];
  for (const { pattern, id, name } of ATTACK_MAP) {
    if (!seen.has(id) && pattern.test(text)) { seen.add(id); out.push({ id, name }); }
    if (out.length >= 4) break;
  }
  return out;
}

function extractIOCs(text: string): IOCResult {
  const t = text.replace(/\[\.]/g, '.').replace(/hxxp/gi, 'http');

  // Context-aware IP extraction — filters out version numbers misclassified as IPs
  const IP_RE = /\b((?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d))\b/g;
  const THREAT_CTX = /\b(?:ip[ -]?address|c2|c&c|host|connect|communicat|download|upload|phish|malware|attack|backdoor|deliver|infrastructure|traffic|src|dst|remote|proxy|scan|exfiltr|indicator|ioc|threat actor|campaign|panel|implant|dropper|payload|beacon|resolv)\b/i;
  const VERSION_BEFORE = /(?:version|ver\.?|firmware|release|build|update|patch|through|prior to|earlier than|up to|affecting|affected)\s{0,4}$/i;

  const seen = new Set<string>();
  const ips: string[] = [];
  let m: RegExpExecArray | null;

  while ((m = IP_RE.exec(t)) !== null && ips.length < 10) {
    const ip = m[1];
    if (seen.has(ip)) continue;
    // Private / reserved ranges
    if (/^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|127\.|0\.|255\.|169\.254\.)/.test(ip)) continue;
    const start = m.index;
    const end   = start + ip.length;
    const before = t.slice(Math.max(0, start - 60), start);
    const after  = t.slice(end, Math.min(t.length, end + 10));
    // Part of a longer version string e.g. "1.0.2.5.6"
    if (/^\.\d/.test(after)) continue;
    // Preceded by version/firmware keywords
    if (VERSION_BEFORE.test(before)) continue;
    // First octet ≤ 20 is characteristic of software versions, not routable threat IPs
    if (parseInt(ip.split('.')[0], 10) <= 20) continue;
    // Require at least one network/threat term in the surrounding 300 chars
    const ctx = t.slice(Math.max(0, start - 200), Math.min(t.length, end + 100));
    if (!THREAT_CTX.test(ctx)) continue;
    seen.add(ip);
    ips.push(ip);
  }
  const sha256 = [...new Set((t.match(/\b[0-9a-fA-F]{64}\b/g) || []).map(h => h.toLowerCase()))];
  const sha1   = [...new Set((t.match(/\b[0-9a-fA-F]{40}\b/g) || []).map(h => h.toLowerCase()))];
  const md5    = [...new Set((t.match(/\b[0-9a-fA-F]{32}\b/g) || []).map(h => h.toLowerCase()))];
  const hashes = [...sha256, ...sha1, ...md5].slice(0, 8);
  const domains = [...new Set(
    (t.match(/\b(?:[a-zA-Z0-9-]+\.)+(?:onion|ru|cn|tk|ml|ga|cf|gq|pw|xyz|top|club|online|site|info|biz)\b/g) || [])
  )].slice(0, 6);
  return { ips, hashes, domains };
}

async function copyToClipboard(text: string): Promise<void> {
  try { await navigator.clipboard.writeText(text); } catch {
    const el = document.createElement('textarea');
    el.value = text;
    Object.assign(el.style, { position: 'fixed', opacity: '0', top: '0', left: '0' });
    document.body.appendChild(el); el.select(); document.execCommand('copy'); document.body.removeChild(el);
  }
}

function generateSplunkQuery(type: 'ip' | 'hash' | 'domain' | 'cve', value: string): string {
  switch (type) {
    case 'ip':
      return `index=* (src_ip="${value}" OR dest_ip="${value}" OR src="${value}" OR dest="${value}")\n| table _time, src_ip, dest_ip, user, host, sourcetype\n| head 100`;
    case 'hash':
      return `index=* ("${value}")\n| table _time, host, user, file_name, file_path, CommandLine\n| head 100`;
    case 'domain':
      return `index=* (dest_host="*${value}*" OR url="*${value}*" OR query="${value}")\n| table _time, src_ip, dest_host, url, user\n| head 100`;
    case 'cve':
      return `(index=vulnerability "${value}") OR (index=* "${value}")\n| stats count by host, severity, signature\n| sort -count`;
  }
}

function exportMispJson(items: NewsItem[], kevSet: Set<string>): void {
  const attributes: Array<{ type: string; category: string; value: string; to_ids: boolean; comment: string }> = [];
  const allCVEs = new Set<string>();
  for (const item of items) {
    const sev = computeSeverity(item, kevSet);
    if (sev.level === 'CRITICAL' || sev.level === 'HIGH') {
      const iocs = extractIOCs(`${item.description} ${item.content}`);
      iocs.ips.forEach(ip => attributes.push({ type: 'ip-dst', category: 'Network activity', value: ip, to_ids: true, comment: item.title.slice(0, 100) }));
      iocs.domains.forEach(d => attributes.push({ type: 'domain', category: 'Network activity', value: d, to_ids: true, comment: item.title.slice(0, 100) }));
      iocs.hashes.forEach(h => {
        const t = h.length === 64 ? 'sha256' : h.length === 40 ? 'sha1' : 'md5';
        attributes.push({ type: t, category: 'Payload delivery', value: h, to_ids: true, comment: item.title.slice(0, 100) });
      });
      item.cves.forEach(c => allCVEs.add(c));
    }
  }
  allCVEs.forEach(c => attributes.push({ type: 'vulnerability', category: 'External analysis', value: c, to_ids: false, comment: 'BriefSec feed' }));
  if (attributes.length === 0) return;
  const event = {
    Event: {
      info: `BriefSec IOC Export — ${new Date().toISOString().slice(0, 10)}`,
      date: new Date().toISOString().slice(0, 10),
      threat_level_id: '2', analysis: '0', distribution: '0',
      Attribute: attributes,
    },
  };
  const blob = new Blob([JSON.stringify(event, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url; a.download = `misp-event-${new Date().toISOString().slice(0, 10)}.json`; a.click();
  URL.revokeObjectURL(url);
}

function cleanSummary(text: string, limit = 600): string {
  const clean = text
    // CISA ICS / CSAF navigation links
    .replace(/View CSAF\b[^\n.;]*/gi, '')
    .replace(/\bCSAF\b[^\n.;]*/gi, '')
    // CVSS score/vector table rows
    .replace(/CVSS\s+(?:v[23]\s+)?[\d.]+\s*(?:CRITICAL|HIGH|MEDIUM|LOW)?[^\n.;]{0,120}/gi, '')
    .replace(/\b(?:Base Score|Vector(?: String)?|Impact Score|Exploitability Score)\s*:?\s*[\d.]+[^\n.;]{0,80}/gi, '')
    // CWE descriptor lines (e.g. "CWE-497: Exposure of System Information...")
    .replace(/\bCWE-\d+:?[^\n.;]{0,120}/gi, '')
    // "Vendor Equipment Vulnerabilities" and similar advisory table fragments
    .replace(/\b\w[\w\s]{0,30}(?:Equipment|Products?)\s+Vulnerabilities?[^\n.;]{0,80}/gi, '')
    // Pipe-delimited table rows that leak in from CSAF HTML
    .replace(/(?:\|\s*[^|]+){2,}\|/g, '')
    // Leftover "v3 6.1" CVSS version+score patterns
    .replace(/\bv[23]\s+[\d.]+\b/gi, '')
    .replace(/\s{2,}/g, ' ')
    .trim();

  if (clean.length <= limit) return clean;

  const slice = clean.slice(0, limit);
  // Prefer a full-sentence boundary
  const lastSent = Math.max(slice.lastIndexOf('. '), slice.lastIndexOf('! '), slice.lastIndexOf('? '));
  if (lastSent > limit * 0.45) return slice.slice(0, lastSent + 1).trimEnd();
  // Fall back to word boundary — never cuts mid-word or mid-CVE-ID
  const lastSpace = slice.lastIndexOf(' ');
  return (lastSpace > limit * 0.3 ? slice.slice(0, lastSpace) : slice).trimEnd() + '…';
}

function generateBrief(items: NewsItem[], kevSet: Set<string>): string {
  const date = new Date().toLocaleDateString('en-US', { year: 'numeric', month: 'long', day: 'numeric' });
  const ts = new Date().toUTCString();
  const enriched = items.map(i => ({ item: i, sev: computeSeverity(i, kevSet) }));
  const critical = enriched.filter(e => e.sev.level === 'CRITICAL');
  const high = enriched.filter(e => e.sev.level === 'HIGH');
  const allCVEs = [...new Set(items.flatMap(i => i.cves))];
  const kevCVEs = allCVEs.filter(c => kevSet.has(c));
  const allIPs = [...new Set(critical.concat(high).flatMap(e => extractIOCs(`${e.item.description} ${e.item.content}`).ips))];
  const allHashes = [...new Set(critical.concat(high).flatMap(e => extractIOCs(`${e.item.description} ${e.item.content}`).hashes))];
  const lines: string[] = [
    `# BriefSec SOC Daily Brief`, `**Date:** ${date}`, `**Generated:** ${ts}`,
    `**Articles:** ${items.length} | **CRITICAL:** ${critical.length} | **HIGH:** ${high.length} | **CVEs:** ${allCVEs.length}`,
    ``, `---`, ``, `## 🔴 CRITICAL Alerts (${critical.length})`, ``,
  ];
  for (const { item, sev } of critical) {
    lines.push(`### ${item.title}`);
    lines.push(`- **Source:** ${item.source} · ${timeAgo(item.pubDate)}`);
    lines.push(`- **Link:** <${item.link}>`);
    if (sev.isKev) lines.push(`- **⚠ CISA KEV:** Confirmed exploited in the wild — patch immediately`);
    if (item.cves.length > 0) lines.push(`- **CVEs:** ${item.cves.map(c => `[${c}](https://nvd.nist.gov/vuln/detail/${c})`).join(', ')}`);
    if (item.description) lines.push(`- **Summary:** ${cleanSummary(item.description)}`);
    lines.push(``);
  }
  lines.push(`---`, ``, `## 🟠 HIGH Priority (${high.length})`, ``);
  high.slice(0, 20).forEach(({ item }) => {
    const cveStr = item.cves.length > 0 ? ` — ${item.cves.join(', ')}` : '';
    lines.push(`- **[${item.title}](${item.link})** — ${item.source}${cveStr}`);
  });
  if (kevCVEs.length > 0) {
    lines.push(``, `---`, ``, `## ⚠ CISA KEV Matches (${kevCVEs.length})`, ``);
    kevCVEs.forEach(c => lines.push(`- [${c}](https://nvd.nist.gov/vuln/detail/${c})`));
  }
  if (allCVEs.length > 0) {
    lines.push(``, `---`, ``, `## CVE Summary (${allCVEs.length})`, ``);
    allCVEs.forEach(c => lines.push(`- [${c}](https://nvd.nist.gov/vuln/detail/${c})`));
  }
  lines.push(``, `---`, ``, `## IOC Summary`, ``);
  if (allIPs.length > 0) { lines.push(`### IP Addresses`); allIPs.forEach(ip => lines.push(`- \`${ip}\``)); lines.push(``); }
  if (allHashes.length > 0) { lines.push(`### File Hashes`); allHashes.forEach(h => lines.push(`- \`${h}\``)); lines.push(``); }
  lines.push(`---`, ``, `*Generated by BriefSec — SOC Intelligence Feed*`);
  return lines.join('\n');
}

function downloadBrief(content: string): void {
  const date = new Date().toISOString().slice(0, 10);
  const blob = new Blob([content], { type: 'text/markdown; charset=utf-8' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url; a.download = `briefsec-soc-brief-${date}.md`; a.click();
  URL.revokeObjectURL(url);
}

// ─── Icons ────────────────────────────────────────────────────────────────────

function IconRefresh({ spin }: { spin: boolean }) {
  return (
    <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor"
      strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round"
      style={{ animation: spin ? 'spin 0.8s linear infinite' : 'none' }}>
      <path d="M23 4v6h-6" /><path d="M1 20v-6h6" />
      <path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15" />
    </svg>
  );
}

function IconSearch() {
  return (
    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor"
      strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"
      style={{ color: 'var(--text-muted)', flexShrink: 0 }}>
      <circle cx="11" cy="11" r="8" /><path d="m21 21-4.35-4.35" />
    </svg>
  );
}

function IconBookmark({ filled }: { filled: boolean }) {
  return (
    <svg width="13" height="13" viewBox="0 0 24 24"
      fill={filled ? 'currentColor' : 'none'}
      stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M19 21l-7-5-7 5V5a2 2 0 0 1 2-2h10a2 2 0 0 1 2 2z" />
    </svg>
  );
}

function IconPin({ filled }: { filled: boolean }) {
  return (
    <svg width="12" height="12" viewBox="0 0 24 24"
      fill={filled ? 'currentColor' : 'none'}
      stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <line x1="12" y1="17" x2="12" y2="22" />
      <path d="M5 17h14v-1.76a2 2 0 0 0-1.11-1.79l-1.78-.9A2 2 0 0 1 15 10.76V6h1a2 2 0 0 0 0-4H8a2 2 0 0 0 0 4h1v4.76a2 2 0 0 1-1.11 1.79l-1.78.9A2 2 0 0 0 5 15.24Z" />
    </svg>
  );
}

function IconSun() {
  return (
    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <circle cx="12" cy="12" r="5" />
      <line x1="12" y1="1" x2="12" y2="3" /><line x1="12" y1="21" x2="12" y2="23" />
      <line x1="4.22" y1="4.22" x2="5.64" y2="5.64" /><line x1="18.36" y1="18.36" x2="19.78" y2="19.78" />
      <line x1="1" y1="12" x2="3" y2="12" /><line x1="21" y1="12" x2="23" y2="12" />
      <line x1="4.22" y1="19.78" x2="5.64" y2="18.36" /><line x1="18.36" y1="5.64" x2="19.78" y2="4.22" />
    </svg>
  );
}

function IconMoon() {
  return (
    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z" />
    </svg>
  );
}

function IconDownload() {
  return (
    <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4" />
      <polyline points="7 10 12 15 17 10" /><line x1="12" y1="15" x2="12" y2="3" />
    </svg>
  );
}

// ─── SEV helper ───────────────────────────────────────────────────────────────

const SEV_CSS_VAR: Record<Severity, string> = {
  CRITICAL: '#ef4444', HIGH: '#f97316', MEDIUM: '#eab308', LOW: '#475569',
};

const CVSS_COLOR = (score: number | null) => {
  if (!score) return '#64748b';
  if (score >= 9) return '#ef4444';
  if (score >= 7) return '#f97316';
  if (score >= 4) return '#eab308';
  return '#22c55e';
};

// ─── Trend Chart (SVG) ────────────────────────────────────────────────────────

interface TrendDay { date: string; CRITICAL: number; HIGH: number; MEDIUM: number; LOW: number; }

function TrendChart({ data }: { data: TrendDay[] }) {
  const maxVal = Math.max(...data.map(d => d.CRITICAL + d.HIGH + d.MEDIUM + d.LOW), 1);
  const W = 700; const H = 180;
  const PAD = { top: 20, right: 20, bottom: 32, left: 36 };
  const chartW = W - PAD.left - PAD.right;
  const chartH = H - PAD.top - PAD.bottom;
  const barW = Math.floor((chartW / data.length) * 0.7);
  const barGap = Math.floor((chartW / data.length) * 0.3);
  const scaleH = (n: number) => Math.round((n / maxVal) * chartH);

  const gridLines = [0.25, 0.5, 0.75, 1];

  return (
    <svg viewBox={`0 0 ${W} ${H}`} style={{ width: '100%', maxWidth: W, height: 'auto', display: 'block' }}>
      {gridLines.map(f => {
        const y = PAD.top + chartH * (1 - f);
        return (
          <g key={f}>
            <line x1={PAD.left} y1={y} x2={PAD.left + chartW} y2={y} stroke="rgba(255,255,255,0.06)" strokeWidth="1" />
            <text x={PAD.left - 4} y={y + 4} textAnchor="end" fill="#475569" fontSize="9">
              {Math.round(maxVal * f)}
            </text>
          </g>
        );
      })}
      {data.map((day, i) => {
        const xBase = PAD.left + i * (chartW / data.length) + barGap / 2;
        const bars = [
          { val: day.LOW,      color: '#334155' },
          { val: day.MEDIUM,   color: '#eab308' },
          { val: day.HIGH,     color: '#f97316' },
          { val: day.CRITICAL, color: '#ef4444' },
        ];
        let yPos = PAD.top + chartH;
        const total = day.CRITICAL + day.HIGH + day.MEDIUM + day.LOW;
        return (
          <g key={day.date}>
            {bars.map(({ val, color }) => {
              if (!val) return null;
              const bh = scaleH(val);
              yPos -= bh;
              return <rect key={color} x={xBase} y={yPos} width={barW} height={bh} fill={color} opacity={0.82} rx={1} />;
            })}
            {total > 0 && (
              <text x={xBase + barW / 2} y={PAD.top + chartH - scaleH(total) - 5}
                textAnchor="middle" fill="#94a3b8" fontSize="9">{total}</text>
            )}
            <text x={xBase + barW / 2} y={H - 6} textAnchor="middle" fill="#64748b" fontSize="9">
              {day.date}
            </text>
          </g>
        );
      })}
      <line x1={PAD.left} y1={PAD.top} x2={PAD.left} y2={PAD.top + chartH} stroke="rgba(255,255,255,0.1)" />
      <line x1={PAD.left} y1={PAD.top + chartH} x2={PAD.left + chartW} y2={PAD.top + chartH} stroke="rgba(255,255,255,0.1)" />
    </svg>
  );
}

// ─── CVE Status Badge ─────────────────────────────────────────────────────────

const STATUS_META: Record<string, { label: string; color: string; bg: string }> = {
  new:          { label: 'New',           color: '#94a3b8', bg: 'rgba(100,116,139,0.15)' },
  investigating:{ label: 'Investigating', color: '#93c5fd', bg: 'rgba(59,130,246,0.15)'  },
  in_progress:  { label: 'In Progress',   color: '#fbbf24', bg: 'rgba(251,191,36,0.15)'  },
  patched:      { label: 'Patched ✓',     color: '#4ade80', bg: 'rgba(74,222,128,0.15)'  },
  not_applicable:{ label: 'N/A',          color: '#64748b', bg: 'rgba(51,65,85,0.3)'     },
};

// ─── Main Component ───────────────────────────────────────────────────────────

export default function BriefSec() {
  // ── Core state ────────────────────────────────────────────────
  const [data,       setData]       = useState<FeedData | null>(null);
  const [loading,    setLoading]    = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [error,      setError]      = useState<string | null>(null);

  // ── KEV ───────────────────────────────────────────────────────
  const [kevCves, setKevCves] = useState<string[]>([]);

  // ── Filter / view ─────────────────────────────────────────────
  const [viewMode,      setViewMode]      = useState<ViewMode>('feed');
  const [sourceFilter,  setSourceFilter]  = useState('all');
  const [tagFilter,     setTagFilter]     = useState('all');
  const [sevFilter,     setSevFilter]     = useState<'ALL' | Severity>('ALL');
  const [search,        setSearch]        = useState('');
  const [timeFilter,    setTimeFilter]    = useState<'all' | '7d' | '24h'>('all');
  const [sortBy,        setSortBy]        = useState<SortBy>('newest');
  const [stackFilter,   setStackFilter]   = useState(false);

  // ── UI state ──────────────────────────────────────────────────
  const [theme,          setTheme]          = useState<'dark' | 'light'>('dark');
  const [autoRefresh,    setAutoRefresh]    = useState(true);
  const [savedArticles,  setSavedArticles]  = useState<Map<string, NewsItem>>(new Map());
  const [pinnedArticles, setPinnedArticles] = useState<Map<string, NewsItem>>(new Map());
  const [expandedIOCs,   setExpandedIOCs]   = useState<Set<string>>(new Set());
  const [lastVisit,      setLastVisit]      = useState<number>(0);
  const [copiedId,       setCopiedId]       = useState<string | null>(null);
  const [toast,          setToast]          = useState<string | null>(null);
  const [critWeekExpanded, setCritWeekExpanded] = useState(true);

  // ── CVE Tracker state ─────────────────────────────────────────
  const [cveTracker,        setCveTracker]        = useState<CveTrackerData | null>(null);
  const [cveTrackerLoading, setCveTrackerLoading] = useState(false);
  const [selectedProduct,   setSelectedProduct]   = useState('all');
  const [cveSort,           setCveSort]           = useState<'cvss' | 'date'>('cvss');
  const [updatingCve,       setUpdatingCve]        = useState<string | null>(null);

  // ── CVSS scores ───────────────────────────────────────────────
  const [cvssScores, setCvssScores] = useState<Record<string, CvssInfo>>({});

  const prevCriticalIds = useRef<Set<string>>(new Set());
  const toastTimer = useRef<ReturnType<typeof setTimeout> | null>(null);

  // ── Bootstrap localStorage ────────────────────────────────────
  useEffect(() => {
    const savedTheme = localStorage.getItem('briefsec-theme') as 'dark' | 'light' | null;
    if (savedTheme) setTheme(savedTheme);

    try {
      const raw = localStorage.getItem('briefsec-saved');
      if (raw) setSavedArticles(new Map(Object.entries(JSON.parse(raw) as Record<string, NewsItem>)));
    } catch { /* ignore */ }

    try {
      const rawPin = localStorage.getItem('briefsec-pinned');
      if (rawPin) setPinnedArticles(new Map(Object.entries(JSON.parse(rawPin) as Record<string, NewsItem>)));
    } catch { /* ignore */ }

    const storedVisit = localStorage.getItem('briefsec-last-visit');
    setLastVisit(storedVisit ? parseInt(storedVisit, 10) : 0);
    localStorage.setItem('briefsec-last-visit', String(Date.now()));
  }, []);

  // ── Theme ─────────────────────────────────────────────────────
  useEffect(() => {
    document.documentElement.classList.toggle('light', theme === 'light');
    localStorage.setItem('briefsec-theme', theme);
  }, [theme]);

  // ── KEV set ───────────────────────────────────────────────────
  const kevSet = useMemo(() => new Set<string>(kevCves), [kevCves]);

  // ── Fetch news ────────────────────────────────────────────────
  const fetchNews = useCallback(async (isRefresh = false) => {
    if (isRefresh) setRefreshing(true); else setLoading(true);
    setError(null);
    try {
      const res = await fetch('/api/news', { cache: 'no-store' });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      setData(await res.json());
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Failed to load');
    } finally { setLoading(false); setRefreshing(false); }
  }, []);

  useEffect(() => { fetchNews(); }, [fetchNews]);

  // ── Auto-refresh ──────────────────────────────────────────────
  useEffect(() => {
    if (!autoRefresh) return;
    const id = setInterval(() => fetchNews(true), 15 * 60 * 1000);
    return () => clearInterval(id);
  }, [autoRefresh, fetchNews]);

  // ── CISA KEV ──────────────────────────────────────────────────
  useEffect(() => {
    fetch('/api/kev').then(r => r.ok ? r.json() : null)
      .then((d: { cves: string[] } | null) => { if (d?.cves) setKevCves(d.cves); })
      .catch(() => {});
  }, []);

  // ── CVSS scores (batch fetch for visible CVEs) ────────────────
  useEffect(() => {
    if (!data) return;
    const ids = [...new Set(data.items.flatMap(i => i.cves))].slice(0, 40);
    if (ids.length === 0) return;
    const missing = ids.filter(id => !(id in cvssScores));
    if (missing.length === 0) return;
    fetch(`/api/cvss?cves=${missing.join(',')}`)
      .then(r => r.ok ? r.json() : null)
      .then((scores: Record<string, CvssInfo> | null) => {
        if (scores) setCvssScores(prev => ({ ...prev, ...scores }));
      })
      .catch(() => {});
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [data]);

  // ── CVE Tracker (lazy load when tab opens) ────────────────────
  const fetchCveTracker = useCallback(async () => {
    setCveTrackerLoading(true);
    try {
      const res = await fetch('/api/cve-tracker');
      if (res.ok) setCveTracker(await res.json());
    } catch { /* ignore */ } finally { setCveTrackerLoading(false); }
  }, []);

  useEffect(() => {
    if (viewMode === 'cve-tracker' && !cveTracker && !cveTrackerLoading) fetchCveTracker();
  }, [viewMode, cveTracker, cveTrackerLoading, fetchCveTracker]);

  // ── CRITICAL toast on refresh ─────────────────────────────────
  useEffect(() => {
    if (!data) return;
    const critIds = new Set(data.items.filter(i => computeSeverity(i, kevSet).level === 'CRITICAL').map(i => i.id));
    const newCrits = [...critIds].filter(id => !prevCriticalIds.current.has(id));
    if (prevCriticalIds.current.size > 0 && newCrits.length > 0) {
      if (toastTimer.current) clearTimeout(toastTimer.current);
      setToast(`${newCrits.length} new CRITICAL alert${newCrits.length > 1 ? 's' : ''} since last refresh`);
      toastTimer.current = setTimeout(() => setToast(null), 10000);
    }
    prevCriticalIds.current = critIds;
  }, [data, kevSet]);

  // ── Derived state ─────────────────────────────────────────────

  const kevSet2 = kevSet; // alias for clarity in memos

  const allTags = useMemo(() => {
    if (!data) return [];
    const counts = new Map<string, number>();
    data.items.forEach(i => i.tags.forEach(t => counts.set(t, (counts.get(t) ?? 0) + 1)));
    return [...counts.entries()].sort((a, b) => b[1] - a[1]).map(([t]) => t);
  }, [data]);

  const threatCounts = useMemo(() => {
    if (!data) return { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, kev: 0 };
    const cutoff = Date.now() - 86_400_000;
    const counts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, kev: 0 };
    data.items.filter(i => new Date(i.pubDate).getTime() > cutoff).forEach(item => {
      const s = computeSeverity(item, kevSet2);
      counts[s.level]++; if (s.isKev) counts.kev++;
    });
    return counts;
  }, [data, kevSet2]);

  // Synthesised threat level for the day
  const threatLevel = useMemo(() => {
    if (!data) return null;
    const cutoff = Date.now() - 86_400_000;
    const t24 = data.items.filter(i => new Date(i.pubDate).getTime() > cutoff);
    const critN  = t24.filter(i => computeSeverity(i, kevSet2).level === 'CRITICAL').length;
    const kevN   = t24.filter(i => computeSeverity(i, kevSet2).isKev).length;
    const zdN    = t24.filter(i => i.tags.includes('Zero-Day')).length;
    const rswN   = t24.filter(i => i.tags.includes('Ransomware')).length;
    const natN   = t24.filter(i => i.tags.includes('Nation-State')).length;
    const highN  = t24.filter(i => computeSeverity(i, kevSet2).level === 'HIGH').length;
    let score = critN * 2 + kevN * 5 + zdN * 3 + rswN * 2 + natN * 1.5 + highN * 0.5;
    const reasons: string[] = [];
    if (kevN > 0)  reasons.push(`${kevN} KEV`);
    if (critN > 0) reasons.push(`${critN} critical`);
    if (zdN > 0)   reasons.push(`${zdN} zero-day`);
    if (rswN > 0)  reasons.push('ransomware activity');
    if (natN > 0)  reasons.push('nation-state threat');
    const level = score >= 15 ? 'SEVERE' : score >= 8 ? 'HIGH' : score >= 3 ? 'ELEVATED' : 'NORMAL';
    return { level, score: Math.round(score), reasons };
  }, [data, kevSet2]);

  const kevCount = useMemo(
    () => (data?.items ?? []).filter(i => i.cves.some(c => kevSet2.has(c))).length,
    [data, kevSet2],
  );

  const unreadCount = useMemo(
    () => lastVisit === 0 ? 0 : (data?.items ?? []).filter(i => new Date(i.pubDate).getTime() > lastVisit).length,
    [data, lastVisit],
  );

  const criticalThisWeek = useMemo(() => {
    if (!data) return [];
    const cutoff = Date.now() - 7 * 86_400_000;
    return data.items
      .filter(i => new Date(i.pubDate).getTime() > cutoff && computeSeverity(i, kevSet2).level === 'CRITICAL')
      .slice(0, 8);
  }, [data, kevSet2]);

  const activeActors = useMemo(() => {
    if (!data) return [];
    const cutoff = Date.now() - 7 * 86_400_000;
    const recent = data.items.filter(i => new Date(i.pubDate).getTime() > cutoff);
    return THREAT_ACTORS
      .map(actor => {
        const hits = recent.filter(i => actor.regex.test(`${i.title} ${i.description}`));
        return { ...actor, count: hits.length, articles: hits };
      })
      .filter(a => a.count > 0)
      .sort((a, b) => b.count - a.count);
  }, [data]);

  const trendData = useMemo((): TrendDay[] => {
    if (!data) return [];
    const days: Record<string, TrendDay> = {};
    for (let i = 6; i >= 0; i--) {
      const d = new Date(); d.setDate(d.getDate() - i);
      const key = d.toISOString().slice(0, 10);
      days[key] = { date: d.toLocaleDateString('en-US', { month: 'short', day: 'numeric' }), CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
    }
    data.items.forEach(item => {
      const day = item.pubDate ? new Date(item.pubDate).toISOString().slice(0, 10) : null;
      if (day && days[day]) { const sev = computeSeverity(item, kevSet2).level; days[day][sev]++; }
    });
    return Object.values(days);
  }, [data, kevSet2]);

  // ── Filtered items ────────────────────────────────────────────
  const filteredItems = useMemo(() => {
    if (viewMode === 'saved') {
      return [...savedArticles.values()].sort((a, b) => new Date(b.pubDate).getTime() - new Date(a.pubDate).getTime());
    }
    if (!data) return [];
    let items = viewMode === 'kev'
      ? data.items.filter(i => i.cves.some(c => kevSet2.has(c)))
      : data.items;

    if (stackFilter) items = items.filter(i => i.tags.some(t => STACK_TAGS.includes(t)));
    if (sourceFilter !== 'all') items = items.filter(i => i.source === sourceFilter);
    if (tagFilter !== 'all') items = items.filter(i => i.tags.includes(tagFilter));
    if (sevFilter !== 'ALL') items = items.filter(i => computeSeverity(i, kevSet2).level === sevFilter);
    if (timeFilter === '24h') items = items.filter(i => new Date(i.pubDate).getTime() > Date.now() - 86_400_000);
    else if (timeFilter === '7d') items = items.filter(i => new Date(i.pubDate).getTime() > Date.now() - 7 * 86_400_000);

    if (search.trim()) {
      const q = search.toLowerCase();
      items = items.filter(i =>
        i.title.toLowerCase().includes(q) || i.description.toLowerCase().includes(q) ||
        i.cves.some(c => c.toLowerCase().includes(q)) || i.source.toLowerCase().includes(q),
      );
    }
    if (sortBy === 'severity') {
      const rank: Record<Severity, number> = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 };
      items = [...items].sort((a, b) => {
        const diff = rank[computeSeverity(a, kevSet2).level] - rank[computeSeverity(b, kevSet2).level];
        return diff !== 0 ? diff : new Date(b.pubDate).getTime() - new Date(a.pubDate).getTime();
      });
    }
    return items;
  }, [data, sourceFilter, tagFilter, sevFilter, search, timeFilter, viewMode, savedArticles, sortBy, kevSet2, stackFilter]);

  const enrichedItems = useMemo<EnrichedItem[]>(
    () => filteredItems.map(item => ({
      item,
      severity: computeSeverity(item, kevSet2),
      iocs: extractIOCs(`${item.description} ${item.content || ''}`),
      techniques: detectTechniques(`${item.title} ${item.description}`),
      isNew: lastVisit > 0 && new Date(item.pubDate).getTime() > lastVisit,
    })),
    [filteredItems, kevSet2, lastVisit],
  );

  // ── CVE Tracker filtered entries ──────────────────────────────
  const filteredCves = useMemo(() => {
    if (!cveTracker) return [];
    let entries = cveTracker.entries;
    if (selectedProduct !== 'all') entries = entries.filter(e => e.product === selectedProduct);
    if (cveSort === 'date') entries = [...entries].sort((a, b) => new Date(b.published).getTime() - new Date(a.published).getTime());
    return entries;
  }, [cveTracker, selectedProduct, cveSort]);

  const hasActiveFilters = stackFilter || sourceFilter !== 'all' || tagFilter !== 'all' || search.trim() !== '' || timeFilter !== 'all' || sevFilter !== 'ALL';

  // ── Handlers ──────────────────────────────────────────────────
  const togglePin = useCallback((item: NewsItem) => {
    setPinnedArticles(prev => {
      const next = new Map(prev);
      if (next.has(item.id)) next.delete(item.id); else next.set(item.id, item);
      const obj: Record<string, NewsItem> = {};
      next.forEach((v, k) => { obj[k] = v; });
      localStorage.setItem('briefsec-pinned', JSON.stringify(obj));
      return next;
    });
  }, []);

  const toggleSave = useCallback((item: NewsItem) => {
    setSavedArticles(prev => {
      const next = new Map(prev);
      if (next.has(item.id)) next.delete(item.id); else next.set(item.id, item);
      const obj: Record<string, NewsItem> = {};
      next.forEach((v, k) => { obj[k] = v; });
      localStorage.setItem('briefsec-saved', JSON.stringify(obj));
      return next;
    });
  }, []);

  const toggleIOC = useCallback((id: string) => {
    setExpandedIOCs(prev => { const next = new Set(prev); if (next.has(id)) next.delete(id); else next.add(id); return next; });
  }, []);

  const handleCopy = useCallback(async (text: string, key: string) => {
    await copyToClipboard(text); setCopiedId(key); setTimeout(() => setCopiedId(null), 1500);
  }, []);

  const markAllRead = useCallback(() => {
    const now = Date.now(); setLastVisit(now); localStorage.setItem('briefsec-last-visit', String(now));
  }, []);

  const clearFilters = useCallback(() => {
    setSourceFilter('all'); setTagFilter('all'); setSearch('');
    setTimeFilter('all'); setSevFilter('ALL'); setStackFilter(false);
  }, []);

  const updateCveStatus = useCallback(async (cveId: string, status: string) => {
    if (!cveTracker) return;
    setUpdatingCve(cveId);
    setCveTracker(prev => prev ? {
      ...prev,
      statuses: { ...prev.statuses, [cveId]: { status, notes: prev.statuses[cveId]?.notes ?? '' } },
    } : prev);
    try {
      await fetch('/api/cve-tracker', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ cveId, status }),
      });
    } catch { /* ignore */ } finally { setUpdatingCve(null); }
  }, [cveTracker]);

  // ── Threat level helpers ──────────────────────────────────────
  const TL_META = {
    NORMAL:   { color: '#4ade80', bg: 'rgba(74,222,128,0.1)',  border: 'rgba(74,222,128,0.3)' },
    ELEVATED: { color: '#fbbf24', bg: 'rgba(251,191,36,0.1)', border: 'rgba(251,191,36,0.3)' },
    HIGH:     { color: '#f97316', bg: 'rgba(249,115,22,0.12)', border: 'rgba(249,115,22,0.4)' },
    SEVERE:   { color: '#ef4444', bg: 'rgba(239,68,68,0.12)',  border: 'rgba(239,68,68,0.45)' },
  };

  // ─────────────────────────────────────────────────────────────
  //  Render
  // ─────────────────────────────────────────────────────────────

  return (
    <>
      {/* ── Toast ── */}
      {toast && (
        <div className="toast-alert">
          <span>⚠ {toast}</span>
          <button className="toast-view-btn" onClick={() => { setSevFilter('CRITICAL'); setToast(null); }}>View</button>
          <button className="toast-close" onClick={() => setToast(null)}>✕</button>
        </div>
      )}

      {/* ── Header ── */}
      <header className="header">
        <div className="header-brand">
          {/* eslint-disable-next-line @next/next/no-img-element */}
          <img src="/favicon.svg" alt="" width={26} height={26} style={{ borderRadius: '5px', flexShrink: 0 }} />
          <div className="header-logo">Brief<span>Sec</span></div>
          <span className="header-subtitle">SOC Intelligence</span>
        </div>

        {/* Threat Level + Strip */}
        {data && !loading && threatLevel && (
          <div className="threat-strip">
            <span className="threat-level-badge"
              style={{ background: TL_META[threatLevel.level as keyof typeof TL_META].bg, color: TL_META[threatLevel.level as keyof typeof TL_META].color, borderColor: TL_META[threatLevel.level as keyof typeof TL_META].border }}>
              {threatLevel.level}
            </span>
            <span className="threat-strip-sep" />
            <span className="threat-item threat-item-crit" onClick={() => setSevFilter(sevFilter === 'CRITICAL' ? 'ALL' : 'CRITICAL')}>
              🔴 {threatCounts.CRITICAL} CRIT
            </span>
            <span className="threat-strip-sep" />
            <span className="threat-item threat-item-high" onClick={() => setSevFilter(sevFilter === 'HIGH' ? 'ALL' : 'HIGH')}>
              🟠 {threatCounts.HIGH} HIGH
            </span>
            <span className="threat-strip-sep" />
            <span className="threat-item threat-item-med" onClick={() => setSevFilter(sevFilter === 'MEDIUM' ? 'ALL' : 'MEDIUM')}>
              🟡 {threatCounts.MEDIUM} MED
            </span>
            {threatCounts.kev > 0 && (
              <>
                <span className="threat-strip-sep" />
                <span className="threat-item threat-item-kev" onClick={() => setViewMode('kev')}>
                  ⚠ {threatCounts.kev} KEV
                </span>
              </>
            )}
          </div>
        )}

        <div className="header-actions">
          {unreadCount > 0 && (
            <button className="btn btn-unread" onClick={markAllRead} title="Mark all as read">
              {unreadCount} new
            </button>
          )}
          <button className="btn btn-misp"
            onClick={() => exportMispJson(filteredItems, kevSet2)}
            title="Export IOCs as MISP-compatible JSON">
            MISP
          </button>
          <button className="btn btn-export"
            onClick={() => downloadBrief(generateBrief(data?.items ?? [], kevSet2))}
            title="Download SOC daily brief as Markdown">
            <IconDownload /><span>Export Brief</span>
          </button>
          <button className="btn btn-icon" onClick={() => setTheme(t => t === 'dark' ? 'light' : 'dark')}
            title={theme === 'dark' ? 'Light mode' : 'Dark mode'}>
            {theme === 'dark' ? <IconSun /> : <IconMoon />}
          </button>
          <button className={`btn btn-refresh${refreshing ? ' spinning' : ''}`}
            onClick={() => fetchNews(true)} disabled={refreshing}>
            <IconRefresh spin={refreshing} /><span className="btn-refresh-text">{refreshing ? 'Refreshing…' : 'Refresh'}</span>
          </button>
          <button className={`btn btn-auto${autoRefresh ? ' active' : ''}`}
            onClick={() => setAutoRefresh(v => !v)}>
            Auto {autoRefresh ? 'ON' : 'OFF'}
          </button>
        </div>
      </header>

      {/* ── Filter Bar ── */}
      <div className="filter-bar">
        <div className="filter-top-row">
          <div className="view-tabs">
            <button className={`view-tab${viewMode === 'feed' ? ' active' : ''}`}
              onClick={() => setViewMode('feed')}>Feed</button>
            <button className={`view-tab${viewMode === 'saved' ? ' active' : ''}`}
              onClick={() => setViewMode('saved')}>
              Saved{savedArticles.size > 0 ? ` (${savedArticles.size})` : ''}
            </button>
            <button className={`view-tab kev-tab${viewMode === 'kev' ? ' active' : ''}`}
              onClick={() => setViewMode('kev')}>
              ⚠ KEV{kevCount > 0 ? ` (${kevCount})` : ''}
            </button>
            <button className={`view-tab cve-tab${viewMode === 'cve-tracker' ? ' active' : ''}`}
              onClick={() => setViewMode('cve-tracker')}>
              Stack CVEs
            </button>
            <button className={`view-tab${viewMode === 'trends' ? ' active' : ''}`}
              onClick={() => setViewMode('trends')}>
              Trends
            </button>
          </div>

          <div className="filter-right-group">
            <button
              className={`view-tab stack-tab${stackFilter ? ' active' : ''}`}
              onClick={() => setStackFilter(v => !v)}
              title="Show only articles affecting your tech stack">
              PF
            </button>
            <span className="filter-sep" />
            <div className="time-tabs">
              <button className={`view-tab${timeFilter === 'all' ? ' active' : ''}`} onClick={() => setTimeFilter('all')}>All</button>
              <button className={`view-tab${timeFilter === '7d'  ? ' active' : ''}`} onClick={() => setTimeFilter('7d')}>7d</button>
              <button className={`view-tab${timeFilter === '24h' ? ' active' : ''}`} onClick={() => setTimeFilter('24h')}>24h</button>
            </div>
            <span className="filter-sep" />
            <div className="sort-tabs">
              <button className={`view-tab${sortBy === 'newest'   ? ' active' : ''}`} onClick={() => setSortBy('newest')}>Newest</button>
              <button className={`view-tab${sortBy === 'severity' ? ' active' : ''}`} onClick={() => setSortBy('severity')}>By Risk</button>
            </div>
          </div>
        </div>

        {/* Severity row — only for feed/saved/kev */}
        {(viewMode === 'feed' || viewMode === 'saved' || viewMode === 'kev') && (
          <>
            <div className="filter-row">
              <span className="filter-label">Risk</span>
              <button className={`pill${sevFilter === 'ALL' ? ' active' : ''}`} onClick={() => setSevFilter('ALL')}>All</button>
              {(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'] as const).map(s => (
                <button key={s} className={`pill sev-pill-${s.toLowerCase()}${sevFilter === s ? ' active' : ''}`}
                  onClick={() => setSevFilter(sevFilter === s ? 'ALL' : s)}>
                  {s === 'CRITICAL' ? '🔴 CRITICAL' : s === 'HIGH' ? '🟠 HIGH' : s === 'MEDIUM' ? '🟡 MEDIUM' : '⚪ LOW'}
                </button>
              ))}
            </div>
            <div className="filter-row">
              <span className="filter-label">Source</span>
              <button className={`pill${sourceFilter === 'all' ? ' active' : ''}`} onClick={() => setSourceFilter('all')}>All</button>
              {(data?.sources ?? []).map(src => (
                <button key={src} className={`pill${sourceFilter === src ? ' active' : ''}`}
                  onClick={() => setSourceFilter(src === sourceFilter ? 'all' : src)}
                  style={sourceFilter === src ? { background: getSourceStyle(src).bg, color: getSourceStyle(src).color, borderColor: getSourceStyle(src).accent } : {}}>
                  {src}
                </button>
              ))}
            </div>
            <div className="filter-row">
              <span className="filter-label">Tag</span>
              <button className={`pill${tagFilter === 'all' ? ' active' : ''}`} onClick={() => setTagFilter('all')}>All</button>
              {allTags.map(tag => {
                const s = getTagStyle(tag);
                return (
                  <button key={tag} className={`pill${tagFilter === tag ? ' active' : ''}`}
                    onClick={() => setTagFilter(tag === tagFilter ? 'all' : tag)}
                    style={tagFilter === tag ? { background: s.bg, color: s.color, borderColor: s.border } : {}}>
                    {tag}
                  </button>
                );
              })}
            </div>
            <div className="search-row">
              <IconSearch />
              <input className="search-input"
                placeholder="Search articles, CVEs, IOCs, sources…"
                value={search} onChange={e => setSearch(e.target.value)} />
            </div>
          </>
        )}
      </div>

      {/* ── Stats Bar ── */}
      {(data || viewMode === 'saved') && !loading && viewMode !== 'cve-tracker' && viewMode !== 'trends' && (
        <div className="stats-bar">
          {viewMode === 'saved' ? (
            <span><span className="stats-count">{savedArticles.size}</span> saved articles</span>
          ) : (
            <>
              <span><span className="stats-count">{filteredItems.length}</span> articles</span>
              {viewMode === 'feed' && <><span>·</span><span><span className="stats-count">{data?.sources.length ?? 0}</span> sources</span></>}
              {viewMode === 'kev' && kevCount > 0 && <><span>·</span><span><span className="stats-kev-count">{kevCount}</span> KEV matches</span></>}
              <span className="live-dot">Live</span>
              {data?.lastRefresh && <span>· Updated {timeAgo(data.lastRefresh)}</span>}
            </>
          )}
          {hasActiveFilters && viewMode !== 'saved' && (
            <button className="btn" style={{ padding: '2px 8px', fontSize: '10px' }} onClick={clearFilters}>
              Clear filters
            </button>
          )}
        </div>
      )}

      {/* ── Critical This Week ── */}
      {!loading && viewMode === 'feed' && criticalThisWeek.length > 0 && (
        <div className="crit-week-section">
          <button className="crit-week-header" onClick={() => setCritWeekExpanded(v => !v)}>
            <span>🔴 Critical This Week</span>
            <span className="crit-week-count">{criticalThisWeek.length}</span>
            <span className="crit-week-toggle">{critWeekExpanded ? '▲' : '▼'}</span>
          </button>
          {critWeekExpanded && (
            <div className="crit-week-list">
              {criticalThisWeek.map(item => {
                const sev = computeSeverity(item, kevSet2);
                return (
                  <a key={item.id} href={item.link} target="_blank" rel="noopener noreferrer" className="crit-week-item">
                    {sev.isKev && <span className="crit-week-kev-badge">KEV</span>}
                    <span className="crit-week-title">{item.title}</span>
                    <span className="crit-week-meta">
                      {item.source} · {timeAgo(item.pubDate)}
                      {item.cves.length > 0 && <span className="crit-week-cve"> · {item.cves[0]}{item.cves.length > 1 ? ` +${item.cves.length - 1}` : ''}</span>}
                    </span>
                  </a>
                );
              })}
              <button className="crit-week-viewall" onClick={() => { setSevFilter('CRITICAL'); setTimeFilter('7d'); }}>
                View all {criticalThisWeek.length} critical this week →
              </button>
            </div>
          )}
        </div>
      )}

      {/* ── Pinned Articles ── */}
      {!loading && viewMode === 'feed' && pinnedArticles.size > 0 && (
        <div className="pinned-section">
          <div className="pinned-section-header"><span>📌 Pinned ({pinnedArticles.size})</span></div>
          <div className="pinned-list">
            {[...pinnedArticles.values()].map(item => {
              const srcStyle = getSourceStyle(item.source);
              const sev = computeSeverity(item, kevSet2);
              return (
                <div key={item.id} className="pinned-item">
                  <span className={`sev-badge sev-badge-${sev.level.toLowerCase()}`}>
                    {sev.level === 'CRITICAL' ? 'CRIT' : sev.level}
                  </span>
                  <span className="source-badge" style={{ background: srcStyle.bg, color: srcStyle.color }}>{item.source}</span>
                  <a href={item.link} target="_blank" rel="noopener noreferrer" className="pinned-item-title">{item.title}</a>
                  <span className="pinned-item-meta">{timeAgo(item.pubDate)}</span>
                  <button className="btn-pin active" onClick={() => togglePin(item)} title="Unpin"><IconPin filled={true} /></button>
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* ── Threat Actor Spotlight ── */}
      {!loading && viewMode === 'feed' && activeActors.length > 0 && (
        <div className="actor-section">
          <div className="actor-header">⚡ Active Threat Actors (past 7 days)</div>
          <div className="actor-list">
            {activeActors.map(actor => (
              <button key={actor.name} className="actor-chip"
                onClick={() => setSearch(actor.name.split('/')[0].split(' ')[0])}
                title={`${actor.origin} · ${actor.sector}`}>
                <span className="actor-name">{actor.name}</span>
                <span className="actor-count">{actor.count}</span>
                <span className="actor-origin">{actor.origin}</span>
              </button>
            ))}
          </div>
        </div>
      )}

      {/* ── Loading / Error / Empty states ── */}
      {loading && (
        <div className="loading-wrap" style={{ marginTop: 'calc(var(--header-h) + var(--filter-h))' }}>
          <div className="spinner" /><span>Fetching security intelligence feeds…</span>
        </div>
      )}
      {error && !loading && (
        <div className="error-wrap" style={{ marginTop: 'calc(var(--header-h) + var(--filter-h))' }}>
          <span style={{ fontSize: '24px' }}>⚠</span>
          <span className="error-msg">{error}</span>
          <button className="btn" onClick={() => fetchNews()}>Retry</button>
        </div>
      )}
      {!loading && !error && viewMode === 'saved' && savedArticles.size === 0 && (
        <div className="empty-wrap" style={{ marginTop: 'calc(var(--header-h) + var(--filter-h))' }}>
          <span style={{ fontSize: '24px' }}>🔖</span><span>No saved articles yet.</span>
        </div>
      )}
      {!loading && !error && viewMode === 'kev' && filteredItems.length === 0 && (
        <div className="empty-wrap" style={{ marginTop: 'calc(var(--header-h) + var(--filter-h))' }}>
          <span style={{ fontSize: '24px' }}>✅</span><span>No KEV matches in current articles.</span>
        </div>
      )}
      {!loading && !error && viewMode === 'feed' && filteredItems.length === 0 && data && (
        <div className="empty-wrap" style={{ marginTop: 'calc(var(--header-h) + var(--filter-h))' }}>
          <span style={{ fontSize: '24px' }}>🔍</span><span>No articles match your filters.</span>
          <button className="btn" onClick={clearFilters}>Clear filters</button>
        </div>
      )}

      {/* ── Trends View ── */}
      {!loading && viewMode === 'trends' && (
        <div className="trends-view">
          <div className="trends-header">
            <h2 className="trends-title">7-Day Threat Volume</h2>
            <div className="trends-legend">
              <span className="legend-dot" style={{ background: '#ef4444' }} />CRITICAL
              <span className="legend-dot" style={{ background: '#f97316', marginLeft: 12 }} />HIGH
              <span className="legend-dot" style={{ background: '#eab308', marginLeft: 12 }} />MEDIUM
              <span className="legend-dot" style={{ background: '#334155', marginLeft: 12 }} />LOW
            </div>
          </div>
          <div className="trends-chart-wrap">
            <TrendChart data={trendData} />
          </div>

          {/* Summary stats */}
          <div className="trends-stats">
            {(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'] as Severity[]).map(level => {
              const total = trendData.reduce((sum, d) => sum + d[level], 0);
              return (
                <div key={level} className={`trends-stat-card sev-${level.toLowerCase()}`}>
                  <div className="trends-stat-num">{total}</div>
                  <div className="trends-stat-label">{level} (7d)</div>
                </div>
              );
            })}
          </div>

          {/* Threat Actor summary in trends */}
          {activeActors.length > 0 && (
            <div className="trends-actors">
              <div className="trends-section-title">Active Threat Actors (past 7 days)</div>
              <div className="actor-list">
                {activeActors.map(actor => (
                  <button key={actor.name} className="actor-chip"
                    onClick={() => { setSearch(actor.name.split('/')[0].split(' ')[0]); setViewMode('feed'); }}>
                    <span className="actor-name">{actor.name}</span>
                    <span className="actor-count">{actor.count}</span>
                    <span className="actor-origin">{actor.origin}</span>
                  </button>
                ))}
              </div>
            </div>
          )}
        </div>
      )}

      {/* ── CVE Stack Tracker View ── */}
      {!loading && viewMode === 'cve-tracker' && (
        <div className="cve-tracker-view">
          <div className="cve-tracker-header">
            <div>
              <h2 className="cve-tracker-title">Stack CVE Tracker</h2>
              {cveTracker && (
                <span className="cve-tracker-sub">
                  {filteredCves.length} CVEs · last updated {timeAgo(new Date(cveTracker.lastFetched).toISOString())}
                </span>
              )}
            </div>
            <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
              <select className="cve-sort-select" value={cveSort} onChange={e => setCveSort(e.target.value as 'cvss' | 'date')}>
                <option value="cvss">Sort: CVSS ↓</option>
                <option value="date">Sort: Newest</option>
              </select>
              <button className="btn" onClick={fetchCveTracker} disabled={cveTrackerLoading}>
                {cveTrackerLoading ? 'Loading…' : 'Refresh'}
              </button>
            </div>
          </div>

          {/* Product filter */}
          <div className="cve-product-tabs">
            <button className={`pill${selectedProduct === 'all' ? ' active' : ''}`} onClick={() => setSelectedProduct('all')}>
              All products
            </button>
            {['Windows Server', 'Azure Active Directory Entra', 'Splunk Enterprise', 'Citrix NetScaler', 'F5 BIG-IP'].map((kw, i) => {
              const labels = ['Windows Server', 'Azure AD', 'Splunk', 'NetScaler', 'F5 BIG-IP'];
              return (
                <button key={kw} className={`pill${selectedProduct === kw ? ' active' : ''}`} onClick={() => setSelectedProduct(selectedProduct === kw ? 'all' : kw)}>
                  {labels[i]}
                </button>
              );
            })}
          </div>

          {cveTrackerLoading && (
            <div className="cve-loading">
              <div className="spinner" />
              <span>Querying NVD for your stack CVEs… (12h cache)</span>
            </div>
          )}

          {!cveTrackerLoading && filteredCves.length === 0 && (
            <div className="cve-empty">No CVEs found for the selected filter.</div>
          )}

          {!cveTrackerLoading && filteredCves.length > 0 && (
            <div className="cve-table-wrap">
              <table className="cve-table">
                <thead>
                  <tr>
                    <th>CVE</th>
                    <th>CVSS</th>
                    <th>Product</th>
                    <th>Published</th>
                    <th>Flags</th>
                    <th>Status</th>
                    <th>Description</th>
                  </tr>
                </thead>
                <tbody>
                  {filteredCves.map(entry => {
                    const st = cveTracker?.statuses[entry.id] ?? { status: 'new', notes: '' };
                    const sm = STATUS_META[st.status] ?? STATUS_META.new;
                    const isUpdating = updatingCve === entry.id;
                    return (
                      <tr key={entry.id} className={`cve-row${entry.isKev ? ' cve-row-kev' : ''}`}>
                        <td>
                          <a className="cve-id-link" href={`https://nvd.nist.gov/vuln/detail/${entry.id}`}
                            target="_blank" rel="noopener noreferrer">
                            {entry.id}
                          </a>
                          <button className="cve-splunk-btn"
                            onClick={() => handleCopy(generateSplunkQuery('cve', entry.id), `splunk-${entry.id}`)}
                            title="Copy Splunk SPL query for this CVE">
                            {copiedId === `splunk-${entry.id}` ? '✓ Copied' : 'SPL'}
                          </button>
                        </td>
                        <td>
                          {entry.score !== null ? (
                            <span className="cvss-score-badge" style={{ color: CVSS_COLOR(entry.score), borderColor: CVSS_COLOR(entry.score) }}>
                              {entry.score.toFixed(1)}
                            </span>
                          ) : <span style={{ color: 'var(--text-muted)' }}>—</span>}
                        </td>
                        <td><span className="cve-product-tag">{entry.productDisplay}</span></td>
                        <td className="cve-date">{new Date(entry.published).toLocaleDateString('en-GB', { day: '2-digit', month: 'short' })}</td>
                        <td>
                          {entry.isKev && <span className="kev-badge">⚠ KEV</span>}
                        </td>
                        <td>
                          <select className="cve-status-select"
                            value={st.status}
                            disabled={isUpdating}
                            onChange={e => updateCveStatus(entry.id, e.target.value)}
                            style={{ color: sm.color, background: sm.bg }}>
                            {Object.entries(STATUS_META).map(([k, v]) => (
                              <option key={k} value={k}>{v.label}</option>
                            ))}
                          </select>
                        </td>
                        <td className="cve-desc">{entry.description}</td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}

      {/* ── Articles Feed ── */}
      {!loading && !error && enrichedItems.length > 0 && (viewMode === 'feed' || viewMode === 'saved' || viewMode === 'kev') && (
        <main className="news-grid">
          {enrichedItems.map(({ item, severity, iocs, techniques, isNew }) => {
            const srcStyle = getSourceStyle(item.source);
            const isSaved = savedArticles.has(item.id);
            const isPinned = pinnedArticles.has(item.id);
            const isIOCOpen = expandedIOCs.has(item.id);
            const totalIOCs = iocs.ips.length + iocs.hashes.length + iocs.domains.length;
            const cardBorderColor = severity.level !== 'LOW' ? SEV_CSS_VAR[severity.level] : srcStyle.accent;

            return (
              <article key={item.id} className="news-card"
                style={{ '--source-color': cardBorderColor } as React.CSSProperties}>

                {/* Card Header */}
                <div className="card-header">
                  <div className="card-header-left">
                    <span className={`sev-badge sev-badge-${severity.level.toLowerCase()}`}>
                      {severity.level === 'CRITICAL' ? 'CRIT' : severity.level}
                    </span>
                    {severity.isKev && <span className="kev-badge">⚠ KEV</span>}
                    <span className="source-badge" style={{ background: srcStyle.bg, color: srcStyle.color }}>
                      {item.source}
                    </span>
                  </div>
                  <div className="card-meta">
                    {isNew && <span className="new-badge">NEW</span>}
                    <span className="time-ago">{timeAgo(item.pubDate)}</span>
                    <button className={`btn-save${isSaved ? ' saved' : ''}`}
                      onClick={() => toggleSave(item)} title={isSaved ? 'Remove from saved' : 'Save'}>
                      <IconBookmark filled={isSaved} />
                    </button>
                    <button className={`btn-pin${isPinned ? ' active' : ''}`}
                      onClick={() => togglePin(item)} title={isPinned ? 'Unpin' : 'Pin to top'}>
                      <IconPin filled={isPinned} />
                    </button>
                    <a className="read-link" href={item.link} target="_blank" rel="noopener noreferrer">Read ↗</a>
                  </div>
                </div>

                {/* Title */}
                <h2 className="card-title">
                  <a href={item.link} target="_blank" rel="noopener noreferrer">{item.title}</a>
                </h2>

                {/* CVE badges with CVSS */}
                {item.cves.length > 0 && (
                  <div className="cve-badges">
                    {item.cves.slice(0, 5).map(cve => {
                      const cvss = cvssScores[cve];
                      return (
                        <span key={cve} className="cve-badge-wrap">
                          <a className="cve-badge"
                            href={`https://nvd.nist.gov/vuln/detail/${cve}`}
                            target="_blank" rel="noopener noreferrer" title={`View ${cve} on NVD`}>
                            {cve}
                            {cvss?.score != null && (
                              <span className="cvss-inline" style={{ color: CVSS_COLOR(cvss.score) }}>
                                {' '}{cvss.score.toFixed(1)}
                              </span>
                            )}
                            {' '}↗
                          </a>
                          <button className="cve-spl-btn"
                            onClick={() => handleCopy(generateSplunkQuery('cve', cve), `spl-${cve}`)}
                            title="Copy Splunk query">
                            {copiedId === `spl-${cve}` ? '✓' : 'SPL'}
                          </button>
                        </span>
                      );
                    })}
                    {item.cves.length > 5 && <span className="cve-badge" style={{ opacity: 0.6 }}>+{item.cves.length - 5}</span>}
                  </div>
                )}

                {/* Description */}
                {item.description && <p className="card-description">{item.description}</p>}

                {/* ATT&CK */}
                {techniques.length > 0 && (
                  <div className="card-attacks">
                    {techniques.map(t => (
                      <span key={t.id} className="attack-badge" title={t.name}>{t.id} · {t.name}</span>
                    ))}
                  </div>
                )}

                {/* Tags */}
                {item.tags.length > 0 && (
                  <div className="card-tags">
                    {item.tags.map(tag => {
                      const ts = getTagStyle(tag);
                      return (
                        <span key={tag} className="tag"
                          style={{ background: ts.bg, color: ts.color, borderColor: ts.border, cursor: 'pointer' }}
                          onClick={() => setTagFilter(tag === tagFilter ? 'all' : tag)}>
                          {tag}
                        </span>
                      );
                    })}
                  </div>
                )}

                {/* IOC Panel */}
                {totalIOCs > 0 && (
                  <div className="ioc-section">
                    <button className={`ioc-toggle${isIOCOpen ? ' open' : ''}`} onClick={() => toggleIOC(item.id)}>
                      <span className="ioc-toggle-arrow">▶</span>
                      {isIOCOpen ? 'Hide IOCs' : `IOCs (${totalIOCs})`}
                    </button>

                    {isIOCOpen && (
                      <div className="ioc-panel">
                        {iocs.ips.length > 0 && (
                          <div>
                            <div className="ioc-group-label">IP Addresses</div>
                            <div className="ioc-group">
                              {iocs.ips.map(ip => {
                                const key = `ip-${ip}`;
                                return (
                                  <span key={ip} className="ioc-chip-row">
                                    <button className={`ioc-chip${copiedId === key ? ' copied' : ''}`}
                                      onClick={() => handleCopy(ip, key)} title={`Copy ${ip}`}>
                                      {ip}<span className="ioc-chip-icon">{copiedId === key ? '✓' : '⎘'}</span>
                                    </button>
                                    <button className="ioc-spl-btn"
                                      onClick={() => handleCopy(generateSplunkQuery('ip', ip), `spl-ip-${ip}`)}
                                      title="Copy Splunk SPL">
                                      {copiedId === `spl-ip-${ip}` ? '✓' : 'SPL'}
                                    </button>
                                  </span>
                                );
                              })}
                            </div>
                          </div>
                        )}

                        {iocs.hashes.length > 0 && (
                          <div>
                            <div className="ioc-group-label">Hashes</div>
                            <div className="ioc-group">
                              {iocs.hashes.map((h, idx) => {
                                const key = `hash-${idx}`;
                                const label = h.length === 64 ? 'SHA256' : h.length === 40 ? 'SHA1' : 'MD5';
                                return (
                                  <span key={h} className="ioc-chip-row">
                                    <button className={`ioc-chip${copiedId === key ? ' copied' : ''}`}
                                      onClick={() => handleCopy(h, key)} title={`${label}: ${h}`}>
                                      {h.slice(0, 16)}…<span className="ioc-chip-icon">{copiedId === key ? '✓' : '⎘'}</span>
                                    </button>
                                    <button className="ioc-spl-btn"
                                      onClick={() => handleCopy(generateSplunkQuery('hash', h), `spl-h-${idx}`)}
                                      title="Copy Splunk SPL">
                                      {copiedId === `spl-h-${idx}` ? '✓' : 'SPL'}
                                    </button>
                                  </span>
                                );
                              })}
                            </div>
                          </div>
                        )}

                        {iocs.domains.length > 0 && (
                          <div>
                            <div className="ioc-group-label">Domains</div>
                            <div className="ioc-group">
                              {iocs.domains.map((d, idx) => {
                                const key = `dom-${idx}`;
                                return (
                                  <span key={d} className="ioc-chip-row">
                                    <button className={`ioc-chip${copiedId === key ? ' copied' : ''}`}
                                      onClick={() => handleCopy(d, key)} title={`Copy ${d}`}>
                                      {d}<span className="ioc-chip-icon">{copiedId === key ? '✓' : '⎘'}</span>
                                    </button>
                                    <button className="ioc-spl-btn"
                                      onClick={() => handleCopy(generateSplunkQuery('domain', d), `spl-d-${idx}`)}
                                      title="Copy Splunk SPL">
                                      {copiedId === `spl-d-${idx}` ? '✓' : 'SPL'}
                                    </button>
                                  </span>
                                );
                              })}
                            </div>
                          </div>
                        )}

                        <button className="ioc-copy-all"
                          onClick={() => handleCopy([...iocs.ips, ...iocs.hashes, ...iocs.domains].join('\n'), `all-${item.id}`)}>
                          {copiedId === `all-${item.id}` ? '✓ Copied all IOCs' : 'Copy all IOCs'}
                        </button>
                      </div>
                    )}
                  </div>
                )}
              </article>
            );
          })}
        </main>
      )}
    </>
  );
}
