'use client';

import { useState, useEffect, useMemo, useCallback, useRef } from 'react';

// ─── Types ───────────────────────────────────────────────────────────────────

interface NewsItem {
  id: string;
  title: string;
  link: string;
  description: string;
  content: string;
  pubDate: string;
  source: string;
  tags: string[];
  cves: string[];
  author: string;
}

type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
type SortBy = 'newest' | 'severity';
type ViewMode = 'feed' | 'saved' | 'kev';

interface SeverityResult { level: Severity; isKev: boolean; }
interface IOCResult { ips: string[]; hashes: string[]; domains: string[]; }
interface AttackTechnique { id: string; name: string; }

interface EnrichedItem {
  item: NewsItem;
  severity: SeverityResult;
  iocs: IOCResult;
  techniques: AttackTechnique[];
  isNew: boolean;
}

interface FeedData {
  items: NewsItem[];
  sources: string[];
  total: number;
  fromCache: boolean;
  lastRefresh: string | null;
}

// ─── Source & Tag Styles (unchanged) ─────────────────────────────────────────

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
};

const TAG_STYLES: Record<string, { bg: string; color: string; border: string }> = {
  'CVE':            { bg: 'rgba(239,68,68,0.12)',   color: '#fca5a5', border: 'rgba(239,68,68,0.4)' },
  'Zero-Day':       { bg: 'rgba(249,115,22,0.12)',  color: '#fdba74', border: 'rgba(249,115,22,0.4)' },
  'Ransomware':     { bg: 'rgba(168,85,247,0.12)',  color: '#d8b4fe', border: 'rgba(168,85,247,0.4)' },
  'Malware':        { bg: 'rgba(139,92,246,0.12)',  color: '#c4b5fd', border: 'rgba(139,92,246,0.4)' },
  'Phishing':       { bg: 'rgba(236,72,153,0.12)',  color: '#f9a8d4', border: 'rgba(236,72,153,0.4)' },
  'Breach':         { bg: 'rgba(239,68,68,0.10)',   color: '#fca5a5', border: 'rgba(239,68,68,0.35)' },
  'Vulnerability':  { bg: 'rgba(234,179,8,0.10)',   color: '#fde047', border: 'rgba(234,179,8,0.35)' },
  'Patch Tuesday':  { bg: 'rgba(59,130,246,0.10)',  color: '#93c5fd', border: 'rgba(59,130,246,0.3)' },
  'APT':            { bg: 'rgba(245,158,11,0.10)',  color: '#fcd34d', border: 'rgba(245,158,11,0.35)' },
  'Nation-State':   { bg: 'rgba(100,116,139,0.15)', color: '#cbd5e1', border: 'rgba(100,116,139,0.4)' },
  'Supply Chain':   { bg: 'rgba(6,182,212,0.10)',   color: '#67e8f9', border: 'rgba(6,182,212,0.3)' },
  'AI/ML':          { bg: 'rgba(99,102,241,0.10)',  color: '#a5b4fc', border: 'rgba(99,102,241,0.3)' },
  'Cloud':          { bg: 'rgba(14,165,233,0.10)',  color: '#7dd3fc', border: 'rgba(14,165,233,0.3)' },
  'Privacy':        { bg: 'rgba(16,185,129,0.10)',  color: '#6ee7b7', border: 'rgba(16,185,129,0.3)' },
  'ICS/OT':         { bg: 'rgba(234,88,12,0.10)',   color: '#fdba74', border: 'rgba(234,88,12,0.3)' },
};

// ─── MITRE ATT&CK Mapping ─────────────────────────────────────────────────────

const ATTACK_MAP: Array<{ pattern: RegExp; id: string; name: string }> = [
  { pattern: /phish|spear.?phish/i,                           id: 'T1566', name: 'Phishing' },
  { pattern: /supply chain|dependency confus|typosquat/i,      id: 'T1195', name: 'Supply Chain' },
  { pattern: /ransomware/i,                                    id: 'T1486', name: 'Data Encrypted' },
  { pattern: /credential.?stuff|brute.?force|password.?spray/i, id: 'T1110', name: 'Brute Force' },
  { pattern: /remote code exec|\brce\b/i,                      id: 'T1059', name: 'Code Execution' },
  { pattern: /sql inject/i,                                    id: 'T1190', name: 'Exploit Public App' },
  { pattern: /zero.?day|0day/i,                                id: 'T1203', name: 'Client Exploit' },
  { pattern: /backdoor|webshell|web shell/i,                   id: 'T1505', name: 'Server Component' },
  { pattern: /privilege.escalat|\beop\b/i,                     id: 'T1068', name: 'Priv Escalation' },
  { pattern: /exfiltrat|data theft|stolen.?data/i,             id: 'T1041', name: 'Exfiltration' },
  { pattern: /command.and.control|\bc2\b|\bc&c\b|beacon/i,     id: 'T1071', name: 'C2 Protocol' },
  { pattern: /pass.the.hash|kerberoast|lateral movement/i,     id: 'T1550', name: 'Alt Auth Material' },
  { pattern: /defense.evasion|obfuscat/i,                      id: 'T1027', name: 'Obfuscation' },
  { pattern: /watering.hole/i,                                 id: 'T1189', name: 'Drive-by' },
  { pattern: /living.off.the.land|lolbin|lolbas/i,             id: 'T1218', name: 'Signed Binary' },
];

// ─── Severity Patterns ────────────────────────────────────────────────────────

const CRIT_KEYWORDS =
  /actively exploit|exploited in the wild|emergency.?patch|weaponized|wormable|mass exploitation|under.?attack/i;

const HIGH_KEYWORDS =
  /\brce\b|remote code exec|unauthenticated|pre.?auth|privilege escalat|arbitrary code|critical.?vuln/i;

// ─── Helper Functions ─────────────────────────────────────────────────────────

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
  if (item.tags.includes('Malware')) return { level: 'MEDIUM', isKev: false };
  if (item.tags.includes('Phishing')) return { level: 'MEDIUM', isKev: false };
  if (item.tags.includes('Breach')) return { level: 'MEDIUM', isKev: false };
  if (item.tags.includes('Patch Tuesday')) return { level: 'MEDIUM', isKev: false };

  return { level: 'LOW', isKev: false };
}

function detectTechniques(text: string): AttackTechnique[] {
  const seen = new Set<string>();
  const out: AttackTechnique[] = [];
  for (const { pattern, id, name } of ATTACK_MAP) {
    if (!seen.has(id) && pattern.test(text)) {
      seen.add(id);
      out.push({ id, name });
    }
    if (out.length >= 4) break;
  }
  return out;
}

function extractIOCs(text: string): IOCResult {
  const t = text.replace(/\[\.]/g, '.').replace(/hxxp/gi, 'http');

  const rawIPs = (t.match(/\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)\b/g) || []);
  const ips = [...new Set(rawIPs)]
    .filter(ip => !/^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|127\.|0\.|255\.|169\.254\.)/.test(ip))
    .slice(0, 10);

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
  try {
    await navigator.clipboard.writeText(text);
  } catch {
    const el = document.createElement('textarea');
    el.value = text;
    Object.assign(el.style, { position: 'fixed', opacity: '0', top: '0', left: '0' });
    document.body.appendChild(el);
    el.select();
    document.execCommand('copy');
    document.body.removeChild(el);
  }
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
    `# BriefSec SOC Daily Brief`,
    `**Date:** ${date}`,
    `**Generated:** ${ts}`,
    `**Articles:** ${items.length} | **CRITICAL:** ${critical.length} | **HIGH:** ${high.length} | **CVEs:** ${allCVEs.length}`,
    ``,
    `---`,
    ``,
    `## 🔴 CRITICAL Alerts (${critical.length})`,
    ``,
  ];

  for (const { item, sev } of critical) {
    lines.push(`### ${item.title}`);
    lines.push(`- **Source:** ${item.source} · ${timeAgo(item.pubDate)}`);
    lines.push(`- **Link:** <${item.link}>`);
    if (sev.isKev) lines.push(`- **⚠ CISA KEV:** Confirmed exploited in the wild — patch immediately`);
    if (item.cves.length > 0) {
      const cveLinks = item.cves.map(c => `[${c}](https://nvd.nist.gov/vuln/detail/${c})`).join(', ');
      lines.push(`- **CVEs:** ${cveLinks}`);
    }
    if (item.description) lines.push(`- **Summary:** ${item.description.slice(0, 300)}`);
    lines.push(``);
  }

  lines.push(`---`, ``, `## 🟠 HIGH Priority (${high.length})`, ``);
  for (const { item } of high.slice(0, 20)) {
    const cveStr = item.cves.length > 0 ? ` — ${item.cves.join(', ')}` : '';
    lines.push(`- **[${item.title}](${item.link})** — ${item.source}${cveStr}`);
  }

  if (kevCVEs.length > 0) {
    lines.push(``, `---`, ``, `## ⚠ CISA KEV Matches (${kevCVEs.length} — Patch Immediately)`, ``);
    kevCVEs.forEach(c => lines.push(`- [${c}](https://nvd.nist.gov/vuln/detail/${c})`));
  }

  if (allCVEs.length > 0) {
    lines.push(``, `---`, ``, `## CVE Summary (${allCVEs.length})`, ``);
    allCVEs.forEach(c => lines.push(`- [${c}](https://nvd.nist.gov/vuln/detail/${c})`));
  }

  lines.push(``, `---`, ``, `## IOC Summary`, ``);
  if (allIPs.length > 0) {
    lines.push(`### IP Addresses`);
    allIPs.forEach(ip => lines.push(`- \`${ip}\``));
    lines.push(``);
  }
  if (allHashes.length > 0) {
    lines.push(`### File Hashes`);
    allHashes.forEach(h => lines.push(`- \`${h}\``));
    lines.push(``);
  }

  lines.push(`---`, ``, `*Generated by BriefSec — SOC Intelligence Feed*`);
  return lines.join('\n');
}

function downloadBrief(content: string): void {
  const date = new Date().toISOString().slice(0, 10);
  const blob = new Blob([content], { type: 'text/markdown; charset=utf-8' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `briefsec-soc-brief-${date}.md`;
  a.click();
  URL.revokeObjectURL(url);
}

// ─── Icons ───────────────────────────────────────────────────────────────────

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
    <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor"
      strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4" />
      <polyline points="7 10 12 15 17 10" />
      <line x1="12" y1="15" x2="12" y2="3" />
    </svg>
  );
}

// ─── SEV Helper ───────────────────────────────────────────────────────────────

const SEV_CSS_VAR: Record<Severity, string> = {
  CRITICAL: '#ef4444',
  HIGH:     '#f97316',
  MEDIUM:   '#eab308',
  LOW:      '#475569',
};

// ─── Main Component ───────────────────────────────────────────────────────────

export default function BriefSec() {
  // ── Core state ──────────────────────────────────────────────
  const [data, setData] = useState<FeedData | null>(null);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // ── KEV state ────────────────────────────────────────────────
  const [kevCves, setKevCves] = useState<string[]>([]);

  // ── Filter/view state ────────────────────────────────────────
  const [viewMode, setViewMode] = useState<ViewMode>('feed');
  const [sourceFilter, setSourceFilter] = useState('all');
  const [tagFilter, setTagFilter] = useState('all');
  const [sevFilter, setSevFilter] = useState<'ALL' | Severity>('ALL');
  const [search, setSearch] = useState('');
  const [timeFilter, setTimeFilter] = useState<'all' | '24h'>('all');
  const [sortBy, setSortBy] = useState<SortBy>('newest');

  // ── UI state ─────────────────────────────────────────────────
  const [theme, setTheme] = useState<'dark' | 'light'>('dark');
  const [autoRefresh, setAutoRefresh] = useState(true);
  const [savedArticles, setSavedArticles] = useState<Map<string, NewsItem>>(new Map());
  const [expandedIOCs, setExpandedIOCs] = useState<Set<string>>(new Set());
  const [lastVisit, setLastVisit] = useState<number>(0);
  const [copiedId, setCopiedId] = useState<string | null>(null);
  const [toast, setToast] = useState<string | null>(null);

  const prevCriticalIds = useRef<Set<string>>(new Set());
  const toastTimer = useRef<ReturnType<typeof setTimeout> | null>(null);

  // ── Bootstrap from localStorage ──────────────────────────────
  useEffect(() => {
    const savedTheme = localStorage.getItem('briefsec-theme') as 'dark' | 'light' | null;
    if (savedTheme) setTheme(savedTheme);

    const raw = localStorage.getItem('briefsec-saved');
    if (raw) {
      try {
        const obj = JSON.parse(raw) as Record<string, NewsItem>;
        setSavedArticles(new Map(Object.entries(obj)));
      } catch { /* ignore */ }
    }

    const storedVisit = localStorage.getItem('briefsec-last-visit');
    const prev = storedVisit ? parseInt(storedVisit, 10) : 0;
    setLastVisit(prev);
    localStorage.setItem('briefsec-last-visit', String(Date.now()));
  }, []);

  // ── Theme ────────────────────────────────────────────────────
  useEffect(() => {
    document.documentElement.classList.toggle('light', theme === 'light');
    localStorage.setItem('briefsec-theme', theme);
  }, [theme]);

  // ── KEV set (derived) ────────────────────────────────────────
  const kevSet = useMemo(() => new Set<string>(kevCves), [kevCves]);

  // ── Fetch news ───────────────────────────────────────────────
  const fetchNews = useCallback(async (isRefresh = false) => {
    if (isRefresh) setRefreshing(true);
    else setLoading(true);
    setError(null);
    try {
      const res = await fetch('/api/news', { cache: 'no-store' });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      setData(await res.json());
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Failed to load');
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }, []);

  useEffect(() => { fetchNews(); }, [fetchNews]);

  // ── Auto-refresh ─────────────────────────────────────────────
  useEffect(() => {
    if (!autoRefresh) return;
    const id = setInterval(() => fetchNews(true), 15 * 60 * 1000);
    return () => clearInterval(id);
  }, [autoRefresh, fetchNews]);

  // ── Fetch CISA KEV ───────────────────────────────────────────
  useEffect(() => {
    fetch('/api/kev')
      .then(r => r.ok ? r.json() : null)
      .then((d: { cves: string[] } | null) => { if (d?.cves) setKevCves(d.cves); })
      .catch(() => {/* KEV gracefully degrades */});
  }, []);

  // ── CRITICAL alert toast on refresh ──────────────────────────
  useEffect(() => {
    if (!data) return;
    const critIds = new Set(
      data.items
        .filter(i => computeSeverity(i, kevSet).level === 'CRITICAL')
        .map(i => i.id)
    );
    const newCrits = [...critIds].filter(id => !prevCriticalIds.current.has(id));
    if (prevCriticalIds.current.size > 0 && newCrits.length > 0) {
      if (toastTimer.current) clearTimeout(toastTimer.current);
      setToast(`${newCrits.length} new CRITICAL alert${newCrits.length > 1 ? 's' : ''} since last refresh`);
      toastTimer.current = setTimeout(() => setToast(null), 10000);
    }
    prevCriticalIds.current = critIds;
  }, [data, kevSet]);

  // ── Tags list (for filter bar) ───────────────────────────────
  const allTags = useMemo(() => {
    if (!data) return [];
    const counts = new Map<string, number>();
    data.items.forEach(i => i.tags.forEach(t => counts.set(t, (counts.get(t) ?? 0) + 1)));
    return [...counts.entries()].sort((a, b) => b[1] - a[1]).map(([t]) => t);
  }, [data]);

  // ── Threat counts (always from full 24h dataset) ─────────────
  const threatCounts = useMemo(() => {
    if (!data) return { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, kev: 0 };
    const cutoff = Date.now() - 86_400_000;
    const recent = data.items.filter(i => new Date(i.pubDate).getTime() > cutoff);
    const counts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, kev: 0 };
    for (const item of recent) {
      const s = computeSeverity(item, kevSet);
      counts[s.level]++;
      if (s.isKev) counts.kev++;
    }
    return counts;
  }, [data, kevSet]);

  // ── KEV article count ────────────────────────────────────────
  const kevCount = useMemo(
    () => (data?.items ?? []).filter(i => i.cves.some(c => kevSet.has(c))).length,
    [data, kevSet]
  );

  // ── Unread count ─────────────────────────────────────────────
  const unreadCount = useMemo(
    () => lastVisit === 0 ? 0 : (data?.items ?? []).filter(i => new Date(i.pubDate).getTime() > lastVisit).length,
    [data, lastVisit]
  );

  // ── Filtered items ───────────────────────────────────────────
  const filteredItems = useMemo(() => {
    if (viewMode === 'saved') {
      return [...savedArticles.values()].sort(
        (a, b) => new Date(b.pubDate).getTime() - new Date(a.pubDate).getTime()
      );
    }

    if (!data) return [];

    let items = viewMode === 'kev'
      ? data.items.filter(i => i.cves.some(c => kevSet.has(c)))
      : data.items;

    if (sourceFilter !== 'all') items = items.filter(i => i.source === sourceFilter);
    if (tagFilter !== 'all') items = items.filter(i => i.tags.includes(tagFilter));
    if (sevFilter !== 'ALL') items = items.filter(i => computeSeverity(i, kevSet).level === sevFilter);

    if (timeFilter === '24h') {
      const cutoff = Date.now() - 86_400_000;
      items = items.filter(i => new Date(i.pubDate).getTime() > cutoff);
    }

    if (search.trim()) {
      const q = search.toLowerCase();
      items = items.filter(i =>
        i.title.toLowerCase().includes(q) ||
        i.description.toLowerCase().includes(q) ||
        i.cves.some(c => c.toLowerCase().includes(q)) ||
        i.source.toLowerCase().includes(q)
      );
    }

    if (sortBy === 'severity') {
      const rank: Record<Severity, number> = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 };
      items = [...items].sort((a, b) => {
        const diff = rank[computeSeverity(a, kevSet).level] - rank[computeSeverity(b, kevSet).level];
        if (diff !== 0) return diff;
        return new Date(b.pubDate).getTime() - new Date(a.pubDate).getTime();
      });
    }

    return items;
  }, [data, sourceFilter, tagFilter, sevFilter, search, timeFilter, viewMode, savedArticles, sortBy, kevSet]);

  // ── Enriched items (computed once per filteredItems change) ──
  const enrichedItems = useMemo<EnrichedItem[]>(
    () => filteredItems.map(item => ({
      item,
      severity: computeSeverity(item, kevSet),
      iocs: extractIOCs(`${item.description} ${item.content || ''}`),
      techniques: detectTechniques(`${item.title} ${item.description}`),
      isNew: lastVisit > 0 && new Date(item.pubDate).getTime() > lastVisit,
    })),
    [filteredItems, kevSet, lastVisit]
  );

  // ── Active filters check ─────────────────────────────────────
  const hasActiveFilters = sourceFilter !== 'all' || tagFilter !== 'all' || search.trim() !== '' || timeFilter !== 'all' || sevFilter !== 'ALL';

  // ── Handlers ─────────────────────────────────────────────────
  const toggleSave = useCallback((item: NewsItem) => {
    setSavedArticles(prev => {
      const next = new Map(prev);
      if (next.has(item.id)) next.delete(item.id);
      else next.set(item.id, item);
      const obj: Record<string, NewsItem> = {};
      next.forEach((v, k) => { obj[k] = v; });
      localStorage.setItem('briefsec-saved', JSON.stringify(obj));
      return next;
    });
  }, []);

  const toggleIOC = useCallback((id: string) => {
    setExpandedIOCs(prev => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  }, []);

  const handleCopy = useCallback(async (text: string, copyKey: string) => {
    await copyToClipboard(text);
    setCopiedId(copyKey);
    setTimeout(() => setCopiedId(null), 1500);
  }, []);

  const markAllRead = useCallback(() => {
    const now = Date.now();
    setLastVisit(now);
    localStorage.setItem('briefsec-last-visit', String(now));
  }, []);

  const clearFilters = useCallback(() => {
    setSourceFilter('all');
    setTagFilter('all');
    setSearch('');
    setTimeFilter('all');
    setSevFilter('ALL');
  }, []);

  // ─────────────────────────────────────────────────────────────
  //  Render
  // ─────────────────────────────────────────────────────────────

  return (
    <>
      {/* ── Toast ── */}
      {toast && (
        <div className="toast-alert">
          <span>⚠ {toast}</span>
          <button className="toast-view-btn" onClick={() => { setSevFilter('CRITICAL'); setToast(null); }}>
            View
          </button>
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

        {/* Threat strip — visible on wide screens */}
        {data && !loading && (
          <div className="threat-strip">
            <span className="threat-item threat-item-crit"
              onClick={() => setSevFilter(sevFilter === 'CRITICAL' ? 'ALL' : 'CRITICAL')}>
              🔴 {threatCounts.CRITICAL} CRIT
            </span>
            <span className="threat-strip-sep" />
            <span className="threat-item threat-item-high"
              onClick={() => setSevFilter(sevFilter === 'HIGH' ? 'ALL' : 'HIGH')}>
              🟠 {threatCounts.HIGH} HIGH
            </span>
            <span className="threat-strip-sep" />
            <span className="threat-item threat-item-med"
              onClick={() => setSevFilter(sevFilter === 'MEDIUM' ? 'ALL' : 'MEDIUM')}>
              🟡 {threatCounts.MEDIUM} MED
            </span>
            {threatCounts.kev > 0 && (
              <>
                <span className="threat-strip-sep" />
                <span className="threat-item threat-item-kev"
                  onClick={() => setViewMode('kev')}>
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
          <button
            className="btn btn-export"
            onClick={() => downloadBrief(generateBrief(data?.items ?? [], kevSet))}
            title="Download SOC daily brief as Markdown"
          >
            <IconDownload />
            <span>Export Brief</span>
          </button>
          <button className="btn btn-icon" onClick={() => setTheme(t => t === 'dark' ? 'light' : 'dark')}
            title={theme === 'dark' ? 'Light mode' : 'Dark mode'}>
            {theme === 'dark' ? <IconSun /> : <IconMoon />}
          </button>
          <button className={`btn btn-refresh${refreshing ? ' spinning' : ''}`}
            onClick={() => fetchNews(true)} disabled={refreshing}>
            <IconRefresh spin={refreshing} />
            {refreshing ? 'Refreshing…' : 'Refresh'}
          </button>
          <button className={`btn btn-auto${autoRefresh ? ' active' : ''}`}
            onClick={() => setAutoRefresh(v => !v)} title="Auto-refresh every 15 minutes">
            Auto {autoRefresh ? 'ON' : 'OFF'}
          </button>
        </div>
      </header>

      {/* ── Filter Bar ── */}
      <div className="filter-bar">
        {/* Row 0: View tabs + time + sort + export */}
        <div className="filter-top-row">
          <div className="view-tabs">
            <button className={`view-tab${viewMode === 'feed' ? ' active' : ''}`}
              onClick={() => setViewMode('feed')}>Feed</button>
            <button className={`view-tab${viewMode === 'saved' ? ' active' : ''}`}
              onClick={() => setViewMode('saved')}>
              Saved{savedArticles.size > 0 ? ` (${savedArticles.size})` : ''}
            </button>
            <button
              className={`view-tab kev-tab${viewMode === 'kev' ? ' active' : ''}`}
              onClick={() => setViewMode('kev')}>
              ⚠ KEV{kevCount > 0 ? ` (${kevCount})` : ''}
            </button>
          </div>

          <div className="filter-right-group">
            <div className="time-tabs">
              <button className={`view-tab${timeFilter === 'all' ? ' active' : ''}`}
                onClick={() => setTimeFilter('all')}>All time</button>
              <button className={`view-tab${timeFilter === '24h' ? ' active' : ''}`}
                onClick={() => setTimeFilter('24h')}>24h</button>
            </div>
            <span className="filter-sep" />
            <div className="sort-tabs">
              <button className={`view-tab${sortBy === 'newest' ? ' active' : ''}`}
                onClick={() => setSortBy('newest')}>Newest</button>
              <button className={`view-tab${sortBy === 'severity' ? ' active' : ''}`}
                onClick={() => setSortBy('severity')}>By Risk</button>
            </div>
          </div>
        </div>

        {/* Row 1: Severity filter */}
        <div className="filter-row">
          <span className="filter-label">Risk</span>
          <button className={`pill${sevFilter === 'ALL' ? ' active' : ''}`}
            onClick={() => setSevFilter('ALL')}>All</button>
          {(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'] as const).map(s => (
            <button key={s}
              className={`pill sev-pill-${s.toLowerCase()}${sevFilter === s ? ' active' : ''}`}
              onClick={() => setSevFilter(sevFilter === s ? 'ALL' : s)}>
              {s === 'CRITICAL' ? '🔴 CRITICAL' : s === 'HIGH' ? '🟠 HIGH' : s === 'MEDIUM' ? '🟡 MEDIUM' : '⚪ LOW'}
            </button>
          ))}
        </div>

        {/* Row 2: Source filter */}
        <div className="filter-row">
          <span className="filter-label">Source</span>
          <button className={`pill${sourceFilter === 'all' ? ' active' : ''}`}
            onClick={() => setSourceFilter('all')}>All</button>
          {(data?.sources ?? []).map(src => (
            <button key={src}
              className={`pill${sourceFilter === src ? ' active' : ''}`}
              onClick={() => setSourceFilter(src === sourceFilter ? 'all' : src)}
              style={sourceFilter === src ? {
                background: getSourceStyle(src).bg,
                color: getSourceStyle(src).color,
                borderColor: getSourceStyle(src).accent,
              } : {}}>
              {src}
            </button>
          ))}
        </div>

        {/* Row 3: Tag filter */}
        <div className="filter-row">
          <span className="filter-label">Tag</span>
          <button className={`pill${tagFilter === 'all' ? ' active' : ''}`}
            onClick={() => setTagFilter('all')}>All</button>
          {allTags.map(tag => {
            const s = getTagStyle(tag);
            return (
              <button key={tag}
                className={`pill${tagFilter === tag ? ' active' : ''}`}
                onClick={() => setTagFilter(tag === tagFilter ? 'all' : tag)}
                style={tagFilter === tag ? { background: s.bg, color: s.color, borderColor: s.border } : {}}>
                {tag}
              </button>
            );
          })}
        </div>

        {/* Row 4: Search */}
        <div className="search-row">
          <IconSearch />
          <input className="search-input"
            placeholder="Search articles, CVEs, IOCs, sources…"
            value={search}
            onChange={e => setSearch(e.target.value)} />
        </div>
      </div>

      {/* ── Threat Summary / Stats Bar ── */}
      {(data || viewMode === 'saved') && !loading && (
        <div className="stats-bar">
          {viewMode === 'saved' ? (
            <span><span className="stats-count">{savedArticles.size}</span> saved articles</span>
          ) : (
            <>
              <span>
                <span className="stats-count">{filteredItems.length}</span> articles
              </span>
              {viewMode === 'feed' && (
                <>
                  <span>·</span>
                  <span><span className="stats-count">{data?.sources.length ?? 0}</span> sources</span>
                </>
              )}
              {viewMode === 'kev' && kevCount > 0 && (
                <>
                  <span>·</span>
                  <span><span className="stats-kev-count">{kevCount}</span> KEV matches</span>
                </>
              )}
              <span className="live-dot">Live</span>
              {data?.lastRefresh && (
                <span>· Updated {timeAgo(data.lastRefresh)}</span>
              )}
            </>
          )}
          {hasActiveFilters && viewMode !== 'saved' && (
            <button className="btn" style={{ padding: '2px 8px', fontSize: '10px' }}
              onClick={clearFilters}>
              Clear filters
            </button>
          )}
        </div>
      )}

      {/* ── Loading ── */}
      {loading && (
        <div className="loading-wrap" style={{ marginTop: 'calc(var(--header-h) + var(--filter-h))' }}>
          <div className="spinner" />
          <span>Fetching security intelligence feeds…</span>
        </div>
      )}

      {/* ── Error ── */}
      {error && !loading && (
        <div className="error-wrap" style={{ marginTop: 'calc(var(--header-h) + var(--filter-h))' }}>
          <span style={{ fontSize: '24px' }}>⚠</span>
          <span className="error-msg">{error}</span>
          <button className="btn" onClick={() => fetchNews()}>Retry</button>
        </div>
      )}

      {/* ── Saved empty state ── */}
      {!loading && !error && viewMode === 'saved' && savedArticles.size === 0 && (
        <div className="empty-wrap" style={{ marginTop: 'calc(var(--header-h) + var(--filter-h))' }}>
          <span style={{ fontSize: '24px' }}>🔖</span>
          <span>No saved articles yet.</span>
          <span style={{ fontSize: '12px', color: 'var(--text-muted)' }}>
            Click the bookmark icon on any article to save it here.
          </span>
        </div>
      )}

      {/* ── KEV empty state ── */}
      {!loading && !error && viewMode === 'kev' && filteredItems.length === 0 && (
        <div className="empty-wrap" style={{ marginTop: 'calc(var(--header-h) + var(--filter-h))' }}>
          <span style={{ fontSize: '24px' }}>✅</span>
          <span>No KEV matches in current articles.</span>
          <span style={{ fontSize: '12px', color: 'var(--text-muted)' }}>
            CISA KEV catalog loaded — no articles reference actively exploited CVEs right now.
          </span>
        </div>
      )}

      {/* ── Feed empty state ── */}
      {!loading && !error && viewMode === 'feed' && filteredItems.length === 0 && data && (
        <div className="empty-wrap" style={{ marginTop: 'calc(var(--header-h) + var(--filter-h))' }}>
          <span style={{ fontSize: '24px' }}>🔍</span>
          <span>No articles match your filters.</span>
          <button className="btn" onClick={clearFilters}>Clear filters</button>
        </div>
      )}

      {/* ── Articles ── */}
      {!loading && !error && enrichedItems.length > 0 && (
        <main className="news-grid">
          {enrichedItems.map(({ item, severity, iocs, techniques, isNew }) => {
            const srcStyle = getSourceStyle(item.source);
            const isSaved = savedArticles.has(item.id);
            const isIOCOpen = expandedIOCs.has(item.id);
            const totalIOCs = iocs.ips.length + iocs.hashes.length + iocs.domains.length;
            const cardBorderColor = severity.level !== 'LOW' ? SEV_CSS_VAR[severity.level] : srcStyle.accent;

            return (
              <article
                key={item.id}
                className="news-card"
                style={{ '--source-color': cardBorderColor } as React.CSSProperties}
              >
                {/* ── Card Header ── */}
                <div className="card-header">
                  <div className="card-header-left">
                    <span className={`sev-badge sev-badge-${severity.level.toLowerCase()}`}>
                      {severity.level === 'CRITICAL' ? 'CRIT' : severity.level}
                    </span>
                    {severity.isKev && <span className="kev-badge">⚠ KEV</span>}
                    <span className="source-badge"
                      style={{ background: srcStyle.bg, color: srcStyle.color }}>
                      {item.source}
                    </span>
                  </div>
                  <div className="card-meta">
                    {isNew && <span className="new-badge">NEW</span>}
                    <span className="time-ago">{timeAgo(item.pubDate)}</span>
                    <button className={`btn-save${isSaved ? ' saved' : ''}`}
                      onClick={() => toggleSave(item)}
                      title={isSaved ? 'Remove from saved' : 'Save article'}>
                      <IconBookmark filled={isSaved} />
                    </button>
                    <a className="read-link" href={item.link} target="_blank" rel="noopener noreferrer">
                      Read ↗
                    </a>
                  </div>
                </div>

                {/* ── Title ── */}
                <h2 className="card-title">
                  <a href={item.link} target="_blank" rel="noopener noreferrer">{item.title}</a>
                </h2>

                {/* ── CVE Badges → NVD Links ── */}
                {item.cves.length > 0 && (
                  <div className="cve-badges">
                    {item.cves.slice(0, 5).map(cve => (
                      <a key={cve}
                        className="cve-badge"
                        href={`https://nvd.nist.gov/vuln/detail/${cve}`}
                        target="_blank"
                        rel="noopener noreferrer"
                        title={`View ${cve} on NVD`}>
                        {cve} ↗
                      </a>
                    ))}
                    {item.cves.length > 5 && (
                      <span className="cve-badge" style={{ opacity: 0.6 }}>
                        +{item.cves.length - 5}
                      </span>
                    )}
                  </div>
                )}

                {/* ── Description ── */}
                {item.description && (
                  <p className="card-description">{item.description}</p>
                )}

                {/* ── ATT&CK Techniques ── */}
                {techniques.length > 0 && (
                  <div className="card-attacks">
                    {techniques.map(t => (
                      <span key={t.id} className="attack-badge" title={t.name}>
                        {t.id} · {t.name}
                      </span>
                    ))}
                  </div>
                )}

                {/* ── Threat Tags ── */}
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

                {/* ── IOC Panel ── */}
                {totalIOCs > 0 && (
                  <div className="ioc-section">
                    <button
                      className={`ioc-toggle${isIOCOpen ? ' open' : ''}`}
                      onClick={() => toggleIOC(item.id)}>
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
                                  <button key={ip}
                                    className={`ioc-chip${copiedId === key ? ' copied' : ''}`}
                                    onClick={() => handleCopy(ip, key)}
                                    title={`Copy ${ip}`}>
                                    {ip}
                                    <span className="ioc-chip-icon">
                                      {copiedId === key ? '✓' : '⎘'}
                                    </span>
                                  </button>
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
                                  <button key={h}
                                    className={`ioc-chip${copiedId === key ? ' copied' : ''}`}
                                    onClick={() => handleCopy(h, key)}
                                    title={`${label}: ${h}`}>
                                    {h.slice(0, 16)}…
                                    <span className="ioc-chip-icon">
                                      {copiedId === key ? '✓' : '⎘'}
                                    </span>
                                  </button>
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
                                  <button key={d}
                                    className={`ioc-chip${copiedId === key ? ' copied' : ''}`}
                                    onClick={() => handleCopy(d, key)}
                                    title={`Copy ${d}`}>
                                    {d}
                                    <span className="ioc-chip-icon">
                                      {copiedId === key ? '✓' : '⎘'}
                                    </span>
                                  </button>
                                );
                              })}
                            </div>
                          </div>
                        )}

                        <button className="ioc-copy-all"
                          onClick={() => {
                            const all = [...iocs.ips, ...iocs.hashes, ...iocs.domains].join('\n');
                            handleCopy(all, `all-${item.id}`);
                          }}>
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
