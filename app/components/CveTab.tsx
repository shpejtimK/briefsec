'use client';

import { useMemo, useState } from 'react';
import type { CveData, CveItem, KevItem, Story } from '@/lib/types';
import { cveVendors } from '@/lib/stack-vendors';
import { CvssBadge, IconSearch, StackBadge, formatDate, nvdUrl, severityOf, timeAgo } from './ui';

const WINDOWS = [
  { key: '24h', label: '24h', ms: 86_400_000 },
  { key: '3d',  label: '3 days', ms: 3 * 86_400_000 },
  { key: '7d',  label: '7 days', ms: 7 * 86_400_000 },
] as const;

const SEVERITIES = ['critical', 'high', 'medium', 'low', 'none'] as const;
const PAGE = 100;

interface Props {
  data: CveData;
  newsByCve: Map<string, Story[]>;
}

export default function CveTab({ data, newsByCve }: Props) {
  const [windowKey, setWindowKey] = useState<(typeof WINDOWS)[number]['key']>('24h');
  const [severities, setSeverities] = useState<Set<string>>(new Set());
  const [hideWordpress, setHideWordpress] = useState(true);
  const [newsOnly, setNewsOnly] = useState(false);
  const [search, setSearch] = useState('');
  const [limit, setLimit] = useState(PAGE);
  const [kevExpanded, setKevExpanded] = useState(false);
  const [stackExpanded, setStackExpanded] = useState(false);

  const kevSet = useMemo(() => new Set(data.kevIds), [data.kevIds]);
  const vendorsOf = useMemo(() => {
    const map = new Map<string, string[]>();
    for (const c of data.cves) map.set(c.id, cveVendors(c.vendor, c.product, c.description));
    return map;
  }, [data.cves]);

  const windowed = useMemo(() => {
    const cutoff = Date.now() - WINDOWS.find(w => w.key === windowKey)!.ms;
    return data.cves.filter(c => new Date(c.published).getTime() >= cutoff);
  }, [data.cves, windowKey]);

  const stats = useMemo(() => {
    const day = Date.now() - 86_400_000;
    const last24 = data.cves.filter(c => new Date(c.published).getTime() >= day);
    return {
      last24: last24.length,
      critical24: last24.filter(c => severityOf(c.score, c.severity) === 'critical').length,
      high24: last24.filter(c => severityOf(c.score, c.severity) === 'high').length,
      kev7: data.kevRecent.filter(k => Date.now() - new Date(k.dateAdded).getTime() <= 7 * 86_400_000).length,
    };
  }, [data]);

  // Stack-vendor CVEs from the whole week, always on top: exploited first, then critical, then
  // high, and newest first within each
  const stackCves = useMemo(() => {
    const rank = (c: CveItem) => (kevSet.has(c.id) ? 0 : ({ critical: 1, high: 2 } as Record<string, number>)[severityOf(c.score, c.severity)] ?? 3);
    return data.cves
      .filter(c => (vendorsOf.get(c.id) || []).length > 0)
      .sort((a, b) => rank(a) - rank(b) || new Date(b.published).getTime() - new Date(a.published).getTime());
  }, [data.cves, vendorsOf, kevSet]);

  const filtered = useMemo(() => {
    let list = windowed;
    if (hideWordpress) list = list.filter(c => !c.wordpress);
    if (severities.size) list = list.filter(c => severities.has(severityOf(c.score, c.severity)));
    if (newsOnly) list = list.filter(c => newsByCve.has(c.id));
    const q = search.trim().toLowerCase();
    if (q) {
      list = list.filter(c => c.id.toLowerCase().includes(q) || c.vendor.toLowerCase().includes(q) ||
        c.product.toLowerCase().includes(q) || c.description.toLowerCase().includes(q));
    }
    return list;
  }, [windowed, hideWordpress, severities, newsOnly, search, newsByCve]);

  const sevCounts = useMemo(() => {
    const counts: Record<string, number> = {};
    for (const c of windowed) {
      if (hideWordpress && c.wordpress) continue;
      const s = severityOf(c.score, c.severity);
      counts[s] = (counts[s] || 0) + 1;
    }
    return counts;
  }, [windowed, hideWordpress]);

  const wordpressCount = windowed.filter(c => c.wordpress).length;
  const kevList = kevExpanded ? data.kevRecent : data.kevRecent.slice(0, 6);

  const toggleSeverity = (s: string) => setSeverities(prev => {
    const next = new Set(prev);
    if (next.has(s)) next.delete(s); else next.add(s);
    return next;
  });

  return (
    <div className="tab-body">
      <div className="stat-row">
        <div className="stat"><span className="stat-num">{stats.last24}</span><span className="stat-label">new CVEs in 24h</span></div>
        <div className="stat stat-critical"><span className="stat-num">{stats.critical24}</span><span className="stat-label">critical</span></div>
        <div className="stat stat-high"><span className="stat-num">{stats.high24}</span><span className="stat-label">high</span></div>
        <div className="stat stat-kev"><span className="stat-num">{stats.kev7}</span><span className="stat-label">added to KEV this week</span></div>
        <div className="stat-sync">NVD synced {timeAgo(data.nvdSyncedAt)} · KEV synced {timeAgo(data.kevSyncedAt)}</div>
      </div>

      {stackCves.length > 0 && (
        <section className="stack-section">
          <div className="section-head">
            <h2>★ Your stack</h2>
            <span className="section-sub">New CVEs for Citrix, Palo Alto, Splunk, VMray, Microsoft, Cisco and Oracle — last 7 days</span>
          </div>
          <CveTable rows={stackExpanded ? stackCves : stackCves.slice(0, 8)} kevSet={kevSet} vendorsOf={vendorsOf} newsByCve={newsByCve} />
          {stackCves.length > 8 && (
            <button className="more" onClick={() => setStackExpanded(v => !v)}>
              {stackExpanded ? 'Show fewer' : `Show all ${stackCves.length}`}
            </button>
          )}
        </section>
      )}

      <section>
        <div className="section-head">
          <h2>Actively exploited</h2>
          <span className="section-sub">Added to CISA&apos;s Known Exploited Vulnerabilities catalog — last 30 days</span>
        </div>
        <div className="kev-list">
          {kevList.map(k => <KevRow key={k.id} kev={k} newsByCve={newsByCve} />)}
        </div>
        {data.kevRecent.length > 6 && (
          <button className="more" onClick={() => setKevExpanded(v => !v)}>
            {kevExpanded ? 'Show fewer' : `Show all ${data.kevRecent.length}`}
          </button>
        )}
      </section>

      <section>
        <div className="section-head">
          <h2>New CVEs</h2>
          <span className="section-sub">Published to NVD · {filtered.length} shown</span>
        </div>
        <div className="toolbar">
          <div className="search">
            <IconSearch />
            <input placeholder="Search CVE ID, vendor, product, description…" value={search}
              onChange={e => { setSearch(e.target.value); setLimit(PAGE); }} />
          </div>
          <div className="seg">
            {WINDOWS.map(w => (
              <button key={w.key} className={windowKey === w.key ? 'active' : ''}
                onClick={() => { setWindowKey(w.key); setLimit(PAGE); }}>{w.label}</button>
            ))}
          </div>
        </div>
        <div className="chips">
          {SEVERITIES.map(s => (
            <button key={s} className={`chip sev-chip-${s}${severities.has(s) ? ' active' : ''}`} onClick={() => toggleSeverity(s)}>
              {s === 'none' ? 'Unscored' : s[0].toUpperCase() + s.slice(1)} <span className="chip-count">{sevCounts[s] || 0}</span>
            </button>
          ))}
          <span className="chip-sep" />
          <button className={`chip${newsOnly ? ' active' : ''}`} onClick={() => setNewsOnly(v => !v)}>In the news</button>
          <button className={`chip${hideWordpress ? ' active' : ''}`} onClick={() => setHideWordpress(v => !v)}
            title="WordPress plugin and theme CVEs make up a large share of new CVEs">
            Hide WordPress plugins <span className="chip-count">{wordpressCount}</span>
          </button>
        </div>
        {filtered.length === 0
          ? <div className="empty">No CVEs match.</div>
          : <CveTable rows={filtered.slice(0, limit)} kevSet={kevSet} vendorsOf={vendorsOf} newsByCve={newsByCve} />}
        {filtered.length > limit && (
          <button className="more" onClick={() => setLimit(l => l + PAGE)}>Show more ({filtered.length - limit} left)</button>
        )}
      </section>
    </div>
  );
}

function CveTable({ rows, kevSet, vendorsOf, newsByCve }: {
  rows: CveItem[]; kevSet: Set<string>; vendorsOf: Map<string, string[]>; newsByCve: Map<string, Story[]>;
}) {
  return (
    <div className="cve-table">
      {rows.map(c => <CveRow key={c.id} cve={c} kev={kevSet.has(c.id)} vendors={vendorsOf.get(c.id) || []} news={newsByCve.get(c.id) || []} />)}
    </div>
  );
}

function CveRow({ cve, kev, vendors, news }: { cve: CveItem; kev: boolean; vendors: string[]; news: Story[] }) {
  const [open, setOpen] = useState(false);
  const product = [cve.vendor, cve.product].filter(Boolean).join(' · ');
  return (
    <div className={`cve-row${kev ? ' cve-row-kev' : ''}`}>
      <CvssBadge score={cve.score} severity={cve.severity} />
      <div className="cve-main">
        <div className="cve-head">
          <a className="cve-id" href={nvdUrl(cve.id)} target="_blank" rel="noopener noreferrer">{cve.id}</a>
          {kev && <span className="kev-badge" title="Actively exploited — in CISA's KEV catalog">KEV</span>}
          <StackBadge vendors={vendors} />
          {product && <span className="cve-product">{product}</span>}
          {news.length > 0 && (
            <a className="news-badge" href={news[0].link} target="_blank" rel="noopener noreferrer"
              title={news.map(s => `${s.source}: ${s.title}`).join('\n')}>
              In the news{news.length > 1 ? ` (${news.length})` : ''}
            </a>
          )}
          <span className="cve-time" title={formatDate(cve.published)}>{timeAgo(cve.published)}</span>
        </div>
        <p className={`cve-desc${open ? ' open' : ''}`} onClick={() => setOpen(v => !v)}>{cve.description}</p>
        {open && (
          <div className="cve-details">
            {cve.cwe && <span>{cve.cwe}</span>}
            {cve.vector && <span className="mono">{cve.vector}</span>}
            {cve.refs.map(r => <a key={r} href={r} target="_blank" rel="noopener noreferrer">{hostOf(r)}</a>)}
          </div>
        )}
      </div>
    </div>
  );
}

function KevRow({ kev, newsByCve }: { kev: KevItem; newsByCve: Map<string, Story[]> }) {
  const vendors = cveVendors(kev.vendor, kev.product, '');
  const news = newsByCve.get(kev.id) || [];
  const overdue = new Date(kev.dueDate).getTime() < Date.now();
  return (
    <div className="kev-row">
      <div className="kev-date">{new Date(kev.dateAdded).toLocaleDateString('en-GB', { day: 'numeric', month: 'short' })}</div>
      <div className="kev-main">
        <div className="cve-head">
          <a className="cve-id" href={nvdUrl(kev.id)} target="_blank" rel="noopener noreferrer">{kev.id}</a>
          <StackBadge vendors={vendors} />
          <span className="cve-product">{kev.vendor} · {kev.product}</span>
          {kev.ransomware && <span className="ransomware-badge">Used by ransomware</span>}
          {news.length > 0 && (
            <a className="news-badge" href={news[0].link} target="_blank" rel="noopener noreferrer"
              title={news.map(s => `${s.source}: ${s.title}`).join('\n')}>
              In the news{news.length > 1 ? ` (${news.length})` : ''}
            </a>
          )}
        </div>
        <div className="kev-name">{kev.name}</div>
      </div>
      <div className={`kev-due${overdue ? ' overdue' : ''}`} title="CISA remediation deadline for US federal agencies">
        due {new Date(kev.dueDate).toLocaleDateString('en-GB', { day: 'numeric', month: 'short' })}
      </div>
    </div>
  );
}

function hostOf(url: string) {
  try { return new URL(url).host.replace(/^www\./, ''); } catch { return url; }
}
