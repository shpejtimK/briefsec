'use client';

import { useState, useEffect, useMemo, useCallback } from 'react';

interface NewsItem {
  id: string;
  title: string;
  link: string;
  description: string;
  pubDate: string;
  source: string;
  tags: string[];
  cves: string[];
  author: string;
}

interface FeedData {
  items: NewsItem[];
  sources: string[];
  total: number;
  fromCache: boolean;
  lastRefresh: string | null;
}

// ── Source colors ──────────────────────────────────────────
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

function getSourceStyle(source: string) {
  return SOURCE_STYLES[source] ?? { bg: '#0d1124', color: '#94a3b8', accent: '#475569' };
}

// ── Tag colors ─────────────────────────────────────────────
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

export default function CyberWatch() {
  const [data, setData] = useState<FeedData | null>(null);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [sourceFilter, setSourceFilter] = useState('all');
  const [tagFilter, setTagFilter] = useState('all');
  const [search, setSearch] = useState('');
  const [autoRefresh, setAutoRefresh] = useState(true);

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

  useEffect(() => {
    if (!autoRefresh) return;
    const id = setInterval(() => fetchNews(true), 15 * 60 * 1000);
    return () => clearInterval(id);
  }, [autoRefresh, fetchNews]);

  const allTags = useMemo(() => {
    if (!data) return [];
    const counts = new Map<string, number>();
    data.items.forEach(i => i.tags.forEach(t => counts.set(t, (counts.get(t) ?? 0) + 1)));
    return [...counts.entries()].sort((a, b) => b[1] - a[1]).map(([t]) => t);
  }, [data]);

  const filteredItems = useMemo(() => {
    if (!data) return [];
    let items = data.items;
    if (sourceFilter !== 'all') items = items.filter(i => i.source === sourceFilter);
    if (tagFilter !== 'all') items = items.filter(i => i.tags.includes(tagFilter));
    if (search.trim()) {
      const q = search.toLowerCase();
      items = items.filter(i =>
        i.title.toLowerCase().includes(q) ||
        i.description.toLowerCase().includes(q) ||
        i.cves.some(c => c.toLowerCase().includes(q)) ||
        i.source.toLowerCase().includes(q)
      );
    }
    return items;
  }, [data, sourceFilter, tagFilter, search]);

  const cveCount = useMemo(() => {
    if (!data) return 0;
    return data.items.filter(i => i.cves.length > 0).length;
  }, [data]);

  return (
    <>
      {/* ── Header ── */}
      <header className="header">
        <div className="header-brand">
          {/* eslint-disable-next-line @next/next/no-img-element */}
          <img src="/favicon.svg" alt="" width={28} height={28} style={{ borderRadius: '5px', flexShrink: 0 }} />
          <div className="header-logo">Cyber<span>Watch</span></div>
          <span className="header-subtitle">Security Intelligence Feed</span>
        </div>
        <div className="header-actions">
          <button
            className={`btn btn-refresh${refreshing ? ' spinning' : ''}`}
            onClick={() => fetchNews(true)}
            disabled={refreshing}
          >
            <IconRefresh spin={refreshing} />
            {refreshing ? 'Refreshing…' : 'Refresh'}
          </button>
          <button
            className={`btn btn-auto${autoRefresh ? ' active' : ''}`}
            onClick={() => setAutoRefresh(v => !v)}
            title="Auto-refresh every 15 minutes"
          >
            Auto {autoRefresh ? 'ON' : 'OFF'}
          </button>
        </div>
      </header>

      {/* ── Filter Bar ── */}
      <div className="filter-bar">
        {/* Row 1: Sources */}
        <div className="filter-row">
          <span className="filter-label">Source</span>
          <button
            className={`pill${sourceFilter === 'all' ? ' active' : ''}`}
            onClick={() => setSourceFilter('all')}
          >All</button>
          {(data?.sources ?? []).map(src => (
            <button
              key={src}
              className={`pill${sourceFilter === src ? ' active' : ''}`}
              onClick={() => setSourceFilter(src === sourceFilter ? 'all' : src)}
              style={sourceFilter === src ? {
                background: getSourceStyle(src).bg,
                color: getSourceStyle(src).color,
                borderColor: getSourceStyle(src).accent,
              } : {}}
            >{src}</button>
          ))}
        </div>

        {/* Row 2: Tags */}
        <div className="filter-row">
          <span className="filter-label">Tag</span>
          <button
            className={`pill${tagFilter === 'all' ? ' active' : ''}`}
            onClick={() => setTagFilter('all')}
          >All</button>
          {allTags.map(tag => {
            const s = getTagStyle(tag);
            return (
              <button
                key={tag}
                className={`pill${tagFilter === tag ? ' active' : ''}`}
                onClick={() => setTagFilter(tag === tagFilter ? 'all' : tag)}
                style={tagFilter === tag ? { background: s.bg, color: s.color, borderColor: s.border } : {}}
              >{tag}</button>
            );
          })}
        </div>

        {/* Row 3: Search (full width on all screens) */}
        <div className="search-row">
          <IconSearch />
          <input
            className="search-input"
            placeholder="Search articles, CVEs, sources…"
            value={search}
            onChange={e => setSearch(e.target.value)}
          />
        </div>
      </div>

      {/* ── Stats Bar ── */}
      {data && !loading && (
        <div className="stats-bar">
          <span><span className="stats-count">{filteredItems.length}</span> articles</span>
          <span>·</span>
          <span><span className="stats-count">{data.sources.length}</span> sources</span>
          {cveCount > 0 && (
            <>
              <span>·</span>
              <span><span className="stats-count" style={{ color: '#ef4444' }}>{cveCount}</span> with CVEs</span>
            </>
          )}
          <span className="live-dot">Live</span>
          {(sourceFilter !== 'all' || tagFilter !== 'all' || search) && (
            <button
              className="btn"
              style={{ padding: '2px 8px', fontSize: '10px' }}
              onClick={() => { setSourceFilter('all'); setTagFilter('all'); setSearch(''); }}
            >Clear filters</button>
          )}
        </div>
      )}

      {/* ── Loading ── */}
      {loading && (
        <div className="loading-wrap" style={{ marginTop: 'calc(var(--header-h) + var(--filter-h))' }}>
          <div className="spinner" />
          <span>Fetching security feeds…</span>
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

      {/* ── Empty ── */}
      {!loading && !error && filteredItems.length === 0 && (
        <div className="empty-wrap" style={{ marginTop: 'calc(var(--header-h) + var(--filter-h))' }}>
          <span style={{ fontSize: '24px' }}>🔍</span>
          <span>No articles match your filters.</span>
          <button className="btn" onClick={() => { setSourceFilter('all'); setTagFilter('all'); setSearch(''); }}>
            Clear filters
          </button>
        </div>
      )}

      {/* ── Articles ── */}
      {!loading && !error && filteredItems.length > 0 && (
        <main className="news-grid">
          {filteredItems.map(item => {
            const srcStyle = getSourceStyle(item.source);
            return (
              <article
                key={item.id}
                className="news-card"
                style={{ '--source-color': srcStyle.accent } as React.CSSProperties}
              >
                <div className="card-header">
                  <span className="source-badge" style={{ background: srcStyle.bg, color: srcStyle.color }}>
                    {item.source}
                  </span>
                  <div className="card-meta">
                    <span className="time-ago">{timeAgo(item.pubDate)}</span>
                    <a className="read-link" href={item.link} target="_blank" rel="noopener noreferrer">
                      Read ↗
                    </a>
                  </div>
                </div>

                <h2 className="card-title">
                  <a href={item.link} target="_blank" rel="noopener noreferrer">{item.title}</a>
                </h2>

                {item.cves.length > 0 && (
                  <div className="cve-badges">
                    {item.cves.slice(0, 4).map(cve => (
                      <span key={cve} className="cve-badge">{cve}</span>
                    ))}
                  </div>
                )}

                {item.description && (
                  <p className="card-description">{item.description}</p>
                )}

                {item.tags.length > 0 && (
                  <div className="card-tags">
                    {item.tags.map(tag => {
                      const ts = getTagStyle(tag);
                      return (
                        <span
                          key={tag}
                          className="tag"
                          style={{ background: ts.bg, color: ts.color, borderColor: ts.border, cursor: 'pointer' }}
                          onClick={() => setTagFilter(tag === tagFilter ? 'all' : tag)}
                        >{tag}</span>
                      );
                    })}
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
