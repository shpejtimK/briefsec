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

export default function BriefSec() {
  const [data, setData] = useState<FeedData | null>(null);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [sourceFilter, setSourceFilter] = useState('all');
  const [tagFilter, setTagFilter] = useState('all');
  const [search, setSearch] = useState('');
  const [autoRefresh, setAutoRefresh] = useState(true);
  const [theme, setTheme] = useState<'dark' | 'light'>('dark');
  const [viewMode, setViewMode] = useState<'feed' | 'saved'>('feed');
  const [timeFilter, setTimeFilter] = useState<'all' | '24h'>('all');
  const [savedArticles, setSavedArticles] = useState<Map<string, NewsItem>>(new Map());
  const [selectedArticle, setSelectedArticle] = useState<NewsItem | null>(null);

  // Load persisted preferences from localStorage
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
  }, []);

  // Apply theme class to <html>
  useEffect(() => {
    document.documentElement.classList.toggle('light', theme === 'light');
    localStorage.setItem('briefsec-theme', theme);
  }, [theme]);

  const toggleSave = useCallback((item: NewsItem) => {
    setSavedArticles(prev => {
      const next = new Map(prev);
      if (next.has(item.id)) {
        next.delete(item.id);
      } else {
        next.set(item.id, item);
      }
      const obj: Record<string, NewsItem> = {};
      next.forEach((v, k) => { obj[k] = v; });
      localStorage.setItem('briefsec-saved', JSON.stringify(obj));
      return next;
    });
  }, []);

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
    const handler = (e: KeyboardEvent) => { if (e.key === 'Escape') setSelectedArticle(null); };
    window.addEventListener('keydown', handler);
    return () => window.removeEventListener('keydown', handler);
  }, []);

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
    if (viewMode === 'saved') {
      return [...savedArticles.values()].sort(
        (a, b) => new Date(b.pubDate).getTime() - new Date(a.pubDate).getTime()
      );
    }

    if (!data) return [];
    let items = data.items;
    if (sourceFilter !== 'all') items = items.filter(i => i.source === sourceFilter);
    if (tagFilter !== 'all') items = items.filter(i => i.tags.includes(tagFilter));
    if (timeFilter === '24h') {
      const cutoff = Date.now() - 24 * 60 * 60 * 1000;
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
    return items;
  }, [data, sourceFilter, tagFilter, search, timeFilter, viewMode, savedArticles]);

  const cveCount = useMemo(() => {
    if (!data) return 0;
    return data.items.filter(i => i.cves.length > 0).length;
  }, [data]);

  const hasActiveFilters = sourceFilter !== 'all' || tagFilter !== 'all' || search || timeFilter !== 'all';

  return (
    <>
      {/* ── Header ── */}
      <header className="header">
        <div className="header-brand">
          {/* eslint-disable-next-line @next/next/no-img-element */}
          <img src="/favicon.svg" alt="" width={28} height={28} style={{ borderRadius: '5px', flexShrink: 0 }} />
          <div className="header-logo">Brief<span>Sec</span></div>
          <span className="header-subtitle">Security Intelligence Feed</span>
        </div>
        <div className="header-actions">
          <button
            className="btn btn-icon"
            onClick={() => setTheme(t => t === 'dark' ? 'light' : 'dark')}
            title={theme === 'dark' ? 'Switch to light mode' : 'Switch to dark mode'}
          >
            {theme === 'dark' ? <IconSun /> : <IconMoon />}
          </button>
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
        {/* Row 0: View tabs + time filter */}
        <div className="filter-top-row">
          <div className="view-tabs">
            <button
              className={`view-tab${viewMode === 'feed' ? ' active' : ''}`}
              onClick={() => setViewMode('feed')}
            >Feed</button>
            <button
              className={`view-tab${viewMode === 'saved' ? ' active' : ''}`}
              onClick={() => setViewMode('saved')}
            >Saved {savedArticles.size > 0 ? `(${savedArticles.size})` : ''}</button>
          </div>
          <div className="time-tabs">
            <button
              className={`view-tab${timeFilter === 'all' ? ' active' : ''}`}
              onClick={() => setTimeFilter('all')}
            >All time</button>
            <button
              className={`view-tab${timeFilter === '24h' ? ' active' : ''}`}
              onClick={() => setTimeFilter('24h')}
            >Last 24h</button>
          </div>
        </div>

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

        {/* Row 3: Search */}
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
      {(data || viewMode === 'saved') && !loading && (
        <div className="stats-bar">
          {viewMode === 'saved' ? (
            <span><span className="stats-count">{savedArticles.size}</span> saved articles</span>
          ) : (
            <>
              <span><span className="stats-count">{filteredItems.length}</span> articles</span>
              <span>·</span>
              <span><span className="stats-count">{data?.sources.length ?? 0}</span> sources</span>
              {cveCount > 0 && (
                <>
                  <span>·</span>
                  <span><span className="stats-count" style={{ color: 'var(--red)' }}>{cveCount}</span> with CVEs</span>
                </>
              )}
              <span className="live-dot">Live</span>
              {data?.lastRefresh && (
                <>
                  <span>·</span>
                  <span>Updated {timeAgo(data.lastRefresh)}</span>
                </>
              )}
            </>
          )}
          {hasActiveFilters && viewMode === 'feed' && (
            <button
              className="btn"
              style={{ padding: '2px 8px', fontSize: '10px' }}
              onClick={() => { setSourceFilter('all'); setTagFilter('all'); setSearch(''); setTimeFilter('all'); }}
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

      {/* ── Feed empty state ── */}
      {!loading && !error && viewMode === 'feed' && filteredItems.length === 0 && data && (
        <div className="empty-wrap" style={{ marginTop: 'calc(var(--header-h) + var(--filter-h))' }}>
          <span style={{ fontSize: '24px' }}>🔍</span>
          <span>No articles match your filters.</span>
          <button className="btn" onClick={() => { setSourceFilter('all'); setTagFilter('all'); setSearch(''); setTimeFilter('all'); }}>
            Clear filters
          </button>
        </div>
      )}

      {/* ── Articles ── */}
      {!loading && !error && filteredItems.length > 0 && (
        <main className="news-grid">
          {filteredItems.map(item => {
            const srcStyle = getSourceStyle(item.source);
            const isSaved = savedArticles.has(item.id);
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
                    <button
                      className={`btn-save${isSaved ? ' saved' : ''}`}
                      onClick={() => toggleSave(item)}
                      title={isSaved ? 'Remove from saved' : 'Save article'}
                    >
                      <IconBookmark filled={isSaved} />
                    </button>
                    <a className="read-link" href={item.link} target="_blank" rel="noopener noreferrer">
                      Read ↗
                    </a>
                  </div>
                </div>

                <h2 className="card-title">
                  <button onClick={() => setSelectedArticle(item)}>{item.title}</button>
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
      {/* ── Article Modal ── */}
      {selectedArticle && (() => {
        const item = selectedArticle;
        const srcStyle = getSourceStyle(item.source);
        return (
          <div className="modal-overlay" onClick={() => setSelectedArticle(null)}>
            <div className="modal" onClick={e => e.stopPropagation()}>
              <div className="modal-header">
                <div className="modal-meta">
                  <span className="source-badge" style={{ background: srcStyle.bg, color: srcStyle.color }}>
                    {item.source}
                  </span>
                  <span className="time-ago">{timeAgo(item.pubDate)}</span>
                </div>
                <button className="modal-close" onClick={() => setSelectedArticle(null)}>×</button>
              </div>

              <h2 className="modal-title">{item.title}</h2>

              {item.cves.length > 0 && (
                <div className="cve-badges" style={{ padding: '10px 20px 0' }}>
                  {item.cves.map(cve => (
                    <span key={cve} className="cve-badge">{cve}</span>
                  ))}
                </div>
              )}

              <div className="modal-body">
                {item.description || 'No summary available for this article.'}
              </div>

              {item.tags.length > 0 && (
                <div className="modal-tags">
                  {item.tags.map(tag => {
                    const ts = getTagStyle(tag);
                    return (
                      <span key={tag} className="tag"
                        style={{ background: ts.bg, color: ts.color, borderColor: ts.border }}>
                        {tag}
                      </span>
                    );
                  })}
                </div>
              )}

              <div className="modal-footer">
                <button className="btn" onClick={() => setSelectedArticle(null)}>Close</button>
                <a className="btn-primary" href={item.link} target="_blank" rel="noopener noreferrer">
                  Read full article ↗
                </a>
              </div>
            </div>
          </div>
        );
      })()}
    </>
  );
}
