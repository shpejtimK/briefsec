'use client';

import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import type { CveData, CveInfo, NewsData, Story } from '@/lib/types';
import NewsTab from './components/NewsTab';
import CveTab from './components/CveTab';
import { IconRefresh, IconTheme, timeAgo } from './components/ui';

type Tab = 'news' | 'cves';

const POLL_MS = 2 * 60 * 1000;       // re-read the API (the server refreshes sources every 5 min)
const REFRESHING_POLL_MS = 20 * 1000; // sooner while the server is mid-refresh

export default function BriefSec() {
  const [tab, setTab] = useState<Tab>('news');
  const [news, setNews] = useState<NewsData | null>(null);
  const [cves, setCves] = useState<CveData | null>(null);
  const [extraCvss, setExtraCvss] = useState<Record<string, { score: number | null; severity: string | null }>>({});
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [theme, setTheme] = useState<'dark' | 'light'>('dark');
  const [saved, setSaved] = useState<Map<string, Story>>(new Map());
  const [lastVisit, setLastVisit] = useState(0);
  const [, setTick] = useState(0); // re-render "x min ago" labels
  const pollTimer = useRef<ReturnType<typeof setTimeout> | null>(null);
  const cveSyncedAt = useRef(0);

  // ── Local state: tab, theme, saved stories, last visit ──
  useEffect(() => {
    if (window.location.hash === '#cves') setTab('cves');
    const storedTheme = localStorage.getItem('briefsec-theme');
    if (storedTheme === 'light' || storedTheme === 'dark') setTheme(storedTheme);
    try {
      const raw = localStorage.getItem('briefsec-saved');
      if (raw) {
        const entries = Object.entries(JSON.parse(raw) as Record<string, Story>)
          .map(([id, s]) => [id, { ...s, coverage: s.coverage ?? [], firstSeen: s.firstSeen ?? s.pubDate, tags: s.tags ?? [], cves: s.cves ?? [] }] as const);
        setSaved(new Map(entries));
      }
    } catch { /* corrupt entry — start empty */ }
    setLastVisit(Number(localStorage.getItem('briefsec-last-visit')) || 0);
    localStorage.setItem('briefsec-last-visit', String(Date.now()));
    const tick = setInterval(() => setTick(t => t + 1), 60_000);
    return () => clearInterval(tick);
  }, []);

  useEffect(() => {
    document.documentElement.classList.toggle('light', theme === 'light');
    localStorage.setItem('briefsec-theme', theme);
  }, [theme]);

  const switchTab = (t: Tab) => {
    setTab(t);
    history.replaceState(null, '', t === 'cves' ? '#cves' : window.location.pathname);
  };

  const toggleSave = useCallback((story: Story) => {
    setSaved(prev => {
      const next = new Map(prev);
      if (next.has(story.id)) next.delete(story.id); else next.set(story.id, story);
      localStorage.setItem('briefsec-saved', JSON.stringify(Object.fromEntries(next)));
      return next;
    });
  }, []);

  // ── Data ──
  const load = useCallback(async () => {
    if (pollTimer.current) clearTimeout(pollTimer.current);
    setLoading(true);
    try {
      const [newsRes, cveRes] = await Promise.all([fetch('/api/news'), fetch(`/api/cves?since=${cveSyncedAt.current}`)]);
      if (!newsRes.ok || !cveRes.ok) throw new Error(`HTTP ${newsRes.ok ? cveRes.status : newsRes.status}`);
      const [newsJson, cveJson] = await Promise.all([
        newsRes.json() as Promise<NewsData>,
        cveRes.json() as Promise<(CveData & { syncedAt: number }) | { unchanged: true; refreshing: boolean }>,
      ]);
      setNews(newsJson);
      if ('unchanged' in cveJson) {
        setCves(prev => (prev ? { ...prev, refreshing: cveJson.refreshing } : prev));
      } else {
        cveSyncedAt.current = cveJson.syncedAt;
        setCves(cveJson);
      }
      setError(null);
      pollTimer.current = setTimeout(load, newsJson.refreshing || cveJson.refreshing ? REFRESHING_POLL_MS : POLL_MS);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load');
      pollTimer.current = setTimeout(load, REFRESHING_POLL_MS);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    load();
    return () => { if (pollTimer.current) clearTimeout(pollTimer.current); };
  }, [load]);

  // CVE score + KEV status for the chips in news headlines
  const cveInfo = useMemo(() => {
    const map = new Map<string, CveInfo>();
    const kev = new Set(cves?.kevIds ?? []);
    for (const c of cves?.cves ?? []) map.set(c.id, { score: c.score, severity: c.severity, kev: kev.has(c.id) });
    for (const [id, v] of Object.entries(extraCvss)) if (!map.has(id)) map.set(id, { ...v, kev: kev.has(id) });
    for (const id of kev) if (!map.has(id)) map.set(id, { score: null, severity: null, kev: true });
    return map;
  }, [cves, extraCvss]);

  // Older CVEs named in recent stories aren't in the week-long NVD feed — look their scores up
  useEffect(() => {
    if (!news || !cves) return;
    const known = new Set([...cves.cves.map(c => c.id), ...Object.keys(extraCvss)]);
    const missing = [...new Set(news.stories.slice(0, 150).flatMap(s => s.cves))].filter(id => !known.has(id)).slice(0, 25);
    if (missing.length === 0) return;
    fetch(`/api/cvss?cves=${missing.join(',')}`)
      .then(r => (r.ok ? r.json() : {}))
      .then((scores: Record<string, { score: number | null; severity: string | null }>) => {
        // Record misses too, so they aren't requested again
        setExtraCvss(prev => ({ ...prev, ...Object.fromEntries(missing.map(id => [id, scores[id] ?? { score: null, severity: null }])) }));
      })
      .catch(() => { /* scores are optional */ });
  }, [news, cves, extraCvss]);

  const newsByCve = useMemo(() => {
    const map = new Map<string, Story[]>();
    for (const s of news?.stories ?? []) for (const id of s.cves) map.set(id, [...(map.get(id) ?? []), s]);
    return map;
  }, [news]);

  const counts = useMemo(() => {
    const day = Date.now() - 86_400_000;
    return {
      news: (news?.stories ?? []).filter(s => new Date(s.pubDate).getTime() >= day).length,
      cves: (cves?.cves ?? []).filter(c => new Date(c.published).getTime() >= day).length,
    };
  }, [news, cves]);

  const updatedAt = tab === 'news' ? news?.updatedAt : cves?.nvdSyncedAt;
  const refreshing = loading || news?.refreshing || cves?.refreshing;

  return (
    <div className="app">
      <header className="header">
        <div className="brand">
          <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinejoin="round">
            <path d="M12 2 4 5v6c0 5 3.4 9.4 8 11 4.6-1.6 8-6 8-11V5z" />
          </svg>
          BriefSec
        </div>
        <nav className="tabs">
          <button className={tab === 'news' ? 'active' : ''} onClick={() => switchTab('news')}>
            Hacking News {news && <span className="tab-count" title="Stories in the last 24 hours">{counts.news}</span>}
          </button>
          <button className={tab === 'cves' ? 'active' : ''} onClick={() => switchTab('cves')}>
            CVEs {cves && <span className="tab-count" title="CVEs published in the last 24 hours">{counts.cves}</span>}
          </button>
        </nav>
        <div className="header-right">
          {updatedAt && <span className="updated">{refreshing ? 'Updating…' : `Updated ${timeAgo(updatedAt)}`}</span>}
          <button className="icon-btn" onClick={load} disabled={loading} title="Reload">
            <IconRefresh spin={!!refreshing} />
          </button>
          <button className="icon-btn" onClick={() => setTheme(t => (t === 'dark' ? 'light' : 'dark'))} title="Toggle theme">
            <IconTheme light={theme === 'light'} />
          </button>
        </div>
      </header>

      <main className="content">
        {error && <div className="error">Couldn&apos;t reach the server ({error}). Retrying…</div>}
        {tab === 'news' && (news
          ? <NewsTab stories={news.stories} cveInfo={cveInfo} saved={saved} onToggleSave={toggleSave} lastVisit={lastVisit} />
          : <div className="empty">Loading the latest news…</div>)}
        {tab === 'cves' && (cves
          ? <CveTab data={cves} newsByCve={newsByCve} />
          : <div className="empty">Loading CVEs from NVD…</div>)}
      </main>
    </div>
  );
}
