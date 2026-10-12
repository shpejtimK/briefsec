'use client';

import { useMemo, useState } from 'react';
import type { CveInfo, Story } from '@/lib/types';
import { isStackStory, storyVendors } from '@/lib/stack-vendors';
import { CveChip, IconBookmark, IconSearch, StackBadge, timeAgo } from './ui';

const CATEGORIES = ['Data Breach', 'Ransomware', 'Cyberattack', 'Actively Exploited', 'Vulnerability', 'Malware',
  'Phishing', 'Nation-State', 'Law Enforcement', 'Supply Chain', 'AI'];

const WINDOWS = [
  { key: '24h', label: '24h', ms: 86_400_000 },
  { key: '3d',  label: '3 days', ms: 3 * 86_400_000 },
  { key: '7d',  label: '7 days', ms: 7 * 86_400_000 },
  { key: 'all', label: '14 days', ms: Infinity },
] as const;

const PAGE = 60;

interface Props {
  stories: Story[];
  cveInfo: Map<string, CveInfo>;
  saved: Map<string, Story>;
  onToggleSave: (story: Story) => void;
  lastVisit: number;
}

export default function NewsTab({ stories, cveInfo, saved, onToggleSave, lastVisit }: Props) {
  const [windowKey, setWindowKey] = useState<(typeof WINDOWS)[number]['key']>('3d');
  const [category, setCategory] = useState<string | null>(null);
  const [search, setSearch] = useState('');
  const [savedOnly, setSavedOnly] = useState(false);
  const [limit, setLimit] = useState(PAGE);
  const [stackExpanded, setStackExpanded] = useState(false);

  // Stack-vendor vulnerability news from the last week, always shown first
  const stackStories = useMemo(() => {
    const cutoff = Date.now() - 7 * 86_400_000;
    return stories.filter(s => new Date(s.pubDate).getTime() >= cutoff && isStackStory(s.title, s.description, s.cves));
  }, [stories]);

  const filtered = useMemo(() => {
    let list = savedOnly ? [...saved.values()].map(s => ({ ...s, coverage: s.coverage ?? [] })) : stories;
    const win = WINDOWS.find(w => w.key === windowKey)!;
    if (!savedOnly && win.ms !== Infinity) {
      const cutoff = Date.now() - win.ms;
      list = list.filter(s => new Date(s.pubDate).getTime() >= cutoff);
    }
    if (category) list = list.filter(s => s.tags.includes(category));
    const q = search.trim().toLowerCase();
    if (q) {
      list = list.filter(s =>
        s.title.toLowerCase().includes(q) || s.description.toLowerCase().includes(q) ||
        s.source.toLowerCase().includes(q) || s.cves.some(c => c.toLowerCase().includes(q)) ||
        s.coverage.some(c => c.title.toLowerCase().includes(q) || c.source.toLowerCase().includes(q)));
    }
    return [...list].sort((a, b) => new Date(b.pubDate).getTime() - new Date(a.pubDate).getTime());
  }, [stories, saved, savedOnly, windowKey, category, search]);

  const categoryCounts = useMemo(() => {
    const cutoff = Date.now() - (WINDOWS.find(w => w.key === windowKey)!.ms);
    const counts: Record<string, number> = {};
    for (const s of stories) {
      if (new Date(s.pubDate).getTime() < cutoff) continue;
      for (const t of s.tags) counts[t] = (counts[t] || 0) + 1;
    }
    return counts;
  }, [stories, windowKey]);

  const showStack = !savedOnly && !category && !search.trim() && stackStories.length > 0;

  return (
    <div className="tab-body">
      <div className="toolbar">
        <div className="search">
          <IconSearch />
          <input placeholder="Search stories, companies, CVE IDs, sources…" value={search}
            onChange={e => { setSearch(e.target.value); setLimit(PAGE); }} />
        </div>
        <div className="seg">
          {WINDOWS.map(w => (
            <button key={w.key} className={windowKey === w.key && !savedOnly ? 'active' : ''}
              onClick={() => { setWindowKey(w.key); setSavedOnly(false); setLimit(PAGE); }}>{w.label}</button>
          ))}
          <button className={savedOnly ? 'active' : ''} onClick={() => setSavedOnly(v => !v)} title="Saved stories">
            <IconBookmark filled={savedOnly} /> {saved.size}
          </button>
        </div>
      </div>

      <div className="chips">
        <button className={`chip${category === null ? ' active' : ''}`} onClick={() => setCategory(null)}>All</button>
        {CATEGORIES.filter(c => categoryCounts[c]).map(c => (
          <button key={c} className={`chip chip-${slug(c)}${category === c ? ' active' : ''}`}
            onClick={() => { setCategory(category === c ? null : c); setLimit(PAGE); }}>
            {c} <span className="chip-count">{categoryCounts[c]}</span>
          </button>
        ))}
      </div>

      {showStack && (
        <section className="stack-section">
          <div className="section-head">
            <h2>★ Your stack</h2>
            <span className="section-sub">Vulnerability news for Citrix, Palo Alto, Splunk, VMray, Microsoft, Cisco and Oracle — last 7 days</span>
          </div>
          {(stackExpanded ? stackStories : stackStories.slice(0, 5)).map(s => (
            <StoryRow key={s.id} story={s} cveInfo={cveInfo} saved={saved.has(s.id)} onToggleSave={onToggleSave} lastVisit={lastVisit} compact />
          ))}
          {stackStories.length > 5 && (
            <button className="more" onClick={() => setStackExpanded(v => !v)}>
              {stackExpanded ? 'Show fewer' : `Show all ${stackStories.length}`}
            </button>
          )}
        </section>
      )}

      <section>
        <div className="section-head">
          <h2>{savedOnly ? 'Saved' : 'Latest'}</h2>
          <span className="section-sub">{filtered.length} stories</span>
        </div>
        {filtered.length === 0 && <div className="empty">No stories match.</div>}
        {filtered.slice(0, limit).map(s => (
          <StoryRow key={s.id} story={s} cveInfo={cveInfo} saved={saved.has(s.id)} onToggleSave={onToggleSave} lastVisit={lastVisit} />
        ))}
        {filtered.length > limit && (
          <button className="more" onClick={() => setLimit(l => l + PAGE)}>Show more ({filtered.length - limit} left)</button>
        )}
      </section>
    </div>
  );
}

function slug(s: string) {
  return s.toLowerCase().replace(/[^a-z]+/g, '-');
}

function StoryRow({ story, cveInfo, saved, onToggleSave, lastVisit, compact = false }: {
  story: Story; cveInfo: Map<string, CveInfo>; saved: boolean; onToggleSave: (s: Story) => void; lastVisit: number; compact?: boolean;
}) {
  const [open, setOpen] = useState(false);
  const vendors = storyVendors(story.title, story.description);
  const isNew = lastVisit > 0 && new Date(story.pubDate).getTime() > lastVisit;
  const developing = new Date(story.pubDate).getTime() - new Date(story.firstSeen).getTime() > 12 * 3_600_000;
  const exploited = story.tags.includes('Actively Exploited') || story.cves.some(c => cveInfo.get(c)?.kev);

  return (
    <article className={`story${exploited ? ' story-exploited' : ''}${compact ? ' story-compact' : ''}`}>
      <div className="story-time" title={new Date(story.pubDate).toLocaleString()}>
        {isNew && <span className="new-dot" title="New since your last visit" />}
        {timeAgo(story.pubDate)}
      </div>
      <div className="story-main">
        <h3 className="story-title">
          <a href={story.link} target="_blank" rel="noopener noreferrer">{story.title}</a>
        </h3>
        {story.cves.length > 0 && (
          <div className="story-cves">
            {story.cves.slice(0, 5).map(id => <CveChip key={id} id={id} info={cveInfo.get(id)} />)}
            {story.cves.length > 5 && <span className="cve-more">+{story.cves.length - 5}</span>}
          </div>
        )}
        {/* Stack-vendor vulnerability story whose CVE ID we couldn't look up (yet) */}
        {story.cves.length === 0 && story.cveStatus !== 'none' && isStackStory(story.title, story.description, story.cves) && (
          <div className="story-cves">
            {story.cveStatus === 'pending'
              ? <span className="cve-unknown" title="Looking up the CVE ID in the full article">CVE: checking…</span>
              : <a className="cve-unknown" href={story.link} target="_blank" rel="noopener noreferrer"
                  title="This site blocks automated reads — open the article to check for a CVE ID">CVE: check article ↗</a>}
          </div>
        )}
        {!compact && story.description && <p className="story-desc">{story.description}</p>}
        <div className="story-meta">
          <span className="story-source">{story.source}</span>
          {story.coverage.length > 0 && (
            <button className="coverage-toggle" onClick={() => setOpen(v => !v)}>
              +{story.coverage.length} source{story.coverage.length > 1 ? 's' : ''} {open ? '▴' : '▾'}
            </button>
          )}
          {developing && <span className="developing" title={`First reported ${timeAgo(story.firstSeen)}`}>first reported {timeAgo(story.firstSeen)}</span>}
          <StackBadge vendors={vendors} />
          {story.tags.filter(t => t !== 'AI' || story.tags.length === 1).slice(0, 3).map(t => (
            <span key={t} className={`tag tag-${slug(t)}`}>{t}</span>
          ))}
          <button className={`save${saved ? ' saved' : ''}`} onClick={() => onToggleSave(story)} title={saved ? 'Remove from saved' : 'Save'}>
            <IconBookmark filled={saved} />
          </button>
        </div>
        {open && (
          <ul className="coverage">
            {story.coverage.map(c => (
              <li key={c.link}>
                <span className="coverage-time">{timeAgo(c.pubDate)}</span>
                <span className="coverage-source">{c.source}</span>
                <a href={c.link} target="_blank" rel="noopener noreferrer">{c.title}</a>
              </li>
            ))}
          </ul>
        )}
      </div>
    </article>
  );
}
