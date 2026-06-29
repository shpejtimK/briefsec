import { NextResponse } from 'next/server';
import Parser from 'rss-parser';
import path from 'path';
import crypto from 'crypto';

export const dynamic = 'force-dynamic';
export const revalidate = 0;

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

const RSS_FEEDS = [
  { url: 'https://krebsonsecurity.com/feed/', name: 'Krebs on Security' },
  { url: 'https://feeds.feedburner.com/TheHackersNews', name: 'The Hacker News' },
  { url: 'https://www.bleepingcomputer.com/feed/', name: 'BleepingComputer' },
  { url: 'https://www.schneier.com/feed/atom/', name: 'Schneier on Security' },
  { url: 'https://isc.sans.edu/rssfeed_full.xml', name: 'SANS ISC' },
  { url: 'https://www.cisa.gov/cybersecurity-advisories/all.xml', name: 'CISA' },
  { url: 'https://grahamcluley.com/feed/', name: 'Graham Cluley' },
  { url: 'https://arstechnica.com/security/feed/', name: 'Ars Technica Security' },
  { url: 'https://nakedsecurity.sophos.com/feed/', name: 'Naked Security' },
  { url: 'https://www.troyhunt.com/rss/', name: 'Troy Hunt' },
  { url: 'https://securityweek.com/feed/', name: 'SecurityWeek' },
  { url: 'https://www.darkreading.com/rss.xml', name: 'Dark Reading' },
];

// When CRON_MODE=true (set in Railway cron service), the API only reads — never refreshes inline.
// The separate cron job (npm run worker:rss) handles all RSS fetching.
const CRON_MODE = process.env.CRON_MODE === 'true';
const STALE_AFTER_MS = 15 * 60 * 1000; // 15 minutes

const parser = new Parser({
  customFields: {
    item: [
      ['media:content', 'mediaContent', { keepArray: true }],
      ['dc:creator', 'creator'],
      ['content:encoded', 'contentEncoded'],
    ],
  },
  timeout: 12000,
  headers: {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
    'Accept': 'application/rss+xml, application/atom+xml, application/xml, text/xml, */*',
  },
});

// Guard against concurrent refreshes within the same server process
let refreshPromise: Promise<void> | null = null;

function stripHtml(html: string): string {
  return (html || '')
    .replace(/<[^>]+>/g, ' ')
    .replace(/&amp;/g, '&').replace(/&lt;/g, '<').replace(/&gt;/g, '>')
    .replace(/&quot;/g, '"').replace(/&apos;/g, "'")
    .replace(/&#\d+;/g, ' ').replace(/\s+/g, ' ').trim();
}

function truncate(text: string, limit: number): string {
  if (text.length <= limit) return text;
  const slice = text.slice(0, limit);
  const lastSentence = Math.max(slice.lastIndexOf('. '), slice.lastIndexOf('! '), slice.lastIndexOf('? '));
  if (lastSentence > limit * 0.5) return slice.slice(0, lastSentence + 1).trimEnd() + '...';
  const lastSpace = slice.lastIndexOf(' ');
  return (lastSpace > 0 ? slice.slice(0, lastSpace) : slice) + '...';
}

function detectTags(title: string, description: string): string[] {
  const text = `${title} ${description}`.toLowerCase();
  const tags: string[] = [];
  if (/\bcve-\d{4}-\d+\b/i.test(text)) tags.push('CVE');
  if (/zero.?day|0day/.test(text)) tags.push('Zero-Day');
  if (/ransomware/.test(text)) tags.push('Ransomware');
  else if (/\bmalware\b|\btrojan\b|\bbackdoor\b|\bspyware\b|\bbotnet\b|\brootkit\b/.test(text)) tags.push('Malware');
  if (/phish/.test(text)) tags.push('Phishing');
  if (/\bbreach\b|\bdata.?leak\b|exfiltrat|stolen data/.test(text)) tags.push('Breach');
  if (/vulnerabilit|\bexploit\b|\brce\b|remote code exec|buffer overflow|sql inject|cross.site/.test(text)) tags.push('Vulnerability');
  if (/patch tuesday|microsoft.*security update/.test(text)) tags.push('Patch Tuesday');
  if (/\bapt\b|advanced persistent threat/.test(text)) tags.push('APT');
  if (/nation.?state|state.?sponsor/.test(text)) tags.push('Nation-State');
  if (/supply chain|dependency confus|typosquat/.test(text)) tags.push('Supply Chain');
  if (/\bai\b|machine learning|\bllm\b|deepfake/.test(text)) tags.push('AI/ML');
  if (/\bcloud\b|\baws\b|\bazure\b|\bgcp\b|\bkubernetes\b/.test(text)) tags.push('Cloud');
  if (/privacy|\bgdpr\b|\bccpa\b|data protect/.test(text)) tags.push('Privacy');
  if (/critical infrastructure|ics\b|\bscada\b/.test(text)) tags.push('ICS/OT');
  return tags;
}

function extractCVEs(text: string): string[] {
  const matches = text.match(/CVE-\d{4}-\d{4,}/gi) || [];
  return [...new Set(matches.map(c => c.toUpperCase()))];
}

function openDb() {
  try {
    const Database = require('better-sqlite3');
    const dbPath = process.env.DATABASE_PATH || path.join(process.cwd(), 'db', 'cyberwatch.sqlite');
    const db = new Database(dbPath);
    db.pragma('journal_mode = WAL');
    db.exec(`
      CREATE TABLE IF NOT EXISTS articles (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        guid TEXT NOT NULL,
        source TEXT NOT NULL,
        title TEXT NOT NULL,
        link TEXT NOT NULL,
        description TEXT DEFAULT '',
        content TEXT DEFAULT '',
        author TEXT DEFAULT '',
        pub_date TEXT,
        published_at INTEGER,
        tags TEXT DEFAULT '[]',
        cves TEXT DEFAULT '[]',
        content_hash TEXT,
        is_duplicate INTEGER DEFAULT 0,
        created_at INTEGER DEFAULT (strftime('%s', 'now')),
        UNIQUE(source, guid)
      );
      CREATE TABLE IF NOT EXISTS meta (
        key TEXT PRIMARY KEY,
        value TEXT
      );
      CREATE INDEX IF NOT EXISTS idx_pub ON articles(published_at DESC);
      CREATE INDEX IF NOT EXISTS idx_hash ON articles(content_hash);
    `);
    try { db.exec(`ALTER TABLE articles ADD COLUMN content TEXT DEFAULT ''`); } catch { /* already exists */ }
    return db;
  } catch {
    return null;
  }
}

function getLastRefreshMs(db: ReturnType<typeof openDb>): number {
  try {
    const row = db!.prepare(`SELECT value FROM meta WHERE key = 'last_refresh_at'`).get() as { value: string } | undefined;
    return row ? parseInt(row.value, 10) : 0;
  } catch {
    return 0;
  }
}

async function refreshDatabase(): Promise<void> {
  const db = openDb();
  if (!db) return;

  const results = await Promise.allSettled(
    RSS_FEEDS.map(async ({ url, name }) => {
      const feed = await parser.parseURL(url);
      return { name, items: feed.items || [] };
    })
  );

  const upsert = db.prepare(`
    INSERT INTO articles (guid, source, title, link, description, content, author, pub_date, published_at, tags, cves, content_hash)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ON CONFLICT(source, guid) DO UPDATE SET
      title = excluded.title,
      description = excluded.description,
      content = excluded.content,
      tags = excluded.tags,
      cves = excluded.cves,
      created_at = strftime('%s', 'now')
  `);

  const checkDup = db.prepare(`SELECT id FROM articles WHERE content_hash = ? AND source != ? LIMIT 1`);

  const insertMany = db.transaction((feedName: string, items: Parser.Item[]) => {
    for (const item of items.slice(0, 30)) {
      const title = stripHtml(item.title || '');
      if (!title) continue;
      const fullText = stripHtml(
        (item as Record<string, unknown>)['contentEncoded'] as string ||
        item.contentSnippet || item.summary || item.content || ''
      );
      const description = truncate(fullText, 600);
      const content = truncate(fullText, 3000);
      const link = item.link || '';
      const guid = item.guid || item.link || title;
      const pubDate = item.pubDate || item.isoDate || new Date().toISOString();
      const publishedAt = Math.floor(new Date(pubDate).getTime() / 1000) || Math.floor(Date.now() / 1000);
      const tags = detectTags(title, description);
      const cves = extractCVEs(`${title} ${description}`);
      const contentHash = crypto.createHash('sha256')
        .update((title + description).toLowerCase()).digest('hex');

      if (checkDup.get(contentHash, feedName)) continue;

      try {
        upsert.run(guid, feedName, title, link, description, content,
          (item as Record<string, unknown>)['creator'] as string || (item as Record<string, unknown>)['author'] as string || '',
          pubDate, publishedAt, JSON.stringify(tags), JSON.stringify(cves), contentHash);
      } catch { /* skip */ }
    }
  });

  for (const result of results) {
    if (result.status === 'fulfilled') {
      insertMany(result.value.name, result.value.items);
    }
  }

  // Keep DB at 500 articles max
  db.prepare(`DELETE FROM articles WHERE id NOT IN (SELECT id FROM articles ORDER BY published_at DESC LIMIT 500)`).run();
  // Record when we last refreshed
  db.prepare(`INSERT OR REPLACE INTO meta VALUES ('last_refresh_at', ?)`).run(String(Date.now()));
  db.close();
}

function readFromDb(): NewsItem[] | null {
  const db = openDb();
  if (!db) return null;
  try {
    const rows = db.prepare(`
      SELECT guid, source, title, link, description, content, author, pub_date, tags, cves
      FROM articles WHERE is_duplicate = 0
      ORDER BY published_at DESC LIMIT 300
    `).all() as Array<{
      guid: string; source: string; title: string; link: string;
      description: string; content: string; author: string; pub_date: string;
      tags: string; cves: string;
    }>;
    db.close();
    if (rows.length === 0) return null;
    return rows.map(r => ({
      id: `${r.source}::${r.guid}`,
      title: r.title,
      link: r.link,
      description: r.description,
      content: r.content || r.description,
      pubDate: r.pub_date,
      source: r.source,
      tags: JSON.parse(r.tags || '[]'),
      cves: JSON.parse(r.cves || '[]'),
      author: r.author,
    }));
  } catch {
    db.close();
    return null;
  }
}

export async function GET() {
  // Check freshness and refresh if stale
  const db = openDb();
  const lastRefresh = db ? getLastRefreshMs(db) : 0;
  db?.close();

  const isStale = Date.now() - lastRefresh > STALE_AFTER_MS;

  // In CRON_MODE the worker process handles refreshes — API only reads.
  // Without CRON_MODE (default), self-refresh on stale data so it works out of the box.
  if (isStale && !CRON_MODE) {
    if (!refreshPromise) {
      refreshPromise = refreshDatabase().finally(() => { refreshPromise = null; });
    }
    await refreshPromise;
  }

  const items = readFromDb();

  const headers = {
    // CDN/proxy caches the response for 5 min; browser revalidates but uses cached version
    'Cache-Control': 'public, s-maxage=300, stale-while-revalidate=900',
  };

  if (items && items.length > 0) {
    const sources = [...new Set(items.map(i => i.source))];
    return NextResponse.json(
      { items, sources, total: items.length, fromCache: !isStale, lastRefresh: new Date(lastRefresh).toISOString() },
      { headers }
    );
  }

  return NextResponse.json(
    { items: [], sources: [], total: 0, fromCache: false, lastRefresh: null },
    { headers }
  );
}
