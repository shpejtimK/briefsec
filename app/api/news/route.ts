import { NextResponse } from 'next/server';
import path from 'path';
import { refreshNews, readArticles, clusterStories, ensureNewsSchema, getMeta } from '@/lib/news-feed';
import { enrichPendingArticles } from '@/lib/cve-enrich';

export const dynamic = 'force-dynamic';
export const revalidate = 0;

// When CRON_MODE=true the separate worker (npm run worker:rss:watch) does all fetching and
// this route only reads.
const CRON_MODE = process.env.CRON_MODE === 'true';
const STALE_AFTER_MS = 5 * 60 * 1000;

let refreshPromise: Promise<void> | null = null;

function openDb() {
  const Database = require('better-sqlite3');
  const dbPath = process.env.DATABASE_PATH || path.join(process.cwd(), 'db', 'briefsec.sqlite');
  const db = new Database(dbPath);
  db.pragma('journal_mode = WAL');
  ensureNewsSchema(db);
  return db;
}

// Fetches all feeds, then looks up CVE IDs on article pages (slow, so it runs after the
// refreshed news is already readable)
function startRefresh(): Promise<void> {
  if (!refreshPromise) {
    refreshPromise = (async () => {
      const db = openDb();
      try {
        await refreshNews(db);
        await enrichPendingArticles(db, { limit: 40 });
      } finally {
        db.close();
      }
    })().catch(() => { /* retried on the next stale read */ }).finally(() => { refreshPromise = null; });
  }
  return refreshPromise;
}

export async function GET() {
  let db = openDb();
  const lastRefresh = Number(getMeta(db, 'news_last_refresh')) || 0;
  const empty = !(db.prepare(`SELECT 1 FROM articles LIMIT 1`).get());
  db.close();

  if (!CRON_MODE && Date.now() - lastRefresh > STALE_AFTER_MS) {
    const refresh = startRefresh();
    // Only make the caller wait when there's nothing to show yet
    if (empty) await refresh;
  }

  db = openDb();
  try {
    const stories = clusterStories(readArticles(db));
    const updatedAt = Number(getMeta(db, 'news_last_refresh')) || 0;
    return NextResponse.json(
      { stories, updatedAt: updatedAt ? new Date(updatedAt).toISOString() : null, refreshing: !!refreshPromise },
      { headers: { 'Cache-Control': 'no-store' } },
    );
  } finally {
    db.close();
  }
}
