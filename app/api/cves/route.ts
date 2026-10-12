import { NextResponse, type NextRequest } from 'next/server';
import path from 'path';
import { refreshCves, cvesAreStale, readCves, ensureCveSchema } from '@/lib/cve-feed';

export const dynamic = 'force-dynamic';
export const revalidate = 0;

const CRON_MODE = process.env.CRON_MODE === 'true';

let refreshPromise: Promise<void> | null = null;

function openDb() {
  const Database = require('better-sqlite3');
  const dbPath = process.env.DATABASE_PATH || path.join(process.cwd(), 'db', 'briefsec.sqlite');
  const db = new Database(dbPath);
  db.pragma('journal_mode = WAL');
  ensureCveSchema(db);
  return db;
}

function startRefresh(): Promise<void> {
  if (!refreshPromise) {
    refreshPromise = (async () => {
      const db = openDb();
      try { await refreshCves(db); } finally { db.close(); }
    })().catch(() => { /* retried on the next stale read */ }).finally(() => { refreshPromise = null; });
  }
  return refreshPromise;
}

export async function GET(req: NextRequest) {
  let db = openDb();
  const stale = cvesAreStale(db);
  const empty = !(db.prepare(`SELECT 1 FROM cve_items LIMIT 1`).get());
  db.close();

  if (!CRON_MODE && stale) {
    const refresh = startRefresh();
    if (empty) await refresh;
  }

  db = openDb();
  try {
    // The page polls every few minutes; only send the (multi-MB) list again when a sync changed it
    const since = req.nextUrl.searchParams.get('since');
    const synced = db.prepare(`SELECT MAX(CAST(value AS INTEGER)) AS t FROM meta WHERE key IN ('nvd_last_sync', 'kev_last_sync')`).get() as { t: number | null };
    if (since && synced.t && synced.t <= Number(since)) {
      return NextResponse.json({ unchanged: true, refreshing: !!refreshPromise }, { headers: { 'Cache-Control': 'no-store' } });
    }
    return NextResponse.json({ ...readCves(db), syncedAt: synced.t ?? 0, refreshing: !!refreshPromise }, { headers: { 'Cache-Control': 'no-store' } });
  } finally {
    db.close();
  }
}
