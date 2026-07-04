import { NextResponse, NextRequest } from 'next/server';
import path from 'path';

export const dynamic = 'force-dynamic';

const CACHE_TTL = 7 * 24 * 60 * 60 * 1000;

function openDb() {
  try {
    const Database = require('better-sqlite3');
    const dbPath = process.env.DATABASE_PATH || path.join(process.cwd(), 'db', 'briefsec.sqlite');
    const db = new Database(dbPath);
    db.pragma('journal_mode = WAL');
    db.exec(`
      CREATE TABLE IF NOT EXISTS cvss_cache (
        cve_id     TEXT PRIMARY KEY,
        score      REAL,
        severity   TEXT,
        fetched_at INTEGER NOT NULL
      );
    `);
    return db;
  } catch { return null; }
}

async function fetchOne(cveId: string): Promise<{ score: number | null; severity: string | null }> {
  const res = await fetch(`https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=${cveId}`,
    { headers: { Accept: 'application/json' }, signal: AbortSignal.timeout(10000) });
  if (!res.ok) return { score: null, severity: null };
  const json = await res.json();
  const cve = json.vulnerabilities?.[0]?.cve;
  if (!cve) return { score: null, severity: null };
  const v31 = cve.metrics?.cvssMetricV31?.[0]?.cvssData;
  if (v31) return { score: v31.baseScore, severity: v31.baseSeverity };
  const v30 = cve.metrics?.cvssMetricV30?.[0]?.cvssData;
  if (v30) return { score: v30.baseScore, severity: v30.baseSeverity };
  return { score: null, severity: null };
}

export async function GET(req: NextRequest) {
  const raw = req.nextUrl.searchParams.get('cves') ?? '';
  const ids = raw.split(',')
    .map(s => s.trim().toUpperCase())
    .filter(s => /^CVE-\d{4}-\d+$/.test(s))
    .slice(0, 25);

  if (ids.length === 0) return NextResponse.json({});

  const db = openDb();
  if (!db) return NextResponse.json({});

  const result: Record<string, { score: number | null; severity: string | null }> = {};
  const toFetch: string[] = [];

  for (const id of ids) {
    const row = db.prepare('SELECT score, severity, fetched_at FROM cvss_cache WHERE cve_id = ?').get(id) as
      { score: number | null; severity: string | null; fetched_at: number } | undefined;
    if (row && Date.now() - row.fetched_at < CACHE_TTL) {
      result[id] = { score: row.score, severity: row.severity };
    } else {
      toFetch.push(id);
    }
  }

  for (let i = 0; i < toFetch.length; i++) {
    const id = toFetch[i];
    try {
      const cvss = await fetchOne(id);
      db.prepare('INSERT OR REPLACE INTO cvss_cache (cve_id, score, severity, fetched_at) VALUES (?, ?, ?, ?)')
        .run(id, cvss.score, cvss.severity, Date.now());
      result[id] = cvss;
    } catch {
      result[id] = { score: null, severity: null };
    }
    if (i < toFetch.length - 1) await new Promise(r => setTimeout(r, 350));
  }

  db.close();
  return NextResponse.json(result, {
    headers: { 'Cache-Control': 'public, s-maxage=3600, stale-while-revalidate=86400' },
  });
}
