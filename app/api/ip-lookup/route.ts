import { NextResponse, NextRequest } from 'next/server';
import path from 'path';

export const dynamic = 'force-dynamic';

const CACHE_TTL = 60 * 60 * 1000; // 1 hour

function openDb() {
  try {
    const Database = require('better-sqlite3');
    const dbPath = process.env.DATABASE_PATH || path.join(process.cwd(), 'db', 'briefsec.sqlite');
    const db = new Database(dbPath);
    db.pragma('journal_mode = WAL');
    db.exec(`
      CREATE TABLE IF NOT EXISTS ip_lookup_cache (
        ip         TEXT PRIMARY KEY,
        data       TEXT NOT NULL,
        fetched_at INTEGER NOT NULL
      );
    `);
    return db;
  } catch { return null; }
}

// ip-api.com — free, no key required
async function fetchGeo(ip: string) {
  try {
    const fields = 'status,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,asname,proxy,hosting,mobile';
    const res = await fetch(`http://ip-api.com/json/${ip}?fields=${fields}`,
      { signal: AbortSignal.timeout(8000) });
    if (!res.ok) return null;
    const d = await res.json() as Record<string, unknown>;
    if (d.status !== 'success') return null;
    return {
      country: d.country as string,
      countryCode: d.countryCode as string,
      region: d.regionName as string,
      city: d.city as string,
      zip: d.zip as string,
      lat: d.lat as number,
      lon: d.lon as number,
      timezone: d.timezone as string,
      isp: d.isp as string,
      org: d.org as string,
      as: d.as as string,
      asname: d.asname as string,
      proxy: d.proxy as boolean,
      hosting: d.hosting as boolean,
      mobile: d.mobile as boolean,
    };
  } catch { return null; }
}

// AbuseIPDB — requires ABUSEIPDB_API_KEY env var (free tier: 1000 checks/day)
async function fetchAbuse(ip: string) {
  const key = process.env.ABUSEIPDB_API_KEY;
  if (!key) return null;
  try {
    const res = await fetch(
      `https://api.abuseipdb.com/api/v2/check?ipAddress=${encodeURIComponent(ip)}&maxAgeInDays=90&verbose`,
      { headers: { Key: key, Accept: 'application/json' }, signal: AbortSignal.timeout(10000) }
    );
    if (!res.ok) return null;
    const { data: d } = await res.json() as { data: Record<string, unknown> };
    return {
      score:            d.abuseConfidenceScore as number,
      totalReports:     d.totalReports as number,
      numDistinctUsers: d.numDistinctUsers as number,
      lastReportedAt:   (d.lastReportedAt ?? null) as string | null,
      isPublic:         d.isPublic as boolean,
      isWhitelisted:    (d.isWhitelisted ?? false) as boolean,
      usageType:        (d.usageType ?? '') as string,
      domain:           (d.domain ?? '') as string,
      hostnames:        (d.hostnames ?? []) as string[],
      isTor:            (d.isTor ?? false) as boolean,
      countryCode:      (d.countryCode ?? '') as string,
    };
  } catch { return null; }
}

// VirusTotal — requires VIRUSTOTAL_API_KEY env var (free tier: 4 req/min, 500/day)
async function fetchVT(ip: string) {
  const key = process.env.VIRUSTOTAL_API_KEY;
  if (!key) return null;
  try {
    const res = await fetch(`https://www.virustotal.com/api/v3/ip_addresses/${ip}`,
      { headers: { 'x-apikey': key }, signal: AbortSignal.timeout(12000) });
    if (!res.ok) return null;
    const { data: d } = await res.json() as { data: Record<string, unknown> };
    const attrs = (d.attributes ?? {}) as Record<string, unknown>;
    const stats = (attrs.last_analysis_stats ?? {}) as Record<string, number>;
    return {
      malicious:        stats.malicious   ?? 0,
      suspicious:       stats.suspicious  ?? 0,
      harmless:         stats.harmless    ?? 0,
      undetected:       stats.undetected  ?? 0,
      total:            Object.values(stats).reduce((a, b) => a + b, 0),
      lastAnalysisDate: attrs.last_analysis_date
        ? new Date((attrs.last_analysis_date as number) * 1000).toISOString() : null,
      reputation: (attrs.reputation ?? 0) as number,
      asOwner:    (attrs.as_owner ?? '')  as string,
      network:    (attrs.network ?? '')   as string,
    };
  } catch { return null; }
}

// Shodan — requires SHODAN_API_KEY env var (free tier: 1 req/sec, 100/month for host lookups)
async function fetchShodan(ip: string) {
  const key = process.env.SHODAN_API_KEY;
  if (!key) return null;
  try {
    const res = await fetch(`https://api.shodan.io/shodan/host/${ip}?key=${key}`,
      { signal: AbortSignal.timeout(12000) });
    if (!res.ok) return null;
    const d = await res.json() as Record<string, unknown>;
    return {
      ports:     (d.ports     ?? []) as number[],
      hostnames: (d.hostnames ?? []) as string[],
      domains:   (d.domains   ?? []) as string[],
      country:   (d.country_name ?? '') as string,
      org:       (d.org  ?? '') as string,
      isp:       (d.isp  ?? '') as string,
      vulns:     Object.keys((d.vulns ?? {}) as object),
      data: ((d.data ?? []) as Record<string, unknown>[]).slice(0, 12).map(s => ({
        port:      s.port      as number,
        transport: s.transport as string,
        product:   s.product   as string | undefined,
        version:   s.version   as string | undefined,
      })),
      lastUpdate: (d.last_update ?? '') as string,
    };
  } catch { return null; }
}

export async function GET(req: NextRequest) {
  const ip = req.nextUrl.searchParams.get('ip')?.trim() ?? '';

  const isIPv4 = /^(\d{1,3}\.){3}\d{1,3}$/.test(ip);
  const isIPv6 = /^[0-9a-fA-F:]{2,45}$/.test(ip) && ip.includes(':');
  if (!ip || (!isIPv4 && !isIPv6)) {
    return NextResponse.json({ error: 'Enter a valid IPv4 or IPv6 address' }, { status: 400 });
  }

  const db = openDb();
  if (db) {
    const cached = db.prepare('SELECT data, fetched_at FROM ip_lookup_cache WHERE ip = ?').get(ip) as
      { data: string; fetched_at: number } | undefined;
    if (cached && Date.now() - cached.fetched_at < CACHE_TTL) {
      db.close();
      return NextResponse.json({ ...JSON.parse(cached.data), cached: true });
    }
  }

  const links = {
    abuseipdb:  `https://www.abuseipdb.com/check/${ip}`,
    virustotal: `https://www.virustotal.com/gui/ip-address/${ip}`,
    shodan:     `https://www.shodan.io/host/${ip}`,
    censys:     `https://search.censys.io/hosts/${ip}`,
    greynoise:  `https://viz.greynoise.io/ip/${ip}`,
    talos:      `https://talosintelligence.com/reputation_center/lookup?search=${ip}`,
    bgp:        `https://bgp.he.net/ip/${ip}`,
    ipinfo:     `https://ipinfo.io/${ip}`,
  };

  const [geo, abuse, vt, shodan] = await Promise.all([
    fetchGeo(ip),
    fetchAbuse(ip),
    fetchVT(ip),
    fetchShodan(ip),
  ]);

  const result = { ip, geo, abuse, vt, shodan, links, cached: false, fetchedAt: Date.now() };

  if (db) {
    try {
      db.prepare('INSERT OR REPLACE INTO ip_lookup_cache (ip, data, fetched_at) VALUES (?, ?, ?)')
        .run(ip, JSON.stringify(result), Date.now());
    } catch { /* cache write failure is non-fatal */ }
    db.close();
  }

  return NextResponse.json(result);
}
