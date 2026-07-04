import { NextResponse } from 'next/server';

export const dynamic = 'force-dynamic';
export const revalidate = 0;

const KEV_URL = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json';
const CACHE_TTL = 6 * 60 * 60 * 1000; // 6 hours

let kevCache: { cves: string[]; fetchedAt: number } | null = null;

export async function GET() {
  if (kevCache && Date.now() - kevCache.fetchedAt < CACHE_TTL) {
    return NextResponse.json(kevCache, {
      headers: { 'Cache-Control': 'public, s-maxage=21600, stale-while-revalidate=3600' },
    });
  }

  try {
    const res = await fetch(KEV_URL, {
      headers: { 'User-Agent': 'BriefSec/1.0 SOC Intelligence Dashboard' },
      signal: AbortSignal.timeout(15000),
    });
    if (!res.ok) throw new Error(`KEV fetch failed: ${res.status}`);
    const data = await res.json() as { vulnerabilities: Array<{ cveID: string }> };
    const cves = data.vulnerabilities.map(v => v.cveID.toUpperCase());
    kevCache = { cves, fetchedAt: Date.now() };
    return NextResponse.json(kevCache, {
      headers: { 'Cache-Control': 'public, s-maxage=21600, stale-while-revalidate=3600' },
    });
  } catch {
    // On error return stale cache or empty list — never break the UI
    if (kevCache) return NextResponse.json(kevCache);
    return NextResponse.json({ cves: [], fetchedAt: 0 });
  }
}
