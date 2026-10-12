'use client';

import type { CveInfo } from '@/lib/types';

export function timeAgo(date: string | number | null | undefined): string {
  if (!date) return '';
  const ms = Date.now() - new Date(date).getTime();
  if (Number.isNaN(ms)) return '';
  const mins = Math.floor(ms / 60000);
  if (mins < 1) return 'just now';
  if (mins < 60) return `${mins}m ago`;
  const hrs = Math.floor(mins / 60);
  if (hrs < 24) return `${hrs}h ago`;
  const days = Math.floor(hrs / 24);
  if (days < 7) return `${days}d ago`;
  return new Date(date).toLocaleDateString('en-GB', { day: 'numeric', month: 'short' });
}

export function formatDate(date: string): string {
  return new Date(date).toLocaleString('en-GB', { day: 'numeric', month: 'short', hour: '2-digit', minute: '2-digit' });
}

export function severityOf(score: number | null, severity: string | null): string {
  if (severity) return severity.toLowerCase();
  if (score == null) return 'none';
  return score >= 9 ? 'critical' : score >= 7 ? 'high' : score >= 4 ? 'medium' : 'low';
}

export const nvdUrl = (id: string) => `https://nvd.nist.gov/vuln/detail/${id}`;

export function CvssBadge({ score, severity }: { score: number | null; severity: string | null }) {
  const sev = severityOf(score, severity);
  return (
    <span className={`cvss cvss-${sev}`} title={severity ? `CVSS ${score} — ${severity}` : 'Not scored yet'}>
      {score != null ? score.toFixed(1) : '—'}
    </span>
  );
}

// CVE ID chip used in news headlines: colored by CVSS, flagged when exploited (KEV)
export function CveChip({ id, info }: { id: string; info?: CveInfo }) {
  const sev = info ? severityOf(info.score, info.severity) : 'unknown';
  return (
    <a className={`cve-chip cve-chip-${sev}`} href={nvdUrl(id)} target="_blank" rel="noopener noreferrer"
      title={info?.score != null ? `CVSS ${info.score}${info.kev ? ' — actively exploited (CISA KEV)' : ''}` : id}>
      {info?.kev && <span className="cve-chip-kev">KEV</span>}
      {id}
      {info?.score != null && <span className="cve-chip-score">{info.score.toFixed(1)}</span>}
    </a>
  );
}

export function StackBadge({ vendors }: { vendors: string[] }) {
  if (vendors.length === 0) return null;
  return <span className="stack-badge" title="A vendor in your stack">★ {vendors.join(' · ')}</span>;
}

export function IconRefresh({ spin }: { spin: boolean }) {
  return (
    <svg className={spin ? 'spin' : ''} width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M21 12a9 9 0 1 1-3-6.7L21 8" /><path d="M21 3v5h-5" />
    </svg>
  );
}

export function IconSearch() {
  return (
    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round">
      <circle cx="11" cy="11" r="7" /><path d="m20 20-3.5-3.5" />
    </svg>
  );
}

export function IconBookmark({ filled }: { filled: boolean }) {
  return (
    <svg width="14" height="14" viewBox="0 0 24 24" fill={filled ? 'currentColor' : 'none'} stroke="currentColor" strokeWidth="2" strokeLinejoin="round">
      <path d="M6 3h12v18l-6-4-6 4z" />
    </svg>
  );
}

export function IconTheme({ light }: { light: boolean }) {
  return light ? (
    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round"><path d="M21 12.8A9 9 0 1 1 11.2 3a7 7 0 0 0 9.8 9.8z" /></svg>
  ) : (
    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round">
      <circle cx="12" cy="12" r="4" /><path d="M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4" />
    </svg>
  );
}
