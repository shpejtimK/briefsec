# BriefSec

Up-to-date hacking news and CVEs in two tabs. Sources refresh every 5 minutes, and vulnerability news and CVEs for the team's vendors (Citrix, Palo Alto, Splunk, VMray, Microsoft, Cisco, Oracle) are always shown first.

![Next.js](https://img.shields.io/badge/Next.js-14-black?logo=next.js)
![TypeScript](https://img.shields.io/badge/TypeScript-5-blue?logo=typescript)
![SQLite](https://img.shields.io/badge/SQLite-3-lightblue?logo=sqlite)

Hosted on Railway — auto-deploys from the `master` branch on every push.

---

## Hacking News

Attacks, breaches, ransomware, exploited vulnerabilities, arrests — from:

- **21 security-news feeds:** BleepingComputer, The Hacker News, SecurityWeek, The Record, Dark Reading, Krebs on Security, Security Affairs, The Register, Infosecurity Magazine, Help Net Security, CyberScoop, DataBreaches.net, TechCrunch, HackRead, CSO Online, Ars Technica, Schneier on Security, Graham Cluley, Troy Hunt, SANS ISC, CISA (alerts and joint advisories)
- **Google News searches** for breaking incidents in the last 24 hours (cyberattack, data breach, ransomware, hackers, zero-day). General press often reports an attack hours before the security outlets; results are filtered for relevance and spam.

Coverage of the same story from several outlets is merged into one entry ("+4 sources"), dated by its newest coverage, so a developing story moves back to the top. Each story gets categories (Data Breach, Ransomware, Cyberattack, Actively Exploited, Vulnerability, Malware, Phishing, Nation-State, Law Enforcement, Supply Chain, AI).

**CVE IDs in headlines:** CVE IDs from the feed text — and, for feeds that only ship a snippet, from the article page itself (`lib/cve-enrich.js`) — are shown under the headline, colored by CVSS and flagged when they're in CISA KEV. The Hacker News, Dark Reading and Google News links can't be read automatically; stack-vendor vulnerability stories from them show a "CVE: check article" link.

**★ Your stack:** vulnerability news for the team's vendors from the last 7 days, pinned above the feed. A vendor has to be named in the headline or lede (passing mentions like "Microsoft has warned" don't count).

## CVEs

- **New CVEs** — everything NVD has published in the last 7 days (synced every 10 minutes), with CVSS score, vendor and product. Filter by 24h / 3 days / 7 days, severity, "in the news", and search. WordPress plugin CVEs (a large share of the volume) are hidden by default.
- **★ Your stack** — the week's CVEs for the team's vendors: exploited first, then critical, then high.
- **Actively exploited** — CISA KEV additions from the last 30 days, with ransomware use and the federal remediation deadline.
- CVEs mentioned in news stories link to that coverage ("In the news").

---

## Architecture

```
lib/news-feed.js  ── feeds + Google News ──┐
lib/cve-feed.js   ── NVD API + CISA KEV ───┼──► SQLite (db/briefsec.sqlite) ──► /api/news, /api/cves ──► app/page.tsx
lib/cve-enrich.js ── article pages ────────┘
```

- `scripts/rss-worker.js --watch` refreshes everything every 5 minutes (production runs it from `scripts/start-prod.sh`).
- Without the worker, `/api/news` and `/api/cves` refresh their data in the background when it's stale, and always answer immediately from SQLite (they only wait when the database is empty).
- `/api/cvss` looks up scores for older CVEs mentioned in the news (7-day cache).

| Table | Contents |
|-------|----------|
| `articles` | News articles from the last 14 days, with CVE IDs found on their pages |
| `cve_items` | CVEs published to NVD in the last 10 days |
| `kev_items` | The CISA KEV catalog |
| `cvss_cache` | Scores for older CVEs |
| `meta` | Last sync times |

## Getting started

```bash
npm install
npm run dev               # http://localhost:63337
npm run worker:rss        # refresh news + CVEs once
npm run worker:rss:watch  # refresh every 5 minutes
```

Production: `npm run build && npm start`.

## Environment variables

| Variable | Default | Purpose |
|----------|---------|---------|
| `DATABASE_PATH` | `db/briefsec.sqlite` | SQLite file location |
| `WORKER_INTERVAL_MINUTES` | `5` | Worker refresh interval |
| `CRON_MODE` | — | `true` makes the API read-only (the worker does all fetching) |
| `NVD_API_KEY` | — | Optional; raises NVD's rate limit |
