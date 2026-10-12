# BriefSec - SOC Intelligence Dashboard

A real-time cybersecurity intelligence tool built for Security Operations Centre (SOC) analysts. BriefSec aggregates 15 trusted security sources, cross-references the CISA Known Exploited Vulnerabilities catalog, tracks CVEs across your technology stack, extracts IOCs, maps MITRE ATT&CK techniques, and exports artifacts ready for Splunk and MISP — all in a single fast dashboard with no external SaaS dependencies.

![Next.js](https://img.shields.io/badge/Next.js-14-black?logo=next.js)
![TypeScript](https://img.shields.io/badge/TypeScript-5-blue?logo=typescript)
![SQLite](https://img.shields.io/badge/SQLite-3-lightblue?logo=sqlite)

---

## Live deployment

Hosted on Railway — auto-deploys from the `master` branch on every push.

---

## Feature overview

### Threat Level Indicator
A synthesised **NORMAL / ELEVATED / HIGH / SEVERE** badge computed in real time from the past 24 hours of ingested data. The score weights:

| Signal | Weight |
|--------|--------|
| CISA KEV match | ×5 |
| Zero-Day article | ×3 |
| CRITICAL-severity article | ×2 |
| Ransomware activity | ×2 |
| Nation-State activity | ×1.5 |
| HIGH-severity article | ×0.5 |

The badge sits in the header alongside per-severity counts (CRIT / HIGH / MED) that are clickable to filter instantly.

---

### Severity Triage (automatic, per article)
Every article is assigned one of four severity levels computed client-side — no manual tagging required:

| Level | Triggers |
|-------|----------|
| **CRITICAL** | CVE matches CISA KEV · CISA advisory · Zero-Day + CVE · "actively exploited", "in the wild", "emergency patch" |
| **HIGH** | Zero-Day · Ransomware · APT/Nation-State · ICS/OT + CVE · Unauthenticated RCE keyword · CVE + high-risk keyword |
| **MEDIUM** | CVE present · Breach/Malware/Phishing tag · Patch Tuesday · Supply Chain |
| **LOW** | Everything else |

Article cards are colour-coded and sortable by risk level.

---

### Stack CVE Tracker (`/api/cve-tracker`)
A dedicated tab that queries the [NVD API v2](https://nvd.nist.gov/developers/vulnerabilities) for the past 90 days of CVEs affecting your technology stack:

- **Windows Server**
- **Azure AD / Entra ID**
- **Splunk Enterprise**
- **NetScaler / Citrix**
- **F5 BIG-IP**

Results are cached in SQLite for 12 hours and cross-referenced with the CISA KEV catalog. The table shows:

| Column | Detail |
|--------|--------|
| CVE ID | Links to NVD detail page |
| CVSS Score | Colour-coded (red ≥9, orange ≥7, yellow ≥4) |
| Product | Which stack component |
| Published | Date |
| KEV | `⚠ KEV` badge if actively exploited |
| Status | Per-CVE patch status persisted to SQLite |

**Patch status** options (persisted to SQLite, shared across team):  
`New` → `Investigating` → `In Progress` → `Patched ✓` → `N/A`

Every CVE in the tracker also has a **SPL** button that copies a ready-to-paste Splunk search query.

---

### 7-Day Threat Trend Chart
A pure SVG stacked bar chart (no charting library) showing daily article volume broken down by severity (CRITICAL / HIGH / MEDIUM / LOW) over the past 7 days. Includes a summary stat grid and the active threat actor list.

---

### Threat Actor Spotlight
Automatically detects mentions of 14 known threat actors across the past 7 days of articles. Clicking an actor chip filters the feed to matching articles.

| Actor | Origin | Target Sector |
|-------|--------|---------------|
| Lazarus Group | DPRK | Financial / Crypto |
| FIN7 | Criminal | Financial / Retail |
| Cl0p | Criminal | Multi-sector |
| LockBit | Criminal | Multi-sector |
| BlackCat / ALPHV | Criminal | Multi-sector |
| Sandworm | Russia GRU | Critical Infrastructure |
| APT29 / Cozy Bear | Russia SVR | Government / Finance |
| Scattered Spider | Criminal | Financial / Tech |
| Fancy Bear / APT28 | Russia GRU | Government / Defence |
| TA505 | Criminal | Financial |
| Volt Typhoon | China | Critical Infrastructure |
| Salt Typhoon | China | Telecom / Government |
| REvil / Sodinokibi | Criminal | Multi-sector |
| Akira | Criminal | Multi-sector |

---

### IOC Extraction (automatic, per article)
The IOC panel on every article card automatically extracts:

- **IP addresses** — IPv4, private ranges excluded (RFC 1918, loopback, link-local)
- **File hashes** — SHA-256 (64 hex chars), SHA-1 (40), MD5 (32)
- **Suspicious domains** — TLDs commonly abused by threat actors (`.onion`, `.ru`, `.cn`, `.tk`, `.xyz`, etc.)
- **Defanged IOCs** — `hxxp://` and `[.]` notation is re-fanged before extraction

Each IOC chip copies to clipboard on click. Every IOC also has a **SPL** button.

---

### Splunk SPL Query Generator
One-click Splunk queries generated from any IOC or CVE, ready to paste directly into Splunk Search:

**IP address:**
```spl
index=* (src_ip="1.2.3.4" OR dest_ip="1.2.3.4" OR src="1.2.3.4" OR dest="1.2.3.4")
| table _time, src_ip, dest_ip, user, host, sourcetype
| head 100
```

**File hash:**
```spl
index=* ("abc123...def")
| table _time, host, user, file_name, file_path, CommandLine
| head 100
```

**Domain:**
```spl
index=* (dest_host="*evil.xyz*" OR url="*evil.xyz*" OR query="evil.xyz")
| table _time, src_ip, dest_host, url, user
| head 100
```

**CVE:**
```spl
(index=vulnerability "CVE-2024-12345") OR (index=* "CVE-2024-12345")
| stats count by host, severity, signature
| sort -count
```

---

### MISP Export
The **MISP** button in the header generates a MISP-compatible JSON event from all IOCs extracted from CRITICAL and HIGH severity articles in the current filtered view, then downloads it as a `.json` file. The event includes:

- `ip-dst` attributes for IP addresses
- `domain` attributes for suspicious domains  
- `sha256` / `sha1` / `md5` attributes for file hashes
- `vulnerability` attributes for all CVE IDs

Compatible with MISP 2.4+ event import.

---

### CVSS Scores on CVE Badges
CVE badges fetch CVSS v3.1 scores from NVD via `/api/cvss` (7-day SQLite cache, batch requests). Scores are displayed inline next to the CVE ID, colour-coded by severity band.

---

### CISA KEV Cross-Reference
The CISA [Known Exploited Vulnerabilities](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) catalog is fetched every 6 hours and cached. Any article whose CVEs appear in the KEV catalog is auto-escalated to CRITICAL severity and shown with an `⚠ KEV` badge. The KEV tab shows only these articles.

---

### MITRE ATT&CK Technique Detection
15 techniques detected by keyword pattern matching on article titles and descriptions:

`T1566 Phishing` · `T1195 Supply Chain` · `T1486 Data Encrypted` · `T1110 Brute Force` · `T1059 Code Execution` · `T1190 Exploit Public App` · `T1203 Client Exploit` · `T1505 Server Component` · `T1068 Priv Escalation` · `T1041 Exfiltration` · `T1071 C2 Protocol` · `T1550 Alt Auth Material` · `T1027 Obfuscation` · `T1189 Drive-by` · `T1218 Signed Binary`

Technique badges appear on each card when a match is detected.

---

### Stack-Specific Tags
Articles are automatically tagged when content matches your technology stack:

`Azure AD` · `Splunk` · `NetScaler` · `F5/BIG-IP` · `M365` · `Windows/AD` · `Financial Sector` · `Regulatory`

**Stack vendor priority:** vulnerability news about the SOC's vendors — Citrix, Palo Alto, Splunk, VMray, Microsoft, Cisco, Oracle — is always ranked first, in every view and sort order, and marked with a green ★ vendor badge. The vendor has to appear in the headline or lede (passing mentions such as "Microsoft has warned" or "disguised as Microsoft Edge" don't count). Raw Microsoft MSRC advisories are ranked below that news: exploited/KEV-listed ones join the top group, remote code execution ones come right after it, and the rest stay in normal order.

---

### Filters & Search
| Filter | Options |
|--------|---------|
| View | Feed · Saved · KEV · Stack CVEs · Trends |
| Time | All · 7 days · 24 hours |
| Sort | Newest · By Risk |
| Severity | ALL · CRITICAL · HIGH · MEDIUM · LOW |
| Source | Per-source pills |
| Tag | Per-tag pills (all detected tags) |
| Search | Full-text across title, description, CVE IDs, source |

---

### Critical This Week
A collapsible red banner above the feed showing up to 8 CRITICAL articles from the past 7 days. Always computed from the full dataset regardless of active filters. Includes a quick link to apply the 7-day CRITICAL filter.

---

### Pin & Save
- **Pin** — Pins articles to a persistent yellow panel at the top of the feed. Survives page reloads (localStorage).
- **Save** — Bookmarks articles to the Saved view. Also localStorage-persisted.

---

### Daily Brief Export
The **Export Brief** button generates a structured Markdown report and downloads it as `briefsec-soc-brief-YYYY-MM-DD.md`, covering:
- CRITICAL alerts with KEV status and IOCs
- HIGH priority articles
- CISA KEV matches
- All CVEs referenced
- Consolidated IP, hash, and domain IOC lists

---

### New Article Tracking
`lastVisit` timestamp is stored in localStorage. Articles published after your last visit show a pulsing **NEW** badge. An unread count appears in the header. "Mark all read" resets the timestamp.

---

### Auto-Refresh
The browser page auto-refreshes every 15 minutes. If new CRITICAL articles arrive since the last refresh, a dismissible toast alert appears. Auto-refresh can be toggled on/off.

---

## Intelligence sources (15 feeds)

| Source | Type |
|--------|------|
| [Krebs on Security](https://krebsonsecurity.com) | Investigative journalism |
| [The Hacker News](https://thehackernews.com) | Breaking news |
| [BleepingComputer](https://www.bleepingcomputer.com) | Ransomware, malware, vulns |
| [Schneier on Security](https://www.schneier.com) | Policy, cryptography, analysis |
| [SANS Internet Storm Center](https://isc.sans.edu) | Daily practitioner diary |
| [CISA](https://www.cisa.gov) | US government advisories |
| [Graham Cluley](https://grahamcluley.com) | Security commentary |
| [Ars Technica Security](https://arstechnica.com/security) | In-depth technical reporting |
| [Naked Security (Sophos)](https://nakedsecurity.sophos.com) | Threat research |
| [Troy Hunt](https://www.troyhunt.com) | Breaches, Have I Been Pwned |
| [SecurityWeek](https://www.securityweek.com) | Enterprise security news |
| [Dark Reading](https://www.darkreading.com) | Threat intelligence |
| [Microsoft MSRC](https://msrc.microsoft.com) | Microsoft security advisories |
| [CERT.at](https://www.cert.at) | European government CERT advisories |
| [ENISA](https://www.enisa.europa.eu) | EU cybersecurity agency |

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     Browser (React)                         │
│                                                             │
│  Threat Level  │  Feed  │  Stack CVEs  │  Trends  │  IOCs  │
└────────────────────────────┬────────────────────────────────┘
                             │ fetch()
                ┌────────────▼────────────────────────────┐
                │           Next.js 14 (App Router)       │
                │                                         │
                │  /api/news        ← RSS + SQLite cache  │
                │  /api/kev         ← CISA KEV (6h cache) │
                │  /api/cve-tracker ← NVD API (12h cache) │
                │  /api/cvss        ← NVD CVSS (7d cache) │
                └────────────────────────────┬────────────┘
                                             │
                               ┌─────────────▼──────────────┐
                               │      briefsec.sqlite       │
                               │                              │
                               │  articles  (600 news+250 MS) │
                               │  cve_tracker_cache  (12h)   │
                               │  cvss_cache         (7d)    │
                               │  cve_patch_status  (shared) │
                               └──────────────────────────────┘
```

**Data flow:**
1. `rss-worker.js` (optional, standalone) or the API route itself ingests feeds into SQLite
   - Articles whose feed snippet has no CVE ID get their article page fetched once (`lib/cve-enrich.js`) and the CVE IDs from the article body are stored alongside (The Hacker News and Dark Reading block automated reads, so those show a "CVE: check article" link instead)
2. `/api/news` returns articles — from SQLite first, live RSS if DB is empty
3. `/api/kev` fetches the CISA KEV JSON catalog every 6 hours
4. `/api/cve-tracker` queries NVD API for each stack product with a 12-hour SQLite cache
5. `/api/cvss` does batch CVSS lookups from NVD with a 7-day SQLite cache
6. All severity triage, IOC extraction, MITRE mapping, Splunk generation, and MISP export happen client-side — no additional API calls

---

## Technology stack

| Layer | Technology |
|-------|-----------|
| Framework | Next.js 14 (App Router) |
| Language | TypeScript 5 |
| Database | SQLite via `better-sqlite3` |
| Feed parsing | `rss-parser` |
| CVE data | NVD API v2 (free, no key required) |
| KEV data | CISA Known Exploited Vulnerabilities JSON |
| Styling | Vanilla CSS (no Tailwind, no UI library) |
| Charts | Pure SVG (no charting library) |
| State | React hooks + localStorage |
| Deployment | Railway (auto-deploy from GitHub) |

No paid APIs. No external authentication. No telemetry.

---

## Project structure

```
briefsec/
├── app/
│   ├── api/
│   │   ├── news/route.ts          # RSS ingestion, SQLite cache, tag/CVE extraction
│   │   ├── kev/route.ts           # CISA KEV catalog (6h in-memory cache)
│   │   ├── cve-tracker/route.ts   # NVD CVE queries per stack product (12h SQLite cache)
│   │   └── cvss/route.ts          # Batch CVSS score lookup (7d SQLite cache)
│   ├── page.tsx                   # Main dashboard — all UI, logic, filters
│   ├── layout.tsx                 # HTML shell, metadata
│   └── globals.css                # Dark security-analyst theme (pure CSS)
├── lib/
│   └── cve-enrich.js              # Fetches article pages to find CVE IDs missing from feed snippets
├── scripts/
│   └── rss-worker.js              # Standalone ingestion script (optional background job)
├── db/
│   └── briefsec.sqlite          # Auto-created on first run (gitignored)
└── package.json
```

---

## Getting started

### Prerequisites

- Node.js 18+
- npm

### Install and run

```bash
git clone https://github.com/shpejtimK/briefsec.git
cd briefsec
npm install
npm run dev
```

Open [http://localhost:63337](http://localhost:63337).

On first load the app fetches all 15 feeds live (~10–15 seconds). After that, articles are served from SQLite and responses are near-instant.

### Pre-populate the database (recommended)

```bash
npm run worker:rss        # ingest once
npm run worker:rss:watch  # ingest continuously every 15 min
```

### Production build

```bash
npm run build
npm start
```

---

## Environment variables

| Variable | Default | Purpose |
|----------|---------|---------|
| `DATABASE_PATH` | `db/briefsec.sqlite` | Absolute path to SQLite file |
| `PORT` | `63337` | HTTP port |

---

## SQLite schema

```sql
-- Core articles (newest 600 news + 250 MSRC, trimmed on each ingestion)
CREATE TABLE articles (
  id           TEXT PRIMARY KEY,
  title        TEXT,
  link         TEXT UNIQUE,
  description  TEXT,
  content      TEXT,
  pub_date     TEXT,
  source       TEXT,
  tags         TEXT,   -- JSON array
  cves         TEXT,   -- JSON array of CVE IDs
  author       TEXT,
  created_at   INTEGER
);

-- NVD CVE data per stack product (12-hour cache)
CREATE TABLE cve_tracker_cache (
  product    TEXT PRIMARY KEY,
  data       TEXT NOT NULL,
  fetched_at INTEGER NOT NULL
);

-- Per-CVE patch status (shared across team)
CREATE TABLE cve_patch_status (
  cve_id     TEXT PRIMARY KEY,
  status     TEXT DEFAULT 'new',
  notes      TEXT DEFAULT '',
  updated_at INTEGER
);

-- CVSS score cache (7-day TTL)
CREATE TABLE cvss_cache (
  cve_id     TEXT PRIMARY KEY,
  score      REAL,
  severity   TEXT,
  fetched_at INTEGER NOT NULL
);
```

---

## License

MIT
