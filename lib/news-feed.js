/* eslint-disable no-console */
// Hacking news: direct security-news feeds plus Google News searches for breaking incidents
// (general press often has an attack or breach hours before the security outlets do).
// Articles land in the `articles` table; clusterStories() merges coverage of the same story.
//
// Shared by scripts/rss-worker.js and app/api/news/route.ts.

const crypto = require('crypto');
const Parser = require('rss-parser');
const { extractCVEs, ensureEnrichmentColumns } = require('./cve-enrich');

const FEEDS = [
  { name: 'BleepingComputer',      url: 'https://www.bleepingcomputer.com/feed/' },
  { name: 'The Hacker News',       url: 'https://feeds.feedburner.com/TheHackersNews' },
  { name: 'SecurityWeek',          url: 'https://www.securityweek.com/feed/' },
  { name: 'The Record',            url: 'https://therecord.media/feed' },
  { name: 'Dark Reading',          url: 'https://www.darkreading.com/rss.xml' },
  { name: 'Krebs on Security',     url: 'https://krebsonsecurity.com/feed/' },
  { name: 'Security Affairs',      url: 'https://securityaffairs.com/feed' },
  { name: 'The Register',          url: 'https://www.theregister.com/security/headlines.atom' },
  { name: 'Infosecurity Magazine', url: 'https://www.infosecurity-magazine.com/rss/news/' },
  { name: 'Help Net Security',     url: 'https://www.helpnetsecurity.com/feed/' },
  { name: 'CyberScoop',            url: 'https://cyberscoop.com/feed/' },
  { name: 'DataBreaches.net',      url: 'https://databreaches.net/feed/' },
  { name: 'TechCrunch',            url: 'https://techcrunch.com/category/security/feed/' },
  { name: 'HackRead',              url: 'https://hackread.com/feed/' },
  { name: 'CSO Online',            url: 'https://www.csoonline.com/feed/' },
  { name: 'Ars Technica',          url: 'https://arstechnica.com/security/feed/' },
  { name: 'Schneier on Security',  url: 'https://www.schneier.com/feed/atom/' },
  { name: 'Graham Cluley',         url: 'https://grahamcluley.com/feed/' },
  { name: 'Troy Hunt',             url: 'https://www.troyhunt.com/rss/' },
  { name: 'SANS ISC',              url: 'https://isc.sans.edu/rssfeed_full.xml' },
  { name: 'CISA',                  url: 'https://www.cisa.gov/cybersecurity-advisories/all.xml' },
];

// Last-24h searches; results are filtered hard (see isRelevantGoogleItem)
const GOOGLE_NEWS_QUERIES = [
  'cyberattack OR "cyber attack"',
  '"data breach" OR "data leak" OR hacked',
  'ransomware',
  'hackers',
  '"zero-day" OR "actively exploited" OR "security flaw"',
];

const KEEP_DAYS = 14;
const MAX_ARTICLES = 2000;
const FEED_CONCURRENCY = 8;

const parser = new Parser({
  customFields: {
    item: [
      ['dc:creator', 'creator'],
      ['content:encoded', 'contentEncoded'],
      ['source', 'gnSource'],
    ],
  },
  timeout: 15000,
  headers: {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36',
    'Accept': 'application/rss+xml, application/atom+xml, application/xml, text/xml, */*',
  },
});

// ─── Text helpers ─────────────────────────────────────────────────────────────

function stripHtml(html) {
  return (html || '')
    .replace(/<[^>]+>/g, ' ')
    .replace(/&nbsp;/g, ' ').replace(/&amp;/g, '&').replace(/&lt;/g, '<').replace(/&gt;/g, '>')
    .replace(/&quot;/g, '"').replace(/&apos;|&#39;|&#8217;|&#x27;/g, "'").replace(/&#\d+;/g, ' ')
    .replace(/\s+/g, ' ').trim();
}

function truncate(text, limit) {
  if (text.length <= limit) return text;
  const slice = text.slice(0, limit);
  const lastSentence = Math.max(slice.lastIndexOf('. '), slice.lastIndexOf('! '), slice.lastIndexOf('? '));
  if (lastSentence > limit * 0.5) return slice.slice(0, lastSentence + 1).trimEnd() + '...';
  const lastSpace = slice.lastIndexOf(' ');
  return (lastSpace > 0 ? slice.slice(0, lastSpace) : slice) + '...';
}

// Feed boilerplate that adds nothing ("The post X appeared first on Y.")
function cleanSummary(text) {
  return text
    .replace(/The post .{0,300}? appeared first on .{0,80}?\.?$/i, '')
    .replace(/\s*(Read more|Continue reading|Read the full article)\b.*$/i, '')
    .trim();
}

// ─── Categories ───────────────────────────────────────────────────────────────

const CATEGORY_RULES = [
  ['Ransomware',      /ransomware|extortion (gang|group)|leak site/],
  ['Data Breach',     /\bbreach|data leak|leaked|stolen data|data (was|were) stolen|exfiltrat|records exposed|exposes? .{0,40}(records|data|people|customers|users)|personal (data|information)|customer data/],
  ['Cyberattack',     /cyber.?attack|\bddos\b|\bhacked\b|hack(ers?)? (hit|target|disrupt|attack|breach|cripple|take down)|attack on|disrupt(ed|s)? (operations|services|systems)/],
  ['Vulnerability',   /vulnerab|\bflaws?\b|\bcve-\d|zero.?day|\b0-?day|\bexploit|\brce\b|remote code|security update|patch(es|ed)?\b/],
  ['Actively Exploited', /actively exploited|exploited in the wild|under active exploitation|zero.?day attacks?|known exploited/],
  ['Malware',         /malware|trojan|backdoor|spyware|botnet|rootkit|infostealer|stealer\b|\bloader\b|\brat\b|wiper/],
  ['Phishing',        /phish|smishing|vishing|scam|fraud|business email compromise/],
  ['Nation-State',    /nation.?state|state.?(sponsored|backed)|\bapt ?\d+|(chinese|russian|north korean|iranian)(-linked)? (hackers|threat actors|state|spies|apt)|lazarus|typhoon|fancy bear|cozy bear|sandworm|kimsuky/],
  ['Law Enforcement', /\barrest|\bcharged\b|sentenced|indict|extradit|\bseized?\b|takedown|pleads? guilty|convicted|europol|\bfbi\b|\bdoj\b/],
  ['Supply Chain',    /supply.?chain|\bnpm\b|\bpypi\b|malicious (packages?|extensions?)|dependency confusion/],
  ['AI',              /\bai\b|artificial intelligence|\bllms?\b|chatgpt|\bclaude\b|gemini|deepfake|agentic|ai agents?/],
];

function detectCategories(title, summary) {
  const text = `${title} ${summary.slice(0, 600)}`.toLowerCase();
  return CATEGORY_RULES.filter(([, re]) => re.test(text)).map(([name]) => name);
}

// ─── Source-specific filters ──────────────────────────────────────────────────

function isNewsItem(source, title, link) {
  // ICS advisories and KEV additions are CVE data — they're on the CVEs tab
  if (source === 'CISA') {
    if (/\/ics-advisories\//.test(link)) return false;
    if (/known exploited vulnerabilit|industrial control systems? advisories/i.test(title)) return false;
  }
  if (source === 'SANS ISC' && /^ISC Stormcast/i.test(title)) return false;
  return true;
}

// Security outlets also publish staff announcements, opinion pieces and product news
const SECURITY_HEADLINE = /hack|breach|attack|ransom|malware|exploit|vulnerab|flaw|patch|phish|leak|stolen|steal|cyber|security|threat|spy|scam|fraud|arrest|ddos|botnet|zero.?day|\bcve\b|\bbugs?\b|backdoor|\bapt\b|espionage|surveillance|password|credential|bypass|compromis|extort|crypto|wallet|trojan|stealer|botnet|rce|injection|takedown|seiz|sanction|indict|sentenc|charged|outage|incident|exposed|privacy|spyware|exfiltrat|hijack|dark ?web|secrets?\b|rogue|malicious|abus|intrusion|infiltrat|poison|impersonat|deepfake|sabotage|prompt injection|\btls\b|certificate/i;

function isHackingNews(title, categories, cves) {
  return categories.length > 0 || cves.length > 0 || SECURITY_HEADLINE.test(title);
}

const GN_INCIDENT = /cyber.?attack|\bhack(ed|ers?|ing)?\b|breach|data leak|leaked|stolen|ransomware|malware|exploit|zero.?day|vulnerab|security flaw|phishing|\bddos\b|spyware|compromised|extort|botnet|backdoor|infostealer|cybercrim/i;
const GN_SPAM = /hacked (\w+ )?to death|hack(ing)? (instagram|facebook|whatsapp|snapchat|tiktok|roblox|gmail)|unlock password|free (followers|robux|coins|v-?bucks)|\[[A-Za-z0-9]{6,}\]|how to hack|hack .{0,20}(apk|mod|generator)/i;
const GN_BLOCKED_PUBLISHERS = /medium|youtube|reddit|linkedin|facebook|quora|tiktok|instagram|pinterest|scribd|slideshare/i;

function isRelevantGoogleItem(title, publisher) {
  if (!GN_INCIDENT.test(title) || GN_SPAM.test(title)) return false;
  if (GN_BLOCKED_PUBLISHERS.test(publisher)) return false;
  // Skip non-English results (Google News mixes some in even with hl=en)
  const nonLatin = (title.match(/[^\u0000-ɏ -⁯€]/g) || []).length;
  return nonLatin / Math.max(title.length, 1) < 0.15;
}

// Google News titles look like "Headline - Publisher"
function splitGoogleTitle(raw, sourceField) {
  const publisher = typeof sourceField === 'string' ? sourceField
    : (sourceField && (sourceField._ || sourceField['#'])) || '';
  const idx = raw.lastIndexOf(' - ');
  if (idx > 20) return { title: raw.slice(0, idx).trim(), publisher: publisher || raw.slice(idx + 3).trim() };
  return { title: raw.trim(), publisher: publisher || 'Google News' };
}

// ─── Schema ───────────────────────────────────────────────────────────────────

function ensureNewsSchema(db) {
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
    CREATE INDEX IF NOT EXISTS idx_pub ON articles(published_at DESC);
    CREATE INDEX IF NOT EXISTS idx_hash ON articles(content_hash);
    CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT);
  `);
  for (const sql of [
    `ALTER TABLE articles ADD COLUMN content TEXT DEFAULT ''`,
    `ALTER TABLE articles ADD COLUMN via TEXT DEFAULT ''`,
  ]) {
    try { db.exec(sql); } catch { /* column already exists */ }
  }
  ensureEnrichmentColumns(db);
}

function getMeta(db, key) {
  const row = db.prepare(`SELECT value FROM meta WHERE key = ?`).get(key);
  return row ? row.value : null;
}

function setMeta(db, key, value) {
  db.prepare(`INSERT OR REPLACE INTO meta (key, value) VALUES (?, ?)`).run(key, String(value));
}

// ─── Ingestion ────────────────────────────────────────────────────────────────

async function mapLimit(items, limit, fn) {
  const results = new Array(items.length);
  let next = 0;
  await Promise.all(Array.from({ length: Math.min(limit, items.length) }, async () => {
    while (next < items.length) {
      const i = next++;
      try { results[i] = { ok: true, value: await fn(items[i]) }; } catch (err) { results[i] = { ok: false, error: err }; }
    }
  }));
  return results;
}

function toRow(job, item) {
  const now = Date.now();
  const rawTitle = stripHtml(item.title || '');
  if (!rawTitle) return null;

  let title = rawTitle;
  let source = job.name;
  let via = '';
  if (job.google) {
    const split = splitGoogleTitle(rawTitle, item.gnSource);
    if (!isRelevantGoogleItem(split.title, split.publisher)) return null;
    title = split.title;
    source = split.publisher;
    via = 'google';
  }

  const link = item.link || item.guid || '';
  if (!isNewsItem(source, title, link)) return null;

  const pubMs = new Date(item.isoDate || item.pubDate || now).getTime();
  const publishedAt = Math.min(Number.isFinite(pubMs) ? pubMs : now, now);
  if (publishedAt < now - KEEP_DAYS * 86_400_000) return null;

  // Google News descriptions are just the headline again as a link
  const fullText = job.google ? '' : cleanSummary(stripHtml(
    item.contentEncoded || item['content:encoded'] || item.content || item.contentSnippet || item.summary || ''
  ));
  const description = truncate(fullText, 600);
  return {
    guid: String(item.guid || item.id || link || title),
    source,
    title,
    link,
    description,
    content: truncate(fullText, 3000),
    author: item.creator || item.author || '',
    pubDate: new Date(publishedAt).toISOString(),
    publishedAt: Math.floor(publishedAt / 1000),
    tags: detectCategories(title, fullText),
    // Full feed text, not the excerpt — long posts often name the CVE further down
    cves: extractCVEs(`${title} ${fullText}`),
    contentHash: crypto.createHash('sha256').update((title + description).toLowerCase()).digest('hex'),
    via,
  };
}

// Fetches every feed and search, upserts the articles and trims old ones
async function refreshNews(db, { log = false } = {}) {
  ensureNewsSchema(db);
  // Microsoft's advisory feed was dropped — its CVEs come from NVD on the CVEs tab now
  db.prepare(`DELETE FROM articles WHERE source = 'Microsoft MSRC'`).run();

  const jobs = [
    ...FEEDS,
    ...GOOGLE_NEWS_QUERIES.map(q => ({
      name: `Google News: ${q}`,
      google: true,
      url: `https://news.google.com/rss/search?q=${encodeURIComponent(`${q} when:1d`)}&hl=en-US&gl=US&ceid=US:en`,
    })),
  ];
  const results = await mapLimit(jobs, FEED_CONCURRENCY, job => parser.parseURL(job.url));

  const upsert = db.prepare(`
    INSERT INTO articles (guid, source, title, link, description, content, author, pub_date, published_at, tags, cves, content_hash, via)
    VALUES (@guid, @source, @title, @link, @description, @content, @author, @pubDate, @publishedAt, @tags, @cves, @contentHash, @via)
    ON CONFLICT(source, guid) DO UPDATE SET
      title = excluded.title,
      description = excluded.description,
      content = excluded.content,
      tags = excluded.tags,
      cves = excluded.cves
  `);
  const seenHash = db.prepare(`SELECT id FROM articles WHERE content_hash = ? AND source != ? LIMIT 1`);

  let stored = 0;
  const failed = [];
  db.transaction(() => {
    results.forEach((result, i) => {
      const job = jobs[i];
      if (!result.ok) { failed.push(`${job.name} (${result.error.message})`); return; }
      for (const item of result.value.items || []) {
        const row = toRow(job, item);
        if (!row) continue;
        if (row.description && seenHash.get(row.contentHash, row.source)) continue;
        upsert.run({ ...row, tags: JSON.stringify(row.tags), cves: JSON.stringify(row.cves) });
        stored++;
      }
    });
  })();

  const cutoff = Math.floor(Date.now() / 1000) - KEEP_DAYS * 86_400;
  db.prepare(`DELETE FROM articles WHERE published_at < ?`).run(cutoff);
  db.prepare(`DELETE FROM articles WHERE id NOT IN (SELECT id FROM articles ORDER BY published_at DESC LIMIT ${MAX_ARTICLES})`).run();
  setMeta(db, 'news_last_refresh', Date.now());

  if (log) {
    console.log(`[News] ${stored} articles from ${jobs.length - failed.length}/${jobs.length} feeds`);
    for (const f of failed) console.log(`  [News skip] ${f}`);
  }
  return stored;
}

// ─── Story clustering ─────────────────────────────────────────────────────────

const STOPWORDS = new Set(('the and for with from that this into over after amid about says said its their they them than then have has had '
  + 'are was were will would could can new more most how why what who when where which your you our out not but all any via '
  + 'warns warn report reports reported attack attacks attacked attackers hackers hacker hacked hacking cyber cyberattack cyberattacks '
  + 'cybersecurity security data flaw flaws million hit hits major latest news update after amid following').split(' '));

// Headlines say "Danish" as often as "Denmark"
const DEMONYMS = {
  danish: 'denmark', french: 'france', german: 'germany', british: 'uk', britain: 'uk', english: 'uk', chinese: 'china',
  russian: 'russia', iranian: 'iran', ukrainian: 'ukraine', japanese: 'japan', korean: 'korea', israeli: 'israel',
  indian: 'india', australian: 'australia', canadian: 'canada', spanish: 'spain', italian: 'italy', dutch: 'netherlands',
  swedish: 'sweden', norwegian: 'norway', finnish: 'finland', polish: 'poland', american: 'us', irish: 'ireland',
};

function titleTokens(title) {
  const words = title.toLowerCase().replace(/[’']s\b/g, '').replace(/[’']/g, '').split(/[^a-z0-9.]+/);
  const out = new Set();
  for (let w of words) {
    w = w.replace(/^\.+|\.+$/g, '');
    if (w.length < 3 || STOPWORDS.has(w) || /^(19|20)\d\d$/.test(w)) continue;
    w = DEMONYMS[w] || w;
    if (w.length > 6) w = w.replace(/(ing|ed)$/, '');
    if (w.length > 3) w = w.replace(/ies$/, 'y').replace(/([^s])s$/, '$1');
    out.add(w);
  }
  return out;
}

const SAME_STORY_THRESHOLD = 0.4;

// Rare words ("CPR", "supermarket") say far more about which story a headline is than common
// ones ("breach", "ransomware"), so overlap is weighted by inverse document frequency
function sameStory(a, b, weight) {
  if (Math.abs(a.publishedMs - b.publishedMs) > 3 * 86_400_000) return false;
  let shared = 0;
  let sharedWeight = 0;
  for (const t of a.tokens) if (b.tokens.has(t)) { shared++; sharedWeight += weight(t); }
  // Same headline CVE and overlapping headlines (newsletters cite a CVE without being the story)
  if (shared >= 1 && a.cves.length && b.cves.length && a.cves.length <= 3 && b.cves.length <= 3 && a.cves[0] === b.cves[0]) return true;
  if (shared < 2) return false;
  const total = tokens => [...tokens].reduce((sum, t) => sum + weight(t), 0);
  return sharedWeight / Math.min(total(a.tokens), total(b.tokens)) >= SAME_STORY_THRESHOLD;
}

// Groups articles about the same story. Each story is represented by its best article (a direct
// feed with a summary beats a Google News link) and dated by its newest coverage, so a story
// that's still developing moves back up the feed.
function clusterStories(articles) {
  const items = articles
    .map(a => ({ ...a, publishedMs: new Date(a.pubDate).getTime(), tokens: titleTokens(a.title) }))
    .sort((a, b) => b.publishedMs - a.publishedMs);

  const df = new Map();
  for (const item of items) for (const t of item.tokens) df.set(t, (df.get(t) || 0) + 1);
  const weight = t => Math.log(1 + items.length / (df.get(t) || 1));

  const clusters = [];
  for (const item of items) {
    // Compared with each story's first article only — matching any member lets loosely related
    // stories chain together
    const home = clusters.find(c => sameStory(c.members[0], item, weight));
    if (home) home.members.push(item);
    else clusters.push({ members: [item] });
  }

  return clusters.map(({ members }) => {
    const rank = m => (m.via === 'google' ? 0 : 2) + (m.description ? 1 : 0);
    const lead = [...members].sort((a, b) => rank(b) - rank(a) || a.publishedMs - b.publishedMs)[0];
    const newest = members.reduce((a, b) => (b.publishedMs > a.publishedMs ? b : a));
    const oldest = members.reduce((a, b) => (b.publishedMs < a.publishedMs ? b : a));
    const cves = [...new Set([...lead.cves, ...members.flatMap(m => m.cves)])];
    const tags = [...new Set(members.flatMap(m => m.tags))];
    return {
      id: lead.id,
      title: lead.title,
      link: lead.link,
      source: lead.source,
      description: lead.description,
      pubDate: newest.pubDate,
      firstSeen: oldest.pubDate,
      tags,
      cves,
      cveStatus: lead.cveStatus,
      coverage: members
        .filter(m => m !== lead)
        .sort((a, b) => b.publishedMs - a.publishedMs)
        .map(m => ({ source: m.source, title: m.title, link: m.link, pubDate: m.pubDate })),
    };
  }).sort((a, b) => new Date(b.pubDate).getTime() - new Date(a.pubDate).getTime());
}

// Articles from the last KEEP_DAYS days, merged with any CVE IDs found on their pages
function readArticles(db) {
  const rows = db.prepare(`
    SELECT guid, source, title, link, description, pub_date, tags, cves, page_cves, cve_scan, via
    FROM articles WHERE is_duplicate = 0 AND published_at >= ?
    ORDER BY published_at DESC
  `).all(Math.floor(Date.now() / 1000) - KEEP_DAYS * 86_400);
  return rows.filter(r => isNewsItem(r.source, r.title, r.link)).map(r => ({
    id: `${r.source}::${r.guid}`,
    title: r.title,
    link: r.link,
    source: r.source,
    description: r.description || '',
    pubDate: r.pub_date,
    // Recomputed so rows stored before a rule change get the current categories
    tags: detectCategories(r.title, r.description || ''),
    cves: [...new Set([...JSON.parse(r.cves || '[]'), ...JSON.parse(r.page_cves || '[]')])],
    cveStatus: r.cve_scan || 'pending',
    via: r.via || '',
  })).filter(a => isHackingNews(a.title, a.tags, a.cves));
}

module.exports = {
  FEEDS,
  ensureNewsSchema,
  refreshNews,
  readArticles,
  clusterStories,
  getMeta,
  setMeta,
  detectCategories,
};
