/* eslint-disable no-console */
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const Parser = require('rss-parser');
const Database = require('better-sqlite3');

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

const parser = new Parser({
  customFields: {
    item: [
      ['media:content', 'mediaContent', { keepArray: true }],
      ['media:thumbnail', 'mediaThumbnail'],
      ['dc:creator', 'creator'],
      ['content:encoded', 'contentEncoded'],
    ],
  },
  timeout: 15000,
  headers: {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
    'Accept': 'application/rss+xml, application/atom+xml, application/xml, text/xml, */*',
  },
});

function stripHtml(html) {
  return (html || '')
    .replace(/<[^>]+>/g, ' ')
    .replace(/&amp;/g, '&').replace(/&lt;/g, '<').replace(/&gt;/g, '>')
    .replace(/&quot;/g, '"').replace(/&apos;/g, "'").replace(/&#\d+;/g, ' ')
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

function detectTags(title, description) {
  const text = `${title} ${description}`.toLowerCase();
  const tags = [];
  if (/\bcve-\d{4}-\d+\b/i.test(text)) tags.push('CVE');
  if (/zero.?day|0day/.test(text)) tags.push('Zero-Day');
  if (/ransomware/.test(text)) tags.push('Ransomware');
  else if (/\bmalware\b|\btrojan\b|\bbackdoor\b|\bspyware\b|\bbotnet\b|\brootkit\b/.test(text)) tags.push('Malware');
  if (/phish/.test(text)) tags.push('Phishing');
  if (/\bbreach\b|\bdata.?leak\b|exfiltrat|stolen data|compromised.*data/.test(text)) tags.push('Breach');
  if (/vulnerabilit|\bexploit\b|\brce\b|remote code exec|buffer overflow|sql inject|cross.site|lfi\b|ssrf\b/.test(text)) tags.push('Vulnerability');
  if (/patch tuesday|microsoft.*security update/.test(text)) tags.push('Patch Tuesday');
  if (/\bapt\b|advanced persistent threat/.test(text)) tags.push('APT');
  if (/nation.?state|state.?sponsor/.test(text)) tags.push('Nation-State');
  if (/supply chain|dependency confus|typosquat|open.?source.*(attack|malicious)/.test(text)) tags.push('Supply Chain');
  if (/\bai\b|machine learning|\bllm\b|deepfake|generative/.test(text)) tags.push('AI/ML');
  if (/\bcloud\b|\baws\b|\bazure\b|\bgcp\b|\bkubernetes\b|\bdocker\b/.test(text)) tags.push('Cloud');
  if (/privacy|\bgdpr\b|\bccpa\b|data protect/.test(text)) tags.push('Privacy');
  if (/\bcritical infrastructure\b|ics\b|\bscada\b|\bots\b/.test(text)) tags.push('ICS/OT');
  return tags;
}

function extractCVEs(text) {
  const matches = text.match(/CVE-\d{4}-\d{4,}/gi) || [];
  return [...new Set(matches.map(c => c.toUpperCase()))];
}

function openDatabase() {
  const dbPath = process.env.DATABASE_PATH || path.join(__dirname, '..', 'db', 'cyberwatch.sqlite');
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
    CREATE INDEX IF NOT EXISTS idx_pub ON articles(published_at DESC);
    CREATE INDEX IF NOT EXISTS idx_hash ON articles(content_hash);
  `);
  try { db.exec(`ALTER TABLE articles ADD COLUMN content TEXT DEFAULT ''`); } catch { /* column already exists */ }
  return db;
}

async function ingestFeed(db, feedConfig) {
  const { url, name } = feedConfig;
  let feed;
  try {
    feed = await parser.parseURL(url);
  } catch (err) {
    console.warn(`[SKIP] ${name}: ${err.message}`);
    return 0;
  }

  const upsert = db.prepare(`
    INSERT INTO articles (guid, source, title, link, description, content, author, pub_date, published_at, tags, cves, content_hash)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ON CONFLICT(source, guid) DO UPDATE SET
      title = excluded.title,
      description = excluded.description,
      content = excluded.content,
      tags = excluded.tags,
      cves = excluded.cves
  `);

  const checkDup = db.prepare(`SELECT id FROM articles WHERE content_hash = ? AND source != ? LIMIT 1`);

  let count = 0;
  const insertMany = db.transaction((items) => {
    for (const item of items) {
      const title = stripHtml(item.title || '');
      const fullText = stripHtml(
        item.contentEncoded || item['content:encoded'] || item.contentSnippet || item.summary || item.content || ''
      );
      const description = truncate(fullText, 600);
      const content = truncate(fullText, 3000);
      const author = item.creator || item.author || '';
      const link = item.link || item.guid || '';
      const guid = item.guid || item.id || item.link || title;
      const pubDate = item.pubDate || item.isoDate || new Date().toISOString();
      const publishedAt = Math.floor(new Date(pubDate).getTime() / 1000) || Math.floor(Date.now() / 1000);

      const tags = detectTags(title, description);
      const cves = extractCVEs(`${title} ${description}`);
      const contentHash = crypto.createHash('sha256')
        .update((title + description).toLowerCase())
        .digest('hex');

      const dup = checkDup.get(contentHash, name);
      if (dup) return;

      try {
        upsert.run(guid, name, title, link, description, content, author, pubDate, publishedAt,
          JSON.stringify(tags), JSON.stringify(cves), contentHash);
        count++;
      } catch {
        // skip
      }
    }
  });

  insertMany(feed.items || []);
  console.log(`[OK] ${name}: +${count} articles`);
  return count;
}

async function run() {
  console.log(`\n[CyberWatch RSS Worker] ${new Date().toISOString()}`);
  const db = openDatabase();
  let total = 0;
  for (const feed of RSS_FEEDS) {
    total += await ingestFeed(db, feed);
  }

  // Trim old articles beyond 500
  db.prepare(`DELETE FROM articles WHERE id NOT IN (SELECT id FROM articles ORDER BY published_at DESC LIMIT 500)`).run();
  db.close();
  console.log(`[Done] Total new: ${total}`);
}

run().catch(console.error);

if (process.argv.includes('--watch')) {
  const interval = parseInt(process.env.WORKER_INTERVAL_MINUTES || '15', 10) * 60 * 1000;
  console.log(`[Watch] Re-running every ${interval / 60000} minutes...`);
  setInterval(() => run().catch(console.error), interval);
}
