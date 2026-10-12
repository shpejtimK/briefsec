/* eslint-disable no-console */
// Background refresh: hacking news, CVEs (NVD + CISA KEV) and CVE lookups on article pages.
//
//   node scripts/rss-worker.js               one run, then exit
//   node scripts/rss-worker.js --watch       run every WORKER_INTERVAL_MINUTES (default 5)
//   node scripts/rss-worker.js --no-enrich   skip the article-page CVE lookups (fast startup seed)
const path = require('path');
const Database = require('better-sqlite3');
const { refreshNews } = require('../lib/news-feed');
const { refreshCves } = require('../lib/cve-feed');
const { enrichPendingArticles } = require('../lib/cve-enrich');

function openDatabase() {
  const dbPath = process.env.DATABASE_PATH || path.join(__dirname, '..', 'db', 'briefsec.sqlite');
  const db = new Database(dbPath);
  db.pragma('journal_mode = WAL');
  return db;
}

let running = false;

async function run() {
  if (running) return; // previous run still going (slow feed or NVD)
  running = true;
  console.log(`\n[BriefSec worker] ${new Date().toISOString()}`);
  const db = openDatabase();
  try {
    await refreshNews(db, { log: true });
    await refreshCves(db, { log: true });
    if (!process.argv.includes('--no-enrich')) {
      await enrichPendingArticles(db, { limit: 60, log: true });
    }
  } catch (err) {
    console.warn(`[Worker] ${err.message}`);
  } finally {
    db.close();
    running = false;
  }
  console.log('[Done]');
}

if (process.argv.includes('--watch')) {
  run();
  const interval = parseInt(process.env.WORKER_INTERVAL_MINUTES || '5', 10) * 60 * 1000;
  console.log(`[Watch] Re-running every ${interval / 60000} minutes...`);
  setInterval(run, interval);
} else {
  // rss-parser leaves keep-alive sockets open (e.g. after a feed times out), which would keep a
  // one-shot run — and the startup seed in start-prod.sh — from ever exiting
  run().finally(() => process.exit(0));
}
