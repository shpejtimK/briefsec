#!/bin/sh
set -e

# Ensure the DB directory exists (mounted volume or fallback)
DB_DIR=$(dirname "${DATABASE_PATH:-/data/briefsec.sqlite}")
mkdir -p "$DB_DIR"

echo "[BriefSec] Seeding database on startup..."
# Article-page CVE lookups are left to the background worker below so Next.js starts sooner
node scripts/rss-worker.js --no-enrich

echo "[BriefSec] Starting background worker (news + CVEs every 5 min)..."
node scripts/rss-worker.js --watch &

echo "[BriefSec] Starting Next.js server..."
exec node_modules/.bin/next start
