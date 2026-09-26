#!/bin/sh
set -e

# Ensure the DB directory exists (mounted volume or fallback)
DB_DIR=$(dirname "${DATABASE_PATH:-/data/briefsec.sqlite}")
mkdir -p "$DB_DIR"

echo "[BriefSec] Seeding database on startup..."
node scripts/rss-worker.js

echo "[BriefSec] Starting background RSS worker (every 15 min)..."
node scripts/rss-worker.js --watch &

echo "[BriefSec] Starting Next.js server..."
exec node_modules/.bin/next start
