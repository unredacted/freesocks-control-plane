#!/usr/bin/env bash
# Generate a self-hosted admin key from the RUNNING docker backend and write a
# correct .env.local pointing the Convex CLI at it. Run `bun run selfhost:up`
# first. This avoids the manual-paste step and the `convex dev` "anonymous
# local" prompt (which spins up a SEPARATE CLI-managed backend, not ours).
set -euo pipefail
cd "$(dirname "$0")/.."

COMPOSE="docker compose --env-file .env.docker"

if ! $COMPOSE ps --status running --services 2>/dev/null | grep -q backend; then
  echo "error: the self-hosted backend isn't running. Start it first:" >&2
  echo "  bun run selfhost:up" >&2
  exit 1
fi

KEY=$($COMPOSE exec -T backend ./generate_admin_key.sh | grep -E '\|' | tail -1 | tr -d '\r ')
if [ -z "$KEY" ]; then
  echo "error: failed to read an admin key from the backend." >&2
  exit 1
fi

cat > .env.local <<EOF
# Convex CLI -> self-hosted docker backend (docker-compose.yml, project "fcp").
# Written by scripts/selfhost-env.sh. Gitignored. Do NOT also set CONVEX_DEPLOYMENT.
CONVEX_SELF_HOSTED_URL=http://127.0.0.1:3210
CONVEX_SELF_HOSTED_ADMIN_KEY=$KEY
# SPA client URLs (used from migration phase P9 onward).
VITE_CONVEX_URL=http://127.0.0.1:3210
VITE_CONVEX_SITE_URL=http://127.0.0.1:3211
EOF

echo "Wrote .env.local for the self-hosted docker backend (admin key length: ${#KEY})."
echo "Next: bun run convex:dev   (deploys convex/ to http://127.0.0.1:3210)"
