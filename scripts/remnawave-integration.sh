#!/usr/bin/env bash
# One-command FCP↔Remnawave integration test: stand up an ephemeral Remnawave
# panel, bootstrap an admin API token into the env, run the provider integration
# test against it, then tear the panel down (always, even on failure).
#
#   bun run test:integration:remnawave
#
# Requires Docker. The panel is pinned to the latest Remnawave release in
# docker-compose.remnawave-test.yml. Safe to run repeatedly (fresh state each time).
set -euo pipefail
cd "$(dirname "$0")/.."

COMPOSE=(docker compose -f docker-compose.remnawave-test.yml)

cleanup() {
  echo "[integration] tearing down the Remnawave test panel"
  "${COMPOSE[@]}" down -v >/dev/null 2>&1 || true
}
trap cleanup EXIT

echo "[integration] starting the Remnawave test panel (this pulls images on first run)"
"${COMPOSE[@]}" up -d

echo "[integration] bootstrapping admin + minting an API token"
if ! BOOT="$(bun scripts/remnawave-test-bootstrap.mjs)"; then
  echo "[integration] bootstrap failed — recent backend logs:" >&2
  "${COMPOSE[@]}" logs --tail=40 rw-test-backend >&2 || true
  exit 1
fi
set -a
eval "$BOOT"
set +a
echo "[integration] panel ready at ${REMNAWAVE_TEST_URL}"

echo "[integration] running the provider integration test"
bunx vitest run --config vitest.integration.config.ts
