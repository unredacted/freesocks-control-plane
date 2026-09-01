#!/usr/bin/env bash
# One-command FCP↔Remnawave integration test: stand up an ephemeral Remnawave
# panel, bootstrap an admin API token into the env, run the provider integration
# test against it, then tear the panel down (always, even on failure).
#
#   bun run test:integration:remnawave
#   REMNAWAVE_TEST_IMAGE=remnawave/backend:2.8.0 bun run test:integration:remnawave
#
# Requires Docker. The panel is pinned in docker-compose.remnawave-test.yml (a
# 3.x release); REMNAWAVE_TEST_IMAGE overrides the image for one run so the
# provider's 2.x contract paths can be proven against a real 2.x panel as well
# (the override is a generated compose file, so the Dependabot-tracked pin stays
# a plain literal). Safe to run repeatedly (fresh state each time).
set -euo pipefail
cd "$(dirname "$0")/.."

COMPOSE=(docker compose -f docker-compose.remnawave-test.yml)
OVERRIDE=""
if [ -n "${REMNAWAVE_TEST_IMAGE:-}" ]; then
  OVERRIDE="$(mktemp -t rw-test-override.XXXXXX.yml)"
  printf 'services:\n  rw-test-backend:\n    image: %s\n' "$REMNAWAVE_TEST_IMAGE" > "$OVERRIDE"
  COMPOSE+=(-f "$OVERRIDE")
  echo "[integration] panel image override: $REMNAWAVE_TEST_IMAGE"
fi

cleanup() {
  echo "[integration] tearing down the Remnawave test panel"
  "${COMPOSE[@]}" down -v >/dev/null 2>&1 || true
  [ -n "$OVERRIDE" ] && rm -f "$OVERRIDE"
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
