#!/usr/bin/env bash
# Managed-node integration run: the ephemeral Remnawave panel PLUS a real
# panel-managed node, a TLS 1.3 target and a pinned Xray client
# (docker-compose.remnawave-node-test.yml), then the node-side contract tests.
#
#   bun run test:integration:remnawave-node
#
# What it establishes that the panel-only run cannot: whether and when a node
# APPLIES a config profile, how many server names production Xray accepts, and
# that a server name works only once the node runs the config that lists it.
# Requires Docker. Always tears down, even on failure.
set -euo pipefail
cd "$(dirname "$0")/.."

export COMPOSE_PROJECT_NAME=rw-node-test
COMPOSE=(docker compose -f docker-compose.remnawave-test.yml -f docker-compose.remnawave-node-test.yml)
mkdir -p .cache/remnawave-node-test
echo '{"log":{"loglevel":"none"},"inbounds":[],"outbounds":[{"protocol":"freedom"}]}' \
  > .cache/remnawave-node-test/client.json

cleanup() {
  echo "[node-integration] tearing down"
  RW_TEST_NODE_SECRET="${RW_TEST_NODE_SECRET:-x}" "${COMPOSE[@]}" --profile client down -v >/dev/null 2>&1 || true
}
trap cleanup EXIT

echo "[node-integration] starting the panel"
RW_TEST_NODE_SECRET=pending "${COMPOSE[@]}" up -d rw-test-db rw-test-redis rw-test-backend rw-test-proxy

echo "[node-integration] bootstrapping admin + minting an API token"
BOOT="$(bun scripts/remnawave-test-bootstrap.mjs)"
set -a
eval "$BOOT"
set +a

echo "[node-integration] fetching the panel's node key"
RW_TEST_NODE_SECRET="$(curl -fsS -H "authorization: Bearer ${REMNAWAVE_TEST_TOKEN}" \
  -H 'x-forwarded-proto: https' -H 'x-forwarded-for: 127.0.0.1' \
  "${REMNAWAVE_TEST_URL}/api/keygen" | bun -e 'const j=JSON.parse(await Bun.stdin.text());console.log(j.response.pubKey)')"
export RW_TEST_NODE_SECRET

echo "[node-integration] starting the node and the target"
"${COMPOSE[@]}" up -d rw-test-node rw-test-origin

export REMNAWAVE_TEST_NODE=1
echo "[node-integration] running the node-side tests"
bunx vitest run --config vitest.node-integration.config.ts
