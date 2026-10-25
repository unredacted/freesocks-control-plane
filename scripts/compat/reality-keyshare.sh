#!/usr/bin/env bash
# REALITY key shares: the pinned sing-box and Mihomo against two real
# Xray-cores, the one the node image runs and a release from v26.9.8 on
# (docker-compose.compat.yml, docs/client-compatibility.md § "REALITY client
# versions").
#
#   bun run test:integration:reality-keyshare
#
# Downloads the pinned engines (checksummed, tests/compat/manifest.ts), builds
# their image, then runs convex/lib/realityKeyShares.integration.test.ts, which
# writes a fresh Xray config, starts the containers and connects through each
# core. Requires Docker (amd64 engines run under emulation on Apple Silicon).
# Always tears down (FCP_REALITY_KEEP=1 leaves the stack up for debugging; the
# next run starts with a teardown). Nothing it prints or keeps carries the
# per-run client id or key: .cache/compat/reality is removed afterwards.
set -euo pipefail
cd "$(dirname "$0")/../.."

export COMPOSE_PROJECT_NAME=fcp-reality-keyshare
# Same Bun as everything else (the compose file reads it for its Bun services).
FCP_COMPAT_BUN_VERSION="$(sed -n 's/.*"packageManager": *"bun@\([^"]*\)".*/\1/p' package.json)"
export FCP_COMPAT_BUN_VERSION
if [ -z "$FCP_COMPAT_BUN_VERSION" ]; then
  echo 'could not read the bun version from package.json' >&2
  exit 1
fi
COMPOSE=(docker compose -f docker-compose.compat.yml)

teardown() {
  "${COMPOSE[@]}" down -v --remove-orphans >/dev/null 2>&1 || true
  rm -rf .cache/compat/reality
}
cleanup() {
  status=$?
  if [ "${FCP_REALITY_KEEP:-}" != 1 ]; then teardown; fi
  exit "$status"
}
teardown
trap cleanup EXIT

bun --no-env-file scripts/compat/download.ts
"${COMPOSE[@]}" build compat-proxy
FCP_REALITY_KEYSHARE=1 bunx vitest run --config vitest.integration.config.ts \
  convex/lib/realityKeyShares.integration.test.ts
