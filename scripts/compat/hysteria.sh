#!/usr/bin/env bash
# Hysteria 2 engines: Xray-core, the pinned sing-box and the pinned Mihomo
# against the real Xray-core the node image runs, serving FCP's own Hysteria
# transport (docker-compose.compat.yml, docs/client-compatibility.md
# § "Hysteria engines").
#
#   bun run test:integration:hysteria
#
# Downloads the pinned engines (checksummed, tests/compat/manifest.ts), builds
# their image, then runs convex/lib/hysteriaEngines.integration.test.ts, which
# writes a fresh certificate pair and password, starts the containers and
# connects, fetches and round-trips a UDP datagram through each engine, and
# checks that a rogue server is refused and handed nothing. Requires Docker
# (amd64 engines run under emulation on Apple Silicon). Always tears down
# (FCP_HYSTERIA_KEEP=1 leaves the stack up for debugging; the next run starts
# with a teardown). Nothing it prints or keeps carries the per-run password:
# .cache/compat/hysteria is removed afterwards.
set -euo pipefail
cd "$(dirname "$0")/../.."

export COMPOSE_PROJECT_NAME=fcp-hysteria-engines
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
  rm -rf .cache/compat/hysteria
}
cleanup() {
  status=$?
  if [ "${FCP_HYSTERIA_KEEP:-}" != 1 ]; then teardown; fi
  exit "$status"
}
teardown
trap cleanup EXIT

bun --no-env-file scripts/compat/download.ts
"${COMPOSE[@]}" build compat-proxy
FCP_HYSTERIA_ENGINES=1 bunx vitest run --config vitest.integration.config.ts \
  convex/lib/hysteriaEngines.integration.test.ts
