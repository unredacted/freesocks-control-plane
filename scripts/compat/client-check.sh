#!/usr/bin/env bash
# FCP's own client check against real Xray-cores (docker-compose.compat.yml,
# docs/edges.md § "FCP's own client check"):
#
#   bun run test:integration:client-check
#
# Builds the edge-client-check service as the stack does, starts two cores of the
# fleet release (minClientVer 1.8.1, and unset) and the target with its echo page,
# then runs convex/lib/edges/clientCheck/clientCheck.integration.test.ts, which
# writes the cores' configs (a fresh key and client id per run) and calls the
# service the way FCP does. Requires Docker (the cores are amd64 images, emulated
# on Apple Silicon). Always tears down (FCP_CLIENT_CHECK_KEEP=1 leaves the stack
# up; the next run starts with a teardown). Nothing it prints or keeps carries
# the per-run client id or key: .cache/compat/client-check is removed afterwards.
set -euo pipefail
cd "$(dirname "$0")/../.."

export COMPOSE_PROJECT_NAME=fcp-client-check
# The compose file's Bun services need it set even when they are not started.
FCP_COMPAT_BUN_VERSION="$(sed -n 's/.*"packageManager": *"bun@\([^"]*\)".*/\1/p' package.json)"
export FCP_COMPAT_BUN_VERSION
COMPOSE=(docker compose -f docker-compose.compat.yml)

teardown() {
  "${COMPOSE[@]}" down -v --remove-orphans >/dev/null 2>&1 || true
  rm -rf .cache/compat/client-check
}
cleanup() {
  status=$?
  if [ "${FCP_CLIENT_CHECK_KEEP:-}" != 1 ]; then teardown; fi
  exit "$status"
}
teardown
trap cleanup EXIT

"${COMPOSE[@]}" build compat-client-check
FCP_CLIENT_CHECK_IT=1 bunx vitest run --config vitest.integration.config.ts \
  convex/lib/edges/clientCheck/clientCheck.integration.test.ts
