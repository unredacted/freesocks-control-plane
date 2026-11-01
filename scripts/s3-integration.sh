#!/usr/bin/env bash
# One-command proof of the S3 mirror path against a REAL S3-compatible store:
# stand up a throwaway SeaweedFS (docker-compose.s3-test.yml), run
# convex/storage.integration.test.ts against it (the real AWS SDK writes and
# deletes, the member-facing URL is read over plain HTTP), then tear it down
# (always, even on failure).
#
#   bun run test:integration:s3
#
# Requires Docker. Safe to run repeatedly (fresh state each time).
set -euo pipefail
cd "$(dirname "$0")/.."

COMPOSE=(docker compose -f docker-compose.s3-test.yml)
PORT="${FCP_S3_TEST_PORT:-18333}"

cleanup() {
  echo "[integration] tearing down the S3 test store"
  "${COMPOSE[@]}" down -v >/dev/null 2>&1 || true
}
trap cleanup EXIT

echo "[integration] starting the S3 test store (this pulls the image on first run)"
"${COMPOSE[@]}" up -d

for _ in $(seq 1 60); do
  code="$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:${PORT}/" || true)"
  [ "$code" != "000" ] && break
  sleep 1
done
if [ "${code:-000}" = "000" ]; then
  echo "[integration] the S3 test store did not come up; recent logs:" >&2
  "${COMPOSE[@]}" logs --tail=40 s3-test >&2 || true
  exit 1
fi
echo "[integration] S3 test store ready on 127.0.0.1:${PORT}"

export FCP_S3_TEST_ENDPOINT="http://127.0.0.1:${PORT}"
bunx vitest run --config vitest.integration.config.ts convex/storage.integration.test.ts
