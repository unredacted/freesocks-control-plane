#!/usr/bin/env bash
# Tear down the front-qualification containers and the throwaway key material.
# Never uploads or prints container logs: they would echo the test credential.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$root"

FCP_COMPAT_BUN_VERSION="$(sed -n 's/.*"packageManager": *"bun@\([^"]*\)".*/\1/p' package.json)"
export FCP_COMPAT_BUN_VERSION

docker compose -p fcp-frontcheck -f docker-compose.compat.yml down -v --remove-orphans
rm -rf .cache/compat/frontcheck
