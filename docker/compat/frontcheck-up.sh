#!/usr/bin/env bash
# Bring up the pinned Xray-core the front-qualification integration test runs
# against (convex/lib/edges/frontCheck/frontCheck.integration.test.ts).
#
# The certificate is minted here rather than committed: the test trusts it
# explicitly through the checker's `dial.ca` seam, which is exactly where
# production trusts nothing but the system CA store. Two days of validity is
# plenty for a CI job and means a stale copy can never be reused.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$root"

tls='.cache/compat/frontcheck'
mkdir -p "$tls"
openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout "$tls/key.pem" -out "$tls/cert.pem" \
  -days 2 -subj '/CN=front.test' \
  -addext 'subjectAltName=DNS:front.test' >/dev/null 2>&1
# The container runs unprivileged and only reads these.
chmod 0644 "$tls/key.pem" "$tls/cert.pem"

# Same pin the rest of the compat stack uses, read from packageManager.
FCP_COMPAT_BUN_VERSION="$(sed -n 's/.*"packageManager": *"bun@\([^"]*\)".*/\1/p' package.json)"
export FCP_COMPAT_BUN_VERSION
if [ -z "$FCP_COMPAT_BUN_VERSION" ]; then
  echo 'could not read the bun version from package.json' >&2
  exit 1
fi

docker compose -p fcp-frontcheck -f docker-compose.compat.yml up -d \
  compat-frontcheck-origin compat-frontcheck-xray

# Xray listens on all four ports at once, so waiting for the last one is enough
# to know the config parsed; poll anyway, the container starts asynchronously.
for port in 18443 18444 18445 18446; do
  ready=''
  for _ in $(seq 1 100); do
    if (exec 3<>"/dev/tcp/127.0.0.1/$port") 2>/dev/null; then
      ready='yes'
      break
    fi
    sleep 0.2
  done
  if [ -z "$ready" ]; then
    echo "xray inbound on $port never accepted a connection" >&2
    docker compose -p fcp-frontcheck -f docker-compose.compat.yml logs compat-frontcheck-xray >&2
    exit 1
  fi
done

echo "FCP_FRONTCHECK_XRAY_URL=https://127.0.0.1:18443"
