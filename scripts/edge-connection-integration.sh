#!/usr/bin/env bash
# Edge connection release gate: a member connects through an edge, with real
# software end to end (docker-compose.edge-connection-test.yml,
# docs/client-compatibility.md "Edge connection").
#
#   bun run test:integration:edge-connection
#
# Boots the ephemeral Remnawave panel, three enrolled relay nodes (REALITY,
# XHTTP under REALITY, WebSocket behind its ingress), two operator nodes (the L4 and L7 protocol
# matrix), a fake L4 edge (TCP forwarder, one address per load balancer), a
# fake L7 edge (CDN-style proxy, one route per proxied record), a web page only
# the nodes reach and a client container (pinned sing-box and Mihomo) that
# reaches only the edges. Then runs the test inside the runner container, where
# FCP (convex-test) binds each node to its edges through the real lifecycle
# and the clients connect with what /api/v1/sub serves.
#
# EC_ONLY=<file filter> runs one test file (wiring, member, ...); EC_KEEP=1
# leaves the stack up afterwards.
#
# Requires Docker. Always tears down, even on failure. Nothing that carries a
# credential (node logs, client configs, subscription bodies) is printed or
# kept outside .cache/edge-connection-test, which the next run wipes.
set -euo pipefail
cd "$(dirname "$0")/.."
export PWD
started=$SECONDS
step() { echo "[edge-connection] +$((SECONDS - started))s $*"; }

export COMPOSE_PROJECT_NAME=fcp-edge-conn
# Same Bun as everything else: packageManager in package.json.
FCP_COMPAT_BUN_VERSION="$(sed -n 's/.*"packageManager": *"bun@\([^"]*\)".*/\1/p' package.json)"
export FCP_COMPAT_BUN_VERSION
if [ -z "$FCP_COMPAT_BUN_VERSION" ]; then
  echo 'could not read the bun version from package.json' >&2
  exit 1
fi
COMPOSE=(docker compose -f docker-compose.remnawave-test.yml -f docker-compose.edge-connection-test.yml --profile runner)
WORK=.cache/edge-connection-test

# Per-run fixture values: `*.example` names only (docs/edges.md: never a real
# provider, region or target). The test reads the same variables.
export EC_ORIGIN_TOKEN="ec-$(openssl rand -hex 12)"
export EC_ORIGIN_HOSTNAME=ws-origin.relay.example
export EC_ORIGIN_PAGE=page.origin.example
export EC_REALITY_TARGET=decoy.example
export EC_L7_ZONE=edges.example
export EC_WS_PATH=/ws
export EC_WS_PORT=8443
# The server name of the operator nodes' TLS transports (their certificate
# also covers the fake CDN zone, as an origin certificate for a zone does).
export EC_TLS_NAME=tls-origin.relay.example
# The Outline server's Shadowsocks password (every key the fake Outline API
# hands out carries it, as one Outline server's keys reach one server).
export EC_OUTLINE_PASSWORD="ec-$(openssl rand -hex 16)"
if [ -n "${GITHUB_ACTIONS:-}" ]; then echo "::add-mask::$EC_OUTLINE_PASSWORD"; fi
export EC_NODE_SECRET=pending
export REMNAWAVE_TEST_TOKEN=pending

cleanup() {
  status=$?
  if [ "$status" -ne 0 ]; then
    # Container states only: logs and configs can carry credentials.
    "${COMPOSE[@]}" ps -a --format '{{.Name}} {{.State}} {{.Status}}' >&2 2>/dev/null || true
  fi
  # Debugging aid: EC_KEEP=1 leaves the stack up to poke at; the next run
  # starts with a teardown anyway.
  if [ "${EC_KEEP:-}" = 1 ]; then
    step "EC_KEEP=1: leaving the stack up (project $COMPOSE_PROJECT_NAME)"
    exit "$status"
  fi
  step "tearing down"
  "${COMPOSE[@]}" down -v --remove-orphans >/dev/null 2>&1 || true
  exit "$status"
}
trap cleanup EXIT

"${COMPOSE[@]}" down -v --remove-orphans >/dev/null 2>&1 || true
rm -rf "$WORK"
mkdir -p "$WORK/pki" "$WORK/logs" "$WORK/client" "$WORK/outline"

step "minting the per-run test CA and certificates"
# A throwaway CA, valid two days: the node's ingress, the fake front and the
# member's client trust it, and nothing else does.
pki="$WORK/pki"
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
  -keyout "$pki/ca-key.pem" -out "$pki/ca.pem" -days 2 -subj '/CN=FCP edge connection test CA' \
  -addext 'basicConstraints=critical,CA:TRUE' -addext 'keyUsage=critical,keyCertSign,cRLSign' \
  >/dev/null 2>&1
leaf() { # file name, common name, SANs
  openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
    -keyout "$pki/$1-key.pem" -out "$pki/$1.csr" -subj "/CN=$2" >/dev/null 2>&1
  printf 'basicConstraints=CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\nsubjectAltName=%s\n' "$3" \
    > "$pki/$1.ext"
  openssl x509 -req -in "$pki/$1.csr" -CA "$pki/ca.pem" -CAkey "$pki/ca-key.pem" \
    -CAcreateserial -days 2 -extfile "$pki/$1.ext" -out "$pki/$1.pem" >/dev/null 2>&1
}
# The origin's subject CN is deliberately not a hostname, as on many real
# origin certificates: FCP must name the certificate by its SANs.
leaf origin "FCP edge connection test origin" "DNS:$EC_ORIGIN_HOSTNAME"
leaf front "*.$EC_L7_ZONE" "DNS:*.$EC_L7_ZONE,DNS:$EC_L7_ZONE"
leaf matrix "FCP edge connection test operator node" "DNS:$EC_TLS_NAME,DNS:*.$EC_L7_ZONE"
rm -f "$pki"/*.csr "$pki"/*.ext "$pki"/*.srl "$pki/ca-key.pem"
# The containers run unprivileged where they can and only read these.
chmod 0644 "$pki"/*.pem
mkdir -p "$WORK/client/mihomo"
chmod 0777 "$WORK/logs" "$WORK/client" "$WORK/client/mihomo"

# The Outline server's data plane (docker-compose.edge-connection-test.yml ec-outline).
printf '{"log":{"level":"warn"},"inbounds":[{"type":"shadowsocks","listen":"::","listen_port":8388,"method":"chacha20-ietf-poly1305","password":"%s"}],"outbounds":[{"type":"direct"}]}\n' \
  "$EC_OUTLINE_PASSWORD" > "$WORK/outline/server.json"
chmod 0644 "$WORK/outline/server.json"

step "building the client engine (pinned sing-box) and the runner images"
bun --no-env-file scripts/compat/download.ts >/dev/null
docker build -q --platform linux/amd64 -f docker/compat/Dockerfile -t fcp-compat-engine:local . >/dev/null
"${COMPOSE[@]}" build -q ec-runner
docker volume create fcp-edge-conn-node-modules >/dev/null
docker volume create fcp-edge-conn-bun-cache >/dev/null

step "starting the panel"
"${COMPOSE[@]}" up -d rw-test-db rw-test-redis rw-test-backend rw-test-proxy

step "bootstrapping admin + minting an API token"
BOOT="$(bun scripts/remnawave-test-bootstrap.mjs)"
REMNAWAVE_TEST_TOKEN="$(printf '%s\n' "$BOOT" | sed -n 's/^REMNAWAVE_TEST_TOKEN=//p')"
if [ -z "$REMNAWAVE_TEST_TOKEN" ]; then
  echo '[edge-connection] the bootstrap returned no API token' >&2
  exit 1
fi
if [ -n "${GITHUB_ACTIONS:-}" ]; then echo "::add-mask::$REMNAWAVE_TEST_TOKEN"; fi
export REMNAWAVE_TEST_TOKEN

step "fetching the panel's node key"
EC_NODE_SECRET="$(curl -fsS -H "authorization: Bearer ${REMNAWAVE_TEST_TOKEN}" \
  -H 'x-forwarded-proto: https' -H 'x-forwarded-for: 127.0.0.1' \
  http://localhost:3000/api/keygen | bun -e 'const j=JSON.parse(await Bun.stdin.text());console.log(j.response.pubKey)')"
if [ -n "${GITHUB_ACTIONS:-}" ]; then echo "::add-mask::$EC_NODE_SECRET"; fi
export EC_NODE_SECRET

step "starting the nodes, the edges, the page and the client"
"${COMPOSE[@]}" up -d ec-node-reality ec-node-xr ec-node-ws ec-node-ws-ingress ec-node-l4m ec-node-l7m ec-outline \
  ec-reality-target ec-l4-forwarder ec-l7-front ec-dns ec-origin-page ec-client
"${COMPOSE[@]}" run --rm --no-deps ec-l4-addresses >/dev/null

step "running the test in the runner container"
"${COMPOSE[@]}" run --rm --no-deps ec-runner bash -c \
  'bun install --frozen-lockfile >/dev/null && bunx vitest run --config vitest.edge-connection.config.ts ${EC_ONLY:-}'
step "done"
