#!/bin/sh
# Runs in the production Caddy image on an isolated loopback network.
set -eu
cd /tmp
cat > Caddyfile <<'CADDY'
import /etc/caddy/Caddyfile

http://:3211 {
	header Content-Security-Policy "sandbox; default-src 'none'"
	header Content-Type "text/html"
	header ETag `"fixture"`
	@revalidate header If-None-Match `"fixture"`
	respond @revalidate 304
	respond "<p>Subscription fixture</p>"
}
CADDY
echo '<p>Member fixture</p>' > /srv/dist/index.html
CADDY_SCHEME=http SITE_ADDRESS=127.0.0.1:8080 caddy run --config Caddyfile &
pid=$!
trap 'kill "$pid" 2>/dev/null || true' EXIT
url=http://127.0.0.1:8080

fetch() {
	curl --fail --silent --show-error --max-time 5 -D headers -o body "$@"
}
policies() {
	sed -n 's/^Content-Security-Policy: //p' headers | tr -d '\r'
}

fetch --retry 5 --retry-connrefused "$url/"
grep -Fxq '<p>Member fixture</p>' body
policies | grep -q "'nonce-"
test "$(policies | wc -l)" -eq 1

fetch "$url/api/v1/sub/fixture"
grep -Fxq '<p>Subscription fixture</p>' body
grep -iq '^Content-Type: text/html' headers
policies | grep -Fxq "sandbox; default-src 'none'"
policies | grep -q "'nonce-"

# A cache updates the stored 200's policy fields from the 304.
fetch -H 'If-None-Match: "fixture"' "$url/api/v1/sub/fixture"
grep -Eq '^HTTP/1\.[01] 304 ' headers
policies | grep -Fxq "sandbox; default-src 'none'"
