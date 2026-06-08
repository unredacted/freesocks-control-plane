#!/usr/bin/env bash
# Reproducible-build check (CDN-blinding Phase 3f). Builds the SPA twice and
# asserts byte-for-byte identical output, then prints the canonical dist hash.
#
# That hash is what we publish out of band (a signed release + the .onion mirror,
# see docs/oob-verification.md) and what an independent rebuilder recomputes to
# attest that the bundle the CDN serves was built from the public source. The
# build is deterministic given a pinned toolchain (bun 1.3.14, a frozen
# lockfile); run from a clean checkout for a publishable hash.
set -euo pipefail

hashdist() {
  # Hash of (relative-path, content) over every file in dist, order-stable.
  ( cd dist && find . -type f | LC_ALL=C sort | xargs sha256sum ) | sha256sum | awk '{print $1}'
}

echo "build 1/2..." >&2
bun run build >/dev/null
h1=$(hashdist)

echo "build 2/2..." >&2
bun run build >/dev/null
h2=$(hashdist)

if [ "$h1" != "$h2" ]; then
  echo "NOT REPRODUCIBLE: two builds differ ($h1 != $h2)" >&2
  exit 1
fi

echo "dist-sha256: $h1"
