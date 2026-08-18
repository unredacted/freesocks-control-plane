#!/usr/bin/env bash
# Reproducible-build check (CDN-blinding Phase 3f). Builds the SPA twice and
# asserts byte-for-byte identical output, then prints the canonical dist hash.
#
# That hash is what we publish out of band (a signed release + the .onion mirror,
# see docs/oob-verification.md) and what an independent rebuilder recomputes to
# attest that the bundle the CDN serves was built from the public source. The
# build is deterministic given a pinned toolchain (the `packageManager` bun
# version + a frozen lockfile); run from a clean checkout for a publishable hash.
set -euo pipefail

# The toolchain half of "pinned toolchain + frozen lockfile" is checked here
# rather than assumed. A different bun MAY produce a different dist-sha256, and
# silently publishing a hash from the wrong toolchain is exactly the failure an
# out-of-band verification protocol cannot tolerate — an honest rebuilder would
# report dissent against a hash that was never wrong, just built differently.
# No literal version lives in this file: package.json is the single source of
# truth (docker/*.Dockerfile and CI's setup-bun both derive from it, locked by
# convex/deployPins.test.ts).
want_bun="$(sed -n 's/.*"packageManager"[[:space:]]*:[[:space:]]*"bun@\([^"]*\)".*/\1/p' package.json)"
have_bun="$(bun --version)"
if [ -z "$want_bun" ]; then
  echo "could not read packageManager from package.json" >&2
  exit 1
fi
if [ "$want_bun" != "$have_bun" ]; then
  msg="toolchain mismatch: package.json pins bun $want_bun, running bun $have_bun"
  if [ "${ALLOW_BUN_MISMATCH:-}" = "true" ]; then
    echo "WARNING: $msg — hash is NOT publishable" >&2
  else
    echo "$msg" >&2
    echo "Install bun $want_bun, or set ALLOW_BUN_MISMATCH=true to build anyway" >&2
    echo "(the resulting dist-sha256 must not be published)." >&2
    exit 1
  fi
fi
echo "toolchain: bun $have_bun" >&2

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
