#!/usr/bin/env bash
# Re-pin the Convex self-hosted images in docker-compose.stack.yml.
#
#   scripts/convex-repin.sh <new-40hex-sha> <backend-digest> <dashboard-digest> \
#     <release-tag> [npm-version]
#
# Rewrites, in place:
#   - the two `convex-backend` refs (the `backend` service + the one-shot
#     `keygen`, which reuses the backend image),
#   - the one `convex-dashboard` ref,
#   - the release-name comment on the `backend` service, which
#     convex/deployPins.test.ts asserts matches the pinned tag.
# Prints the OLD pinned sha on stdout (the caller builds the compare link from
# it). Exits 0 with a notice when the file already pins <new-40hex-sha>.
#
# <npm-version> (e.g. 1.45.0) names the ship.convex.dev release this build
# anchors; when given, the comment gains "(the npm <version> anchor)". Omit it
# only for the raw-release escape hatch (a pin that is not an npm anchor).
#
# Digests are the bare 64-hex value (no "sha256:" prefix) — the multi-arch
# INDEX digest, i.e. `docker buildx imagetools inspect <image>:<sha>` →
# Manifest.Digest, NOT a per-platform manifest digest.
#
# perl -pi, not sed -i: BSD sed (darwin) takes an argument after -i and GNU sed
# does not, and this script must run identically on the operator's Mac and the
# ubuntu runner. Each substitution's replacement count is asserted — perl and
# sed both exit 0 on zero matches, which would otherwise leave a silently
# half-rewritten compose file. All edits land on a temp copy first, so a failed
# assertion leaves the real file untouched.
set -euo pipefail

usage() {
  echo "usage: $0 <new-40hex-sha> <backend-digest> <dashboard-digest> <release-tag> [npm-version]" >&2
  exit 2
}

[ "$#" -ge 4 ] && [ "$#" -le 5 ] || usage

NEW="$1"
BDIG="$2"
DDIG="$3"
TAG="$4"
VER="${5:-}"

repo_root="$(cd "$(dirname "$0")/.." && pwd)"
FILE="$repo_root/docker-compose.stack.yml"

[[ "$NEW" =~ ^[0-9a-f]{40}$ ]] || {
  echo "error: new sha must be 40 lowercase hex chars, got: $NEW" >&2
  exit 2
}
[[ "$BDIG" =~ ^[0-9a-f]{64}$ ]] || {
  echo "error: backend digest must be 64 bare hex chars (no sha256: prefix), got: $BDIG" >&2
  exit 2
}
[[ "$DDIG" =~ ^[0-9a-f]{64}$ ]] || {
  echo "error: dashboard digest must be 64 bare hex chars (no sha256: prefix), got: $DDIG" >&2
  exit 2
}
[[ "$TAG" =~ ^precompiled-[0-9]{4}-[0-9]{2}-[0-9]{2}-[0-9a-f]{7}$ ]] || {
  echo "error: release tag must look like precompiled-YYYY-MM-DD-<sha7>, got: $TAG" >&2
  exit 2
}
[ -z "$VER" ] || [[ "$VER" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || {
  echo "error: npm version must look like X.Y.Z, got: $VER" >&2
  exit 2
}
NEW7="${NEW:0:7}"
[ "${TAG##*-}" = "$NEW7" ] || {
  echo "error: release tag suffix (${TAG##*-}) does not match the new sha ($NEW7)" >&2
  exit 2
}

OLD="$(grep -oE 'ghcr\.io/get-convex/convex-backend:[0-9a-f]{40}' "$FILE" | head -1 | cut -d: -f2)"
[ -n "$OLD" ] || {
  echo "error: no git-sha-tagged convex-backend pin found in $FILE" >&2
  exit 1
}

if [ "$OLD" = "$NEW" ]; then
  echo "already pinned to $NEW7 ($TAG); nothing to do" >&2
  echo "$OLD"
  exit 0
fi

if [ -n "$VER" ]; then
  COMMENT="$NEW7 = $TAG (the npm $VER anchor)"
else
  COMMENT="$NEW7 = $TAG"
fi

tmp="$(mktemp "$FILE.XXXXXX")"
trap 'rm -f "$tmp"' EXIT
cp "$FILE" "$tmp"

# Each perl pass prints its replacement count on stderr; -pi sends the rewritten
# lines to the file, so stderr is free for the count.
substitute() { # <expected-count> <label> <perl-expression>
  local expected="$1" label="$2" expr="$3" got
  got="$(perl -pi -e "$expr" "$tmp" 2>&1)"
  if [ "$got" != "$expected" ]; then
    echo "error: expected $expected $label replacement(s), made ${got:-0} — docker-compose.stack.yml no longer matches the shape this script expects; fix the script or the file" >&2
    exit 1
  fi
}

export NEW BDIG DDIG COMMENT
substitute 2 'convex-backend ref' \
  '$c += s{(image:\s*ghcr\.io/get-convex/convex-backend:)[0-9a-f]{40}\@sha256:[0-9a-f]{64}}{$1$ENV{NEW}\@sha256:$ENV{BDIG}}g; END { print STDERR $c // 0 }'
substitute 1 'convex-dashboard ref' \
  '$c += s{(image:\s*ghcr\.io/get-convex/convex-dashboard:)[0-9a-f]{40}\@sha256:[0-9a-f]{64}}{$1$ENV{NEW}\@sha256:$ENV{DDIG}}g; END { print STDERR $c // 0 }'
substitute 1 'release-name comment' \
  '$c += s{\b[0-9a-f]{7} = precompiled-\d{4}-\d{2}-\d{2}-[0-9a-f]{7}(?: \(the npm \d+\.\d+\.\d+ anchor\))?}{$ENV{COMMENT}}g; END { print STDERR $c // 0 }'

mv "$tmp" "$FILE"
trap - EXIT

echo "re-pinned ${OLD:0:7} -> $NEW7 ($TAG)" >&2
echo "$OLD"
