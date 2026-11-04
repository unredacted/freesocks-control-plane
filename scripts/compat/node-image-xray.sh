#!/usr/bin/env bash
# The REALITY hold: every remnawave/node image a compose file pins must bundle
# Xray-core v26.7.28 or older.
#
#   bash scripts/compat/node-image-xray.sh
#
# From Xray-core v26.9.8 on, a REALITY server refuses a Client Hello that does
# not offer the X25519MLKEM768 key share, and sing-box (and every app on it)
# never offers it: a node image past the hold locks every sing-box member out of
# REALITY (docs/client-compatibility.md § "REALITY client versions").
# .github/dependabot.yml holds the image; this catches a hand bump, and a
# release that moves Xray under an unchanged-looking tag. Reads each image's own
# `xray version`. Requires Docker. Lift the hold (here and in dependabot.yml)
# only once sing-box sends the key share.
set -euo pipefail
cd "$(dirname "$0")/../.."

hold='26.7.28'

images="$(sed -nE 's/^[[:space:]]*image:[[:space:]]*["'\'']?((docker\.io\/)?remnawave\/node:[^[:space:]"'\'']+).*/\1/p' docker-compose*.yml | sort -u)"
if [ -z "$images" ]; then
  echo 'found no remnawave/node image in docker-compose*.yml, so the scan itself is broken' >&2
  exit 1
fi

status=0
for image in $images; do
  out="$(docker run --rm --platform linux/amd64 --entrypoint xray "$image" version)"
  version="$(awk '$1 == "Xray" { print $2; exit }' <<<"$out")"
  if [ -z "$version" ]; then
    echo "::error::could not read the Xray version of $image"
    status=1
  elif [ "$(printf '%s\n%s\n' "$hold" "$version" | sort -V | tail -n 1)" != "$hold" ]; then
    echo "::error::$image bundles Xray-core v$version, past the REALITY hold (v$hold or older): from v26.9.8 on, a REALITY server refuses sing-box, which never sends the X25519MLKEM768 key share. Keep the node image at a release with Xray v$hold or older until sing-box sends it (docs/client-compatibility.md § \"REALITY client versions\", .github/dependabot.yml)."
    status=1
  else
    echo "$image bundles Xray-core v$version (hold: v$hold or older)"
  fi
done
exit "$status"
