#!/usr/bin/env bash
# Packaged-SFL driver entrypoint (client-compatibility CI, docker/compat/desktop.Dockerfile).
#
# The official Linux client shows its main UI, and validates every imported
# profile, only through its bundled sing-box daemon, which the .deb normally
# starts via systemd. There is no systemd inside the container, so start the
# daemon exactly as the shipped unit file does, wait for its socket, then drive
# the application under Xvfb. The daemon dies with the container.
set -euo pipefail

mkdir -p /var/lib/sing-box-daemon
chmod 0700 /var/lib/sing-box-daemon
/opt/sing-box/resources/daemon/sing-box-daemon run \
  --working-directory /var/lib/sing-box-daemon \
  --socket /run/sing-box.socket &

for _ in $(seq 1 100); do
  if [ -S /run/sing-box.socket ]; then break; fi
  sleep 0.1
done
if [ ! -S /run/sing-box.socket ]; then
  echo "sing-box-daemon socket never appeared" >&2
  exit 1
fi

bun --no-env-file build tests/compat/sfl.ts --target=node --packages=external \
  --outfile .cache/compat/runtime/sfl.mjs
xvfb-run -a node .cache/compat/runtime/sfl.mjs
