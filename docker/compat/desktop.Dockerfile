# Packaged application smoke tests; full distro tests use disposable VM runners.
ARG BUN_VERSION
FROM oven/bun:${BUN_VERSION} AS bun
FROM node:24-bookworm-slim AS node
FROM fcp-compat-engine:local
COPY --from=node /usr/local/bin/node /usr/local/bin/node
COPY --from=bun /usr/local/bin/bun /usr/local/bin/bun
COPY .cache/compat/bin/sfl.deb /tmp/sfl.deb
RUN apt-get update && apt-get install -y --no-install-recommends /tmp/sfl.deb xvfb xauth dbus-x11 libasound2t64 && rm -rf /var/lib/apt/lists/* /tmp/sfl.deb
COPY docker/compat/sfl-entrypoint.sh /usr/local/bin/sfl-entrypoint
WORKDIR /repo
