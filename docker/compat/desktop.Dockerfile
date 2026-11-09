# Packaged application smoke tests; full distro tests use disposable VM runners.
ARG BUN_VERSION
FROM oven/bun:${BUN_VERSION} AS bun
FROM node:24.22.2-bookworm-slim@sha256:01d566e8d94d8c619591d78652babfccd3c6992a3dffa9ed5ab39e11cf6c70e9 AS node
FROM fcp-compat-engine:local
COPY --from=node /usr/local/bin/node /usr/local/bin/node
COPY --from=bun /usr/local/bin/bun /usr/local/bin/bun
COPY .cache/compat/bin/sfl.deb /tmp/sfl.deb
RUN apt-get update && apt-get install -y --no-install-recommends /tmp/sfl.deb xvfb xauth dbus-x11 libasound2t64 && rm -rf /var/lib/apt/lists/* /tmp/sfl.deb
RUN useradd --create-home --uid 10001 --user-group fcp-browser
COPY docker/compat/sfl-entrypoint.sh /usr/local/bin/sfl-entrypoint
WORKDIR /repo
