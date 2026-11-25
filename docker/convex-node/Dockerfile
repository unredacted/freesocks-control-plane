# The Node inside the Convex images: the backend runs every "use node" action on
# it, and the dashboard serves its Next.js app with it.
#
# Upstream installs the exact version in its .nvmrc (NodeSource
# `nodejs=<ver>-1nodesource1`, copied to /usr/bin/node) and does not follow Node
# security releases: the release FCP pins shipped 22.22.2 (March 2026) while
# 22.23.0, 22.23.2 and 22.23.4 carried security fixes. Re-pinning Convex cannot
# fix that, so this overlay swaps in the official binary from a pinned node
# image. The pin below is ours to move: this folder has its own Dependabot entry,
# checked every day, so a Node release reaches a PR within a day.
#
# The Convex image arrives as a build arg from docker-compose.stack.yml, where
# scripts/convex-repin.sh keeps it. Stay on the major in upstream's .nvmrc at
# that pin: the executor is built and tested there, and a minor or patch moves
# within one major keep the same ABI.
ARG CONVEX_IMAGE

FROM node:22.23.5-bookworm-slim@sha256:be979e5523c76fa4d5ca4ebd3099078f220aa47ec39c48ad5b5df9314debd6eb AS node

FROM ${CONVEX_IMAGE}
COPY --from=node /usr/local/bin/node /usr/bin/node
# Fails the build if the binary cannot load against the image's libraries.
RUN ["node", "--version"]
# Let the backend run as an unprivileged user (docker-compose.stack.yml sets
# `user:`): upstream ships its binaries and scripts owner-only executable
# (0744, root), so a non-root uid could not start them. Node does the chmod so
# the same file works for the dashboard image, which has none of these files.
RUN ["node", "-e", "const fs = require('node:fs'); for (const f of ['convex-local-backend', 'generate_key', 'run_backend.sh', 'read_credentials.sh', 'generate_admin_key.sh']) { const p = '/convex/' + f; if (fs.existsSync(p)) fs.chmodSync(p, 0o755); }"]
