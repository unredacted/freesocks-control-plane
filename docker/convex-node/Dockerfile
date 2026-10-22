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

FROM node:22.23.4-bookworm-slim@sha256:de170b39439eb0e5a3444ad7d60b015614a381e10fecae2e30ec9e735122f38d AS node

FROM ${CONVEX_IMAGE}
COPY --from=node /usr/local/bin/node /usr/bin/node
# Fails the build if the binary cannot load against the image's libraries.
RUN ["node", "--version"]
