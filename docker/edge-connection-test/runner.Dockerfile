# The test runner of the edge connection test: Node + Bun to run vitest (FCP in
# convex-test), and the Docker CLI to drive the client container through the
# host's Docker socket.
#
# Why a container and not the host: FCP's own checks reach the relay nodes the
# way production does. The WebSocket node's ingress check resolves the origin
# hostname through real DNS and dials the node's public address; inside the
# test networks that is Docker's resolver and a bridge address, neither of
# which exists from a macOS host.
# The Bun version is packageManager's (passed in by the run script), like the
# rest of the compat stack.
ARG BUN_VERSION
FROM docker:29.9.3-cli@sha256:2357639ad1ea7d0194134bf3292622fd4e562483966ed674e5d7c945b5f3b28d AS docker-cli
FROM oven/bun:${BUN_VERSION} AS bun
FROM node:24.22.2-bookworm-slim@sha256:01d566e8d94d8c619591d78652babfccd3c6992a3dffa9ed5ab39e11cf6c70e9
COPY --from=docker-cli /usr/local/bin/docker /usr/local/bin/docker
COPY --from=bun /usr/local/bin/bun /usr/local/bin/bun
RUN ln -s /usr/local/bin/bun /usr/local/bin/bunx
