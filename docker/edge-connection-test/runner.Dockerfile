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
FROM docker:29.9.2-cli@sha256:5e6baf67325a79f64ed3bed6863954d5e05d0f3d4e57cbdb14809346814bbfdb AS docker-cli
FROM oven/bun:${BUN_VERSION} AS bun
FROM node:24.22.1-bookworm-slim@sha256:55fb5f5a527ea2c5c4a95f963e48ef90aa38c7b346054fdc8ee9957a2b55d205
COPY --from=docker-cli /usr/local/bin/docker /usr/local/bin/docker
COPY --from=bun /usr/local/bin/bun /usr/local/bin/bun
RUN ln -s /usr/local/bin/bun /usr/local/bin/bunx
