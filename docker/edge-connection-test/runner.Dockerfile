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
FROM docker:28.5.2-cli@sha256:625d9431a9f54c5a2bc90f24f0e1c3d55b1349fd857dd85035f98c2c9acbdd4d AS docker-cli
FROM oven/bun:${BUN_VERSION} AS bun
FROM node:24-bookworm-slim@sha256:0e0ff40c39bc087845bfb27465a0df4ea419520094bc35842ff83dd8cbe6f9b6
COPY --from=docker-cli /usr/local/bin/docker /usr/local/bin/docker
COPY --from=bun /usr/local/bin/bun /usr/local/bin/bun
RUN ln -s /usr/local/bin/bun /usr/local/bin/bunx
