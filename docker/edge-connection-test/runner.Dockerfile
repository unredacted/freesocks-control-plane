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
FROM docker:29.10.0-cli@sha256:34507eb5069d8be82c95dd3b6987d4250fd5fee49b82e2509b7d7a7030740d6d AS docker-cli
FROM oven/bun:${BUN_VERSION} AS bun
FROM node:24.22.3-bookworm-slim@sha256:dc26ae92c9fb15cf6b1d63e20f0944b2efe0f115b20e00be48fb23fceb061c54
COPY --from=docker-cli /usr/local/bin/docker /usr/local/bin/docker
COPY --from=bun /usr/local/bin/bun /usr/local/bin/bun
RUN ln -s /usr/local/bin/bun /usr/local/bin/bunx
