# FCP's client-check service (docs/edges.md § "FCP's own client check"): a real
# client engine connects through an edge address with FCP's check credential and
# fetches an egress-IP page through it. Build context = the repo root (the
# service shares its wire contract with FCP: convex/lib/edges/clientCheck/).
#
# The engines come from their projects' own images, digest pinned, and are
# copied into the Bun runtime the rest of the stack uses (the Bun pin must equal
# `packageManager`, convex/deployPins.test.ts). Dependabot proposes new pins daily
# (.github/dependabot.yml). sing-box is what most members' apps run; Xray is the
# other family, and the only one that speaks XHTTP.
FROM ghcr.io/sagernet/sing-box:v1.14.3@sha256:80c639ba467885b28511fb7c980565c2d30a8752f778e7bc8abdbc91fbfd95ec AS singbox
FROM ghcr.io/xtls/xray-core:26.10.21@sha256:d5c3729dfeed7c412af17a63b941c48c76ba68afee5b6184fe4078f8fa8bedcc AS xray

FROM oven/bun:1.4.4@sha256:1d22548f177f4ff38e0c15baa3c2c46c6c2060ba2d1bc573bb4720b407548f1d AS build
WORKDIR /src
COPY src/shared/contracts/edgeCodes.ts src/shared/contracts/
COPY convex/lib/edges/ip.ts convex/lib/edges/
COPY convex/lib/edges/clientCheck/protocol.ts convex/lib/edges/clientCheck/signing.ts convex/lib/edges/clientCheck/sanitize.ts convex/lib/edges/clientCheck/engine.ts convex/lib/edges/clientCheck/
COPY docker/edge-client-check/server.ts docker/edge-client-check/
RUN bun build docker/edge-client-check/server.ts --target=bun --outfile=/out/server.js

FROM oven/bun:1.4.4@sha256:1d22548f177f4ff38e0c15baa3c2c46c6c2060ba2d1bc573bb4720b407548f1d
COPY --from=singbox /usr/local/bin/sing-box /usr/local/bin/sing-box
COPY --from=xray /usr/local/bin/xray /usr/local/bin/xray
COPY --from=build /out/server.js /app/server.js
USER bun
EXPOSE 8080
CMD ["bun", "/app/server.js"]
