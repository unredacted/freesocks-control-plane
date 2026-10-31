# FCP's client-check service (docs/edges.md § "FCP's own client check"): a real
# client engine connects through an edge address with FCP's check credential and
# fetches an egress-IP page through it. Build context = the repo root (the
# service shares its wire contract with FCP: convex/lib/edges/clientCheck/).
#
# The engines come from their projects' own images, digest pinned, and are
# copied into the Bun runtime the rest of the stack uses (the Bun pin must equal
# `packageManager`, convex/deployPins.test.ts). Dependabot proposes new pins daily
# (.github/dependabot.yml). sing-box is what most members' apps run; Xray is the
# other family, and the only one that speaks XHTTP; Mihomo is the Clash family's
# engine (a test of a send's server names runs it too).
FROM ghcr.io/sagernet/sing-box:v1.14.4@sha256:0788ffbddab2c68a99a2dd4780bbc50902f159af6f589df3ee74a8389d278279 AS singbox
FROM ghcr.io/xtls/xray-core:26.10.31@sha256:ceabeac03a89d991d2a247361825c1d1d2e9c91cd5dc010f298c7dc0c2f325c9 AS xray
FROM docker.io/metacubex/mihomo:v1.19.33@sha256:9211361a3ed85305383288d38c05e85862d6d5a590c10007c37fc059cca82e9c AS mihomo

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
COPY --from=mihomo /mihomo /usr/local/bin/mihomo
COPY --from=build /out/server.js /app/server.js
USER bun
EXPOSE 8080
CMD ["bun", "/app/server.js"]
