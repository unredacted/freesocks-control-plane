# Multi-stage image for the beta web tier: build the Svelte SPA with Bun, then
# serve it (and reverse-proxy the Convex HTTP actions) with Caddy. The whole repo
# is the build context (the SPA imports from src/shared); .dockerignore keeps
# node_modules / dist / .git / .env* and database exports out. The final stage
# copies only dist/ and the Caddyfile. See docs/beta-deploy.md.

# --- build the SPA ---------------------------------------------------------
FROM oven/bun:1.4.4@sha256:1d22548f177f4ff38e0c15baa3c2c46c6c2060ba2d1bc573bb4720b407548f1d AS build
WORKDIR /app

# Install against the lockfile first so deps cache independently of source.
COPY package.json bun.lock ./
RUN bun install --frozen-lockfile

COPY . .

# CDN-blinding (app-layer encryption) pins. Left EMPTY for beta, so the SPA ships
# "dark" (plaintext dual-mode over TLS, no sealing). To turn it on, pass these as
# build args (the matching private halves go in the Convex deployment env). The
# SPA build needs no convex/ codegen (tsconfig excludes convex).
ARG VITE_FS_MANIFEST_PK=""
ARG VITE_FS_MANIFEST_PK_PQ=""
ARG VITE_FS_SERVER_HPKE_KID=""
ARG VITE_FS_SERVER_HPKE_PK=""
ARG VITE_CONVEX_SITE_URL=""
ENV VITE_FS_MANIFEST_PK=$VITE_FS_MANIFEST_PK \
    VITE_FS_MANIFEST_PK_PQ=$VITE_FS_MANIFEST_PK_PQ \
    VITE_FS_SERVER_HPKE_KID=$VITE_FS_SERVER_HPKE_KID \
    VITE_FS_SERVER_HPKE_PK=$VITE_FS_SERVER_HPKE_PK \
    VITE_CONVEX_SITE_URL=$VITE_CONVEX_SITE_URL

RUN bun run build

# --- serve with Caddy ------------------------------------------------------
# Pinned by digest (P1-20) for reproducible, supply-chain-safe builds — matches
# the digest-pinning of the Convex backend/dashboard images. Multi-arch manifest
# digest for caddy:2-alpine. Re-pin on upgrade:
#   docker buildx imagetools inspect caddy:2-alpine
FROM caddy:2-alpine@sha256:e70b164da81ef698b3ad19af799ea6086ce6d9e48ed4079eb9fe26f6fbf14ee5
COPY --from=build /app/dist /srv/dist
# A default Caddyfile so the image runs standalone; compose bind-mounts the repo
# copy over it so header tweaks reload without rebuilding the SPA image.
COPY Caddyfile /etc/caddy/Caddyfile
