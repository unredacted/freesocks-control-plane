# FreeSocks Control Plane: Bun self-host image.
# Build with:    docker build -t freesocks-control-plane:bun .
# Run with:      docker run --rm -p 3000:3000 -e SQLITE_PATH=/data/freesocks.sqlite \
#                  -v ./data:/data --env-file ./.env freesocks-control-plane:bun
#
# This image is for users who prefer to self-host on a VPS / Fly.io / Railway / Render
# instead of Cloudflare Workers. The Cloudflare Workers deploy path (`bun run deploy:prod`)
# is the recommended primary target for low-latency edge access; this is the alternative.

# ---- builder ----
FROM oven/bun:1.3.14-alpine AS builder
WORKDIR /app

# Cache deps separately from source
COPY package.json bun.lock* ./
RUN bun install --frozen-lockfile

# Copy the rest and build
COPY . .
# We build with the Cloudflare-flavored config because that's what the Vite plugin
# emits a static SPA from (dist/client/). The Bun runtime entry doesn't use the
# emitted dist/ssr/wrangler.json at all, so production-vs-beta config selection
# only matters for assets like the Turnstile site key embedded into the SPA.
RUN bun run build:prod

# Strip dev dependencies for the runtime image
RUN bun install --production --frozen-lockfile

# ---- runtime ----
FROM oven/bun:1.3.14-alpine AS runtime
WORKDIR /app

# better-sqlite3 needs a few system libs for native compilation; the Alpine image
# we use ships them, but we still set up a non-root user for least-privilege.
RUN addgroup -S app && adduser -S app -G app && \
    mkdir -p /data && chown -R app:app /data

# Copy built artifacts + production node_modules
COPY --from=builder --chown=app:app /app/dist ./dist
COPY --from=builder --chown=app:app /app/node_modules ./node_modules
COPY --from=builder --chown=app:app /app/package.json ./package.json
COPY --from=builder --chown=app:app /app/src ./src
COPY --from=builder --chown=app:app /app/src-entries ./src-entries

USER app

ENV PORT=3000
ENV SQLITE_PATH=/data/freesocks.sqlite
EXPOSE 3000

# Healthcheck hits the worker's healthz endpoint
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD bun -e "fetch('http://localhost:'+process.env.PORT+'/api/healthz').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"

CMD ["bun", "src-entries/bun.ts"]
