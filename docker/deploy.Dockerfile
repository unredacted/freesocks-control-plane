# One-shot deployer: pushes the Convex functions, sets the deployment env, and
# seeds, all inside the compose stack (no host Bun, no manual admin-key copy).
# It uses the convex CLI from the repo lockfile and reads the admin key from the
# shared volume the `keygen` service writes. See docs/beta-deploy.md.
FROM oven/bun:1.4.0@sha256:5ff609364c049b54eb0ff560ec96319729a972078ef2c755d758f0c6ef89c2d6
WORKDIR /app

COPY package.json bun.lock ./
RUN bun install --frozen-lockfile
COPY . .
RUN chmod +x docker/deploy-entrypoint.sh

ENTRYPOINT ["./docker/deploy-entrypoint.sh"]
