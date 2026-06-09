# One-shot deployer: pushes the Convex functions, sets the deployment env, and
# seeds, all inside the compose stack (no host Bun, no manual admin-key copy).
# It uses the convex CLI from the repo lockfile and reads the admin key from the
# shared volume the `keygen` service writes. See docs/beta-deploy.md.
FROM oven/bun:1.3.14
WORKDIR /app

COPY package.json bun.lock ./
RUN bun install --frozen-lockfile
COPY . .
RUN chmod +x docker/deploy-entrypoint.sh

ENTRYPOINT ["./docker/deploy-entrypoint.sh"]
