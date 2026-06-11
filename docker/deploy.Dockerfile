# One-shot deployer: pushes the Convex functions, sets the deployment env, and
# seeds, all inside the compose stack (no host Bun, no manual admin-key copy).
# It uses the convex CLI from the repo lockfile and reads the admin key from the
# shared volume the `keygen` service writes. See docs/beta-deploy.md.
FROM oven/bun:1.3.14@sha256:e10577f0db68676a7024391c6e5cb4b879ebd17188ab750cf10024a6d700e5c4
WORKDIR /app

COPY package.json bun.lock ./
RUN bun install --frozen-lockfile
COPY . .
RUN chmod +x docker/deploy-entrypoint.sh

ENTRYPOINT ["./docker/deploy-entrypoint.sh"]
