# One-shot deployer: pushes the Convex functions, sets the deployment env, and
# seeds, all inside the compose stack (no host Bun, no manual admin-key copy).
# It uses the convex CLI from the repo lockfile and reads the admin key from the
# shared volume the `keygen` service writes. See docs/beta-deploy.md.
FROM oven/bun:1.4.5@sha256:3aa040e5445efa09d75bb428a64ba50db13e2b3ac9b6b0c7f145615f62b2ee18
WORKDIR /app

COPY package.json bun.lock ./
RUN bun install --frozen-lockfile
# Everything .dockerignore lets through lands in the image, so database exports
# and env captures live outside the checkout (docs/beta-deploy.md § Exports stay
# outside the checkout) and .dockerignore drops any left behind.
COPY . .
RUN chmod +x docker/deploy-entrypoint.sh

ENTRYPOINT ["./docker/deploy-entrypoint.sh"]
