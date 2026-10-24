# One-shot deployer: pushes the Convex functions, sets the deployment env, and
# seeds, all inside the compose stack (no host Bun, no manual admin-key copy).
# It uses the convex CLI from the repo lockfile and reads the admin key from the
# shared volume the `keygen` service writes. See docs/beta-deploy.md.
FROM oven/bun:1.4.4@sha256:1d22548f177f4ff38e0c15baa3c2c46c6c2060ba2d1bc573bb4720b407548f1d
WORKDIR /app

COPY package.json bun.lock ./
RUN bun install --frozen-lockfile
# Everything .dockerignore lets through lands in the image, so database exports
# and env captures live outside the checkout (docs/beta-deploy.md § Exports stay
# outside the checkout) and .dockerignore drops any left behind.
COPY . .
RUN chmod +x docker/deploy-entrypoint.sh

ENTRYPOINT ["./docker/deploy-entrypoint.sh"]
