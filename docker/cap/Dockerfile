# Dependabot's /docker/cap entry watches the tag AND digest. patch.mjs checks
# the exact modules before applying the privacy overlay. A new
# upstream release must be reviewed and pass the real integration suite.
FROM tiago2/cap:4.0.16@sha256:d997debb413e7519553f56c74847c466687328f4f9c7ef8dc397ed318a228d6b
COPY --chown=bun:bun patch.mjs context.mjs start.mjs ./fcp/
RUN ["bun", "./fcp/patch.mjs"]
ENTRYPOINT ["bun", "./fcp/start.mjs"]
