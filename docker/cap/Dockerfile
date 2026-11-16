# Dependabot's /docker/cap entry watches the tag AND digest. patch.mjs checks
# the exact modules before applying the privacy overlay. A new
# upstream release must be reviewed and pass the real integration suite.
FROM tiago2/cap:4.0.14@sha256:11b3f84e1e5ebc988fdd1cdb464c6cfb911f98368052ada65c1c1df94689a13d
COPY --chown=bun:bun patch.mjs context.mjs start.mjs ./fcp/
RUN ["bun", "./fcp/patch.mjs"]
ENTRYPOINT ["bun", "./fcp/start.mjs"]
