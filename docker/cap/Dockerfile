# Dependabot's /docker/cap entry watches the tag AND digest. patch.mjs checks
# the exact modules before applying the privacy overlay. A new
# upstream release must be reviewed and pass the real integration suite.
FROM tiago2/cap:4.0.9@sha256:23f4521fc8a1105b78620a15730f01b137399a98a23efb775c33ae1132e39d89
COPY --chown=bun:bun patch.mjs context.mjs start.mjs ./fcp/
RUN ["bun", "./fcp/patch.mjs"]
ENTRYPOINT ["bun", "./fcp/start.mjs"]
