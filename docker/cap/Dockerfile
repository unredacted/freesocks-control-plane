# Dependabot's /docker/cap entry watches the tag AND digest. patch.mjs checks
# the exact modules before applying the privacy overlay. A new
# upstream release must be reviewed and pass the real integration suite.
FROM tiago2/cap:4.0.13@sha256:9eb46e4282e78dacb15b535204ececa1506650499e498a50831e0377b7ac98d1
COPY --chown=bun:bun patch.mjs context.mjs start.mjs ./fcp/
RUN ["bun", "./fcp/patch.mjs"]
ENTRYPOINT ["bun", "./fcp/start.mjs"]
