# Dependabot's /docker/cap entry watches the tag AND digest. patch.mjs checks
# the exact modules before applying the privacy overlay. A new
# upstream release must be reviewed and pass the real integration suite.
FROM tiago2/cap:4.0.18@sha256:0c3900ef768d1ba73b59dd99650faa4011128bcbaed6a22c692b58375d7f741a
COPY --chown=bun:bun patch.mjs context.mjs start.mjs ./fcp/
RUN ["bun", "./fcp/patch.mjs"]
ENTRYPOINT ["bun", "./fcp/start.mjs"]
