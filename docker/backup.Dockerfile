# age, built from source with a current Go. Debian's package is compiled with
# the Go Debian had when it was packaged (1.24.4 in trixie), so every later Go
# security release showed up as an unfixable finding against it. The age
# version is docker/age/go.mod (Dependabot's gomod entry); the Go toolchain is
# this base image (Dependabot's docker entry). Both move without anyone
# tracking them.
FROM golang:1.27.3-trixie@sha256:fbb7ae40b62ff8afe31662df570d39b4f5052ac32b90dae8e60d7657a20a74f4 AS age
WORKDIR /src
COPY docker/age/ ./
RUN CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o /out/ \
  filippo.io/age/cmd/age filippo.io/age/cmd/age-keygen

# A3 backup sidecar: pg_dump (matching PG18 client) + the AWS CLI for S3-compatible
# offsite upload + age for at-rest encryption of the dumps. Based on the same
# Postgres image so the dump client version matches the server. See docker/backup.sh.
FROM postgres:18@sha256:edb0c08dc33befd0262ab3b5cf1c4f3f8cfd8b09e88c05b45adee29d6761ddb6
RUN apt-get update \
  && apt-get install -y --no-install-recommends awscli ca-certificates \
  && rm -rf /var/lib/apt/lists/*
COPY --from=age /out/age /out/age-keygen /usr/local/bin/
COPY docker/backup.sh /usr/local/bin/backup.sh
RUN chmod +x /usr/local/bin/backup.sh
ENTRYPOINT ["/usr/local/bin/backup.sh"]
