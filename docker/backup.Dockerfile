# A3 backup sidecar: pg_dump (matching PG18 client) + the AWS CLI for S3-compatible
# offsite upload + age for at-rest encryption of the dumps. Based on the same
# Postgres image so the dump client version matches the server. See docker/backup.sh.
FROM postgres:18.7-trixie@sha256:eb63372c1e05c755f55fa30cbd07aecc443676fc6c0fa90b9002d01537841e1a
RUN apt-get update \
  && apt-get install -y --no-install-recommends awscli age ca-certificates \
  && rm -rf /var/lib/apt/lists/*
COPY docker/backup.sh /usr/local/bin/backup.sh
RUN chmod +x /usr/local/bin/backup.sh
ENTRYPOINT ["/usr/local/bin/backup.sh"]
