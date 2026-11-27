# A3 backup sidecar: pg_dump (matching PG18 client) + the AWS CLI for S3-compatible
# offsite upload + age for at-rest encryption of the dumps. Based on the same
# Postgres image so the dump client version matches the server. See docker/backup.sh.
FROM postgres:18.7-trixie@sha256:c699303802144847d238196173655dbbecf7a96aeca1565f2b02eb671a1f0b6b
RUN apt-get update \
  && apt-get install -y --no-install-recommends awscli age ca-certificates openssl \
  && rm -rf /var/lib/apt/lists/*
COPY docker/backup.sh /usr/local/bin/backup.sh
RUN chmod +x /usr/local/bin/backup.sh
ENTRYPOINT ["/usr/local/bin/backup.sh"]
