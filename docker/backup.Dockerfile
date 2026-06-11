# A3 backup sidecar: pg_dump (matching PG18 client) + the AWS CLI for S3-compatible
# offsite upload. Based on the same Postgres image so the dump client version
# matches the server. See docker/backup.sh.
FROM postgres:18@sha256:fd03421d521b789274856f57ba64914f8271255ef1415ac307cbc907121c8c7b
RUN apt-get update \
  && apt-get install -y --no-install-recommends awscli ca-certificates \
  && rm -rf /var/lib/apt/lists/*
COPY docker/backup.sh /usr/local/bin/backup.sh
RUN chmod +x /usr/local/bin/backup.sh
ENTRYPOINT ["/usr/local/bin/backup.sh"]
