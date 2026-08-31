# A3 backup sidecar: pg_dump (matching PG18 client) + the AWS CLI for S3-compatible
# offsite upload + age for at-rest encryption of the dumps. Based on the same
# Postgres image so the dump client version matches the server. See docker/backup.sh.
FROM postgres:18@sha256:4ef4dbc939d61acea57712655ddb4b4ab27419c913f94cca0cd57cb3ea3c2280
RUN apt-get update \
  && apt-get install -y --no-install-recommends awscli age ca-certificates \
  && rm -rf /var/lib/apt/lists/*
COPY docker/backup.sh /usr/local/bin/backup.sh
RUN chmod +x /usr/local/bin/backup.sh
ENTRYPOINT ["/usr/local/bin/backup.sh"]
