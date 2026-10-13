FROM debian:13-slim@sha256:a29215f6a35e51e22adffa17f89e9d2ef06214e64a2bad10d765c46aea49f11f
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl openssl python3 procps && rm -rf /var/lib/apt/lists/*
COPY .cache/compat/bin/sing-box /usr/local/bin/sing-box
COPY .cache/compat/bin/mihomo /usr/local/bin/mihomo
COPY scripts/compat/probe.py /probe.py
CMD ["sleep", "infinity"]
